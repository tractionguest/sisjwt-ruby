# frozen_string_literal: true

module Sisjwt
  # The results of verifying a token with {SisJwt#verify}.
  class VerificationResult
    include ActiveModel::Validations

    MAX_ALLOWED_AGE = 1.hour

    attr_reader :allowed_aud, :allowed_iss, :aud, :headers, :initial_lifetime,
                :iss, :jwt_error, :payload, :token_type

    def self.error(msg)
      new(nil, nil, error: msg)
    end

    def initialize(headers, payload, error: nil, options: nil)
      @options = options
      @headers = (headers || {}).freeze
      @payload = (payload || {}).freeze
      @jwt_error = error

      @token_type = @headers['alg']
      @initial_lifetime = (exp - iat).to_i
      @iss = @payload['iss']
      @aud = @payload['aud']

      clear_allowed! # Will handle calling validate
    end

    validate do
      # Check to see if we have an additional error to report
      if jwt_error.present?
        errors.add(:base, jwt_error)

        # There is no point in running the rest of the checks as they will all
        # trigger and just add noise
        next if headers.blank? && payload.blank?
      end

      errors.add(:base, 'Token is longer lived than allowed') if age > MAX_ALLOWED_AGE.to_i
      errors.add(:base, 'Token is expired') if expired?
      errors.add(:iss, "#{iss.inspect} is not in the approved list") unless payload_allowed?(:iss)
      errors.add(:aud, "#{aud.inspect} is not in the approved list") unless payload_allowed?(:aud)

      unless @options&.arn_inventory.blank?
        arn_inventory = @options&.arn_inventory

        unless arn_inventory.valid_arn?(allowed_iss, @headers['kid'])
          errors.add(:iss, 'not signed with an approved key')
        end
      end
    end

    # @return [Time] When the token expires.
    def exp
      @exp ||= payload.fetch('exp', Time.now.to_i - 1)
    end

    # @return [Time] When the token was issued.
    def iat
      @iat ||= payload.fetch('iat', Time.now.to_i)
    end

    # @return [Integer] The time until the token expires, in seconds.
    def life_left
      exp - Time.now.to_i
    end

    # @return [Integer] The age of the token, in seconds.
    def age
      Time.now.to_i - iat.to_i
    end

    def expired?
      life_left <= 0
    end

    def to_h
      @to_h ||=
        if Runtime.production_env?
          build_hash
        else
          build_hash.merge(lifetime: dev_lifetime)
        end
    end

    def to_json(*args)
      to_h.to_json(*args)
    end

    #
    # Allowed Management
    #
    def clear_allowed!
      @allowed_aud = []
      @allowed_iss = []
      mark_dirty!
    end

    # @param aud [#to_s] A valid, case-insensitive audience for the token being
    #   validated.
    def add_allowed_aud(aud)
      return if aud.blank? || allowed_aud.include?(aud.to_s)

      allowed_aud << aud.to_s
      mark_dirty!
    end

    # @param iss [#to_s] A valid, case-insensitive issuer for the token being
    #   validated.
    def add_allowed_iss(iss)
      return if iss.blank? || allowed_iss.include?(iss.to_s)

      allowed_iss << iss.to_s
      mark_dirty!
    end

    private

    def mark_dirty!(validate: true)
      @to_h = nil
      self.validate if validate
    end

    def build_hash
      {
        headers: headers,
        payload: payload,
        allowed: { aud: allowed_aud, iss: allowed_iss },
        valid: valid?,
        errors: errors,
      }
    end

    def dev_lifetime
      { life_left: life_left, age: age, expired: expired? }
    end

    def payload_allowed?(payload_key)
      val = send(payload_key)
      send(:"allowed_#{payload_key}").any? { |allowed| allowed.casecmp?(val) }
    end
  end
end
