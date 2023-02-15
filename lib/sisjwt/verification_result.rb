# frozen_string_literal: true

module Sisjwt
  class VerificationResult
    include ActiveModel::Validations

    MAX_ALLOWED_AGE = 1.hour

    attr_reader :token_type, :initial_lifetime, :iss, :aud, :payload, :jwt_error

    def initialize(headers, payload, error: nil)
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
      if @jwt_error.present?
        errors.add(:base, @jwt_error)

        # There is no point in running the rest of the checks as they will all
        # trigger and just add noise
        next if @headers.blank? && @payload.blank?
      end

      errors.add(:base, 'Token is longer lived than allowed') if age > MAX_ALLOWED_AGE.to_i
      errors.add(:base, 'Token is expired') if expired?
      errors.add(:iss, 'not on the approved list') unless @allowed_iss.include?(iss)
      errors.add(:aud, 'not on the approved list') unless @allowed_aud.include?(aud)
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
        if SisJwtOptions.production_env?
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

    def add_allowed_aud(allowed_aud)
      return unless allowed_aud.present? || @allowed_aud.include?(allowed_aud)

      @allowed_aud << allowed_aud
      @allowed_aud.flatten!
      mark_dirty!
    end

    def add_allowed_iss(allowed_iss)
      return unless allowed_iss.present? || @allowed_iss.include?(allowed_iss)

      @allowed_iss << allowed_iss
      @allowed_iss.flatten!
      mark_dirty!
    end

    private

    def mark_dirty!(validate: true)
      @hash = nil
      self.validate if validate
    end

    def build_hash
      {
        headers: @headers,
        payload: @payload,
        allowed: {
          aud: @allowed_aud,
          iss: @allowed_iss
        },
        valid: valid?,
        errors: errors
      }
    end

    def dev_lifetime
      { life_left: life_left, age: age, expired: expired? }
    end
  end
end
