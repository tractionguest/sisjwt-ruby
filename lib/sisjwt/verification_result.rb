module Sisjwt
  class VerificationResult
    include ActiveModel::Validations

    MAX_ALLOWED_AGE = 3_600

    attr_reader :token_type, :initial_lifetime, :iss, :aud, :payload, :jwt_error

    def initialize(headers, payload, error:nil)
      @headers = (headers || {}).freeze
      @payload = (payload || {}).freeze
      @jwt_error = error

      @token_type = @headers["alg"]
      @initial_lifetime = exp - iat.to_i
      @iss = @payload["iss"]
      @aud = @payload["aud"]

      clear_allowed!  # Will handle calling validate
    end

    validate do
      # Check to see if we have an additional error to report
      if @jwt_error.present?
        errors.add(:base, @jwt_error)

        if @headers.blank? && @payload.blank?
          # There is no point in running the rest of the checks as they
          # will all trigger and just add noise
          next
        end
      end

      if expired?
        errors.add(:base, "Token is expired")
      end
      if age > MAX_ALLOWED_AGE
        errors.add(:base, "Token is longer lived than allowed")
      end

      unless @allowed_iss.include?(iss)
        errors.add(:iss, "not on the approved list")
      end
      unless @allowed_aud.include?(aud)
        errors.add(:aud, "not on the approved list")
      end
    end

    def exp
      @exp ||= payload.fetch("exp", Time.now.to_i - 1)
    end

    def iat
      @iat ||= payload.fetch("iat", Time.now.to_i)
    end

    def life_left
      exp - Time.now.to_i
    end

    def age
      Time.now.to_i - iat.to_i
    end

    def expired?
      life_left <= 0
    end

    def to_h
      @hash ||=
        {
          headers: @headers,
          payload: @payload,
          allowed: {
            aud: @allowed_aud,
            iss: @allowed_iss,
          },

        }
      if Rails.env.development?
        return @hash.merge( lifetime: {
          life_left: life_left,
          age: age,
          expired: expired?,
        })
      end
      @hash
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
      return if allowed_aud.blank?
      unless @allowed_aud.include?(allowed_aud)
        @allowed_aud << allowed_aud
        @allowed_aud.flatten!
        mark_dirty!
      end
    end

    def add_allowed_iss(allowed_iss)
      return if allowed_iss.blank?
      unless @allowed_iss.include?(allowed_iss)
        @allowed_iss << allowed_iss
        @allowed_iss.flatten!
        mark_dirty!
      end
    end

    private

    def mark_dirty!(validate: true)
      @hash = nil
      self.validate if validate
    end
  end
end

