require 'active_model'

module Sisjwt
  TOKEN_TYPE_V1 = "SISJWT1.0".freeze
  TOKEN_TYPE_DEV = "SISJWTd".freeze

  class SisJwtOptions
    include ActiveModel::Validations

    # attr_accessor :key_id, :key_alg, :token_type
    # attr_accessor :exp, :iss, :iat, :sub
    attr_accessor :token_type, :key_alg, :key_id, :aws_region
    attr_accessor :token_lifetime, :iss, :aud, :iat, :exp

    validates_presence_of :token_type
    validates_presence_of :key_alg
    validates_presence_of :key_id
    validates_presence_of :aws_region
    validates_presence_of :token_lifetime
    validates_presence_of :iss
    validates_presence_of :aud
    # validates_presence_of :iat
    # validates_presence_of :exp

    # iss
    validate do |rec|
      next unless rec.iss == rec.aud
      errors.add(:iss, "Can not be equal to AUDience!")
    end

    # token_type
    validate do |rec|
      next if rec.token_type =~ /^SISKMSd?$/
      errors.add(:token_type, "is not a valid token type!")
    end

    # exp
    validate do |rec|
      exp = rec.exp
      next if exp.nil? # Default

      unless exp.is_a?(Numeric)
        errors.add(:exp, "must be the unix timestamp the token expires")
      end

      if exp < rec.iat
        errors.add(:exp, "can not be before the token was issued (iat)")
      end
    end

    def self.current
      @current ||= SisJwtOptions.defaults
    end

    def self.defaults
      is_prod = ENV['RAILS_ENV'] == 'production'
      SisJwtOptions.new.tap do |opts|
        opts.token_type = is_prod ? TOKEN_TYPE_V1 : TOKEN_TYPE_DEV

        opts.aws_region = ENV.fetch("AWS_REGION", "us-west-2")
        opts.key_id = ENV["SISJWT_KEY_ID"]
        opts.key_alg = ENV.fetch("SISJWT_KEY_ALG", "ECDSA_SHA_256")
        opts.iss = ENV.fetch("SISJWT_ISS", "SIS")
        opts.aud = ENV.fetch("SISJWT_AUD", "SIS")

        opts.token_lifetime = (is_prod ? 1.minute : 1.hour).to_i
        opts.iat = nil
        opts.exp = nil

        opts.validate
      end
    end

    def iat
      return @iat unless @iat.nil?
      DateTime.now.to_f
    end

    def exp
      return @exp unless @exp.nil?
      (iat + token_lifetime.to_i).to_i
    end

    def token_type
      return @token_type unless defined?(Rails)
      if Rails.env.production? && @token_type == TOKEN_TYPE_DEV
        raise Error("Can not issue dev tokens in production!")
      end
      @token_type
    end
  end
end
