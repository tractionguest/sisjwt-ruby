require 'active_model'

module Sisjwt
  TOKEN_TYPE_V1 = "SISKMS1.0".freeze
  TOKEN_TYPE_DEV = "SISKMSd".freeze

  class SisJwtOptions
    include ActiveModel::Validations

    attr_accessor :token_type, :key_alg, :key_id, :aws_region, :aws_profile
    attr_accessor :token_lifetime, :iss, :aud, :iat, :exp

    validates_presence_of :token_type
    validates_presence_of :key_alg
    validates_presence_of :key_id
    validates_presence_of :aws_region
    validates_presence_of :token_lifetime
    validates_presence_of :iss
    validates_presence_of :aud

    # iss
    validate do |rec|
      if rec.iss == rec.aud
        errors.add(:iss, "Can not be equal to AUDience!")
      end
    end

    # token_type
    validate do |rec|
      unless rec.token_type =~ /^SISKMSd?$/
        errors.add(:token_type, "is not a valid token type!")
      end
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

    # token_token / config
    validate do |rec|
      if SisJwtOptions.production_env? && !rec.production_config?
        errors.add(:base, "Can not issue non-production tokens in a production environment")
      end

      if SisJwtOptions.production_env? && !rec.kms_configured?
        errors.add(:base, "AWS KMS is not properly configured")
      end
    end

    def self.current
      @current ||= SisJwtOptions.defaults
    end

    def self.defaults
      SisJwtOptions.new.tap do |opts|
        opts.token_type = production_env? ? TOKEN_TYPE_V1 : TOKEN_TYPE_DEV

        opts.aws_region = ENV.fetch("AWS_PROFILE", production_env? ? '' : "dev")
        opts.aws_region = ENV.fetch("AWS_REGION", "us-west-2")
        opts.key_id = ENV["SISJWT_KEY_ID"]
        opts.key_alg = ENV.fetch("SISJWT_KEY_ALG", "RSASSA_PKCS1_V1_5_SHA_256")
        opts.iss = ENV.fetch("SISJWT_ISS", "SIS")
        opts.aud = ENV.fetch("SISJWT_AUD", "SIS")

        opts.token_lifetime = (production_env? ? 1.minute : 1.hour).to_i
        opts.iat = nil
        opts.exp = nil

        opts.validate
      end
    end

    # Are we running in a production environment?
    def self.production_env?
      if defined?(Rails)
        true if Rails.env.production?
      end

      if (env = ENV['RAILS_ENV']).present?
        true if env.downcase.strip == "production"
      end

      false
    end

    def error_messages(revalidate: true)
      validate if revalidate
      return if valid?

      msg = %w(Errors:)
      errors.messages.each do |attr, errors|
        errors.each do |error|
          msg << "\t#{attr} #{error}"
        end
      end

      msg.join("\n")
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

      # Check to make sure that we are not returning weak dev tokens in prod envs
      if Rails.env.production? && @token_type == TOKEN_TYPE_DEV
        raise Error("Can not issue dev tokens in production!")
      end
      @token_type
    end

    def production_config?
      @token_type != TOKEN_TYPE_DEV
    end

    # Are all the values requried to make a KMS call configured?
    def kms_configured?
      return true if token_type != TOKEN_TYPE_DEV &&
        aws_region.present? &&
        key_id.present? &&
        key_alg.present?
    end
  end
end
