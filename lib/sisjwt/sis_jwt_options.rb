require 'active_model'
require 'active_support'
require 'active_support/core_ext'

module Sisjwt
  TOKEN_TYPE_V1 = "SISKMS1.0".freeze
  TOKEN_TYPE_DEV = "SISKMSd".freeze

  class SisJwtOptions
    include ActiveModel::Validations

    def self.valid_token_type(token_type)
      [
        TOKEN_TYPE_V1,
        SisJwtOptions.production_env? ? nil : TOKEN_TYPE_DEV,
      ].compact.include?(token_type)
    end

    attr_reader :mode
    attr_accessor :token_type, :key_alg, :key_id, :aws_region, :aws_profile
    attr_accessor :token_lifetime, :iss, :aud, :iat, :exp

    def initialize(mode: :sign)
      raise "invalid mode: #{mode}" unless %i[sign verify].include?(mode)
      @mode = mode
    end

    def to_h
      {
        mode: mode,
        token_type: token_type,
        key_alg: key_alg,
        key_id: key_id,
        aws_region: aws_region,
        aws_profile: aws_profile,
        token_lifetime: token_lifetime,
        iss: iss,
        aud: aud,
        iat: iat,
        exp: exp,
      }.compact
    end

    validates_presence_of :token_type, if: -> { mode == :sign }
    validates_presence_of :key_alg, if: -> { mode == :sign }
    validates_presence_of :key_id, if: -> { mode == :sign }
    validates_presence_of :aws_region, if: -> { mode == :sign }
    validates_presence_of :token_lifetime, if: -> { mode == :sign }
    validates_presence_of :iss, if: -> { mode == :sign }
    validates_presence_of :aud, if: -> { mode == :sign }

    # Common (sign/verify) validations
    validate do |rec|
      unless rec.valid_token_type?
        errors.add(:token_type, "is invalid")
      end
    end

    # Signing Mode Validations
    validate do |rec|
      next unless rec.mode == :sign

      # iss/aud distinctness
      if rec.iss == rec.aud
        errors.add(:iss, "Can not be equal to AUDience!")
      end

      # exp
      exp = rec.exp
      if exp.present?
        unless exp.is_a?(Numeric)
          errors.add(:exp, "must be the unix timestamp the token expires")
        end

        if exp < rec.iat
          errors.add(:exp, "can not be before the token was issued (iat)")
        end
      end

      # token_type / config
      unless rec.token_type =~ /^SISKMSd?$/
        errors.add(:token_type, "is not a valid token type!")
      end
      if SisJwtOptions.production_env? && !rec.production_token_type?
        errors.add(:base, "Can not issue non-production tokens in a production environment")
      end

      if SisJwtOptions.production_env? && !rec.kms_configured?
        errors.add(:base, "AWS KMS is not properly configured")
      end
    end

    def self.current
      @current ||= SisJwtOptions.defaults
    end

    def self.defaults(mode: :sign)
      SisJwtOptions.new(mode: mode).tap do |opts|
        opts.token_type = production_env? ? TOKEN_TYPE_V1 : TOKEN_TYPE_DEV

        opts.aws_profile = ENV.fetch("AWS_PROFILE", (production_env? ? '' : "dev"))
        opts.aws_region = ENV.fetch("AWS_REGION", "us-west-2")
        opts.key_id = ENV["SISJWT_KEY_ID"]
        opts.key_alg = ENV.fetch("SISJWT_KEY_ALG", "RSASSA_PKCS1_V1_5_SHA_256")
        opts.iss = ENV.fetch("SISJWT_ISS", "SIS")
        opts.aud = ENV.fetch("SISJWT_AUD", "SIS")

        opts.token_lifetime = (production_env? ? 60 : 3_600).to_i
        opts.iat = nil
        opts.exp = nil

        opts.validate if mode == :sign
      end
    end

    # Are we running in a production environment?
    def self.production_env?
      if (env = ENV['RAILS_ENV']).present?
        return true if env.downcase.strip == "production"
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

    def key_id
      return unless kms_configured?
      @key_id
    end

    def key_alg
      return unless kms_configured?
      @key_alg
    end

    def token_type
      return @token_type unless defined?(Rails)

      # Check to make sure that we are not returning weak dev tokens in prod envs
      if self.class.production_env? && @token_type == TOKEN_TYPE_DEV
        raise Error("Can not issue dev tokens in production!")
      end
      @token_type
    end

    def production_token_type?
      [
        TOKEN_TYPE_V1,
      ].include?(@token_type)
    end

    def valid_token_type?
      self.class.valid_token_type(@token_type)
    end

    # Are all the values requried to make a KMS call configured?
    def kms_configured?
      return true if production_token_type? &&
        @aws_region.present? &&
        @key_id.present? &&
        @key_alg.present?
    end
  end
end
