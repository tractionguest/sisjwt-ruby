# frozen_string_literal: true

require 'active_model'
require 'active_support'
require 'active_support/core_ext'

module Sisjwt
  AWS_REGION = ENV.fetch('AWS_REGION', 'us-west-2')
  SISJWT_AUD = ENV.fetch('SISJWT_AUD', 'SISa')
  SISJWT_ISS = ENV.fetch('SISJWT_ISS', 'SISi')
  SISJWT_KEY_ALG = ENV.fetch('SISJWT_KEY_ALG', 'RSASSA_PKCS1_V1_5_SHA_256')
  SISJWT_KEY_ID = ENV['SISJWT_KEY_ID']
  TOKEN_TYPE_DEV = 'SISKMSd'
  TOKEN_TYPE_V1 = 'SISKMS1.0'
  VALID_MODES = %i[sign verify].freeze

  class SisJwtOptions
    include ActiveModel::Validations

    attr_reader :mode
    attr_writer :exp, :iat, :key_alg, :key_id, :token_type
    attr_accessor :aws_region, :aws_profile, :token_lifetime, :iss, :aud

    validates_presence_of :key_alg, if: -> { mode == :sign && kms_configured? }
    validates_presence_of :key_id, if: -> { mode == :sign && kms_configured? }
    validates_presence_of :aws_region, if: -> { mode == :sign && kms_configured? }
    validates_presence_of :token_lifetime, if: -> { mode == :sign }
    validates_presence_of :iss, if: -> { mode == :sign }
    validates_presence_of :aud, if: -> { mode == :sign }

    # Common (sign/verify) validations
    validate do |rec|
      errors.add(:token_type, 'is invalid') unless rec.valid_token_type?
    end

    # Signing Mode Validations
    validate do |rec|
      next unless rec.mode == :sign

      # iss/aud distinctness
      if rec.iss == rec.aud
        errors.add(:iss, 'Can not be equal to AUDience!')
      end

      # exp
      exp = rec.exp
      if exp.present?
        if exp.is_a?(Numeric)
          if exp < rec.iat
            errors.add(:exp, 'can not be before the token was issued (iat)')
          end
        else
          errors.add(:exp, 'must be the unix timestamp the token expires')
        end
      end

      # token_type / config
      unless rec.token_type =~ /^SISKMS/
        errors.add(:token_type, "(#{rec.token_type}) is not a valid token type!")
      end
      if SisJwtOptions.production_env? && !rec.production_token_type?
        errors.add(:base, 'Can not issue non-production tokens in a production environment')
      end

      if SisJwtOptions.production_env? && !rec.kms_configured?
        errors.add(:base, 'AWS KMS is not properly configured')
      end
    end

    class << self
      def valid_token_type(token_type)
        [
          TOKEN_TYPE_V1,
          SisJwtOptions.production_env? ? nil : TOKEN_TYPE_DEV
        ].compact.include?(token_type)
      end

      def current
        @current ||= SisJwtOptions.defaults
      end

      def defaults(mode: :sign)
        SisJwtOptions.new(mode: mode).tap do |opts|
          assign_options(opts)
          opts.validate if mode == :sign
        end
      end

      # Are we running in a production environment?
      def production_env?
        # This is more complex for a reason:
        #   It isn't a clear distinction on what to use
        #   in which order, so *if* we have Rails available
        #   (the primary, but not exclusive, use case) then
        #   we offload the problem to Rails and let thier
        #   core devs deal with that problem.
        #   It is written like this so it can easily be tested.
        if Module.const_defined?(:Rails)
          rails = Module.const_get(:Rails)
          return true if rails.respond_to?(:env) && rails.env.production?
        end
        if (env = ENV['RAILS_ENV']).present?
          return true if env.downcase.strip == 'production'
        end

        false
      end

      private

      def assign_options(opts)
        opts.token_type = production_env? ? TOKEN_TYPE_V1 : TOKEN_TYPE_DEV

        opts.aws_profile = ENV.fetch('AWS_PROFILE', (production_env? ? '' : 'dev'))
        opts.aws_region = AWS_REGION
        opts.key_id = SISJWT_KEY_ID
        opts.key_alg = SISJWT_KEY_ALG
        opts.iss = SISJWT_ISS
        opts.aud = SISJWT_AUD

        opts.token_lifetime = (production_env? ? 60 : 3_600).to_i
        opts.iat = nil
        opts.exp = nil
      end
    end

    def initialize(mode: :sign)
      @mode = mode
      raise ArgumentError, "invalid mode: #{mode}" unless VALID_MODES.include?(mode)
    end

    def to_h
      {
        mode: mode, token_type: token_type, key_alg: key_alg, key_id: key_id,
        aws_region: aws_region, aws_profile: aws_profile,
        token_lifetime: token_lifetime, iss: iss, aud: aud, iat: iat, exp: exp
      }.compact
    end

    def error_messages(revalidate: true)
      validate if revalidate
      return if valid?

      %w[Errors:].concat(
        errors.messages.flat_map do |attr, errors|
          errors.map { |error| "\t#{attr} #{error}" }
        end
      ).join('\n')
    end

    def iat
      @ait.present? ? @iat : DateTime.now.to_f
    end

    def exp
      @exp.present? ? @exp : (iat + token_lifetime.to_i).to_i
    end

    def key_id
      @key_id if kms_configured?
    end

    def key_alg
      @key_alg if kms_configured?
    end

    def token_type
      return @token_type unless defined?(Rails)
      raise Error('Can not issue dev tokens in production!') if dev_token_in_prod?

      @token_type
    end

    def dev_token_in_prod?
      self.class.production_env? && @token_type == TOKEN_TYPE_DEV
    end

    def production_token_type?
      [
        TOKEN_TYPE_V1
      ].include?(@token_type)
    end

    def valid_token_type?
      self.class.valid_token_type(@token_type)
    end

    # Are all the values requried to make a KMS call configured?
    def kms_configured?
      production_token_type? &&
        @aws_region.present? &&
        @key_id.present? &&
        @key_alg.present?
    end
  end
end
