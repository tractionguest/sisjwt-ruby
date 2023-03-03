# frozen_string_literal: true

require 'sisjwt/sis_jwt_options/validations'

module Sisjwt
  # Options to control the behavior of {SisJwt}.
  class SisJwtOptions
    include Validations

    VALID_MODES = %i[sign verify].freeze

    attr_reader :mode
    attr_writer :exp, :iat, :key_alg, :key_id, :token_type
    attr_accessor :aws_region, :aws_profile, :token_lifetime, :iss, :aud

    class << self
      def valid_token_type?(token_type)
        @allowed_tokens ||= begin
          dev_token_override ||= ENV.fetch('SISJWT_UNSAFE_ALLOW_DEV_TOKEN_IN_PROD', "false") =~ /^\s*(y|yes|t|true|1)\s*$/i
          [
            TOKEN_TYPE_V1,
            (TOKEN_TYPE_DEV if dev_token_override || !production_env?),
          ].compact
        end
        @allowed_tokens.include?(token_type)
      end

      def current
        @current ||= defaults
      end

      def defaults(mode: :sign)
        new(mode: mode).tap do |opts|
          assign_options(opts)
          opts.validate if mode == :sign
        end
      end

      # @return [Boolean] Are we running in a production environment?
      def production_env?
        # This is complex for a reason:
        # It isn't a clear distinction on what to use in which order, so *if* we
        # have Rails available (the primary, but not exclusive, use case) then
        # we offload the problem to Rails and let thier core devs deal with that
        # problem. It is written like this so it can easily be tested.
        if Module.const_defined?(:Rails)
          rails = Module.const_get(:Rails)
          return true if rails.respond_to?(:env) && rails.env.production?
        end

        env = ENV.fetch('RAILS_ENV', nil)
        env.present? && env.downcase.strip == 'production'
      end

      private

      def assign_options(opts)
        opts.token_type = production_env? ? TOKEN_TYPE_V1 : TOKEN_TYPE_DEV
        opts.token_lifetime = (production_env? ? 60 : 3_600).to_i
        opts.iat = nil
        opts.exp = nil
        assign_env_options(opts)
      end

      def assign_env_options(opts)
        opts.aws_profile = ENV.fetch('AWS_PROFILE', (production_env? ? '' : 'dev'))
        opts.aws_region = ENV.fetch('AWS_REGION', 'us-west-2')
        opts.key_id = ENV.fetch('SISJWT_KEY_ID', nil)
        opts.key_alg = ENV.fetch('SISJWT_KEY_ALG', 'RSASSA_PKCS1_V1_5_SHA_256')
        opts.iss = ENV.fetch('SISJWT_ISS', 'SISi')
        opts.aud = ENV.fetch('SISJWT_AUD', 'SISa')
      end
    end

    # @param mode [Symbol] One of {VALID_MODES}.
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
        end,
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
        TOKEN_TYPE_V1,
      ].include?(@token_type)
    end

    def valid_token_type?
      self.class.valid_token_type?(@token_type)
    end

    # Are all the values requried to make a KMS call configured?
    def kms_configured?
      production_token_type? &&
        @aws_region.present? &&
        @key_id.present? &&
        @key_alg.present?
    end

    def sign?
      mode == :sign
    end
  end
end
