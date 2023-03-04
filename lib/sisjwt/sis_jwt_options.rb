# frozen_string_literal: true

require 'sisjwt/sis_jwt_options/validations'

module Sisjwt
  # Options to control the behavior of {SisJwt}.
  class SisJwtOptions
    include Validations

    VALID_MODES = %i[sign verify].freeze

    attr_reader :mode, :arn_inventory
    attr_writer :exp, :iat, :key_alg, :key_id, :token_type
    attr_accessor :aws_region, :aws_profile, :token_lifetime, :iss, :aud

    class << self
      def current
        @current ||= defaults
      end

      def defaults(mode: :sign)
        new(mode: mode).tap do |opts|
          assign_options(opts)
          opts.validate if mode == :sign
        end
      end

      private

      def assign_options(opts)
        opts.token_type = Runtime.token_type
        opts.token_lifetime = Runtime.token_lifetime
        opts.iat = nil
        opts.exp = nil
        assign_env_options(opts)
      end

      def assign_env_options(opts)
        opts.aws_profile = Runtime.aws_profile
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
      @arn_inventory = ArnInventory.new
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
      Runtime.valid_token_type?(@token_type)
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
