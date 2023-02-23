# frozen_string_literal: true

require 'aws-sdk-kms'
require 'openssl'

module Sisjwt
  module Algo
    # The custom JWT algorithm used to sign and verify tokens.
    class SisJwtV1
      attr_reader :logger, :options

      delegate :token_type, :key_alg, :key_id, :aws_region, :aws_profile,
               to: :options

      # @params options [SisJwtOptions]
      # @params logger [Logger]
      def initialize(options, logger: nil)
        @logger = logger || Logger.new($stderr, level: :unknown)
        @options = options
        @options.validate

        # We invoke kms_client here because that will raise a detailed error as
        # to the current state of the configuration
        kms_client unless @options.valid?
      end

      # Needed by jwt to be considered an algorithim
      def alg
        options.token_type
      end

      # Needed by jwt to be considered an algorithim
      def valid_alg?(alg_to_validate)
        # alg_to_validate == alg
        SisJwtOptions.valid_token_type?(alg_to_validate)
      end

      # Needed by jwt to be considered an algorithim
      def sign(data:, signing_key:)
        logger.info "[#{alg}] sign: kms=#{options.kms_configured?} signing_key=#{signing_key.size} data=#{data.size}"

        if options.kms_configured?
          kms_sign(data)
        else
          OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha512'), data, signing_key)
        end
      end

      # Needed by jwt to be considered an algorithim
      # @return [Boolean]
      def verify(data:, signature:, verification_key:)
        aws_alg, key_arn = split_verification_key(data, signature, verification_key)

        if options.kms_configured?
          logger.debug do
            File.binwrite('token_intercepted.sig', signature)
            "[#{alg}] verify-kms2: Writing #{file_name}: #{signature.size} bytes"
          end
          kms_verify(data, signature, aws_alg, key_arn)
        else
          devmode_verify(data, signature, verification_key)
        end
      end

      private

      def split_verification_key(data, signature, verification_key)
        verification_key.split(';', 2).tap do |aws_alg, key_arn|
          logger.debug("[#{alg}] verify-kms2: kms=#{options.kms_configured?} aws_alg=#{aws_alg} " \
                       "key_arn=#{key_arn} data=#{data.size} signature=#{signature.size}")
        end
      end

      # This is NOT a secure operation and should use OpenSSL.secure_compare
      # however as this is a symetric operation inteded only for dev use this
      # doesn't matter and doesn't warrent a dependancy on rails just to have
      # this already insecure operation be more secure.
      def devmode_verify(data, signature, verification_key)
        shared_secret_sig = sign(data: data, signing_key: verification_key)
        signature == shared_secret_sig
      end

      def kms_client
        @kms_client ||= begin
          assert_configured!
          logger.debug("Creating Aws::KMS::Client(region: #{options.aws_region}, " \
                       "profile: #{options.aws_profile})")
          Aws::KMS::Client.new(
            region: options.aws_region,
            profile: options.aws_profile
          )
        end
      end

      def assert_configured!
        return if options.kms_configured?

        raise Error,
              'KMS is not configured properly, KMS signing not allowed!' \
              "\n#{@options.error_messages}"
      end

      def build_kms_params(params)
        {
          key_id: options.key_id,
          signing_algorithm: options.key_alg,
          message_type: 'RAW'
        }.merge(params)
      end

      def kms_sign(data)
        logger.debug("kms_sign message(#{data.size}b)>>#{data}<<")
        params = build_kms_params(message: data)
        kms_client.sign(params).signature
      end

      def kms_verify(message, signature, signing_algorithm, verification_key_id)
        logger.debug("kms_verify message(#{message.size}b)>>#{message}<< signature>>" \
                     "#{signature.size}<< alg>>#{signing_algorithm}<< key_id>>#{verification_key_id}<<")
        params = build_kms_params(message: message, signature: signature,
                                  key_id: verification_key_id,
                                  signing_algorithm: signing_algorithm)

        kms_client.verify(params).signature_valid
        true
      rescue Aws::KMS::Errors::KMSInvalidSignatureException
        false
      end
    end
  end
end
