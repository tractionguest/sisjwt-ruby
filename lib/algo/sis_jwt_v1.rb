require 'aws-sdk-kms'

module Sisjwt::Algo
  class SisJwtV1
    attr_reader :options
    delegate :token_type, :key_alg, :key_id, :aws_region, :aws_profile, to: :options
    # attr_reader :key_id, :signing_algorithm, :aws_region, :aws_profile

    # SIG_ALG = 'ECDSA_SHA_256'.freeze
    # SIG_ALG = 'RSASSA_PSS_SHA_256'.freeze
    # SIG_ALG = 'RSASSA_PKCS1_V1_5_SHA_256'.freeze

    def initialize(options)
      @options = options
      @options.validate

      #Rails.logger.info "[#{alg}] initialized kms_configured?=#{@options.kms_configured?}"
      if !@options.valid?
        # We invoke kms_client here because that will raise a detailed error as to
        # the current state of the configuration
        kms_client
      end
    end

    def alg
      return @options.token_type
    end

    def valid_alg?(alg_to_validate)
      alg_to_validate == alg
    end

    def sign(data:, signing_key:)
      #Rails.logger.info "[#{alg}] sign: signing_key=#{signing_key.size} data=#{data.size}"

      if aws_configured?
        kms_sign(data)
      else
        OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha512'), data, signing_key)
      end
    end

    def verify(data:, signature:, verification_key:)
      # aws_alg = verification_key[0]
      # key_arn = verification_key[1]
      aws_alg, key_arn = verification_key.split(";")
      #Rails.logger.info "[#{alg}] verify: aws_alg=#{aws_alg} key_arn=#{key_arn} data=#{data.size} signature=#{signature.size}"

      if aws_configured?
        tag = "token"
        puts "Writing #{tag}_intercepted.sig: #{signature.size} bytes"
        File.open("#{tag}_intercepted.sig", "wb") do |f|
          f.write signature
        end
        kms_verify(data, signature, aws_alg, key_arn)
      else
        ::OpenSSL.secure_compare(sign(data: data, signing_key: verification_key), signature)
      end
    end

    def aws_configured?
      @options.kms_configured? && @options.valid? && @options.production_config?
    end

    private

    def kms_client
      return @kms_client unless @kms_client.nil?

      if !aws_configured?
        raise "KMS is not configured properly, KMS signing not allowed! \n#{@options.error_messages}"
      end

      $stdout.puts "Creating Aws::KMS::Client(region: #{@options.aws_region}, profile: #{@options.aws_profile})"
      @kms_client ||= Aws::KMS::Client.new(
        region: @options.aws_region,
        profile: @options.aws_profile
      )
    end

    def build_kms_params(params)
      {
        key_id: @options.key_id,
        signing_algorithm: @options.key_alg,
        message_type: "RAW",
      }.merge(params)
    end

    def kms_sign(data)
      puts "kms_sign message >>#{data}<<"
      params = build_kms_params(message: data)
      kms_client.sign(params).signature
    end

    def kms_verify(message, signature, signing_algorithm, verification_key_id)
      puts "kms_verify message>>#{message}<< signature>>#{signature.size}<< alg>>#{signing_algorithm}<< key_id>>#{verification_key_id}<<"
      params = build_kms_params(
        message: message,
        signature: signature,
        key_id: verification_key_id,
        signing_algorithm: signing_algorithm,
      )
      begin
        kms_client.verify(params).signature_valid
      rescue Aws::KMS::Errors::KMSInvalidSignatureException
        return false
      end

      true
    end
  end
end
