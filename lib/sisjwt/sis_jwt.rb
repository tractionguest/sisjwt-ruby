# frozen_string_literal: true

require 'jwt'

module Sisjwt
  # The primary interface for {#build building} and {#verify verifying} tokens.
  class SisJwt
    attr_reader :options, :logger

    def self.build
      SisJwt.new(SisJwtOptions.current)
    end

    # @param options [SisJwtOptions]
    # @param logger [Logger]
    def initialize(opts, logger: nil)
      @logger = logger || Logger.new($stderr, level: :unknown)
      @options = opts
    end

    def encode(payload)
      raise ArgumentError, 'payload should be a hash' unless payload.is_a?(Hash)

      merge_options!(payload)

      logger.debug do
        info = wrap_headers_payload(encode_headers, payload)
        "SISJWT-encode: #{info.inspect}"
      end

      JWT.encode(payload, jwt_secret, jwt_alg, encode_headers)
    end

    # @return [VerificationResult]
    def verify(token)
      logger.debug "SISJWT-verify: #{token}"
      payload, headers = decode_jwt(token)
      new_result(headers, payload).tap do |ret|
        logger.debug("SISJWT-verifed: #{ret.inspect}")
      end
    rescue JWT::DecodeError, KeyNotFoundError => e
      # We can rescue from this error and return a result
      logger.error("[SISJWT-verify]: [#{e.class}] #{e}")
      VerificationResult.error(e.message)
    end

    private

    # @return [Array] The JWT token's payload and headers.
    def decode_jwt(token)
      JWT.decode(token, jwt_secret, true, { algorithm: jwt_alg }) do |headers, payload|
        if options.kms_configured?
          find_jwt_key(token, CaseInsensitiveHash.new(headers), payload)
        else
          logger.debug "SISJWT-verify-dev: #{token} DEV"
          jwt_secret
        end
      end
    end

    def find_jwt_key(token, headers, payload)
      [headers['AWS_ALG'], headers['kid']].join(';').tap do |kms_key_finder|
        logger.debug do
          info = wrap_headers_payload(headers, payload)
          "SISJWT-verify-kms1: #{token} KMS: #{kms_key_finder}; #{info.inspect}"
        end
      end
    end

    def new_result(headers, payload)
      VerificationResult.new(CaseInsensitiveHash.new(headers), payload,
                             options: options)
    end

    # Make sure that we tag the token with our issuer so that we can easily
    # decode it in the future.
    def merge_options!(payload) # rubocop:disable Metrics/AbcSize
      payload['iss'] = options.iss
      payload['aud'] = options.aud
      payload['iat'] = options.iat unless payload['iat'].is_a?(Numeric)
      payload['exp'] = options.exp unless payload['exp'].is_a?(Numeric)
      payload.compact!
    end

    def encode_headers
      @encode_headers ||= {
        alg: options.token_type,
        kid: options.key_id,
        AWS_ALG: options.key_alg,
      }.compact
    end

    def jwt_secret
      's3cr37' # TODO: awesome, hard-coded secret
    end

    def jwt_alg
      @jwt_alg ||= Algo::SisJwtV1.new(options, logger: logger)
    end

    def wrap_headers_payload(headers, payload)
      { headers: headers, payload: payload }
    end
  end
end
