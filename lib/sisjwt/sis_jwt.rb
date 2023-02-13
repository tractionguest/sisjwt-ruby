require 'jwt'

module Sisjwt
  class Error < StandardError; end

  class SisJwt
    attr_reader :options, :logger
    def self.build
      SisJwt.new(SisJwtOptions.current)
    end

    def initialize(opts, logger: nil)
      @logger = logger || Logger.new($stderr, level: :unknown)
      @options = opts
    end

    def encode(payload)
      raise "payload should be a hash" unless payload.is_a?(Hash)

      # Make sure that we tag the token with our issuer so that we can
      # easily decode it in the future.
      payload["iss"] = options.iss
      payload["aud"] = options.aud
      payload["iat"] = options.iat unless payload["iat"].is_a?(Numeric)
      payload["exp"] = options.exp unless payload["exp"].is_a?(Numeric)
      payload = payload.compact

      headers = {
        alg: options.token_type,
        kid: options.key_id,
        AWS_ALG: options.key_alg,
      }.compact

      @logger.debug do
        info = wrap_headers_payload(headers, payload)
        "SISJWT-encode: #{info.inspect}"
      end

      ::JWT.encode(payload, jwt_secret, jwt_alg, headers = headers)
    end

    def verify(token)
      alg = jwt_alg
      @logger.debug "SISJWT-verify: #{token}"
      payload, headers = ::JWT.decode(token, jwt_secret, true, { algorithm: alg }) do |headers, payload|
        if options.kms_configured?
          kms_key_finder = [
            headers['AWS_ALG'],
            headers['kid'],
          ].join(";")
          @logger.debug do
            info = wrap_headers_payload(headers, payload)
            "SISJWT-verify-kms1: #{token} KMS: #{kms_key_finder}; #{info.inspect}"
          end
          kms_key_finder
        else
          @logger.debug "SISJWT-verify-dev: #{token} DEV"
          jwt_secret
        end
      end

      # ret = wrap_headers_payload(headers, payload)
      ret = VerificationResult.new(headers, payload)
      @logger.debug "SISJWT-verifed: #{ret.inspect}"
      ret
    rescue JWT::DecodeError => e
      # We can rescue from this error and return a result
      @logger.error("[SISJWT-verify]: [#{e.class}]#{e}")
      return VerificationResult.new(nil, nil, error: e.message)
    end

    private

    def jwt_secret
      "s3cr37"
    end

    def jwt_alg
      @jwt_alg ||= Sisjwt::Algo::SisJwtV1.new(@options, logger: @logger)
    end

    def wrap_headers_payload(headers, payload)
      {
        headers: headers,
        payload: payload,
      }
    end
  end
end
