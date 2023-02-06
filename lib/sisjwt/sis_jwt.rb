module Sisjwt
  class Error < StandardError; end

  class SisJwt
    attr_reader :options

    def self.build
      SisJwt.new(SisJwtOptions.current)
    end

    def initialize(opts)
      @options = opts
    end

    def encode(payload)
      raise "payload should be a hash" unless payload.is_a?(Hash)

      # Make sure that we tag the token with our issuer so that we can
      # easily decode it in the future.
      payload["iss"] = options.issuer
      payload["iat"] = Time.now.to_f
      payload["exp"] = Time.now.to_f + options.exp_time

      headers = {
        kid: options.key_id,
        AWS_ALG: options.key_alg,
      }

      JWT.encode(payload, jwt_secret, jwt_alg, headers = headers)
    end

    def decode(token)
      alg = jwt_alg
      JWT.decode(token, jwt_secret, true, { algorithm: alg }) do |headers, payload|
        if alg.aws_configured?
          Rails.logger.info "[JwtKms] decode-findKey. aws_configured=true aws_alg=#{headers['AWS_ALG']} key=#{payload['iss']}"
          [
            headers['AWS_ALG'],
            payload["iss"],
          ].join(";")
        else
          Rails.logger.info "[JwtKms] decode-findKey. aws_configured=false key=jwt_secret"
          jwt_secret
        end
      end
    end

    private

    def jwt_secret
      "s3cr37"
    end

    def jwt_alg
      # return jwt_alg unless jwt_alg =~ /^SISKMSd?$/
      @jwt_alg ||= SisKmsJwtAlgo.new(key_id: key_id, kms_enabled: @kms_enabled, kms_required: @kms_enabled)
    end
  end
end
