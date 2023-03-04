# frozen_string_literal: true

module Sisjwt
  # Describes the runtime this library is being run in and the constants that
  # vary depending on its environment.
  class Runtime
    TRUTHY_PATTERN = /^\s*(y|yes|t|true|1)\s*$/i.freeze

    class << self
      def current
        @current ||= new
      end

      def method_missing(*args)
        current.send(*args)
      end

      def respond_to_missing?(name, include_private = false)
        current.respond_to?(name) || super
      end
    end

    def valid_token_type?(token_type)
      [
        TOKEN_TYPE_V1,
        (TOKEN_TYPE_DEV if allow_dev_token?),
      ].compact.include?(token_type)
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

      ENV.fetch('RAILS_ENV', 'development').downcase.strip == 'production'
    end

    def allow_dev_token?
      return true unless production_env?

      ENV.fetch('SISJWT_UNSAFE_ALLOW_DEV_TOKEN_IN_PROD', 'false') =~ TRUTHY_PATTERN
    end

    def token_type
      production_env? ? TOKEN_TYPE_V1 : TOKEN_TYPE_DEV
    end

    def token_lifetime
      production_env? ? 60 : 3_600
    end

    def aws_profile
      ENV.fetch('AWS_PROFILE', (production_env? ? '' : 'dev'))
    end
  end
end
