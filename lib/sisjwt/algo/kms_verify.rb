# frozen_string_literal: true

module Sisjwt
  module Algo
    # With Amazon KMS's strict rules about sharing keys across AWS regional
    # boundaries, and the complexity of "multi-region keys," it's apparently not
    # always trivial to know the ARN of the correct key to use to verify the
    # signature of a signed JWT.
    #
    # This service iterates through several strategies, returning the result of
    # the first that works, or raising {KeyNotFoundError} if none do.
    class KmsVerify
      DEFAULT_STRATEGIES = [KeyStrategies::AsGiven,
                            KeyStrategies::SwapRegion,
                            KeyStrategies::EnvKey].freeze

      attr_reader :kms_client, :strategies

      def initialize(kms_client, strategies: DEFAULT_STRATEGIES)
        @kms_client = kms_client
        @strategies = strategies
      end

      def call(params)
        iterate_strategies(params) || raise(KeyNotFoundError, params[:key_id])
      end

      private

      def iterate_strategies(params)
        strategies.lazy.filter_map { execute(_1, params) }.first
      end

      def execute(klass, params)
        klass.new(kms_client).call(params)
      rescue Aws::KMS::Errors::NotFoundException
        nil
      end
    end
  end
end
