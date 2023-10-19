# frozen_string_literal: true

module Sisjwt
  module Algo
    module KeyStrategies
      # The base class for all strategies in this module. Each strategy is
      # expected to return +nil+ if it chose not to run for some reason, return
      # a {Aws::KMS::Types::VerifyResponse}, or forward any
      # {Aws::KMS::Errors::NotFoundException} raised by {#kms_client}.
      class Base
        attr_reader :kms_client

        def initialize(kms_client)
          @kms_client = kms_client
        end

        # @return [Aws::KMS::Types::VerifyResponse,nil] The result of attempting
        #   to verify the signature, or +nil+, if this strategy was unsuitable.
        # @raises Aws::KMS::Errors::NotFoundException
        def call(params)
          raise NotImplementedError
        end
      end
    end
  end
end
