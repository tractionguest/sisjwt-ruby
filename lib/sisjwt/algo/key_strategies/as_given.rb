# frozen_string_literal: true

module Sisjwt
  module Algo
    module KeyStrategies
      # Try the key ID provided from the verification key.
      class AsGiven < KeyStrategies::Base
        def call(params)
          kms_client.verify(params)
        end
      end
    end
  end
end
