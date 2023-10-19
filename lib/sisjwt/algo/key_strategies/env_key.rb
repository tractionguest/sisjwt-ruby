# frozen_string_literal: true

module Sisjwt
  module Algo
    module KeyStrategies
      # Try the key provided by this app's environment.
      # @see KEY_ID_ENV_NAME
      class EnvKey < KeyStrategies::Base
        def call(params)
          return nil unless env_key_id && env_key_id != params[:key_id]

          kms_client.verify(params.merge(key_id: env_key_id))
        end

        private

        def env_key_id
          ENV.fetch(KEY_ID_ENV_NAME, nil)
        end
      end
    end
  end
end
