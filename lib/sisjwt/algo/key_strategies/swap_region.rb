# frozen_string_literal: true

module Sisjwt
  module Algo
    module KeyStrategies
      # It's possible that the given key exists both in the foreign region and
      # this region, so try modifying the region-portion of the given key ID.
      class SwapRegion < KeyStrategies::Base
        def call(params)
          swapped_key_id = swap_region(params[:key_id])
          return nil unless swapped_key_id && swapped_key_id != params[:key_id]

          kms_client.verify(params.merge(key_id: swapped_key_id))
        end

        private

        def swap_region(key_id)
          return nil unless key_id.start_with?('arn:aws:kms:')

          parts = key_id.split(':')
          [parts[0..2], kms_client.config.region, parts[4..]].flatten.join(':')
        end
      end
    end
  end
end
