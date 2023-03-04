# frozen_string_literal: true

module Sisjwt
  class SisJwtOptions
    # Validates whether {SisJwtOptions} are valid for either signing or
    # verifying.
    module Validations
      extend ActiveSupport::Concern

      included do
        include ActiveModel::Validations

        validates_presence_of :key_alg, if: -> { sign? && kms_configured? }
        validates_presence_of :key_id, if: -> { sign? && kms_configured? }
        validates_presence_of :aws_region, if: -> { sign? && kms_configured? }
        validates_presence_of :token_lifetime, if: -> { sign? }
        validates_presence_of :iss, if: -> { sign? }
        validates_presence_of :aud, if: -> { sign? }

        # Common (sign/verify) validations
        validate { errors.add(:token_type, 'is invalid') unless valid_token_type? }

        # Signing Mode Validations
        validate do
          next unless sign?

          # iss/aud distinctness
          errors.add(:iss, 'Can not be equal to AUDience!') if iss == aud

          # exp
          if exp.is_a?(Numeric)
            errors.add(:exp, 'can not be before the token was issued (iat)') if exp < iat
          elsif exp.present?
            errors.add(:exp, 'must be the unix timestamp the token expires')
          end

          # token_type / config
          errors.add(:token_type, "(#{token_type}) is not a valid token type!") unless token_type =~ /^SISKMS/

          if Runtime.production_env?
            unless production_token_type?
              errors.add(:base, 'Can not issue non-production tokens in a production environment')
            end
            errors.add(:base, 'AWS KMS is not properly configured') unless kms_configured?
          end
        end
      end
    end
  end
end
