# frozen_string_literal: true

RSpec.describe Sisjwt::VerificationResult do
  subject(:result) { described_class.new(headers, payload, error: init_error) }

  let(:token_type) { Sisjwt::TOKEN_TYPE_V1 }
  let(:key_id) { 'arn:key' }
  let(:key_alg) { 'RSASSA_PKCS1_V1_5_SHA_256' }
  let(:headers) { { alg: token_type, kid: key_id, AWS_ALG: key_alg }.with_indifferent_access }
  let(:aud) { 'SIC' }
  let(:iss) { 'SIE' }
  let(:iat) { Time.now.to_f }
  let(:exp) { iat + 3_600 }
  let(:payload_overrides) { {} }
  let(:payload) { base_payload.merge(payload_overrides).with_indifferent_access }
  let(:base_payload) { { aud: aud, iss: iss, iat: iat, exp: exp } }
  let(:init_error) { nil }

  around { |test| freeze_time(&test) }

  describe '#initialize' do
    it 'copies values as expected' do
      expect(result.jwt_error).to eq init_error

      expect(result.token_type).to eq token_type
      expect(result.initial_lifetime).to eq 3_600
      expect(result.iss).to eq iss
      expect(result.aud).to eq aud
    end

    it 'has expected state' do
      expect(result).not_to be_expired
      expect(result.life_left).to be_within(0.5).of(3_600)
      expect(result.age).to be_within(0.5).of(0)
    end
  end

  describe '#to_h' do
    let(:hash) { result.to_h.with_indifferent_access }

    context 'when in a non-production environment' do
      mock_env 'RAILS_ENV', 'development'

      it 'includes debugging data' do
        expect(hash).to have_key(:lifetime)
      end
    end

    context 'when in a production environment' do
      mock_env 'RAILS_ENV', 'production'

      it "doesn't include debugging keys" do
        expect(hash).not_to have_key :lifetime
      end
    end
  end

  describe 'validations' do
    context 'with an error passed to initializer' do
      let(:init_error) { StandardError.new('uniqKey:LQpgr7N') }

      context 'without headers or payload data' do
        let(:headers) { nil }
        let(:payload) { nil }

        it 'returns only error object message' do
          errors = result.errors.full_messages_for(:base)
          expect(errors.size).to eq 1
          expect(errors[0]).to eq init_error
        end
      end
    end
  end

  describe '#add_allowed_aud' do
    it 'changes allowed_aud' do
      expect { result.add_allowed_aud(:test) }.to \
        change(result, :allowed_aud).from([]).to([:test])
    end

    it 'is included in to_h' do
      expect { result.add_allowed_aud(:test) }.to \
        change(result, :to_h).to(include(allowed: include(aud: [:test])))
    end
  end

  describe '#add_allowed_iss' do
    it 'changes allowed_iss' do
      expect { result.add_allowed_iss(:test) }.to \
        change(result, :allowed_iss).from([]).to([:test])
    end

    it 'is included in to_h' do
      expect { result.add_allowed_iss(:test) }.to \
        change(result, :to_h).to(include(allowed: include(iss: [:test])))
    end
  end
end
