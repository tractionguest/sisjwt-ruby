# frozen_string_literal: true

RSpec.describe Sisjwt::SisJwt do
  let :dev_options do
    Sisjwt::SisJwtOptions.defaults.tap do |o|
      o.token_type = Sisjwt::TOKEN_TYPE_DEV
    end
  end

  let :kms_options do
    Sisjwt::SisJwtOptions.defaults.tap do |o|
      o.aws_region = 'us-west-2'
      o.token_type = Sisjwt::TOKEN_TYPE_V1
      o.key_alg = 'KEWL_AWS_SIGNING_ALG'
      o.key_id = 'arn:key'
    end
  end

  describe '#build' do
    subject(:sis_jwt) { described_class.build }

    let(:options) { {} }

    before do
      allow(Sisjwt::SisJwtOptions).to receive(:current).and_return(options)
      allow(described_class).to receive(:new).with(options).and_call_original
    end

    it 'uses SisJwtOptions.current' do
      expect(sis_jwt.options).to be options

      expect(Sisjwt::SisJwtOptions).to have_received(:current)
      expect(described_class).to have_received(:new).with(options)
    end
  end

  describe '.initialize' do
    subject(:sis_jwt) { described_class.new(options, logger: logger) }

    let(:options) { Sisjwt::SisJwtOptions.current }
    let(:logger) { Logger.new('/dev/null') }

    it 'assigns options and logger' do
      expect(sis_jwt.options).to be options
      expect(sis_jwt.logger).to be logger
    end
  end

  describe '.encode' do
    subject(:sis_jwt) { described_class.new(options) }

    let(:options) { dev_options }
    let(:payload) { { a: 1 } }
    let(:jwt_secret) { a_kind_of(String) }
    let(:jwt_algo) { a_kind_of(Sisjwt::Algo::SisJwtV1) }
    let(:pseudo_token) { 'LOLIMAJWT' }

    before { allow(JWT).to receive(:encode).and_return(pseudo_token) }

    it do
      expect(options).not_to be_kms_configured
      expect(options).to be_valid
    end

    it 'requires that payload is a hash' do
      expect { sis_jwt.encode(:not_a_hash) }.to raise_error ArgumentError
    end

    context 'with a payload' do
      let(:payload) { { 'iat' => 12_345.1, 'exp' => 67_890.2 } }
      let(:headers) { a_kind_of(Hash) }

      describe 'overriding values if present' do
        let(:hash_with_iss) { a_hash_including('iss' => options.iss) }
        let(:hash_with_aud) { a_hash_including('aud' => options.aud) }

        it 'iss' do
          expect(sis_jwt.encode(payload)).to eq pseudo_token
          expect(JWT).to have_received(:encode).with(hash_with_iss, jwt_secret, jwt_algo, headers)
        end

        it 'aud' do
          expect(sis_jwt.encode(payload)).to eq pseudo_token
          expect(JWT).to have_received(:encode).with(hash_with_aud, jwt_secret, jwt_algo, headers)
        end
      end

      describe 'using values if present' do
        context 'with numerics in payload' do
          let(:hash_with_iat) { a_hash_including('iat' => 7.7) }
          let(:hash_with_exp) { a_hash_including('exp' => 7.7) }

          it 'iat' do
            payload['iat'] = 7.7
            expect(sis_jwt.encode(payload)).to eq pseudo_token
            expect(JWT).to have_received(:encode).with(hash_with_iat, jwt_secret, jwt_algo, headers)
          end

          it 'exp' do
            payload['exp'] = 7.7
            expect(sis_jwt.encode(payload)).to eq pseudo_token
            expect(JWT).to have_received(:encode).with(hash_with_exp, jwt_secret, jwt_algo, headers)
          end
        end

        context 'with non-numerics in payload' do
          it 'iat' do
            payload['iat'] = :not_numeric
            token = sis_jwt.encode(payload)
            expect(token).to eq pseudo_token
            expected = a_hash_including('iat' => be_within(0.5).of(options.iat))
            expect(JWT).to have_received(:encode).with(expected, jwt_secret, jwt_algo, headers)
          end

          it 'exp' do
            payload['exp'] = :not_numeric
            token = sis_jwt.encode(payload)

            expect(token).to eq pseudo_token
            expected = a_hash_including('exp' => be_within(0.5).of(options.exp))
            expect(JWT).to have_received(:encode).with(expected, jwt_secret, jwt_algo, headers)
          end
        end
      end

      it 'removes nil values' do
        payload['non-empty'] = :value
        payload['empty'] = nil
        expected = a_hash_including(payload.dup)
        expect(sis_jwt.encode(payload)).to eq pseudo_token

        expect(JWT).not_to have_received(:encode).with(expected, jwt_secret, jwt_algo, headers)
      end
    end

    describe 'headers' do
      context 'with KMS' do
        let(:options) { kms_options }

        let :expected do
          {
            alg: Sisjwt::TOKEN_TYPE_V1,
            kid: options.key_id,
            AWS_ALG: options.key_alg,
          }
        end

        it 'alg / kid / AWS_ALG' do
          expect(options).to be_kms_configured
          token = sis_jwt.encode(payload)
          expect(token).to eq pseudo_token
          expect(JWT).to have_received(:encode)
            .with(a_kind_of(Hash), jwt_secret, jwt_algo, expected)
        end
      end

      context 'without KMS' do
        it 'alg' do
          expect(sis_jwt.encode(payload)).to eq pseudo_token

          expected = a_hash_including(alg: Sisjwt::TOKEN_TYPE_DEV)
          expect(JWT).to have_received(:encode).with(payload, jwt_secret, jwt_algo, expected)
        end

        it 'kid' do
          sis_jwt.encode(payload)

          expected = a_hash_including(kid: a_kind_of(Object))
          expect(JWT).not_to have_received(:encode).with(payload, jwt_secret, jwt_algo, expected)
        end

        it 'AWS_ALG' do
          sis_jwt.encode(payload)

          expected = a_hash_including(AWS_ALG: a_kind_of(Object))
          expect(JWT).not_to have_received(:encode).with(payload, jwt_secret, jwt_algo, expected)
        end
      end

      it 'removes null values' do
        sis_jwt.encode(payload)

        expected = a_hash_including(alg: nil, kid: nil, AWS_ALG: nil)
        expect(JWT).not_to have_received(:encode).with(payload, jwt_secret, jwt_algo, expected)
      end
    end
  end

  describe '.verify' do
    subject(:sis_jwt) { described_class.new(options) }

    let(:pseudo_token) { 'LOLIMAJWT' }
    let(:options) { dev_options }
    let(:headers) { {} }
    let(:payload) { {} }

    before { allow(JWT).to receive(:decode).and_call_original }

    it 'uses JWT library to decode token' do
      sis_jwt.verify(pseudo_token)

      expect(JWT).to have_received(:decode).with(
        pseudo_token, 's3cr37', true, algorithm: a_kind_of(Sisjwt::Algo::SisJwtV1)
      )
    end

    context 'when AWS KMS configured' do
      before do
        allow(JWT).to receive(:decode).and_yield(headers, payload).and_return([payload, headers])
      end

      let(:options) { kms_options }
      let(:headers) { { 'AWS_ALG' => 'alg!', 'kid' => 'kid!' } }
      let(:payload) { { 'data' => 'data' } }

      it 'returns KMS verification context' do
        result = sis_jwt.verify(pseudo_token)
        expect(result.headers).to eq headers
        expect(result.payload).to be payload
      end
    end

    context 'when AWS KMS is configured but the key cannot be found' do
      let(:options) { kms_options }
      let(:headers) { { 'AWS_ALG' => 'alg!', 'kid' => 'kid!' } }
      let(:payload) { { 'data' => 'data' } }
      let(:pseudo_token) { described_class.new(Sisjwt::SisJwtOptions.defaults).encode({}) }
      let(:kms_double) { instance_double(Aws::KMS::Client) }
      let(:err) { Aws::KMS::Errors::NotFoundException.new(nil, 'unknown key') }

      before do
        allow(Aws::KMS::Client).to receive(:new).and_return(kms_double)
        allow(kms_double).to receive(:verify).and_raise(err)
      end

      it 'returns an error' do
        result = sis_jwt.verify(pseudo_token)
        expect(result.errors.full_messages).to include "key_id not found: ''"
      end
    end

    context 'when dev mode is configured' do
      let(:options) { dev_options }
      let(:token) { sis_jwt.encode(data) }
      let(:data) { { 'foo' => 'bar' } }

      it 'returns dev result' do
        result = sis_jwt.verify(token)
        expect(result.headers).to match('alg' => Sisjwt::TOKEN_TYPE_DEV)
        expect(result.payload).to match(data)
      end
    end
  end
end
