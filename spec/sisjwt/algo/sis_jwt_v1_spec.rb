# frozen_string_literal: true

RSpec.describe Sisjwt::Algo::SisJwtV1 do
  subject(:algo) { described_class.new(options, logger: logger) }

  let(:options) { dev_options }
  let(:logger) { nil }

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

  describe '#initialize' do
    it 'sets and validates options' do
      expect(algo.options).to be_a Sisjwt::SisJwtOptions
      expect(algo.options).to be_valid
    end

    context 'with dev mode' do
      context 'when in a production environment' do
        mock_env 'RAILS_ENV', 'production'

        it 'raises error' do
          expect { algo }.to raise_error Sisjwt::Error, /KMS is not configured properly/
        end
      end
    end

    it { expect(algo.logger).to be_present }
  end

  describe 'ruby-kwt algorithim contract' do
    describe '#alg' do
      it { expect(algo.alg).to be options.token_type }
    end

    describe '#valid_alg?' do
      context 'when in a dev environment' do
        it do
          expect(algo).to be_valid_alg Sisjwt::TOKEN_TYPE_V1
          expect(algo).to be_valid_alg Sisjwt::TOKEN_TYPE_DEV
        end
      end

      context 'when in a production environment' do
        mock_env 'RAILS_ENV', 'production'
        let(:options) { kms_options }

        it do
          expect(algo).to be_valid_alg Sisjwt::TOKEN_TYPE_V1
          expect(algo).not_to be_valid_alg Sisjwt::TOKEN_TYPE_DEV
        end
      end
    end
  end

  describe '.sign' do
    let(:data) { 'data' }
    let(:signing_key) { 'key' }

    context 'with KMS' do
      let(:options) { kms_options }
      let(:kms_double) { instance_double(Aws::KMS::Client) }
      let(:sign_result) { Struct.new(:signature).new }

      before do
        allow(Aws::KMS::Client).to receive(:new).and_return(kms_double)
        allow(kms_double).to receive(:sign).and_return(sign_result)
      end

      it 'calls KMS' do
        algo.sign(data: data, signing_key: signing_key)

        expect(kms_double).to have_received(:sign).with(
          key_id: options.key_id, message: data, message_type: 'RAW',
          signing_algorithm: options.key_alg
        )
      end
    end

    context 'when in Development' do
      let(:options) { dev_options }

      before { allow(OpenSSL::HMAC).to receive(:digest) }

      it 'uses SHA512 HMAC /w shared secret' do
        algo.sign(data: data, signing_key: signing_key)

        expect(OpenSSL::HMAC).to have_received(:digest).with(
          a_kind_of(OpenSSL::Digest), data, signing_key
        )
      end
    end
  end

  describe '.verify' do
    let(:data) { 'data' }
    let(:signature) { 'signature' }
    let(:key_id) { 'key_id' }
    let(:signing_algorithm) { 'signing_algorithm' }
    let(:verification_key) { [signing_algorithm, key_id].join(';') }

    context 'with KMS' do
      let(:options) { kms_options }
      let(:kms_double) { instance_double(Aws::KMS::Client) }
      let(:verify_result) { Struct.new(:signature_valid).new }

      before { allow(Aws::KMS::Client).to receive(:new).and_return(kms_double) }

      context 'when it finds the key' do
        before do
          allow(kms_double).to receive(:verify).and_return(verify_result)
        end

        it 'calls KMS' do
          algo.verify(data: data, signature: signature, verification_key: verification_key)

          expect(kms_double).to have_received(:verify).with(
            key_id: key_id, message: data, message_type: 'RAW',
            signature: signature, signing_algorithm: signing_algorithm
          )
        end
      end

      context 'when it cannot finds the key' do
        let(:err) { Aws::KMS::Errors::NotFoundException.new(nil, 'region name') }

        before { allow(kms_double).to receive(:verify).and_raise(err) }

        it 'raises a KeyNotFoundError' do
          expect { algo.verify(data: data, signature: signature, verification_key: verification_key) }.to \
            raise_error(Sisjwt::KeyNotFoundError, "key_id not found: '#{key_id}'")
        end
      end
    end

    context 'when in Development' do
      let(:options) { dev_options }

      before { allow(OpenSSL::HMAC).to receive(:digest) }

      it 'uses SHA512 HMAC /w shared secret' do
        algo.verify(data: data, signature: signature, verification_key: verification_key)

        expect(OpenSSL::HMAC).to have_received(:digest).with(
          a_kind_of(OpenSSL::Digest), data, verification_key
        )
      end
    end
  end
end
