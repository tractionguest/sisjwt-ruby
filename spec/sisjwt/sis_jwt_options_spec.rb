# frozen_string_literal: true

RSpec.describe Sisjwt::SisJwtOptions do
  describe '#defaults' do
    subject(:options) { klass.defaults }

    let(:klass) { described_class }

    it { is_expected.not_to be_kms_configured }

    context 'when AWS_PROFILE=testToken' do
      mock_env 'AWS_PROFILE', 'testToken'
      it { expect(options.aws_profile).to eq 'testToken' }
    end

    context 'when AWS_REGION=testToken' do
      mock_env 'AWS_REGION', 'testToken'
      it { expect(options.aws_region).to eq 'testToken' }
    end

    context 'when SISJWT_KEY_ID=testToken' do
      mock_env 'SISJWT_KEY_ID', 'testToken'
      mock_kms configured: true

      it { expect(options.key_id).to eq 'testToken' }
    end

    context 'when SISJWT_KEY_ALG=testToken' do
      mock_env 'SISJWT_KEY_ALG', 'testToken'
      mock_kms configured: true

      it { expect(options.key_alg).to eq 'testToken' }
    end

    context 'when SISJWT_ISS=testToken' do
      mock_env 'SISJWT_ISS', 'testToken'
      it { expect(options.iss).to eq 'testToken' }
    end

    context 'when SISJWT_AUD=testToken' do
      mock_env 'SISJWT_AUD', 'testToken'
      it { expect(options.aud).to eq 'testToken' }
    end

    context 'when in a non-production environment' do
      let(:now) { DateTime.now }

      it { is_expected.to be_valid }

      it 'uses dev token' do
        expect(options.token_type).to be Sisjwt::TOKEN_TYPE_DEV
      end

      it 'uses 1h as token_lifetime' do
        expect(options.token_lifetime).to be 3_600
      end

      it 'iat uses now' do
        allow(DateTime).to receive(:now).and_return(now)
        expect(options.iat).to eq now.to_f
      end

      it 'exp uses iat+token_lifetime' do
        now = DateTime.now
        allow(DateTime).to receive(:now).and_return(now)
        expect(options.exp).to eq now.to_i + options.token_lifetime
      end

      context 'when AWS_PROFILE is unset' do
        mock_env 'AWS_PROFILE', nil

        it "aws_profile defaults to 'dev'" do
          expect(options.aws_profile).to eq 'dev'
        end
      end

      context 'when AWS_REGION is unset' do
        mock_env 'AWS_REGION', nil

        it "aws_region defaults to 'us-west-2'" do
          expect(options.aws_region).to eq 'us-west-2'
        end
      end

      context 'when SISJWT_KEY_ID is unset' do
        mock_env 'SISJWT_KEY_ID', nil
        mock_kms configured: true

        it "key_id defaults to ''" do
          expect(options.key_id).to be_blank
        end
      end

      context 'when SISJWT_KEY_ALG is unset' do
        mock_env 'SISJWT_KEY_ALG', nil
        mock_kms configured: true

        it "key_alg defaults to 'RSA'" do
          expect(options.key_alg).to eq 'RSASSA_PKCS1_V1_5_SHA_256'
        end
      end

      context 'when SISJWT_ISS is unset' do
        mock_env 'SISJWT_ISS', nil

        it 'iss defaults to "SISi"' do
          expect(options.iss).to eq 'SISi'
        end
      end

      context 'when SISJWT_AUD is unset' do
        mock_env 'SISJWT_AUD', nil

        it 'aud defaults to "SISa"' do
          expect(options.aud).to eq 'SISa'
        end
      end
    end

    context 'when in a production_env' do
      mock_env 'RAILS_ENV', 'production'

      it 'uses v1 token' do
        expect(options.token_type).to be Sisjwt::TOKEN_TYPE_V1
      end

      it 'uses 1m as token_lifetime' do
        expect(options.token_lifetime).to be 60
      end

      it 'is not kms_configured' do
        expect(options.key_id).to be_blank
        expect(options.key_alg).to be_blank
        expect(options).not_to be_kms_configured
        expect(options).to be_production_token_type
      end

      context 'when key_id and key_alg are set' do
        before do
          options.key_id = 'arn:token'
          options.key_alg = 'arn:token'
        end

        it 'is kms_configured' do
          expect(options).to be_kms_configured
        end
      end

      context 'when AWS_PROFILE is unset' do
        mock_env 'AWS_PROFILE', nil
        it { expect(options.aws_profile).to eq '' }
      end
    end
  end

  describe 'validations' do
    subject(:options) { described_class.defaults }

    before do
      options.token_type = Sisjwt::TOKEN_TYPE_V1
      options.key_id = 'arn:key'
      options.key_alg = 'magic'
      options.iss = 'SIE'
      options.aud = 'SIC'
    end

    def error_msgs_for(key)
      options.validate
      options.errors.full_messages_for(key)
    end

    context 'when in signing mode' do
      context 'with required attrs' do
        context 'with KMS attributes' do
          mock_kms configured: true

          it 'key_alg' do
            expect(error_msgs_for(:key_alg)).to be_empty

            options.key_alg = nil

            expect(error_msgs_for(:key_alg)).not_to be_empty
          end

          it 'key_id' do
            expect(error_msgs_for(:key_id)).to be_empty

            options.key_id = nil

            expect(error_msgs_for(:key_id)).not_to be_empty
          end

          it 'aws_region' do
            expect(error_msgs_for(:aws_region)).to be_empty

            options.aws_region = nil

            expect(error_msgs_for(:aws_region)).not_to be_empty
          end
        end

        it 'token_lifetime' do
          expect(error_msgs_for(:token_lifetime)).to be_empty

          options.token_lifetime = nil

          expect(error_msgs_for(:token_lifetime)).not_to be_empty
        end

        it 'iss' do
          expect(error_msgs_for(:iss)).to be_empty

          options.iss = nil

          expect(error_msgs_for(:iss)).not_to be_empty
        end

        it 'aud' do
          expect(error_msgs_for(:aud)).to be_empty

          options.aud = nil

          expect(error_msgs_for(:aud)).not_to be_empty
        end
      end

      it "doesn't allow ISS==AUD" do
        expect(error_msgs_for(:aud)).to be_empty
        expect(error_msgs_for(:iss)).to be_empty

        options.iss = options.aud

        expect(error_msgs_for(:aud)).to be_empty
        expect(error_msgs_for(:iss)).not_to be_empty
      end

      it 'requires numeric exp' do
        expect(error_msgs_for(:exp)).to be_empty

        options.exp = '1d'

        expect(error_msgs_for(:exp)).not_to be_empty
      end

      it 'requires exp is after iat' do
        expect(error_msgs_for(:exp)).to be_empty

        options.exp = options.iat - 3_600

        expect(error_msgs_for(:exp)).not_to be_empty
      end

      context 'with a token / production config' do
        mock_env 'RAILS_ENV', 'production'
        before { options.token_type = Sisjwt::TOKEN_TYPE_V1 }

        it "doesn't allow dev tokens to be issued" do
          expect(error_msgs_for(:token_type)).to be_empty

          options.token_type = Sisjwt::TOKEN_TYPE_DEV

          expect(error_msgs_for(:token_type)).not_to be_empty
        end

        it 'KMS configured check' do
          expect(error_msgs_for(:base)).to be_empty
          expect(options).to be_kms_configured

          # Will break KMS Setup
          options.key_id = nil

          expect(options).not_to be_kms_configured
          expect(error_msgs_for(:base)).not_to be_empty
        end
      end
    end
  end
end
