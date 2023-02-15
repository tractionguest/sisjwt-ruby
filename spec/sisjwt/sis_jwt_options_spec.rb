# frozen_string_literal: true
module Sisjwt
  RSpec.describe SisJwtOptions do
    describe "#production_env?" do
      subject { SisJwtOptions.production_env? }

      before do
        expect(defined?(Rails)).to be_falsy
      end

      context "w/o Rails" do
        it "RAILS_ENV undefined", env: "RAILS_ENV" do
          expect(Module.const_defined?(:Rails)).to be_falsy
          expect(subject).to be_falsy
        end

        it "RAILS_ENV=test", env: "RAILS_ENV=test" do
          expect(Module.const_defined?(:Rails)).to be_falsy
          expect(subject).to be_falsy
        end

        it "RAILS_ENV=development", env: "RAILS_ENV=development" do
          expect(Module.const_defined?(:Rails)).to be_falsy
          expect(subject).to be_falsy
        end

        it "RAILS_ENV=production", env: "RAILS_ENV=production" do
          expect(Module.const_defined?(:Rails)).to be_falsy
          expect(subject).to be_truthy
        end
      end

      context "/w Rails" do
        let(:rails) { OpenStruct.new }
        before do
          allow(Module).to receive(:const_defined?).with(:Rails).and_return(true)
          allow(Module).to receive(:const_get).with(:Rails).and_return(rails)
        end

        it "Rails.env.test" do
          rails.env = ActiveSupport::StringInquirer.new("test")
          expect(Module.const_defined?(:Rails)).to be_truthy

          expect(subject).to be_falsy
        end

        it "Rails.env.development" do
          rails.env = ActiveSupport::StringInquirer.new("development")
          expect(Module.const_defined?(:Rails)).to be_truthy

          expect(subject).to be_falsy
        end

        it "Rails.env.production" do
          rails.env = ActiveSupport::StringInquirer.new("production")
          expect(Module.const_defined?(:Rails)).to be_truthy

          expect(subject).to be_truthy
        end
      end
    end

    describe "#valid_token_type" do
      context "non-production env" do
        subject { SisJwtOptions }

        it "allows v1 token type" do
          expect(subject.valid_token_type(TOKEN_TYPE_V1)).to be_truthy
        end

        it "allows dev token type" do
          expect(subject.valid_token_type(TOKEN_TYPE_DEV)).to be_truthy
        end
      end

      context "production env" do
        subject { SisJwtOptions }

        before do
          expect(subject).to receive(:production_env?).and_return(true)
        end

        it "allows v1 token type" do
          expect(subject.valid_token_type(TOKEN_TYPE_V1)).to be_truthy
        end

        it "DOES NOT allow dev token type" do
          expect(subject.valid_token_type(TOKEN_TYPE_DEV)).to be_falsy
        end
      end
    end

    describe "#defaults" do
      let(:klass) { SisJwtOptions }
      subject { klass.defaults }

      context "ENV overrides" do
        it "$AWS_PROFILE", env: "AWS_PROFILE=testToken" do
          expect(subject.aws_profile).to eq "testToken"
        end

        it "$AWS_REGION", env: "AWS_REGION=testToken" do
          expect(subject.aws_region).to eq "testToken"
        end

        it "$SISJWT_KEY_ID", env: "SISJWT_KEY_ID=testToken" do
          allow(subject).to receive(:kms_configured?).and_return(true)
          expect(subject.key_id).to eq "testToken"
        end

        it "$SISJWT_KEY_ALG", env: "SISJWT_KEY_ALG=testToken" do
          allow(subject).to receive(:kms_configured?).and_return(true)
          expect(subject.key_alg).to eq "testToken"
        end

        it "$SISJWT_ISS", env: "SISJWT_ISS=testToken" do
          expect(subject.iss).to eq "testToken"
        end

        it "$SISJWT_AUD", env: "SISJWT_AUD=testToken" do
          expect(subject.aud).to eq "testToken"
        end

        it "kms_configured?" do
          expect(subject.kms_configured?).to be_falsy
        end
      end

      context "non-production env" do
        it "is valid" do
          expect(subject).to be_valid
        end

        it "aws_profile = 'dev'", env: "AWS_PROFILE" do
          expect(subject.aws_profile).to eq 'dev'
        end

        it "aws_regions = 'us-west-2'", env: "AWS_REGION" do
          expect(subject.aws_region).to eq 'us-west-2'
        end

        it "uses dev token" do
          expect(subject.token_type == TOKEN_TYPE_DEV)
        end

        it "uses 1h as token_lifetime" do
          expect(subject.token_lifetime == 3_600)
        end

        it "key_id = ''", env: "SISJWT_KEY_ID" do
          allow(subject).to receive(:kms_configured?).and_return(true)
          expect(subject.key_id).to be_blank
        end

        it "key_alg = RSA", env: "SISJWT_KEY_ALG" do
          allow(subject).to receive(:kms_configured?).and_return(true)
          expect(subject.key_alg).to eq "RSASSA_PKCS1_V1_5_SHA_256"
        end

        it "iss = SIS", env: "SISJWT_ISS" do
          expect(subject.iss).to eq "SISi"
        end

        it "aud = SIS", env: "SISJWT_AUD" do
          expect(subject.aud).to eq "SISa"
        end

        it "iat uses now" do
          now = DateTime.now
          allow(DateTime).to receive(:now).and_return(now)
          expect(subject.iat).to eq now.to_f
        end

        it "exp uses iat+token_lifetime" do
          now = DateTime.now
          allow(DateTime).to receive(:now).and_return(now)
          expect(subject.exp).to eq now.to_i + subject.token_lifetime
        end
      end

      context "production_env" do
        before do
          allow(SisJwtOptions).to receive(:production_env?).and_return(true)
        end

        it "uses v1 token" do
          expect(subject.token_type == TOKEN_TYPE_V1)
        end

        it "uses 1m as token_lifetime" do
          expect(subject.token_lifetime == 60)
        end

        it "uses AWS_PROFILE=''", env: "AWS_PROFILE" do
          expect(subject.aws_profile).to eq ''
        end

        it "kms_configured?" do
          expect(subject.kms_configured?).to be_falsy
          expect(subject.production_token_type?).to be_truthy
          expect(subject.key_id).to be_blank
          expect(subject.key_alg).to be_blank

          subject.key_id = "arn:token"
          subject.key_alg = "arn:token"
          expect(subject.kms_configured?).to be_truthy
        end
      end
    end

    describe "validations" do
      subject { SisJwtOptions.defaults }

      before do
        subject.token_type = TOKEN_TYPE_V1
        subject.key_id = "arn:key"
        subject.key_alg = "magic"
        subject.iss = "SIE"
        subject.aud = "SIC"
      end

      def error_msgs_for(key)
        subject.validate
        subject.errors.full_messages_for(key)
      end

      context "signing mode" do
        context "of required attrs" do
          context "KMS attributes" do
            before do
              allow(subject).to receive(:kms_configured?).and_return(true)
            end

            it "key_alg" do
              expect(error_msgs_for(:key_alg)).to be_empty

              subject.key_alg = nil

              expect(error_msgs_for(:key_alg)).to_not be_empty
            end

            it "key_id" do
              expect(error_msgs_for(:key_id)).to be_empty

              subject.key_id = nil

              expect(error_msgs_for(:key_id)).to_not be_empty
            end

            it "aws_region" do
              expect(error_msgs_for(:aws_region)).to be_empty

              subject.aws_region = nil

              expect(error_msgs_for(:aws_region)).to_not be_empty
            end
          end

          it "token_lifetime" do
            expect(error_msgs_for(:token_lifetime)).to be_empty

            subject.token_lifetime = nil

            expect(error_msgs_for(:token_lifetime)).to_not be_empty
          end

          it "iss" do
            expect(error_msgs_for(:iss)).to be_empty

            subject.iss = nil

            expect(error_msgs_for(:iss)).to_not be_empty
          end

          it "aud" do
            expect(error_msgs_for(:aud)).to be_empty

            subject.aud = nil

            expect(error_msgs_for(:aud)).to_not be_empty
          end
        end

        it "doesn't allow ISS==AUD" do
          expect(error_msgs_for(:aud)).to be_empty
          expect(error_msgs_for(:iss)).to be_empty

          subject.iss = subject.aud

          expect(error_msgs_for(:aud)).to be_empty
          expect(error_msgs_for(:iss)).to_not be_empty
        end

        it "requires numeric exp" do
          expect(error_msgs_for(:exp)).to be_empty

          subject.exp = "1d"

          expect(error_msgs_for(:exp)).to_not be_empty
        end

        it "requires exp is after iat" do
          expect(error_msgs_for(:exp)).to be_empty

          subject.exp = subject.iat - 3_600

          expect(error_msgs_for(:exp)).to_not be_empty
        end

        context "token / production config" do
          before do
            allow(subject.class).to receive(:production_env?).and_return(true)
            subject.token_type = TOKEN_TYPE_V1
          end

          it "doesn't allow dev tokens to be issued" do
            expect(error_msgs_for(:token_type)).to be_empty

            subject.token_type = TOKEN_TYPE_DEV

            expect(error_msgs_for(:token_type)).to_not be_empty
          end

          it "KMS configured check" do
            expect(error_msgs_for(:base)).to be_empty
            expect(subject.kms_configured?).to be_truthy

            # Will break KMS Setup
            subject.key_id = nil

            expect(subject.kms_configured?).to be_falsy
            expect(error_msgs_for(:base)).to_not be_empty
          end
        end

      end
    end
  end
end