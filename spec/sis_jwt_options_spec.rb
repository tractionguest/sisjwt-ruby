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
      # let(:token_type_v1) { ::TOKEN_TYPE_V1 }
      # let(:token_type_dev) { SisJwtOptions::TOKEN_TYPE_DEV }

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
          expect(subject.iss).to eq "SIS"
        end

        it "aud = SIS", env: "SISJWT_AUD" do
          expect(subject.aud).to eq "SIS"
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
  end
end
