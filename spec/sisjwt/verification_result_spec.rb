# frozen_string_literal: true
module Sisjwt
  RSpec.describe VerificationResult do
    let(:token_type) { Sisjwt::TOKEN_TYPE_V1 }
    let(:key_id) { "arn:key" }
    let(:key_alg) { "RSASSA_PKCS1_V1_5_SHA_256" }
    let(:headers) { { alg: token_type, kid: key_id, AWS_ALG: key_alg }.with_indifferent_access }
    let(:aud) { "SIC" }
    let(:iss) { "SIE" }
    let(:iat) { Time.now.to_f }
    let(:exp) { iat + 3_600 }
    let(:payload_overrides) { {} }
    let(:payload) { {aud: aud, iss: iss, iat: iat, exp: exp}.merge(payload_overrides).with_indifferent_access }
    let(:init_error) { nil }
    subject { VerificationResult.new(headers, payload, error: init_error) }

    describe "#initialize" do
      it "copies values as expected" do
        expect(subject.jwt_error).to eq init_error

        expect(subject.token_type).to eq token_type
        expect(subject.initial_lifetime).to eq 3_600
        expect(subject.iss).to eq iss
        expect(subject.aud).to eq aud
      end

      it "has expected state" do
        expect(subject).to_not be_expired
        expect(subject.life_left).to be_within(0.5).of(3_600)
        expect(subject.age).to be_within(0.5).of(0)
      end
    end

    describe "#to_h" do
      let(:hash) { subject.to_h.with_indifferent_access }

      context "non-production", env: "RAILS_ENV=development" do
        it "includes debugging data" do
          expect(hash).to have_key(:lifetime)
        end
      end

      context "production" do
        it "doesn't include debugging keys", env: "RAILS_ENV=production" do
          expect(hash).to_not have_key(:lifetime)
        end
      end
    end

    describe "validations" do
      context "error passed to initializer" do
        let(:init_error) { StandardError.new("uniqKey:LQpgr7N") }

        context "w/o headers or payload data" do
          let(:headers) { nil }
          let(:payload) { nil }

          it "returns only error object message" do
            errors = subject.errors.full_messages_for(:base)
            expect(errors.size).to eq 1
            expect(errors[0]).to eq init_error
          end
        end
      end
    end
  end
end

