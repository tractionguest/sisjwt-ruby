# frozen_string_literal: true
module Sisjwt::Algo
  RSpec.describe SisJwtV1 do
    describe ".initialize" do
      it "sets and validates options"

      context "KMS mode" do
        it "raises error if options are invalid"
      end

      context "dev mode" do
        it "raises error if runing in production"
      end

      it "sets or creates logger"
    end

    describe "ruby-kwt algorithim contract" do
      it "alg"

      it "valid_alg?"

      it "sign"

      it "verify"
    end

    describe ".sign" do
      context "KMS" do
        it "calls KMS"
      end

      context "Development" do
        it "uses SHA512 HMAC /w shared secret"
      end
    end

    describe ".verify" do
      context "KMS" do
        it "calls KMS"
      end

      context "Development" do
        it "uses SHA512 HMAC /w shared secret"
      end
    end
  end
end

