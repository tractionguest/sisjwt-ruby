# frozen_string_literal: true
module Sisjwt
  RSpec.describe SisJwt do
    describe "#build" do
      it "uses SisJwtOptions.current" do
        options = {}
        expect(SisJwtOptions).to receive(:current).and_return(options)
        expect(SisJwt).to receive(:new).with(options).and_call_original

        jwt = SisJwt.build

        expect(jwt.options).to be options
      end
    end

    describe ".initialize" do
      it "assigns options and logger" do
        options = SisJwtOptions.current
        logger = Logger.new("/dev/null")

        jwt = SisJwt.new(options, logger: logger)

        expect(jwt.options).to be options
        expect(jwt.logger).to be logger
      end
    end

    describe ".encode" do
      it "requires that payload is a hash"

      context "payload" do
        context "overrides values if present" do
          it "iss"

          it "aud"

          it "iat"
        end

        context "uses values if present" do
          it "iat"

          it "exp"
        end

        it "removes nil values"
      end

      context "headers" do
        it "alg"

        it "kid"

        it "AWS_ALG"

        it "removes null values"
      end

      it "calls JWT library to create token"
    end

    describe ".verify" do
      it "uses JWT library to decode token"

      context "AWS KMS configured" do
        it "returns KMS verification context"
      end

      context "dev mode is configured" do
        it "returns shared secret"
      end
    end
  end
end

