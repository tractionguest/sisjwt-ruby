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

    describe ".encode"

    describe ".verify"
  end
end

