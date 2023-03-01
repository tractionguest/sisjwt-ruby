# frozen_string_literal: true

module KmsExampleGroupHelpers
  def mock_kms(options = nil, configured:)
    before do
      opts = options || subject # rubocop:disable RSpec/NamedSubject
      allow(opts).to receive(:kms_configured?).and_return(configured)
    end
  end
end

RSpec.configure do |config|
  config.extend KmsExampleGroupHelpers
end
