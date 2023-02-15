# frozen_string_literal: true

RSpec.describe Sisjwt::VERSION do
  subject { Sisjwt::VERSION }

  let :semver_regex do
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/
  end

  it 'is a Semver version number' do
    is_expected.to match(semver_regex)
  end
end
