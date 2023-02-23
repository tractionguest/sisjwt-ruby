# frozen_string_literal: true

RSpec.describe Sisjwt::VERSION do
  subject(:version) { Sisjwt::VERSION } # rubocop:disable RSpec/DescribedClass

  # See https://semver.org/
  let :semver_regex do
    /
      ^
      (0|[1-9]\d*)\.
      (0|[1-9]\d*)\.
      (0|[1-9]\d*)
      (?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)
           (?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?
      (?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?
      $
    /x
  end

  it 'is a Semver version number' do
    expect(version).to match semver_regex
  end
end
