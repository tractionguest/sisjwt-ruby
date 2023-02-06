# frozen_string_literal: true

require_relative "lib/sisjwt/version"

Gem::Specification.new do |spec|
  spec.name = "sisjwt"
  spec.version = Sisjwt::VERSION
  spec.authors = ["Andrew Burns"]
  spec.email = ["andrew.burns@signinsolutions.com"]

  spec.summary = "Ruby implementation of Sign In Solutions JWT Standard"
  spec.description = spec.summary
  # spec.homepage = "TODO: Put your gem's website or public repo URL here."
  spec.required_ruby_version = ">= 2.6.0"

  # spec.metadata["allowed_push_host"] = "TODO: Set to your gem server 'https://example.com'"

  # spec.metadata["homepage_uri"] = spec.homepage
  # spec.metadata["source_code_uri"] = "TODO: Put your gem's public repo URL here."
  # spec.metadata["changelog_uri"] = "TODO: Put your gem's CHANGELOG.md URL here."

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "bin"
  spec.executables << "sisjwt" #spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "jwt", "~> 2.6.0"
  spec.add_dependency "activesupport", "~> 6.0.5"
  spec.add_dependency "activemodel", "~> 6.0.5"

  spec.add_development_dependency "solargraph"
  spec.add_development_dependency "pry"
end
