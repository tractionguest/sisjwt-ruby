# frozen_string_literal: true
require 'simplecov'
SimpleCov.start

require "sisjwt"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.around(:example, :env) do |example|
    env_meta = Array(example.metadata[:env])
    orig_values = {}

    env_meta.each do |entry|
      key,value = entry.split("=", 2)

      orig_values[key] = ENV[key]
      if value.nil?
        ENV.delete(key)
      else
        ENV[key] = value
      end
    end

    example.run

    orig_values.each do |key, orig_value|
      ENV[key] = orig_value
    end
  end

end
