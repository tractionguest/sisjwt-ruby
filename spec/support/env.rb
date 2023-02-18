# frozen_string_literal: true
RSpec.configure do |config|
  config.around(:example, :env) do |example|
    env_meta = Array(example.metadata[:env])
    orig_values = {}

    env_meta.each do |entry|
      key, value = entry.split('=', 2)

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
