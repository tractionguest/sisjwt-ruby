# frozen_string_literal: true

module EnvExampleGroupHelpers
  def mock_env(name, value)
    around do |example|
      pre_exist = ENV.key?(name)
      old_value = ENV.fetch(name, nil)

      value ? ENV[name] = value : ENV.delete(name)
      example.call
      pre_exist ? ENV[name] = old_value : ENV.delete(name)
    end
  end
end

RSpec.configure do |config|
  config.extend EnvExampleGroupHelpers
end
