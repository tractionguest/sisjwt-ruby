# frozen_string_literal: true

group :test_then_lint, halt_on_fail: true do
  guard :rspec, cmd: './bin/rspec' do
    watch(%r{^lib/(.+).rb}) { |m| "spec/#{m[1]}_spec.rb" }
    watch(%r{^spec/(.+)_spec.rb})
  end

  guard :rubocop, keep_failed: false, cmd: './bin/rubocop', cli: '-DES' do
    watch(/.+\.rb$/)
    watch(%r{(?:.+/)?\.rubocop(?:_todo)?\.yml$}) { |m| File.dirname(m[0]) }
  end
end
