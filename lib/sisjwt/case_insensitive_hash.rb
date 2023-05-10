# frozen_string_literal: true

module Sisjwt
  # An immutable {Hash} subclass where every key is a case-insensitive string.
  class CaseInsensitiveHash < Hash
    # @param src [Hash<#to_s, Object>, nil]
    def initialize(src = nil)
      super()
      @keys = Hash(src).to_h { |k, _| [normalize_key(k), k] }.freeze
      merge!(Hash(src).slice(*@keys.values))
      freeze
    end

    def fetch(key, *args, &blk)
      super(@keys[normalize_key(key)], *args, &blk)
    end

    def [](key)
      fetch(key, nil)
    end

    def key?(key)
      @keys.key?(normalize_key(key))
    end

    def ==(other)
      return false unless other.is_a?(Hash) && size == other.size

      other.each do |key, value|
        return false unless key?(key) && self[key] == value
      end

      true
    end

    private

    def normalize_key(key)
      key.to_s.downcase
    end
  end
end
