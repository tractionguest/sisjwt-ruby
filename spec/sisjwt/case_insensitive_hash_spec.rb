# frozen_string_literal: true

RSpec.describe Sisjwt::CaseInsensitiveHash do
  context 'when empty' do
    subject(:hash) { described_class.new }

    it 'is empty' do
      expect(hash).to be_empty
      expect(hash.size).to eq 0
    end
  end

  context 'with duplicate keys' do
    subject(:hash) { described_class.new(src) }

    let(:src) { { 'key' => 'lower', 'KeY' => 'MiXeD', 'KEY' => 'UPPER' } }

    it 'only keeps the last entry' do
      expect(hash.size).to eq 1
      expect(hash.values.first).to eq 'UPPER'
    end

    describe '#fetch' do
      it 'returns the same value for all capitalizations' do
        src.each_key { |key| expect(hash.fetch(key)).to eq 'UPPER' }
      end
    end

    describe '#[]' do
      it 'returns the same value for all capitalizations' do
        src.each_key { |key| expect(hash[key]).to eq 'UPPER' }
      end
    end

    describe '#key?' do
      it 'returns true for each key capitalization' do
        src.each_key { |key| expect(hash).to be_key key }
      end
    end

    describe '#keys' do
      it 'returns the keys with their original capitalization' do
        expect(hash.keys).to eq ['KEY']
      end
    end

    describe '#==' do
      context 'with another CaseInsensitiveHash' do
        it { expect(hash).to eq described_class.new('key' => 'UPPER') }
        it { expect(hash).to eq described_class.new('KeY' => 'UPPER') }
        it { expect(hash).not_to eq described_class.new('KEY' => 'lower') }
      end

      context 'with a Hash' do
        it { expect(hash).to eq('key' => 'UPPER') }
        it { expect(hash).to eq('KeY' => 'UPPER') }
        it { expect(hash).not_to eq('KEY' => 'lower') }
      end

      context 'with a string' do
        it { expect(hash).not_to eq '{ "KEY" => "UPPER" }' }
      end
    end
  end
end
