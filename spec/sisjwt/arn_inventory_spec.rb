# frozen_string_literal: true

RSpec.describe Sisjwt::ArnInventory do
  subject(:inventory) { described_class.new }

  let(:inventory_config_path) { 'spec/support/fixtures/arn_inventory.yaml' }
  let(:env) { :test }
  let(:sie_arns) { %w[arn:A] }
  let(:sic_arns) { %w[arn:C] }

  describe '#add_from_config' do
    context 'when env: test' do
      before do
        inventory.add_from_config(inventory_config_path, env: env)
      end

      it { expect(inventory).not_to be_empty }

      it 'loads inventory from SIE section' do
        sie_arns.each do |arn|
          expect(inventory.valid_arn?(:sie, arn)).to be_truthy, "Expected arn '#{arn}' to be present"
        end
      end

      it 'loads inventory from SIC section' do
        sic_arns.each do |arn|
          expect(inventory.valid_arn?(:sic, arn)).to be_truthy, "Expected arn '#{arn}' to be present"
        end
      end

      it 'returns false if arn isnt in inventory' do
        expect(inventory).not_to be_valid_arn(:sie, sic_arns.sample)
        expect(inventory).not_to be_valid_arn(:sic, sie_arns.sample)
      end

      it 'allows strings for issuer' do
        expect(inventory).to be_valid_arn('sie', sie_arns.sample)
        expect(inventory).to be_valid_arn('sic', sic_arns.sample)
      end
    end

    context 'when env: devkube' do
      let(:env) { :devkube }
      let(:sie_arns) { %w[arn:a arn:b] }
      let(:sic_arns) { %w[arn:c arn:d] }

      before { inventory.add_from_config(inventory_config_path, env: env) }

      it { expect(inventory).not_to be_empty }

      it 'loads inventory from SIE section' do
        sie_arns.each do |arn|
          expect(inventory.valid_arn?(:sie, arn)).to be_truthy, "Expected arn '#{arn}' to be present"
        end
      end

      it 'loads inventory from SIC section' do
        sic_arns.each do |arn|
          expect(inventory.valid_arn?(:sic, arn)).to be_truthy, "Expected arn '#{arn}' to be present"
        end
      end
    end

    context 'with ERB parsing' do
      let(:inventory_config_path) { 'spec/support/fixtures/arn_inventory.yaml.erb' }

      it 'expands template and loads file' do
        ENV['SIE_ARN'] = 'echo'
        ENV['SIC_ARN'] = 'charlie'

        inventory.add_from_config(inventory_config_path, env: :test)

        expect(inventory).to be_valid_arn(:sie, 'echo')
        expect(inventory).to be_valid_arn(:sic, 'charlie')
      end
    end
  end

  describe '#empty?' do
    it { expect(inventory).to be_empty }
  end

  describe '#find_issuer' do
    before { inventory.add_from_config(inventory_config_path, env: env) }

    it { expect(inventory).not_to be_empty }

    it 'finds the correct issuer' do
      expect(inventory.find_issuer(sic_arns.sample)).to eq 'sic'
    end

    it 'returns nil if issuer not in inventory' do
      expect(inventory.find_issuer('arn:missing')).to be_nil
    end
  end
end
