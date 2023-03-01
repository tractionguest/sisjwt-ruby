# frozen_string_literal: true

RSpec.describe Sisjwt::ArnInventory do
  let(:inventory_config_path) { "spec/support/fixtures/arn_inventory.yaml" }
  let(:env) { :test }
  let(:sie_arns) { %w(arn:A) }
  let(:sic_arns) { %w(arn:C) }

  describe '#add_from_config' do
    context "env: test" do
      before do
        expect(subject).to be_empty
        subject.add_from_config(inventory_config_path, env: env)
        expect(subject).to_not be_empty
      end

      it 'loads inventory from expected section' do
        sie_arns.each do |arn|
          expect(subject.valid_arn?(:sie, arn)).to be_truthy, "Expected arn '#{arn}' to be present"
        end
        sic_arns.each do |arn|
          expect(subject.valid_arn?(:sic, arn)).to be_truthy, "Expected arn '#{arn}' to be present"
        end
      end

      it 'returns false if arn isnt in inventory' do
        expect(subject.valid_arn?(:sie, sic_arns.sample)).to be_falsy
        expect(subject.valid_arn?(:sic, sie_arns.sample)).to be_falsy
      end

      it 'allows strings for issuer' do
        expect(subject.valid_arn?('sie', sie_arns.sample)).to be_truthy
        expect(subject.valid_arn?('sic', sic_arns.sample)).to be_truthy
      end
    end

    context "env: devkube" do
      let(:env) { :devkube }
      let(:sie_arns) { %w(arn:a arn:b) }
      let(:sic_arns) { %w(arn:c arn:d) }

      before do
        expect(subject).to be_empty
        subject.add_from_config(inventory_config_path, env: env)
        expect(subject).to_not be_empty
      end

      it 'loads inventory from expected section' do
        sie_arns.each do |arn|
          expect(subject.valid_arn?(:sie, arn)).to be_truthy, "Expected arn '#{arn}' to be present"
        end
        sic_arns.each do |arn|
          expect(subject.valid_arn?(:sic, arn)).to be_truthy, "Expected arn '#{arn}' to be present"
        end
      end
    end
  end

  describe "#find_issuer" do
    before do
      expect(subject).to be_empty
      subject.add_from_config(inventory_config_path, env: env)
      expect(subject).to_not be_empty
    end

    it 'finds the correct issuer' do
      expect(subject.find_issuer(sic_arns.sample)).to eq "sic"
    end

    it 'returns nil if issuer not in inventory' do
      expect(subject.find_issuer("arn:missing")).to be_nil
    end
  end
end
