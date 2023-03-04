# frozen_string_literal: true

RSpec.describe Sisjwt::Runtime do
  subject(:runtime) { described_class.new }

  describe '#production_env?' do
    subject(:options) { runtime.production_env? }

    it { expect(defined?(Rails)).to be_falsy }

    context 'without Rails' do
      context 'when RAILS_ENV is unset' do
        mock_env 'RAILS_ENV', nil

        it { expect(Module).not_to be_const_defined :Rails }
        it { is_expected.to be_falsy }
      end

      context 'when RAILS_ENV=test' do
        mock_env 'RAILS_ENV', 'test'

        it { expect(Module).not_to be_const_defined(:Rails) }
        it { is_expected.to be_falsy }
      end

      context 'when RAILS_ENV=development' do
        mock_env 'RAILS_ENV', 'development'

        it { expect(Module).not_to be_const_defined(:Rails) }
        it { is_expected.to be_falsy }
      end

      context 'when RAILS_ENV=production' do
        mock_env 'RAILS_ENV', 'production'

        it { expect(Module).not_to be_const_defined(:Rails) }
        it { is_expected.to be_truthy }
      end
    end

    context 'with Rails' do
      let(:rails) { Struct.new('Rails', :env).new }

      before do
        allow(Module).to receive(:const_defined?).with(:Rails).and_return(true)
        allow(Module).to receive(:const_get).with(:Rails).and_return(rails)
      end

      it 'Rails.env.test' do
        rails.env = ActiveSupport::StringInquirer.new('test')
        expect(Module).to be_const_defined(:Rails)

        expect(options).to be_falsy
      end

      it 'Rails.env.development' do
        rails.env = ActiveSupport::StringInquirer.new('development')
        expect(Module).to be_const_defined(:Rails)

        expect(options).to be_falsy
      end

      it 'Rails.env.production' do
        rails.env = ActiveSupport::StringInquirer.new('production')
        expect(Module).to be_const_defined(:Rails)

        expect(options).to be_truthy
      end
    end
  end

  describe '.valid_token_type?' do
    context 'when in a non-production env' do
      it 'allows v1 token type' do
        expect(runtime).to be_valid_token_type(Sisjwt::TOKEN_TYPE_V1)
      end

      it 'allows dev token type' do
        expect(runtime).to be_valid_token_type(Sisjwt::TOKEN_TYPE_DEV)
      end
    end

    context 'when in a production env' do
      mock_env 'RAILS_ENV', 'production'

      it 'allows v1 token type' do
        expect(runtime).to be_valid_token_type(Sisjwt::TOKEN_TYPE_V1)
      end

      it 'DOES NOT allow dev token type' do
        expect(runtime).not_to be_valid_token_type(Sisjwt::TOKEN_TYPE_DEV)
      end
    end
  end
end
