require 'spec_helper_acceptance'

describe 'ssh class' do
  context 'with default values for all parameters' do
    it_behaves_like 'an idempotent resource' do
      let(:manifest) { 'include ssh' }
    end

    describe package('openssh-clients'), if: fact('os.family') == 'RedHat' do
      it { is_expected.to be_installed }
    end

    describe package('openssh-client'), if: fact('os.family') == 'Debian' do
      it { is_expected.to be_installed }
    end

    describe service('sshd') do
      it { is_expected.to be_running }
      it { is_expected.to be_enabled }
    end
  end
end
