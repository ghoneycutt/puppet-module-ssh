require 'spec_helper_acceptance'

describe 'ssh class' do
  context 'ssh' do
    context 'with default values for all parameters' do
      context 'it should be idempotent' do
        # if fact('osfamily') == 'Debian' and fact('operatingsystemrelease') == '16.04'
        #   before { skip('Ubuntu 16.04 has a systemd issue that makes setting the service enable not idempotent. Skipping test.') }
        # end

        it 'work with no errors' do
          pp = <<-EOS
          include ssh
          EOS

          # Run it twice and test for idempotency
          apply_manifest(pp, catch_failures: true)
          apply_manifest(pp, catch_changes: true)
        end
      end

      context 'should contain resources' do
        pp = <<-EOS
        include ssh
        EOS

        apply_manifest(pp, catch_failures: true)

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
  end
end
