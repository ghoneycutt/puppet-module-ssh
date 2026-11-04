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

  context 'with non-default server and client config and config_files' do
    ciphers = ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr']
    macs = ['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512']
    kex_algorithms = ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512']

    # PermitRootLogin and PasswordAuthentication are left alone because
    # beaker logs in to the containers as root with a password
    it_behaves_like 'an idempotent resource' do
      let(:manifest) do
        <<-PUPPET
        class { 'ssh::server':
          ciphers                  => #{ciphers},
          macs                     => #{macs},
          kex_algorithms           => #{kex_algorithms},
          log_level                => 'VERBOSE',
          max_auth_tries           => 4,
          max_sessions             => 5,
          max_startups             => '10:30:60',
          login_grace_time         => 60,
          client_alive_interval    => 300,
          client_alive_count_max   => 2,
          banner                   => '/etc/sshd_banner',
          banner_content           => "Authorized uses only.\\n",
          permit_empty_passwords   => 'no',
          permit_user_environment  => 'no',
          hostbased_authentication => 'no',
          ignore_rhosts            => 'yes',
          allow_tcp_forwarding     => 'no',
          use_pam                  => 'yes',
          x11_forwarding           => 'yes',
          include                  => '/etc/ssh/sshd_config.d/*.conf',
          config_files             => {
            '50-acceptance' => {
              'lines' => {
                # overrides x11_forwarding above, as sshd keeps the first
                # value it reads and Include is at the top of sshd_config
                'X11Forwarding'                   => 'no',
                'AuthorizedPrincipalsCommand'     => '/bin/echo %u',
                'AuthorizedPrincipalsCommandUser' => 'nobody',
              },
            },
          },
        }

        class { 'ssh':
          server_alive_interval => 120,
          include               => '/etc/ssh/ssh_config.d/*.conf',
          config_files          => {
            '50-acceptance' => {
              'custom' => [
                'Host acceptance',
                '  ForwardAgent yes',
                '  LocalForward 8085 127.0.0.1:8085',
              ],
            },
          },
        }
        PUPPET
      end
    end

    describe command('/usr/sbin/sshd -t') do
      its(:exit_status) { is_expected.to eq 0 }
    end

    describe command('/usr/sbin/sshd -T') do
      its(:exit_status) { is_expected.to eq 0 }
      its(:stdout) { is_expected.to match %r{^ciphers #{ciphers.join(',')}$} }
      its(:stdout) { is_expected.to match %r{^macs #{macs.join(',')}$} }
      its(:stdout) { is_expected.to match %r{^kexalgorithms #{kex_algorithms.join(',')}$} }
      its(:stdout) { is_expected.to match %r{^loglevel VERBOSE$} }
      its(:stdout) { is_expected.to match %r{^maxauthtries 4$} }
      its(:stdout) { is_expected.to match %r{^maxsessions 5$} }
      its(:stdout) { is_expected.to match %r{^maxstartups 10:30:60$} }
      its(:stdout) { is_expected.to match %r{^logingracetime 60$} }
      its(:stdout) { is_expected.to match %r{^clientaliveinterval 300$} }
      its(:stdout) { is_expected.to match %r{^clientalivecountmax 2$} }
      its(:stdout) { is_expected.to match %r{^banner /etc/sshd_banner$} }
      its(:stdout) { is_expected.to match %r{^permitemptypasswords no$} }
      its(:stdout) { is_expected.to match %r{^permituserenvironment no$} }
      its(:stdout) { is_expected.to match %r{^hostbasedauthentication no$} }
      its(:stdout) { is_expected.to match %r{^ignorerhosts yes$} }
      its(:stdout) { is_expected.to match %r{^allowtcpforwarding no$} }
      its(:stdout) { is_expected.to match %r{^usepam yes$} }
      its(:stdout) { is_expected.to match %r{^x11forwarding no$} }
      its(:stdout) { is_expected.to match %r{^authorizedprincipalscommand /bin/echo %u$} }
      its(:stdout) { is_expected.to match %r{^authorizedprincipalscommanduser nobody$} }
    end

    describe file('/etc/sshd_banner') do
      its(:content) { is_expected.to eq "Authorized uses only.\n" }
    end

    describe service('sshd') do
      it { is_expected.to be_running }
      it { is_expected.to be_enabled }
    end

    describe command('ssh -G acceptance') do
      its(:exit_status) { is_expected.to eq 0 }
      its(:stdout) { is_expected.to match %r{^serveraliveinterval 120$} }
      its(:stdout) { is_expected.to match %r{^forwardagent yes$} }
      its(:stdout) { is_expected.to match %r{^localforward 8085 \[?127\.0\.0\.1\]?:8085$} }
    end

    # a Host block in an included file must not apply to other hosts
    describe command('ssh -G example.com') do
      its(:exit_status) { is_expected.to eq 0 }
      its(:stdout) { is_expected.to match %r{^serveraliveinterval 120$} }
      its(:stdout) { is_expected.to match %r{^forwardagent no$} }
      its(:stdout) { is_expected.not_to match %r{^localforward } }
    end
  end
end
