require 'spec_helper'
describe 'ssh::config_file_client' do
  let(:title) { '/test/ing' }

  # The following tests are OS independent, so we only test one
  redhat = {
    supported_os: [
      {
        'operatingsystem'        => 'RedHat',
        'operatingsystemrelease' => ['7'],
      },
    ],
  }

  content_header = <<-END.gsub(%r{^\s+\|}, '')
    |# This file is being maintained by Puppet.
    |# DO NOT EDIT
    |
  END

  on_supported_os(redhat).sort.each do |os, os_facts|
    let(:facts) { os_facts }

    context "on #{os} with default values for parameters" do
      it { is_expected.to compile.with_all_deps }
      it do
        is_expected.to contain_file('/test/ing').only_with(
          {
            'ensure'  => 'present',
            'path'    => '/test/ing',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'content' => content_header,
          },
        )
      end
    end

    context "on #{os} with ensure set to valid value" do
      let(:params) { { ensure: 'absent' } }

      it { is_expected.to contain_file('/test/ing').with_ensure('absent') }
    end

    context "on #{os} with path set to valid value" do
      let(:params) { { path: '/specific/path' } }

      it { is_expected.to contain_file('/specific/path').with_path('/specific/path') }
    end

    context "on #{os} with owner set to valid value" do
      let(:params) { { owner: 'test' } }

      it { is_expected.to contain_file('/test/ing').with_owner('test') }
    end

    context "on #{os} with group set to valid value" do
      let(:params) { { group: 'test' } }

      it { is_expected.to contain_file('/test/ing').with_group('test') }
    end

    context "on #{os} with mode set to valid value" do
      let(:params) { { mode: '0242' } }

      it { is_expected.to contain_file('/test/ing').with_mode('0242') }
    end

    context "on #{os} with lines set to valid value" do
      let(:params) do
        {
          lines: {
            'Host'                             => 'test.ing',
            'Match'                            => 'test',
            'AddKeysToAgent'                   => 'confirm',
            'AddressFamily'                    => 'inet6',
            'BatchMode'                        => 'yes',
            'BindAddress'                      => 'test',
            'BindInterface'                    => 'test',
            'CanonicalDomains'                 => 'test',
            'CanonicalizeFallbackLocal'        => 'yes',
            'CanonicalizeHostname'             => 'always',
            'CanonicalizeMaxDots'              => 242,
            'CanonicalizePermittedCNAMEs'      => 'test',
            'CASignatureAlgorithms'            => 'test',
            'CertificateFile'                  => 'test',
            'CheckHostIP'                      => 'yes',
            'Ciphers'                          => 'test',
            'ClearAllForwardings'              => 'yes',
            'Compression'                      => 'yes',
            'ConnectionAttempts'               => 242,
            'ConnectTimeout'                   => 242,
            'ControlMaster'                    => 'auto',
            'ControlPath'                      => 'test',
            'ControlPersist'                   => 'test',
            'DynamicForward'                   => 'test',
            'EnableEscapeCommandline'          => 'yes',
            'EnableSSHKeysign'                 => 'yes',
            'EscapeChar'                       => 'test',
            'ExitOnForwardFailure'             => 'yes',
            'FingerprintHash'                  => 'sha256',
            'ForkAfterAuthentication'          => 'yes',
            'ForwardAgent'                     => 'yes',
            'ForwardX11'                       => 'yes',
            'ForwardX11Timeout'                => 'test',
            'ForwardX11Trusted'                => 'yes',
            'GatewayPorts'                     => 'yes',
            'GlobalKnownHostsFile'             => 'test',
            'GSSAPIAuthentication'             => 'yes',
            'GSSAPIDelegateCredentials'        => 'yes',
            'HashKnownHosts'                   => 'yes',
            'HostbasedAcceptedAlgorithms'      => 'test',
            'HostbasedAuthentication'          => 'yes',
            'HostKeyAlgorithms'                => 'test',
            'HostKeyAlias'                     => 'test',
            'Hostname'                         => 'test',
            'IdentitiesOnly'                   => 'yes',
            'IdentityAgent'                    => 'test',
            'IdentityFile'                     => 'test',
            'IgnoreUnknown'                    => 'test',
            'Include'                          => 'test',
            'IPQoS'                            => 'test',
            'KbdInteractiveAuthentication'     => 'yes',
            'KbdInteractiveDevices'            => 'test',
            'KexAlgorithms'                    => 'test',
            'KnownHostsCommand'                => 'test',
            'LocalCommand'                     => 'test',
            'LocalForward'                     => 'test',
            'LogLevel'                         => 'VERBOSE',
            'LogVerbose'                       => 'test',
            'MACs'                             => 'test',
            'NoHostAuthenticationForLocalhost' => 'yes',
            'NumberOfPasswordPrompts'          => 242,
            'PasswordAuthentication'           => 'yes',
            'PermitLocalCommand'               => 'yes',
            'PermitRemoteOpen'                 => 'test',
            'PKCS11Provider'                   => 'test',
            'Port'                             => 242,
            'PreferredAuthentications'         => 'test',
            'ProxyCommand'                     => 'test',
            'ProxyJump'                        => 'test',
            'ProxyUseFdpass'                   => 'yes',
            'PubkeyAcceptedAlgorithms'         => 'test',
            'PubkeyAuthentication'             => 'yes',
            'RekeyLimit'                       => 'test',
            'RemoteCommand'                    => 'test',
            'RemoteForward'                    => 'test',
            'RequestTTY'                       => 'auto',
            'RequiredRSASize'                  => 242,
            'RevokedHostKeys'                  => 'test',
            'SecurityKeyProvider'              => 'test',
            'SendEnv'                          => 'test',
            'ServerAliveCountMax'              => 'test',
            'ServerAliveInterval'              => 'test',
            'SessionType'                      => 'subsystem',
            'SetEnv'                           => 'test',
            'StdinNull'                        => 'yes',
            'StreamLocalBindMask'              => '0242',
            'StreamLocalBindUnlink'            => 'yes',
            'StrictHostKeyChecking'            => 'off',
            'SyslogFacility'                   => 'DAEMON',
            'TCPKeepAlive'                     => 'yes',
            'Tunnel'                           => 'point-to-point',
            'TunnelDevice'                     => 'test',
            'UpdateHostKeys'                   => 'yes',
            'User'                             => 'test',
            'UserKnownHostsFile'               => 'test',
            'VerifyHostKeyDNS'                 => 'ask',
            'VisualHostKey'                    => 'yes',
            'XAuthLocation'                    => 'test',
          },
        }
      end

      content_full = <<-END.gsub(%r{^\s+\|}, '')
        |# This file is being maintained by Puppet.
        |# DO NOT EDIT
        |
        |Host test.ing
        |Match test
        |AddKeysToAgent confirm
        |AddressFamily inet6
        |BatchMode yes
        |BindAddress test
        |BindInterface test
        |CanonicalDomains test
        |CanonicalizeFallbackLocal yes
        |CanonicalizeHostname always
        |CanonicalizeMaxDots 242
        |CanonicalizePermittedCNAMEs test
        |CASignatureAlgorithms test
        |CertificateFile test
        |CheckHostIP yes
        |Ciphers test
        |ClearAllForwardings yes
        |Compression yes
        |ConnectionAttempts 242
        |ConnectTimeout 242
        |ControlMaster auto
        |ControlPath test
        |ControlPersist test
        |DynamicForward test
        |EnableEscapeCommandline yes
        |EnableSSHKeysign yes
        |EscapeChar test
        |ExitOnForwardFailure yes
        |FingerprintHash sha256
        |ForkAfterAuthentication yes
        |ForwardAgent yes
        |ForwardX11 yes
        |ForwardX11Timeout test
        |ForwardX11Trusted yes
        |GatewayPorts yes
        |GlobalKnownHostsFile test
        |GSSAPIAuthentication yes
        |GSSAPIDelegateCredentials yes
        |HashKnownHosts yes
        |HostbasedAcceptedAlgorithms test
        |HostbasedAuthentication yes
        |HostKeyAlgorithms test
        |HostKeyAlias test
        |Hostname test
        |IdentitiesOnly yes
        |IdentityAgent test
        |IdentityFile test
        |IgnoreUnknown test
        |Include test
        |IPQoS test
        |KbdInteractiveAuthentication yes
        |KbdInteractiveDevices test
        |KexAlgorithms test
        |KnownHostsCommand test
        |LocalCommand test
        |LocalForward test
        |LogLevel VERBOSE
        |LogVerbose test
        |MACs test
        |NoHostAuthenticationForLocalhost yes
        |NumberOfPasswordPrompts 242
        |PasswordAuthentication yes
        |PermitLocalCommand yes
        |PermitRemoteOpen test
        |PKCS11Provider test
        |Port 242
        |PreferredAuthentications test
        |ProxyCommand test
        |ProxyJump test
        |ProxyUseFdpass yes
        |PubkeyAcceptedAlgorithms test
        |PubkeyAuthentication yes
        |RekeyLimit test
        |RemoteCommand test
        |RemoteForward test
        |RequestTTY auto
        |RequiredRSASize 242
        |RevokedHostKeys test
        |SecurityKeyProvider test
        |SendEnv test
        |ServerAliveCountMax test
        |ServerAliveInterval test
        |SessionType subsystem
        |SetEnv test
        |StdinNull yes
        |StreamLocalBindMask 0242
        |StreamLocalBindUnlink yes
        |StrictHostKeyChecking off
        |SyslogFacility DAEMON
        |TCPKeepAlive yes
        |Tunnel point-to-point
        |TunnelDevice test
        |UpdateHostKeys yes
        |User test
        |UserKnownHostsFile test
        |VerifyHostKeyDNS ask
        |VisualHostKey yes
        |XAuthLocation test
      END

      it { is_expected.to contain_file('/test/ing').with_content(content_full) }
    end

    context "on #{os} with custom set to valid value" do
      let(:params) { { custom: ['Directive Value', 'Test2 Value2'] } }

      content_custom = <<-END.gsub(%r{^\s+\|}, '')
        |# This file is being maintained by Puppet.
        |# DO NOT EDIT
        |
        |Directive Value
        |Test2 Value2
      END
      it { is_expected.to contain_file('/test/ing').with_content(content_custom) }
    end

    context "on #{os} with lines and custom set to valid value" do
      let(:params) { { lines: { 'AddressFamily' => 'inet6', 'Ciphers' => 'test' }, custom: ['Directive Value', 'Test2 Value2'] } }

      content_mix = <<-END.gsub(%r{^\s+\|}, '')
        |# This file is being maintained by Puppet.
        |# DO NOT EDIT
        |
        |AddressFamily inet6
        |Ciphers test
        |Directive Value
        |Test2 Value2
      END
      it { is_expected.to contain_file('/test/ing').with_content(content_mix) }
    end

    context "on #{os} with lines set to invalid value" do
      let(:params) { { lines: { 'AddressFamily' => 'test' } } }

      it 'fail' do
        expect { is_expected.to contain_class(:subject) }.to raise_error(Puppet::Error, %r{expects a match})
      end
    end
  end
end
