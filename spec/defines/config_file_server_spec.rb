require 'spec_helper'
describe 'ssh::config_file_server' do
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
            'mode'    => '0600',
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
            'AcceptEnv'                       => 'test',
            'AddressFamily'                   => 'inet6',
            'AllowAgentForwarding'            => 'yes',
            'AllowGroups'                     => 'test',
            'AllowStreamLocalForwarding'      => 'local',
            'AllowTcpForwarding'              => 'local',
            'AllowUsers'                      => 'test',
            'AuthenticationMethods'           => 'test',
            'AuthorizedKeysCommand'           => 'test',
            'AuthorizedKeysCommandUser'       => 'test',
            'AuthorizedKeysFile'              => 'test',
            'AuthorizedPrincipalsCommand'     => 'test',
            'AuthorizedPrincipalsCommandUser' => 'test',
            'AuthorizedPrincipalsFile'        => 'test',
            'Banner'                          => 'test',
            'CASignatureAlgorithms'           => 'test',
            'ChallengeResponseAuthentication' => 'yes',
            'ChannelTimeout'                  => 'test',
            'ChrootDirectory'                 => 'test',
            'Ciphers'                         => 'test',
            'ClientAliveCountMax'             => 242,
            'ClientAliveInterval'             => 242,
            'Compression'                     => 'delayed',
            'DenyGroups'                      => 'test',
            'DenyUsers'                       => 'test',
            'DisableForwarding'               => 'yes',
            'ExposeAuthInfo'                  => 'yes',
            'FingerprintHash'                 => 'sha256',
            'ForceCommand'                    => 'test',
            'GatewayPorts'                    => 'clientspecified',
            'GSSAPIAuthentication'            => 'yes',
            'GSSAPICleanupCredentials'        => 'yes',
            'GSSAPIStrictAcceptorCheck'       => 'yes',
            'HostbasedAcceptedAlgorithms'     => 'test',
            'HostbasedAuthentication'         => 'yes',
            'HostbasedUsesNameFromPacketOnly' => 'yes',
            'HostCertificate'                 => 'test',
            'HostKey'                         => 'test',
            'HostKeyAgent'                    => 'test',
            'HostKeyAlgorithms'               => 'test',
            'IgnoreRhosts'                    => 'yes',
            'IgnoreUserKnownHosts'            => 'yes',
            'Include'                         => 'test',
            'IPQoS'                           => 'test',
            'KbdInteractiveAuthentication'    => 'yes',
            'KerberosAuthentication'          => 'yes',
            'KerberosGetAFSToken'             => 'yes',
            'KerberosOrLocalPasswd'           => 'yes',
            'KerberosTicketCleanup'           => 'yes',
            'KexAlgorithms'                   => 'test',
            'ListenAddress'                   => 'test',
            'LoginGraceTime'                  => 242,
            'LogLevel'                        => 'VERBOSE',
            'LogVerbose'                      => 'test',
            'MACs'                            => 'test',
            'Match'                           => 'test',
            'MaxAuthTries'                    => 242,
            'MaxSessions'                     => 242,
            'MaxStartups'                     => 'test',
            'ModuliFile'                      => '/test/ing',
            'PasswordAuthentication'          => 'yes',
            'PermitEmptyPasswords'            => 'yes',
            'PermitListen'                    => 'test',
            'PermitOpen'                      => 'test',
            'PermitRootLogin'                 => 'prohibit-password',
            'PermitTTY'                       => 'yes',
            'PermitTunnel'                    => 'point-to-point',
            'PermitUserEnvironmen'            => 'test',
            'PermitUserRC'                    => 'yes',
            'PerSourceMaxStartups'            => 'test',
            'PerSourceNetBlockSize'           => 'test',
            'PidFile'                         => 'test',
            'Port'                            => 242,
            'PrintLastLog'                    => 'yes',
            'PrintMotd'                       => 'yes',
            'PubkeyAcceptedAlgorithms'        => 'test',
            'PubkeyAuthOptions'               => 'verify-required',
            'PubkeyAuthentication'            => 'yes',
            'RekeyLimit'                      => 'test',
            'RequiredRSASize'                 => 242,
            'RevokedKeys'                     => 'test',
            'RDomain'                         => 'test',
            'SecurityKeyProvider'             => '/test/ing',
            'SetEnv'                          => 'test',
            'StreamLocalBindMask'             => '0242',
            'StreamLocalBindUnlink'           => 'yes',
            'StrictModes'                     => 'yes',
            'Subsystem'                       => 'test',
            'SyslogFacility'                  => 'DAEMON',
            'TCPKeepAlive'                    => 'yes',
            'TrustedUserCAKeys'               => 'test',
            'UseDNS'                          => 'yes',
            'UsePAM'                          => 'yes',
            'VersionAddendum'                 => 'test',
            'X11DisplayOffset'                => 242,
            'X11Forwarding'                   => 'yes',
            'X11UseLocalhost'                 => 'yes',
            'XAuthLocation'                   => 'test',
          },
        }
      end

      content_full = <<-END.gsub(%r{^\s+\|}, '')
        |# This file is being maintained by Puppet.
        |# DO NOT EDIT
        |
        |AcceptEnv test
        |AddressFamily inet6
        |AllowAgentForwarding yes
        |AllowGroups test
        |AllowStreamLocalForwarding local
        |AllowTcpForwarding local
        |AllowUsers test
        |AuthenticationMethods test
        |AuthorizedKeysCommand test
        |AuthorizedKeysCommandUser test
        |AuthorizedKeysFile test
        |AuthorizedPrincipalsCommand test
        |AuthorizedPrincipalsCommandUser test
        |AuthorizedPrincipalsFile test
        |Banner test
        |CASignatureAlgorithms test
        |ChallengeResponseAuthentication yes
        |ChannelTimeout test
        |ChrootDirectory test
        |Ciphers test
        |ClientAliveCountMax 242
        |ClientAliveInterval 242
        |Compression delayed
        |DenyGroups test
        |DenyUsers test
        |DisableForwarding yes
        |ExposeAuthInfo yes
        |FingerprintHash sha256
        |ForceCommand test
        |GatewayPorts clientspecified
        |GSSAPIAuthentication yes
        |GSSAPICleanupCredentials yes
        |GSSAPIStrictAcceptorCheck yes
        |HostbasedAcceptedAlgorithms test
        |HostbasedAuthentication yes
        |HostbasedUsesNameFromPacketOnly yes
        |HostCertificate test
        |HostKey test
        |HostKeyAgent test
        |HostKeyAlgorithms test
        |IgnoreRhosts yes
        |IgnoreUserKnownHosts yes
        |Include test
        |IPQoS test
        |KbdInteractiveAuthentication yes
        |KerberosAuthentication yes
        |KerberosGetAFSToken yes
        |KerberosOrLocalPasswd yes
        |KerberosTicketCleanup yes
        |KexAlgorithms test
        |ListenAddress test
        |LoginGraceTime 242
        |LogLevel VERBOSE
        |LogVerbose test
        |MACs test
        |Match test
        |MaxAuthTries 242
        |MaxSessions 242
        |MaxStartups test
        |ModuliFile /test/ing
        |PasswordAuthentication yes
        |PermitEmptyPasswords yes
        |PermitListen test
        |PermitOpen test
        |PermitRootLogin prohibit-password
        |PermitTTY yes
        |PermitTunnel point-to-point
        |PermitUserEnvironmen test
        |PermitUserRC yes
        |PerSourceMaxStartups test
        |PerSourceNetBlockSize test
        |PidFile test
        |Port 242
        |PrintLastLog yes
        |PrintMotd yes
        |PubkeyAcceptedAlgorithms test
        |PubkeyAuthOptions verify-required
        |PubkeyAuthentication yes
        |RekeyLimit test
        |RequiredRSASize 242
        |RevokedKeys test
        |RDomain test
        |SecurityKeyProvider /test/ing
        |SetEnv test
        |StreamLocalBindMask 0242
        |StreamLocalBindUnlink yes
        |StrictModes yes
        |Subsystem test
        |SyslogFacility DAEMON
        |TCPKeepAlive yes
        |TrustedUserCAKeys test
        |UseDNS yes
        |UsePAM yes
        |VersionAddendum test
        |X11DisplayOffset 242
        |X11Forwarding yes
        |X11UseLocalhost yes
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
