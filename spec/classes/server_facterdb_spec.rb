require 'spec_helper'
describe 'ssh::server' do
  header = <<-END.gsub(%r{^\s+\|}, '')
    |# This file is being maintained by Puppet.
    |# DO NOT EDIT
    |#
    |# See https://man.openbsd.org/sshd_config for more info
    |
  END

  on_supported_os.sort.each do |os, os_facts|
    context "on #{os} with default values for parameters" do
      let(:facts) { os_facts }

      # OS specific defaults
      case "#{os_facts[:os]['name']}-#{os_facts[:os]['release']['full']}"
      when %r{CentOS.*}, %r{OracleLinux.*}, %r{RedHat.*}, %r{Scientific.*}
        config_mode       = '0600'
        packages          = ['openssh-server']
        service_hasstatus = true
        service_name      = 'sshd'
      when %r{SLED.*}, %r{SLES.*}
        config_mode       = '0600'
        packages          = []
        service_name      = 'sshd'
        service_hasstatus = true
      when %r{Debian.*}, %r{Ubuntu.*}
        config_mode       = '0600'
        packages          = ['openssh-server']
        service_hasstatus = true
        service_name      = 'ssh'
      when %r{Solaris-9.*}
        config_mode       = '0644'
        packages          = 'SUNWsshdr', 'SUNWsshdu'
        packages_source   = '/var/spool/pkg'
        service_hasstatus = false
        service_name      = 'sshd'
      when %r{Solaris-10.*}
        config_mode       = '0644'
        packages          = 'SUNWsshdr', 'SUNWsshdu'
        packages_source   = '/var/spool/pkg'
        service_hasstatus = true
        service_name      = 'ssh'
      when %r{Solaris-11.*}
        config_mode       = '0644'
        packages          = ['service/network/ssh']
        service_hasstatus = true
        service_name      = 'ssh'
      end

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_class('ssh::server') }

      packages.each do |package|
        it do
          is_expected.to contain_package(package).only_with(
            {
              'ensure'    => 'installed',
              'source'    => packages_source,
              'adminfile' => nil,
              'before'    => 'File[sshd_config]',
            },
          )
        end
      end

      content_fixture = File.read(fixtures("#{os_facts[:os]['name']}-#{os_facts[:os]['release']['major']}_sshd_config"))

      it do
        is_expected.to contain_file('sshd_config').only_with(
          {
            'ensure'  => 'file',
            'path'    => '/etc/ssh/sshd_config',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => config_mode,
            'content' => content_fixture,
          },
        )
      end

      it { is_expected.not_to contain_file('sshd_banner') }

      it do
        is_expected.to contain_service('sshd_service').only_with(
          {
            'ensure'     => 'running',
            'name'       => service_name,
            'enable'     => true,
            'hasrestart' => service_hasstatus,
            'hasstatus'  => true,
            'subscribe'  => 'File[sshd_config]',
          },
        )
      end
    end
  end

  # test parameters
  # they aren't OS dependent, so we use a fictional OS without any default values
  let(:facts) { { os: { family: 'UnitTesting' } } }

  parameters = {
    'accept_env'                           => { str: 'AcceptEnv',                        val: [['LANG'], ['TEST', 'ING']], sep: "\nAcceptEnv ", },
    'address_family'                       => { str: 'AddressFamily',                    val: ['any', 'inet', 'inet6'], },
    'allow_agent_forwarding'               => { str: 'AllowAgentForwarding',             val: ['yes', 'no'], },
    'allow_groups'                         => { str: 'AllowGroups',                      val: [['test'], ['test', 'ing']], sep: ' ', },
    'allow_stream_local_forwarding'        => { str: 'AllowStreamLocalForwarding',       val: ['yes', 'all', 'no', 'local', 'remote'], },
    'allow_tcp_forwarding'                 => { str: 'AllowTcpForwarding',               val: ['yes', 'no', 'local', 'remote'], },
    'allow_users'                          => { str: 'AllowUsers',                       val: [['test'], ['test', 'ing']], sep: ' ', },
    'authentication_methods'               => { str: 'AuthenticationMethods',            val: [['publickey'], ['publickey', 'keyboard-interactive']], sep: ',', },
    'authorized_keys_command'              => { str: 'AuthorizedKeysCommand',            val: ['/test/ing', '/test/ing/%u-%U'], },
    'authorized_keys_command_user'         => { str: 'AuthorizedKeysCommandUser',        val: ['test', 'ing'], },
    'authorized_keys_file'                 => { str: 'AuthorizedKeysFile',               val: [['ssh-ed25519'], ['ssh-ed25519', 'ssh-rsa']], sep: ' ', },
    'authorized_principals_command'        => { str: 'AuthorizedPrincipalsCommand',      val: ['/test/ing', '/test/ing/%u-%U'], },
    'authorized_principals_command_user'   => { str: 'AuthorizedPrincipalsCommandUser',  val: ['test', 'ing'], },
    'authorized_principals_file'           => { str: 'AuthorizedPrincipalsFile',         val: ['/test/ing', '/test/ing/%u-%U'], },
    'banner'                               => { str: 'Banner',                           val: ['Hello', 'Test'], },
    'ca_signature_algorithms'              => { str: 'CASignatureAlgorithms',            val: [['ssh-ed25519'], ['ssh-ed25519', 'rsa-sha2-512']], sep: ',', },
    'challenge_response_authentication'    => { str: 'ChallengeResponseAuthentication',  val: ['yes', 'no'], },
    'chroot_directory'                     => { str: 'ChrootDirectory',                  val: ['none', '/test/ing'], },
    'ciphers'                              => { str: 'Ciphers',                          val: [['3des-cbc'], ['3des-cbc', 'aes256-cbc']], sep: ',', },
    'client_alive_count_max'               => { str: 'ClientAliveCountMax',              val: [3, 242], },
    'client_alive_interval'                => { str: 'ClientAliveInterval',              val: [3, 242], },
    'compression'                          => { str: 'Compression',                      val: ['yes', 'delayed', 'no'], },
    'deny_groups'                          => { str: 'DenyGroups',                       val: [['test'], ['test', 'ing']], sep: ' ', },
    'deny_users'                           => { str: 'DenyUsers',                        val: [['test'], ['test', 'ing']], sep: ' ', },
    'disable_forwarding'                   => { str: 'DisableForwarding',                val: ['yes', 'no'], },
    'expose_auth_info'                     => { str: 'ExposeAuthInfo',                   val: ['yes', 'no'], },
    'fingerprint_hash'                     => { str: 'FingerprintHash',                  val: ['md5', 'sha256'], },
    'force_command'                        => { str: 'ForceCommand',                     val: ['none', '/test/ing'], },
    'gateway_ports'                        => { str: 'GatewayPorts',                     val: ['no', 'yes', 'clientspecified'], },
    'gss_api_authentication'               => { str: 'GSSAPIAuthentication',             val: ['yes', 'no'], },
    'gss_api_cleanup_credentials'          => { str: 'GSSAPICleanupCredentials',         val: ['yes', 'no'], },
    'gss_api_strict_acceptor_check'        => { str: 'GSSAPIStrictAcceptorCheck',        val: ['yes', 'no'], },
    'hostbased_accepted_key_types'         => { str: 'HostbasedAcceptedKeyTypes',        val: [['ssh-ed25519'], ['ssh-ed25519', 'rsa-sha2-512']], sep: ',', },
    'hostbased_authentication'             => { str: 'HostbasedAuthentication',          val: ['yes', 'no'], },
    'hostbased_uses_name_from_packet_only' => { str: 'HostbasedUsesNameFromPacketOnly',  val: ['yes', 'no'], },
    'host_certificate'                     => { str: 'HostCertificate',                  val: ['/test/ing', '/test/ing2'], },
    'host_key'                             => { str: 'HostKey',                          val: [['/test/ing'], ['/test/ing1', '/test/ing2']], sep: "\nHostKey ", },
    'host_key_agent'                       => { str: 'HostKeyAgent',                     val: ['/test/ing', '/test/ing2'], },
    'host_key_algorithms'                  => { str: 'HostKeyAlgorithms',                val: [['ssh-ed25519'], ['ssh-ed25519', 'rsa-sha2-512']], sep: ',', },
    'ignore_rhosts'                        => { str: 'IgnoreRhosts',                     val: ['yes', 'no'], },
    'ignore_user_known_hosts'              => { str: 'IgnoreUserKnownHosts',             val: ['yes', 'no'], },
    'include'                              => { str: 'Include',                          val: ['/test/ing', '~/test/ing'], },
    'ip_qos'                               => { str: 'IPQoS',                            val: ['af42', 'af42 cs3'], },
    'kbd_interactive_authentication'       => { str: 'KbdInteractiveAuthentication',     val: ['yes', 'no'], },
    'kerberos_authentication'              => { str: 'KerberosAuthentication',           val: ['yes', 'no'], },
    'kerberos_get_afs_token'               => { str: 'KerberosGetAFSToken',              val: ['yes', 'no'], },
    'kerberos_or_local_passwd'             => { str: 'KerberosOrLocalPasswd',            val: ['yes', 'no'], },
    'kerberos_ticket_cleanup'              => { str: 'KerberosTicketCleanup',            val: ['yes', 'no'], },
    'kex_algorithms'                       => { str: 'KexAlgorithms',                    val: [['^test-242'], ['-diffie-hellman-group14-sha256', '+test-242']], sep: ',', },
    'listen_address'                       => { str: 'ListenAddress',                    val: [['3.3.3.3:242'], ['3.3.3.3', '242.242.242.242']], sep: "\nListenAddress ", },
    'login_grace_time'                     => { str: 'LoginGraceTime',                   val: [3, 242], },
    'log_level'                            => { str: 'LogLevel',                         val: ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3'], },
    'macs'                                 => { str: 'MACs',                             val: [['hmac-sha2-512'], ['hmac-sha2-512', 'hmac-sha2-256']], sep: ',', },
    'max_auth_tries'                       => { str: 'MaxAuthTries',                     val: [3, 242], },
    'max_sessions'                         => { str: 'MaxSessions',                      val: [3, 242], },
    'max_startups'                         => { str: 'MaxStartups',                      val: ['10:30:100', '2:4:2'], },
    'password_authentication'              => { str: 'PasswordAuthentication',           val: ['yes', 'no'], },
    'permit_empty_passwords'               => { str: 'PermitEmptyPasswords',             val: ['yes', 'no'], },
    'permit_listen'                        => { str: 'PermitListen',                     val: [['242'], ['242', 'localhost:242']], sep: ' ', },
    'permit_root_login'                    => { str: 'PermitRootLogin',                  val: ['yes', 'no', 'prohibit-password', 'without-password', 'forced-commands-only'], },
    'permit_tty'                           => { str: 'PermitTTY',                        val: ['yes', 'no'], },
    'permit_tunnel'                        => { str: 'PermitTunnel',                     val: ['yes', 'point-to-point', 'ethernet', 'no'], },
    'permit_user_environment'              => { str: 'PermitUserEnvironment',            val: ['yes', 'no', 'LANG,LC_*'], },
    'permit_user_rc'                       => { str: 'PermitUserRC',                     val: ['yes', 'no'], },
    'pid_file'                             => { str: 'PidFile',                          val: ['/test/ing.pid', 'none'], },
    'port'                                 => { str: 'Port',                             val: [[3], [3, 242]], sep: "\nPort ", },
    'print_last_log'                       => { str: 'PrintLastLog',                     val: ['yes', 'no'], },
    'print_motd'                           => { str: 'PrintMotd',                        val: ['yes', 'no'], },
    'pubkey_accepted_key_types'            => { str: 'PubkeyAcceptedKeyTypes',           val: [['+ssh-dss'], ['ssh-test', 'ssh-ed242']], sep: ',', },
    'pubkey_authentication'                => { str: 'PubkeyAuthentication',             val: ['yes', 'no'], },
    'rekey_limit'                          => { str: 'RekeyLimit',                       val: ['242G', 'default none'], },
    'revoked_keys'                         => { str: 'RevokedKeys',                      val: ['/test/ing', 'default none'], },
    'rdomain'                              => { str: 'RDomain',                          val: ['%D', 'test'], },
    'set_env'                              => { str: 'SetEnv',                           val: [['LANG'], ['TEST', 'ING']], sep: "\nSetEnv " },
    'stream_local_bind_mask'               => { str: 'StreamLocalBindMask',              val: ['0177', '0242'], },
    'stream_local_bind_unlink'             => { str: 'StreamLocalBindUnlink',            val: ['yes', 'no'], },
    'strict_modes'                         => { str: 'StrictModes',                      val: ['yes', 'no'], },
    'subsystem'                            => { str: 'Subsystem',                        val: ['sftp /test/ing', 'sftp internal-sftp'], },
    'syslog_facility'                      => { str: 'SyslogFacility',                   val: ['DAEMON', 'USER', 'AUTH', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7', 'AUTHPRIV'], }, # rubocop:disable Layout/LineLength
    'tcp_keep_alive'                       => { str: 'TCPKeepAlive',                     val: ['yes', 'no'], },
    'trusted_user_ca_keys'                 => { str: 'TrustedUserCAKeys',                val: ['/test/ing', 'default none'], },
    'use_dns'                              => { str: 'UseDNS',                           val: ['yes', 'no'], },
    'use_pam'                              => { str: 'UsePAM',                           val: ['yes', 'no'], },
    'version_addendum'                     => { str: 'VersionAddendum',                  val: ['test', 'none'], },
    'x11_display_offset'                   => { str: 'X11DisplayOffset',                 val: [3, 242], },
    'x11_forwarding'                       => { str: 'X11Forwarding',                    val: ['yes', 'no'], },
    'x11_use_localhost'                    => { str: 'X11UseLocalhost',                  val: ['yes', 'no'], },
    'xauth_location'                       => { str: 'XAuthLocation',                    val: ['/test/ing', '~/test/ing'], },
  }

  parameters.each do |param, data|
    data[:val].each do |value|
      context "with #{param} set to valid #{value} (as #{value.class})" do
        let(:params) { { "#{param}": value } }

        if value.class == Array
          it { is_expected.to contain_file('sshd_config').with_content(header + "#{data[:str]} #{value.join(data[:sep])}" + "\n") }
        else
          it { is_expected.to contain_file('sshd_config').with_content(header + "#{data[:str]} #{value}\n") }
        end
      end
    end
  end

  context 'with custom set to valid ["keyword value"] (as Array)' do
    let(:params) { { custom: ['KeyWord value'] } }

    it { is_expected.to contain_file('sshd_config').with_content(header + "KeyWord value\n") }
  end

  context 'with custom set to valid ["keyword value", "test ing"] (as Array)' do
    let(:params) { { custom: ['KeyWord value', 'Test ing'] } }

    it { is_expected.to contain_file('sshd_config').with_content(header + "KeyWord value\nTest ing\n") }
  end

  ['SLED', 'SLES'].each do |name|
    ['10', '11', '12'].each do |major|
      context "on #{name} #{major} with i386 architecture path for sftp subsystem is /usr/lib/ssh/sftp-server" do
        let(:facts) do
          {
            os: {
              architecture: 'i386',
              name: name,
              release: {
                major: major,
              },
            },
          }
        end

        it { is_expected.to contain_file('sshd_config').with_content(%r{^Subsystem sftp \/usr\/lib\/ssh\/sftp-server$}) }
      end
    end
  end
end
