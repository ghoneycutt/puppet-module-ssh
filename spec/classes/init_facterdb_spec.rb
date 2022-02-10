require 'spec_helper'
describe 'ssh' do
  header = <<-END.gsub(%r{^\s+\|}, '')
    |# This file is being maintained by Puppet.
    |# DO NOT EDIT
    |#
    |# See https://man.openbsd.org/ssh_config for more info
    |
    |Host *
  END

  on_supported_os.sort.each do |os, os_facts|
    context "on #{os} with default values for parameters" do
      # OS specific SSH versions
      case "#{os_facts[:os]['name']}-#{os_facts[:os]['release']['major']}"
      when 'CentOS-5', 'OracleLinux-5', 'RedHat-5', 'Scientific-5'
        ssh_version = 'OpenSSH_4.3p2'
        ssh_version_numeric = '4.3'
      when 'CentOS-6', 'OracleLinux-6', 'RedHat-6', 'Scientific-6'
        ssh_version = 'OpenSSH_5.3p1'
        ssh_version_numeric = '5.3'
      when 'CentOS-7', 'OracleLinux-7', 'RedHat-7', 'Scientific-7'
        ssh_version = 'OpenSSH_6.6p1'
        ssh_version_numeric = '6.6'
      when 'SLED-10', 'SLES-10'
        ssh_version = 'OpenSSH_5.1p1'
        ssh_version_numeric = '5.1'
      when 'SLED-11', 'SLED-12', 'SLES-11', 'SLES-12'
        ssh_version = 'OpenSSH_6.6.1p1'
        ssh_version_numeric = '6.6'
      when 'SLED-15', 'SLES-15'
        ssh_version = 'OpenSSH_8.4p1'
        ssh_version_numeric = '8.4'
      when 'Solaris-9', 'Solaris-10', 'Solaris-11'
        ssh_version = 'Sun_SSH_2.2'
        ssh_version_numeric = '2.2'
      when 'Ubuntu-14.04'
        ssh_version = 'OpenSSH 6.6p1'
        ssh_version_numeric = '6.6'
      when 'Ubuntu-16.04'
        ssh_version = 'OpenSSH_7.2p2'
        ssh_version_numeric = '7.2'
      when 'Ubuntu-18.04'
        ssh_version = 'OpenSSH_7.6p1'
        ssh_version_numeric = '7.6'
      when 'Ubuntu-20.04'
        ssh_version = 'OpenSSH_8.2p1'
        ssh_version_numeric = '8.2'
      when 'Debian-7'
        ssh_version = 'OpenSSH_6.0p1'
        ssh_version_numeric = '6.0'
      when 'Debian-8'
        ssh_version = 'OpenSSH_6.7p1'
        ssh_version_numeric = '6.7'
      when 'Debian-9'
        ssh_version = 'OpenSSH_7.4p1'
        ssh_version_numeric = '7.4'
      when 'Debian-10'
        ssh_version = 'OpenSSH_7.9p1'
        ssh_version_numeric = '7.9'
      when 'Debian-11'
        ssh_version = 'OpenSSH_8.4p1'
        ssh_version_numeric = '8.4'
      else
        ssh_version = 'UnkownSSH_2.42'
        ssh_version_numeric = '2.42'
      end

      let(:facts) do
        os_facts.merge(
          {
            ssh_version: ssh_version,
            ssh_version_numeric: ssh_version_numeric,
          },
        )
      end

      # OS specific defaults
      case "#{os_facts[:os]['name']}-#{os_facts[:os]['release']['full']}"
      when %r{CentOS.*}, %r{OracleLinux.*}, %r{RedHat.*}, %r{Scientific.*}
        packages_default = ['openssh-clients']
      when %r{SLED.*}, %r{SLES.*}
        packages_default = ['openssh']
      when %r{Debian.*}, %r{Ubuntu.*}
        packages_default = ['openssh-client']
      when %r{Solaris-9.*}, %r{Solaris-10.*}
        packages_default    = ['SUNWsshcu', 'SUNWsshr', 'SUNWsshu']
        packages_ssh_source = '/var/spool/pkg'
      when %r{Solaris-11.*}
        packages_default    = ['network/ssh', 'network/ssh/ssh-key']
        packages_ssh_source = nil
      end

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_class('ssh') }

      packages_default.each do |package|
        it do
          is_expected.to contain_package(package).only_with(
            {
              'ensure'    => 'installed',
              'source'    => packages_ssh_source,
              'adminfile' => nil,
              'before'    => ['File[ssh_config]', 'File[ssh_known_hosts]'],
            },
          )
        end
      end

      content_fixture = File.read(fixtures("#{os_facts[:os]['name']}-#{os_facts[:os]['release']['major']}_ssh_config"))

      it do
        is_expected.to contain_file('ssh_config').only_with(
          {
            'ensure'  => 'file',
            'path'    => '/etc/ssh/ssh_config',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'content' => content_fixture,
          },
        )
      end

      it { is_expected.not_to contain_exec("mkdir_p-#{os_facts[:root_home]}/.ssh") }
      it { is_expected.not_to contain_file('root_ssh_dir') }
      it { is_expected.not_to contain_file('root_ssh_config') }

      it { is_expected.to have_sshkey_resource_count(0) }

      it do
        is_expected.to contain_file('ssh_known_hosts').only_with(
          {
            'ensure'  => 'file',
            'path'    => '/etc/ssh/ssh_known_hosts',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
          },
        )
      end

      it { is_expected.to contain_resources('sshkey').with_purge('true') }
      it { is_expected.to have_ssh__config_entry_resource_count(0) }
      it { is_expected.to have_ssh_authorized_key_resource_count(0) }
      it { is_expected.to contain_class('ssh::server') }
    end
  end

  # test parameters
  # they aren't OS dependent, so we use a fictional OS without any default values
  let(:facts) { { os: { family: 'UnitTesting' } } }

  parameters = {
    'add_keys_to_agent'                    => { str: 'AddKeysToAgent',                    val: ['yes', 'no', 'ask', 'confirm'], },
    'address_family'                       => { str: 'AddressFamily',                     val: ['any', 'inet', 'inet6'], },
    'batch_mode'                           => { str: 'BatchMode',                         val: ['yes', 'no'], },
    'bind_address'                         => { str: 'BindAddress',                       val: ['10.11.12.13', '192.168.3.3'], },
    'bind_interface'                       => { str: 'BindInterface',                     val: ['eth0', 'eth1'], },
    'canonical_domains'                    => { str: 'CanonicalDomains',                  val: [['unit.test.ing'], ['h1.test.ing', 'h2.test.ing']], sep: ' ', },
    'canonicalize_fallback_local'          => { str: 'CanonicalizeFallbackLocal',         val: ['yes', 'no'], },
    'canonicalize_hostname'                => { str: 'CanonicalizeHostname',              val: ['yes', 'no', 'always'], },
    'canonicalize_max_dots'                => { str: 'CanonicalizeMaxDots',               val: [3, 242], },
    'canonicalize_permitted_cnames'        => { str: 'CanonicalizePermittedCNAMEs',       val: [['*.test.ing:*.spec.ing'], ['*.test1.ing:*.spec.ing', '*.test2.ing:*.spec.ing']], sep: ',' },
    'ca_signature_algorithms'              => { str: 'CASignatureAlgorithms',             val: [['test-242'], ['-rsa-sha2-256', '+rsa-sha2-242']], sep: ',' },
    'certificate_file'                     => { str: 'CertificateFile',                   val: [['/test/ing'], ['/test/ing1', '/test/ing2']], sep: "\n  CertificateFile " },
    'challenge_response_authentication'    => { str: 'ChallengeResponseAuthentication',   val: ['yes', 'no'], },
    'check_host_ip'                        => { str: 'CheckHostIP',                       val: ['yes', 'no'], },
    'ciphers'                              => { str: 'Ciphers',                           val: [['test242-ctr'], ['test242-ctr', 'test512-ctr']], sep: ',' },
    'clear_all_forwardings'                => { str: 'ClearAllForwardings',               val: ['yes', 'no'], },
    'compression'                          => { str: 'Compression',                       val: ['yes', 'no'], },
    'connect_timeout'                      => { str: 'ConnectTimeout',                    val: [3, 242], },
    'connection_attempts'                  => { str: 'ConnectionAttempts',                val: [3, 242], },
    'control_master'                       => { str: 'ControlMaster',                     val: ['yes', 'no', 'ask', 'auto', 'autoask'], },
    'control_path'                         => { str: 'ControlPath',                       val: ['/test/ing', '~/.ssh/testing/%r@%h-%p'], },
    'control_persist'                      => { str: 'ControlPersist',                    val: ['3h', '242h'], },
    'dynamic_forward'                      => { str: 'DynamicForward',                    val: ['3', '242', '2300'], },
    'enable_ssh_keysign'                   => { str: 'EnableSSHKeysign',                  val: ['yes', 'no'], },
    'escape_char'                          => { str: 'EscapeChar',                        val: ['~.', '~B'], },
    'exit_on_forward_failure'              => { str: 'ExitOnForwardFailure',              val: ['yes', 'no'], },
    'fingerprint_hash'                     => { str: 'FingerprintHash',                   val: ['sha256', 'md5'], },
    'forward_agent'                        => { str: 'ForwardAgent',                      val: ['yes', 'no'], },
    'forward_x11'                          => { str: 'ForwardX11',                        val: ['yes', 'no'], },
    'forward_x11_timeout'                  => { str: 'ForwardX11Timeout',                 val: ['3h', '242m', '2300s'], },
    'forward_x11_trusted'                  => { str: 'ForwardX11Trusted',                 val: ['yes', 'no'], },
    'gateway_ports'                        => { str: 'GatewayPorts',                      val: ['yes', 'no'], },
    'global_known_hosts_file'              => { str: 'GlobalKnownHostsFile',              val: [['/test/ing'], ['/test/ing', '/unit/test']], sep: ' ', },
    'gss_api_authentication'               => { str: 'GSSAPIAuthentication',              val: ['yes', 'no'], },
    'gss_api_delegate_credentials'         => { str: 'GSSAPIDelegateCredentials',         val: ['yes', 'no'], },
    'hash_known_hosts'                     => { str: 'HashKnownHosts',                    val: ['yes', 'no'], },
    'hostbased_authentication'             => { str: 'HostbasedAuthentication',           val: ['yes', 'no'], },
    'hostbased_key_types'                  => { str: 'HostbasedKeyTypes',                 val: [['^ssh-test'], ['-ssh-rsa', '+ssh-test']], sep: ',', },
    'host_key_algorithms'                  => { str: 'HostKeyAlgorithms',                 val: [['^ssh-test'], ['-ssh-rsa', '+ssh-test']], sep: ',', },
    'host_key_alias'                       => { str: 'HostKeyAlias',                      val: ['testhost', 'test242'], },
    'hostname'                             => { str: 'Hostname',                          val: ['testhost', '242.242.242.242'], },
    'identities_only'                      => { str: 'IdentitiesOnly',                    val: ['yes', 'no'], },
    'identity_agent'                       => { str: 'IdentityAgent',                     val: ['/test/ing', '~/test/ing'], },
    'identity_file'                        => { str: 'IdentityFile',                      val: [['~/.ssh/id_dsa'], ['/test/ing1', '/test/ing2']], sep: ',', },
    'ignore_unknown'                       => { str: 'IgnoreUnknown',                     val: [['AddKeysToAgent'], ['AddKeysToAgent', 'UseKeychain']], sep: ',', },
    'include'                              => { str: 'Include',                           val: ['/test/ing', '~/test/ing'], },
    'ip_qos'                               => { str: 'IPQoS',                             val: ['af42', 'af42 cs3'], },
    'kbd_interactive_authentication'       => { str: 'KbdInteractiveAuthentication',      val: ['yes', 'no'], },
    'kbd_interactive_devices'              => { str: 'KbdInteractiveDevices',             val: [['pam'], ['bsdauth', 'pam']], sep: ',', },
    'kex_algorithms'                       => { str: 'KexAlgorithms',                     val: [['^test-242'], ['-diffie-hellman-group14-sha256', '+test-242']], sep: ',', },
    'local_command'                        => { str: 'LocalCommand',                      val: ['/test/ing', '~/test/ing'], },
    'local_forward'                        => { str: 'LocalForward',                      val: ['242 localhost:242', '8080 127.0.0.1:8080'], },
    'log_level'                            => { str: 'LogLevel',                          val: ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3'], },
    'no_host_authentication_for_localhost' => { str: 'NoHostAuthenticationForLocalhost',  val: ['yes', 'no'], },
    'number_of_password_prompts'           => { str: 'NumberOfPasswordPrompts',           val: [3, 242], },
    'password_authentication'              => { str: 'PasswordAuthentication',            val: ['yes', 'no'], },
    'permit_local_command'                 => { str: 'PermitLocalCommand',                val: ['yes', 'no'], },
    'pkcs11_provider'                      => { str: 'PKCS11Provider',                    val: ['/test/ing.so'], },
    'port'                                 => { str: 'Port',                              val: [3, 242], },
    'preferred_authentications'            => { str: 'PreferredAuthentications',          val: [['publickey'], ['gssapi-with-mic', 'hostbased']], sep: ',', },
    'protocol'                             => { str: 'Protocol',                          val: ['2', '2,1', '1'], },
    'proxy_command'                        => { str: 'ProxyCommand',                      val: ['/usr/bin/nc -X connect -x 192.0.2.0:8080 %h %p'], },
    'proxy_jump'                           => { str: 'ProxyJump',                         val: [['/test/ing connect -x 127.2.4.2'], ['/test/ing1', '/test/ing2']], sep: ',', },
    'proxy_use_fdpass'                     => { str: 'ProxyUseFdpass',                    val: ['yes', 'no'], },
    'pubkey_accepted_key_types'            => { str: 'PubkeyAcceptedKeyTypes',            val: [['+ssh-dss'], ['ssh-test', 'ssh-ed242']], sep: ',', },
    'pubkey_authentication'                => { str: 'PubkeyAuthentication',              val: ['yes', 'no'], },
    'rekey_limit'                          => { str: 'RekeyLimit',                        val: ['242G', 'default none'], },
    'remote_command'                       => { str: 'RemoteCommand',                     val: ['/test/ing', '~/.ssh/testing/%r@%h-%p'], },
    'remote_forward'                       => { str: 'RemoteForward',                     val: ['242 localhost:242'], },
    'request_tty'                          => { str: 'RequestTTY',                        val: ['no', 'yes', 'force', 'auto'], },
    'revoked_host_keys'                    => { str: 'RevokedHostKeys',                   val: ['/test/ing', '~/test/ing'], },
    'send_env'                             => { str: 'SendEnv',                           val: [['LANG'], ['TEST', 'ING']], sep: "\n  SendEnv " },
    'server_alive_count_max'               => { str: 'ServerAliveCountMax',               val: [3, 242], },
    'server_alive_interval'                => { str: 'ServerAliveInterval',               val: [3, 242], },
    'set_env'                              => { str: 'SetEnv',                            val: [['LANG'], ['TEST', 'ING']], sep: "\n  SetEnv " },
    'stream_local_bind_mask'               => { str: 'StreamLocalBindMask',               val: ['0177', '0242'], },
    'stream_local_bind_unlink'             => { str: 'StreamLocalBindUnlink',             val: ['yes', 'no'], },
    'strict_host_key_checking'             => { str: 'StrictHostKeyChecking',             val: ['yes', 'no', 'accept-new', 'off', 'ask'], },
    'syslog_facility'                      => { str: 'SyslogFacility',                    val: ['DAEMON', 'USER', 'AUTH', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7', 'AUTHPRIV'], }, # rubocop:disable Layout/LineLength
    'tcp_keep_alive'                       => { str: 'TCPKeepAlive',                      val: ['yes', 'no'], },
    'tunnel'                               => { str: 'Tunnel',                            val: ['yes', 'no', 'point-to-point', 'ethernet'], },
    'tunnel_device'                        => { str: 'TunnelDevice',                      val: ['tun0', 'tun1' ], },
    'update_host_keys'                     => { str: 'UpdateHostKeys',                    val: ['yes', 'no', 'ask'], },
    'user'                                 => { str: 'User',                              val: ['unit', 'testing'], },
    'user_known_hosts_file'                => { str: 'UserKnownHostsFile',                val: [['/test/ing'], ['/test', '/ing']], sep: ' ', },
    'verify_host_key_dns'                  => { str: 'VerifyHostKeyDNS',                  val: ['yes', 'no', 'ask'], },
    'visual_host_key'                      => { str: 'VisualHostKey',                     val: ['yes', 'no'], },
    'xauth_location'                       => { str: 'XAuthLocation',                     val: ['/test/ing', '~/test/ing'], },
  }

  parameters.each do |param, data|
    data[:val].each do |value|
      context "with #{param} set to valid #{value} (as #{value.class})" do
        let(:params) { { "#{param}": value } }

        if value.class == Array
          it { is_expected.to contain_file('ssh_config').with_content(header + "  #{data[:str]} #{value.join(data[:sep])}" + "\n") }
        else
          it { is_expected.to contain_file('ssh_config').with_content(header + "  #{data[:str]} #{value}\n") }
        end
      end
    end
  end

  context 'with custom set to valid ["keyword value"] (as Array)' do
    let(:params) { { custom: ['KeyWord value'] } }

    it { is_expected.to contain_file('ssh_config').with_content(header + "  KeyWord value\n") }
  end

  context 'with custom set to valid ["keyword value", "test ing"] (as Array)' do
    let(:params) { { custom: ['KeyWord value', 'Test ing'] } }

    it { is_expected.to contain_file('ssh_config').with_content(header + "  KeyWord value\n  Test ing\n") }
  end
end
