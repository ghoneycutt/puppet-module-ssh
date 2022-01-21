require 'spec_helper'
describe 'ssh' do
  debian = {
    supported_os: [
      {
        'operatingsystem'        => 'Debian',
        'operatingsystemrelease' => ['9'],
      },
    ],
  }

  header = <<-END.gsub(%r{^\s+\|}, '')
    |# This file is being maintained by Puppet.
    |# DO NOT EDIT
    |#
    |# See https://man.openbsd.org/sshd_config for more info
    |
    |Host *
  END

=begin
  rh_default_content = <<-END.gsub(%r{^\s+\|}, '')
    |  ForwardX11Trusted yes
    |  GSSAPIAuthentication yes
    |  SendEnv LANG
    |  SendEnv LANGUAGE
    |  SendEnv LC_ADDRESS
    |  SendEnv LC_ALL
    |  SendEnv LC_COLLATE
    |  SendEnv LC_CTYPE
    |  SendEnv LC_IDENTIFICATION
    |  SendEnv LC_MEASUREMENT
    |  SendEnv LC_MESSAGES
    |  SendEnv LC_MONETARY
    |  SendEnv LC_NAME
    |  SendEnv LC_NUMERIC
    |  SendEnv LC_PAPER
    |  SendEnv LC_TELEPHONE
    |  SendEnv LC_TIME
    |  SendEnv XMODIFIERS
  END

  on_supported_os.sort.each do |os, os_facts|
    context "on #{os} with default values for parameters" do
      let(:facts) { os_facts }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_class('ssh') }

      it do
        is_expected.to contain_package('openssh-clients').only_with(
          {
            'ensure'    => 'installed',
            'source'    => nil,
            'adminfile' => nil,
          },
        )
      end

      content = if os_facts[:os]['family'] == 'RedHat'
                  rh_default_content
                else
                  ''
                end

      it do
        is_expected.to contain_file('ssh_config').only_with(
          {
            'ensure'  => 'file',
            'path'    => '/etc/ssh/ssh_config',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'content' => header + content,
            'require' => 'Package[openssh-clients]',
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
            'require' => 'Package[openssh-clients]',
          },
        )
      end

      # FIXME: add test for
      # Sshkey <<||>> {
      #   target => $global_known_hosts,
      # }

      it { is_expected.to contain_resources('sshkey').with_purge('true') }
      it { is_expected.to have_ssh__config_entry_resource_count(0) }
      it { is_expected.to have_ssh_authorized_key_resource_count(0) }

      it { is_expected.to contain_class('ssh::server') }

      # only needed to reach 100% resource coverage
      it { is_expected.to contain_file('sshd_config') }
      it { is_expected.to contain_package('openssh-server') }
      it { is_expected.to contain_service('sshd_service') }
    end
  end
=end

  # test parameters
  # they aren't OS dependent, no need to test with each OS
  on_supported_os(debian).sort.each do |os, os_facts|
    let(:facts) { os_facts }

    parameters = {
=begin
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
=end
      'hash_known_hosts'                     => { str: 'HashKnownHosts',                    val: ['yes', 'no'], },
      'hostbased_authentication'             => { str: 'HostbasedAuthentication',           val: ['yes', 'no'], },
      'hostbased_key_types'                  => { str: 'HostbasedKeyTypes',                 val: [['^ssh-test'], ['-ssh-rsa', '+ssh-test']], sep: ',', },
      'host_key_algorithms'                  => { str: 'HostKeyAlgorithms',                 val: [['^ssh-test'], ['-ssh-rsa', '+ssh-test']], sep: ',', },
      'host_key_alias'                       => { str: 'HostKeyAlias',                      val: ['testhost', 'test242'], },
      'hostname'                             => { str: 'Hostname',                          val: ['testhost', '242.242.242.242'], },
      'identities_only'                      => { str: 'IdentitiesOnly',                    val: ['yes', 'no'], },
      'identity_agent'                       => { str: 'IdentityAgent',                     val: ['/test/ing', '~/test/ing'], },
      'identity_file'                        => { str: 'IdentityFile',                      val: [['~/.ssh/id_dsa']], }, # TODO: make multiline ?

#      ''    => { str: '',      val: },
#      'no_host_authentication_for_localhost' => { str: 'NoHostAuthenticationForLocalhost', val: ['yes', 'no'], },
    }
    parameters.each do |param, data|
      data[:val].each do |value|
        context "on #{os} with #{param} set to valid #{value} (as #{value.class})" do
          let(:params) { { "#{param}": value } }

          if value.class == Array
            it { is_expected.to contain_file('ssh_config').with_content(header + "  #{data[:str]} #{value.join(data[:sep])}" + "\n") }
          else
            it { is_expected.to contain_file('ssh_config').with_content(header + "  #{data[:str]} #{value}\n") }
          end
        end
      end
    end

  end
end
