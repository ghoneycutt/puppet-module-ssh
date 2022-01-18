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

  # test parameters
  # they aren't OS dependent, no need to test with each OS
  on_supported_os(debian).sort.each do |os, os_facts|
    let(:facts) { os_facts }

    ['yes', 'no', 'ask', 'confirm'].each do |value|
      context "on #{os} with add_keys_to_agent set to valid #{value}" do
        let(:params) { { add_keys_to_agent: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  AddKeysToAgent ' + value + "\n") }
      end
    end

    ['any', 'inet', 'inet6'].each do |value|
      context "on #{os} with address_family set to valid #{value}" do
        let(:params) { { address_family: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  AddressFamily ' + value + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with batch_mode set to valid #{value}" do
        let(:params) { { batch_mode: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  BatchMode ' + value + "\n") }
      end
    end

    ['10.11.12.13', '192.168.3.3'].each do |value|
      context "on #{os} with bind_address set to valid #{value}" do
        let(:params) { { bind_address: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  BindAddress ' + value + "\n") }
      end
    end

    ['10.11.12.13', '192.168.3.3'].each do |value|
      context "on #{os} with bind_interface set to valid #{value}" do
        let(:params) { { bind_interface: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  BindInterface ' + value + "\n") }
      end
    end

    ['10.11.12.13', '192.168.3.3'].each do |value|
      context "on #{os} with bind_interface set to valid #{value}" do
        let(:params) { { bind_interface: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  BindInterface ' + value + "\n") }
      end
    end

    [['unit.test.ing'], ['host1.test.ing', 'host2.test.ing']].each do |value|
      context "on #{os} with canonical_domains set to valid #{value}" do
        let(:params) { { canonical_domains: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  CanonicalDomains ' + value.join(' ') + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with canonicalize_fallback_local set to valid #{value}" do
        let(:params) { { canonicalize_fallback_local: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  CanonicalizeFallbackLocal ' + value + "\n") }
      end
    end

    ['yes', 'no', 'always'].each do |value|
      context "on #{os} with canonicalize_hostname set to valid #{value}" do
        let(:params) { { canonicalize_hostname: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  CanonicalizeHostname ' + value + "\n") }
      end
    end

    [3, 242].each do |value|
      context "on #{os} with canonicalize_max_dots set to valid #{value}" do
        let(:params) { { canonicalize_max_dots: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  CanonicalizeMaxDots ' + value.to_s + "\n") }
      end
    end

    [['unit.test.ing'], ['host1.test.ing', 'host2.test.ing']].each do |value|
      context "on #{os} with canonicalize_permitted_cnames set to valid #{value}" do
        let(:params) { { canonicalize_permitted_cnames: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  CanonicalizePermittedCNAMEs ' + value.join(',') + "\n") }
      end
    end

    [['unit.test.ing'], ['host1.test.ing', 'host2.test.ing']].each do |value|
      context "on #{os} with ca_signature_algorithms set to valid #{value}" do
        let(:params) { { ca_signature_algorithms: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  CASignatureAlgorithms ' + value.join(',') + "\n") }
      end
    end

    [['unit.test.ing'], ['host1.test.ing', 'host2.test.ing']].each do |value|
      context "on #{os} with certificate_file set to valid #{value}" do
        let(:params) { { certificate_file: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  CertificateFile ' + value.join("\n  CertificateFile ") + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with challenge_response_authentication set to valid #{value}" do
        let(:params) { { challenge_response_authentication: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ChallengeResponseAuthentication ' + value + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with check_host_ip set to valid #{value}" do
        let(:params) { { check_host_ip: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  CheckHostIP ' + value + "\n") }
      end
    end

    [['test242-ctr'], ['test242-ctr', 'test512-ctr']].each do |value|
      context "on #{os} with ciphers set to valid #{value}" do
        let(:params) { { ciphers: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  Ciphers ' + value.join(',') + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with clear_all_forwardings set to valid #{value}" do
        let(:params) { { clear_all_forwardings: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ClearAllForwardings ' + value + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with compression set to valid #{value}" do
        let(:params) { { compression: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  Compression ' + value + "\n") }
      end
    end

    [3, 242].each do |value|
      context "on #{os} with connect_timeout set to valid #{value}" do
        let(:params) { { connect_timeout: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ConnectTimeout ' + value.to_s + "\n") }
      end
    end

    [3, 242].each do |value|
      context "on #{os} with connection_attempts set to valid #{value}" do
        let(:params) { { connection_attempts: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ConnectionAttempts ' + value.to_s + "\n") }
      end
    end

    ['yes', 'no', 'ask', 'auto', 'autoask'].each do |value|
      context "on #{os} with control_master set to valid #{value}" do
        let(:params) { { control_master: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ControlMaster ' + value + "\n") }
      end
    end

    ['/test/ing', '~/.ssh/testing/%r@%h-%p'].each do |value|
      context "on #{os} with control_path set to valid #{value}" do
        let(:params) { { control_path: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ControlPath ' + value + "\n") }
      end
    end

    ['3h', '242h'].each do |value|
      context "on #{os} with control_persist set to valid #{value}" do
        let(:params) { { control_persist: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ControlPersist ' + value + "\n") }
      end
    end

    ['3', '242', '2300'].each do |value|
      context "on #{os} with dynamic_forward set to valid #{value}" do
        let(:params) { { dynamic_forward: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  DynamicForward ' + value + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with enable_ssh_keysign set to valid #{value}" do
        let(:params) { { enable_ssh_keysign: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  EnableSSHKeysign ' + value + "\n") }
      end
    end

    ['~.', '~B'].each do |value|
      context "on #{os} with escape_char set to valid #{value}" do
        let(:params) { { escape_char: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  EscapeChar ' + value + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with exit_on_forward_failure set to valid #{value}" do
        let(:params) { { exit_on_forward_failure: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ExitOnForwardFailure ' + value + "\n") }
      end
    end

    ['sha256', 'md5'].each do |value|
      context "on #{os} with fingerprint_hash set to valid #{value}" do
        let(:params) { { fingerprint_hash: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  FingerprintHash ' + value + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with forward_agent set to valid #{value}" do
        let(:params) { { forward_agent: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ForwardAgent ' + value + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with forward_x11 set to valid #{value}" do
        let(:params) { { forward_x11: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ForwardX11 ' + value + "\n") }
      end
    end

    ['3', '242', '2300'].each do |value|
      context "on #{os} with forward_x11_timeout set to valid #{value}" do
        let(:params) { { forward_x11_timeout: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ForwardX11Timeout ' + value + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with forward_x11_trusted set to valid #{value}" do
        let(:params) { { forward_x11_trusted: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  ForwardX11Trusted ' + value + "\n") }
      end
    end

    ['yes', 'no'].each do |value|
      context "on #{os} with gateway_ports set to valid #{value}" do
        let(:params) { { gateway_ports: value } }

        it { is_expected.to contain_file('ssh_config').with_content(header + '  GatewayPorts ' + value + "\n") }
      end
    end

    ['/test/ing', ['/test/ing', '/unit/test']].each do |value|
      context "on #{os} with global_known_hosts_file set to valid #{value}" do
        let(:params) { { global_known_hosts_file: value } }

        value = value.split if value.is_a?(String)

        it { is_expected.to contain_file('ssh_config').with_content(header + '  GlobalKnownHostsFile ' + value.join(' ') + "\n") }
      end
    end
  end
end
