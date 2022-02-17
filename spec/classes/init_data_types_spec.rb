require 'spec_helper'

describe 'ssh' do
  context 'validate data types of parameters' do
    # these tests are OS independent, so we use a fictional OS without any default values
    let(:facts) { { root_home: '/root', os: { family: 'UnitTesting' } } }

    validations = {
      'Array of strings (optional)' => {
        name:     ['canonical_domains', 'canonicalize_permitted_cnames', 'ca_signature_algorithms',
                   'certificate_file', 'ciphers', 'custom', 'global_known_hosts_file',
                   'hostbased_key_types', 'host_key_algorithms', 'identity_file', 'ignore_unknown',
                   'kbd_interactive_devices', 'kex_algorithms', 'packages',
                   'preferred_authentications', 'proxy_jump', 'pubkey_accepted_key_types',
                   'send_env', 'set_env', 'user_known_hosts_file'],
        valid:    [['array', 'of', 'strings'], :undef],
        invalid:  ['string', { 'ha' => 'sh' }, 3, 2.42, false, [0]],
        message: 'Undef or Array|expects a String value|Error while evaluating a Resource Statement',
      },
      'Boolean' => {
        name:     ['manage_global_known_hosts', 'manage_root_ssh_config', 'manage_sshkey',
                   'manage_server', 'purge_keys'],
        valid:    [true, false],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, 3, 2.42, 'false', nil],
        message: 'expects a Boolean',
      },
      'Enumeration of valid strings for add_keys_to_agent (optional)' => {
        name:     ['add_keys_to_agent'],
        valid:    ['yes', 'no', 'ask', 'confirm', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Enumeration of valid strings for address_family (optional)' => {
        name:     ['address_family'],
        valid:    ['any', 'inet', 'inet6', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Enumeration of valid strings for canonicalize_hostname (optional)' => {
        name:     ['canonicalize_hostname'],
        valid:    ['yes', 'no', 'always', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Enumeration of valid strings for control_master (optional)' => {
        name:     ['control_master'],
        valid:    ['yes', 'no', 'ask', 'auto', 'autoask', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Enumeration of valid strings for fingerprint_hash (optional)' => {
        name:     ['fingerprint_hash'],
        valid:    ['sha256', 'md5', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Enumeration of valid strings for request_tty (optional)' => {
        name:     ['request_tty'],
        valid:    ['yes', 'no', 'force', 'auto', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Enumeration of valid strings for strict_host_key_checking (optional)' => {
        name:     ['strict_host_key_checking'],
        valid:    ['yes', 'no', 'accept-new', 'off', 'ask', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Enumeration of valid strings for syslog_facility (optional)' => {
        name:     ['syslog_facility'],
        valid:    ['DAEMON', 'USER', 'AUTH', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7', 'AUTHPRIV', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false, 'USER0', 'daemon'],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Enumeration of valid strings for tunnel (optional)' => {
        name:     ['tunnel'],
        valid:    ['yes', 'no', 'point-to-point', 'ethernet', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Enumeration of valid strings for yes, no, ask (optional)' => {
        name:     ['update_host_keys', 'verify_host_key_dns'],
        valid:    ['yes', 'no', 'ask', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Hash' => {
        name:    ['config_entries', 'keys'],
        valid:   [], # valid hashes are to complex to block test them here.
        invalid: ['string', 3, 2.42, ['array'], false, nil],
        message: 'expects a Hash value',
      },
      'Integer' => {
        name:     ['number_of_password_prompts'],
        valid:    [0, 1, 23],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, 2.42, false, nil],
        message: 'expects a Integer|Error while evaluating a Resource Statement',
      },
      'Integer => 0 (optional)' => {
        name:     ['canonicalize_max_dots', 'connection_attempts', 'connect_timeout'],
        valid:    [0, 1, 23, :undef],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'Undef or Integer|Error while evaluating a Resource Statement',
      },
      'Ssh::Log_level (optional)' => {
        name:     ['log_level'],
        valid:    ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false, 'INFO1'],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Stdlib::Absolutepath' => {
        name:     ['config_path', 'global_known_hosts_path'],
        valid:    ['/absolute/filepath', '/absolute/directory/'],
        invalid:  ['../invalid', ['array'], { 'ha' => 'sh' }, 3, 2.42, false, nil],
        message: 'expects a (match for|match for Stdlib::Absolutepath =|Stdlib::Absolutepath =) Variant\[Stdlib::Windowspath.*Stdlib::Unixpath',
      },
      'Stdlib::Absolutepath (optional)' => {
        name:     ['package_adminfile', 'package_source'],
        valid:    ['/absolute/filepath', '/absolute/directory/', :undef],
        invalid:  ['../invalid', ['array'], { 'ha' => 'sh' }, 3, 2.42, false],
        message: 'expects a (match for|match for Stdlib::Absolutepath =|Stdlib::Absolutepath =) Variant\[Stdlib::Windowspath.*Stdlib::Unixpath',
      },
      'Stdlib::Filemode' => {
        name:     ['config_mode', 'global_known_hosts_mode', 'stream_local_bind_mask'],
        valid:    ['0644', '0755', '0640', '1740'],
        invalid:  [2770, '0844', '00644', 'string', ['array'], { 'ha' => 'sh' }, 3, 2.42, false, nil],
        message: 'expects a match for Stdlib::Filemode|Error while evaluating a Resource Statement',
      },
      'Stdlib::Port (optional)' => {
        name:     ['port'],
        valid:    [0, 242, 65_535, :undef],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, -1, 2.42, 65_536, false],
        message: 'expects a value of type Undef or Array|Error while evaluating a Resource Statement',
      },
      'String' => {
        name:     ['config_group', 'config_owner', 'global_known_hosts_group',
                   'global_known_hosts_owner', 'host', 'root_ssh_config_content'],
        valid:    ['string'],
        invalid:  [['array'], { 'ha' => 'sh' }, 3, 2.42, false], # undef should be invalid too
        message: 'expects a String value',
      },
      'String (optional)' => {
        name:     ['bind_address', 'bind_interface', 'control_path', 'control_persist',
                   'dynamic_forward', 'escape_char', 'host_key_alias', 'hostname', 'identity_agent',
                   'include', 'ip_qos', 'local_command', 'local_forward', 'pkcs11_provider',
                   'protocol', 'proxy_command', 'rekey_limit', 'remote_command', 'remote_forward',
                   'revoked_host_keys', 'tunnel_device', 'user', 'xauth_location'],
        valid:    ['string', :undef],
        invalid:  [['array'], { 'ha' => 'sh' }, 3, 2.42, false],
        message: 'expects a value of type Undef or String',
      },
      'String or Integer (optional)' => {
        name:     ['forward_x11_timeout', 'server_alive_count_max', 'server_alive_interval'],
        valid:    ['3s', '242m', 3, 242, :undef],
        invalid:  [['array'], { 'ha' => 'sh' }, 2.42, false],
        message: 'String or Array|expects a String value|Error while evaluating a Resource Statement',
      },
      'yes or no (optional)' => {
        name:     ['batch_mode', 'canonicalize_fallback_local', 'check_host_ip',
                   'clear_all_forwardings', 'compression', 'enable_ssh_keysign',
                   'exit_on_forward_failure', 'fork_after_authentication', 'forward_agent',
                   'forward_x11_trusted', 'forward_x11', 'gateway_ports',
                   'gss_api_authentication', 'gss_api_delegate_credentials', 'hash_known_hosts',
                   'hostbased_authentication', 'identities_only', 'kbd_interactive_authentication',
                   'no_host_authentication_for_localhost', 'password_authentication',
                   'permit_local_command', 'proxy_use_fdpass', 'pubkey_authentication',
                   'stream_local_bind_unlink', 'tcp_keep_alive', 'use_roaming', 'visual_host_key'],
        valid:    ['yes', 'no', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false, 'YES', 'No'],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
    }

    validations.sort.each do |type, var|
      mandatory_params = {} if mandatory_params.nil?
      var[:name].each do |var_name|
        var[:params] = {} if var[:params].nil?
        var[:valid].each do |valid|
          context "when #{var_name} (#{type}) is set to valid #{valid} (as #{valid.class})" do
            let(:facts) { [mandatory_facts, var[:facts]].reduce(:merge) } unless var[:facts].nil?
            let(:params) { [mandatory_params, var[:params], { "#{var_name}": valid, }].reduce(:merge) }

            it { is_expected.to compile }
          end
        end

        var[:invalid].each do |invalid|
          context "when #{var_name} (#{type}) is set to invalid #{invalid} (as #{invalid.class})" do
            let(:params) { [mandatory_params, var[:params], { "#{var_name}": invalid, }].reduce(:merge) }

            it 'fail' do
              expect { is_expected.to contain_class(:subject) }.to raise_error(Puppet::Error, %r{#{var[:message]}})
            end
          end
        end
      end # var[:name].each
    end # validations.sort.each
  end # describe 'validate data types of parameters'
end
