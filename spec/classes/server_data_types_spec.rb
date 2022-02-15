require 'spec_helper'

describe 'ssh::server' do
  context 'validate data types of parameters' do
    # these tests are OS independent, so we use a fictional OS without any default values
    let(:facts) { { os: { family: 'UnitTesting' } } }

    validations = {
      'Array of Stdlib::Port (optional)' => {
        name:     ['port'],
        valid:    [[0], [242, 65_535], :undef],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, -1, 2.42, 65_536, false],
        message: 'expects a value of type Undef or Array|Error while evaluating a Resource Statement',
      },
      'Array of strings (optional)' => {
        name:     ['accept_env', 'allow_groups', 'allow_users', 'authentication_methods',
                   'authorized_keys_file', 'ca_signature_algorithms', 'ciphers', 'custom',
                   'deny_groups', 'deny_users', 'host_key', 'host_key_algorithms',
                   'hostbased_accepted_key_types', 'kex_algorithms', 'listen_address', 'macs',
                   'permit_listen', 'pubkey_accepted_key_types', 'set_env'],
        valid:    [['array', 'of', 'strings'], :undef],
        invalid:  ['string', { 'ha' => 'sh' }, 3, 2.42, false, [0]],
        message: 'Undef or Array|expects a String value|Error while evaluating a Resource Statement',
      },
      'Boolean' => {
        name:     ['manage_service', 'service_enable', 'service_hasrestart', 'service_hasstatus'],
        valid:    [true, false],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, 3, 2.42, 'false', nil],
        message: 'expects a Boolean',
      },
      'Ssh::Log_level (optional)' => {
        name:     ['log_level'],
        valid:    ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false, 'INFO1'],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Stdlib::Absolutepath' => {
        name:     ['banner_path', 'config_path'],
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
      'Stdlib::Ensure::Service' => {
        name:     ['service_ensure'],
        valid:    ['running', 'stopped'],
        invalid:  ['present', 'absent', ['array'], { 'ha' => 'sh' }, 3, 2.42, false, nil],
        message: 'expects a match for Stdlib::Ensure::Service',
      },
      'Stdlib::Filemode' => {
        name:     ['banner_mode', 'config_mode'],
        valid:    ['0644', '0755', '0640', '1740'],
        invalid:  [2770, '0844', '00644', 'string', ['array'], { 'ha' => 'sh' }, 3, 2.42, false, nil],
        message: 'expects a match for Stdlib::Filemode|Error while evaluating a Resource Statement',
      },
      'String (optional)' => {
        name:     ['authorized_keys_command', 'authorized_keys_command_user',
                   'authorized_principals_command', 'authorized_principals_command_user',
                   'authorized_principals_file', 'banner', 'banner_content', 'chroot_directory',
                   'force_command', 'host_certificate', 'host_key_agent', 'ip_qos', 'max_startups',
                   'permit_user_environment', 'pid_file', 'rdomain', 'rekey_limit', 'revoked_keys',
                   'subsystem', 'trusted_user_ca_keys', 'version_addendum', 'xauth_location'],
        valid:    ['string', :undef],
        invalid:  [['array'], { 'ha' => 'sh' }, 3, 2.42, false],
        message: 'expects a value of type Undef or String',
      },
      'String or Array of strings' => {
        name:     ['packages'],
        valid:    ['strings', ['array', 'of', 'strings']],
        invalid:  [{ 'ha' => 'sh' }, 3, 2.42, false, [0]],
        message: 'String or Array|expects a String value|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for address_family (optional)' => {
        name:     ['address_family'],
        valid:    ['any', 'inet', 'inet6', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for allow_stream_local_forwarding (optional)' => {
        name:     ['allow_stream_local_forwarding'],
        valid:    ['yes', 'all', 'no', 'local', 'remote', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for allow_tcp_forwarding (optional)' => {
        name:     ['allow_tcp_forwarding'],
        valid:    ['yes', 'no', 'local', 'remote', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for compression (optional)' => {
        name:     ['compression'],
        valid:    ['yes', 'no', 'delayed', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for fingerprint_hash (optional)' => {
        name:     ['fingerprint_hash'],
        valid:    ['md5', 'sha256', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for gateway_ports (optional)' => {
        name:     ['gateway_ports'],
        valid:    ['yes', 'no', 'clientspecified', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for permit_root_login (optional)' => {
        name:     ['permit_root_login'],
        valid:    ['yes', 'prohibit-password', 'without-password', 'forced-commands-only', 'no', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for permit_tunnel (optional)' => {
        name:     ['permit_tunnel'],
        valid:    ['yes', 'point-to-point', 'ethernet', 'no', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for syslog_facility (optional)' => {
        name:     ['syslog_facility'],
        valid:    ['DAEMON', 'USER', 'AUTH', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7', 'AUTHPRIV', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false, 'USER0', 'daemon'],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'four digit octal (optional) for umask' => {
        name:     ['stream_local_bind_mask'],
        valid:    ['0000', '1234', '7777', :undef],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, -1, 2.42, false, '00000', 'x234', '77e1', '011'],
        message: 'Error while evaluating a Resource Statement',
      },
      'integer => 0 (optional)' => {
        name:     ['client_alive_count_max', 'client_alive_interval', 'login_grace_time', 'max_sessions', 'x11_display_offset'],
        valid:    [0, 1, 23, :undef],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'Undef or Integer|Error while evaluating a Resource Statement',
      },
      'integer => 2 (optional)' => {
        name:     ['max_auth_tries'],
        valid:    [2, 23, :undef],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, -1, 2.42, 0, 1, false],
        message: 'Undef or Integer|Error while evaluating a Resource Statement',
      },
      'yes or no (optional)' => {
        name:     ['allow_agent_forwarding', 'challenge_response_authentication',
                   'disable_forwarding', 'expose_auth_info', 'gss_api_authentication',
                   'gss_api_cleanup_credentials', 'gss_api_strict_acceptor_check',
                   'hostbased_authentication', 'hostbased_uses_name_from_packet_only',
                   'ignore_rhosts', 'ignore_user_known_hosts', 'kbd_interactive_authentication',
                   'kerberos_authentication', 'kerberos_get_afs_token', 'kerberos_or_local_passwd',
                   'kerberos_ticket_cleanup', 'password_authentication', 'permit_empty_passwords',
                   'permit_tty', 'permit_user_rc', 'print_last_log', 'print_motd',
                   'pubkey_authentication', 'stream_local_bind_unlink', 'strict_modes',
                   'tcp_keep_alive', 'use_dns', 'use_pam', 'x11_forwarding', 'x11_use_localhost'],
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
