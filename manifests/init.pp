# @summary Class to manage SSH client
#
# Notes: `Match` and `Host` attributes are not directly supported as multiple
# match/host blocks can exist. Use the `custom` parameter for that.
#
# @param packages
#
# @param package_source
#
# @param package_adminfile
#
# @param config_path
#
# @param config_owner
#
# @param config_group
#
# @param config_mode
#
# @param global_known_hosts
#
# @param global_known_hosts_owner
#
# @param global_known_hosts_group
#
# @param global_known_hosts_mode
#
# @param manage_root_ssh_config
#
# @param root_ssh_config_content
#
# @param manage_server
#
# @param key_export
#
# @param purge_keys
#
# @param ssh_key_ensure
#
# @param ssh_key_import
#
# @param ssh_key_type
#
# @param keys
#
# @param config_entries
#
# @param host
#
# @param add_keys_to_agent
#
# @param address_family
#
# @param batch_mode
#
# @param bind_address
#
# @param bind_interface
#
# @param canonical_domains
#
# @param canonicalize_fallback_local
#
# @param canonicalize_hostname
#
# @param canonicalize_max_dots
#
# @param canonicalize_permitted_cnames
#
# @param ca_signature_algorithms
#
# @param certificate_file
#
# @param challenge_response_authentication
#
# @param check_host_ip
#
# @param ciphers
#
# @param clear_all_forwardings
#
# @param compression
#
# @param connection_attempts
#
# @param connect_timeout
#
# @param control_master
#
# @param control_path
#
# @param control_persist
#
# @param dynamic_forward
#
# @param enable_ssh_keysign
#
# @param escape_char
#
# @param exit_on_forward_failure
#
# @param fingerprint_hash
#
# @param forward_agent
#
# @param forward_x11
#
# @param forward_x11_timeout
#
# @param forward_x11_trusted
#
# @param gateway_ports
#
# @param global_known_hosts_file
#
# @param gss_api_authentication
#
# @param gss_api_delegate_credentials
#
# @param hash_known_hosts
#
# @param hostbased_authentication
#
# @param hostbased_key_types
#
# @param host_key_algorithms
#
# @param host_key_alias
#
# @param host_name
#
# @param identities_only
#
# @param identity_agent
#
# @param identity_file
#
# @param ignore_unknown
#
# @param include
#
# @param ip_qos
#
# @param kbd_interactive_authentication
#
# @param kbd_interactive_devices
#
# @param kex_algorithms
#
# @param local_command
#
# @param local_forward
#
# @param log_level
#
# @param no_host_authentication_for_localhost
#
# @param number_of_password_prompts
#
# @param password_authentication
#
# @param permit_local_command
#
# @param pkcs11_provider
#
# @param port
#
# @param preferred_authentications
#
# @param proxy_command
#
# @param proxy_jump
#
# @param proxy_use_fdpass
#
# @param pubkey_accepted_key_types
#
# @param pubkey_authentication
#
# @param rekey_limit
#
# @param remote_command
#
# @param remote_forward
#
# @param request_tty
#
# @param revoked_host_keys
#
# @param send_env
#
# @param server_alive_count_max
#
# @param server_alive_interval
#
# @param set_env
#
# @param stream_local_bind_mask
#
# @param stream_local_bind_unlink
#
# @param strict_host_key_checking
#
# @param syslog_facility
#
# @param tcp_keep_alive
#
# @param tunnel
#
# @param tunnel_device
#
# @param update_host_keys
#
# @param user
#
# @param user_known_hosts_file
#
# @param verify_host_key_dns
#
# @param visual_host_key
#
# @param xauth_location
#
# @param custom
#
class ssh (
  Variant[String[1], Array[String[1]]] $packages = 'openssh-clients',
  Optional[Stdlib::Absolutepath] $package_source = undef,
  Optional[Stdlib::Absolutepath] $package_adminfile = undef,
  Stdlib::Absolutepath $config_path = '/etc/ssh/ssh_config',
  String[1] $config_owner = 'root',
  String[1] $config_group = 'root',
  Stdlib::Filemode $config_mode = '0644',
  Stdlib::Absolutepath $global_known_hosts = '/etc/ssh/ssh_known_hosts',
  String[1] $global_known_hosts_owner = 'root',
  String[1] $global_known_hosts_group = 'root',
  Stdlib::Filemode $global_known_hosts_mode = '0644',
  Boolean $manage_root_ssh_config = false,
  String[1] $root_ssh_config_content = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
  Boolean $manage_server = true,
  Boolean $key_export = false,
  Boolean $purge_keys = true,
  Enum['present', 'absent'] $ssh_key_ensure = 'present',
  Boolean $ssh_key_import = false,
  Ssh::Key::Type $ssh_key_type = 'ssh-rsa',
  Hash $keys = {},
  Hash $config_entries = {},
  # class parameters below this line directly correlate with ssh_config parameters
  String[1] $host = '*',
  Optional[Enum['yes', 'no', 'ask', 'confirm']] $add_keys_to_agent = undef,
  Optional[Enum['any', 'inet', 'inet6']] $address_family = undef,
  Optional[Ssh::Yes_no] $batch_mode = undef,
  Optional[String[1]] $bind_address = undef,
  Optional[String[1]] $bind_interface = undef,
  Optional[Array[String[1]]] $canonical_domains = undef,
  Optional[Ssh::Yes_no] $canonicalize_fallback_local = undef,
  Optional[Enum['yes', 'no', 'always']] $canonicalize_hostname = undef,
  Optional[Integer[0]] $canonicalize_max_dots = undef,
  Optional[Array[String[1]]] $canonicalize_permitted_cnames = undef,
  Optional[Array[String[1]]] $ca_signature_algorithms = undef,
  Optional[Array[String[1]]] $certificate_file = undef,
  Optional[Ssh::Yes_no] $challenge_response_authentication = undef,
  Optional[Ssh::Yes_no] $check_host_ip = undef,
  Optional[Array[String[1]]] $ciphers = undef,
  Optional[Ssh::Yes_no] $clear_all_forwardings = undef,
  Optional[Ssh::Yes_no] $compression = undef,
  Optional[Integer[0]] $connection_attempts = undef,
  Optional[Integer[0]] $connect_timeout = undef,
  Optional[Enum['yes', 'no', 'ask', 'auto', 'autoask']] $control_master = undef,
  Optional[String[1]] $control_path = undef,
  Optional[String[1]] $control_persist = undef,
  Optional[String[1]] $dynamic_forward = undef,
  Optional[Ssh::Yes_no] $enable_ssh_keysign = undef,
  Optional[String[1]] $escape_char = undef,
  Optional[Ssh::Yes_no] $exit_on_forward_failure = undef,
  Optional[Enum['sha256', 'md5']] $fingerprint_hash = undef,
  Optional[Ssh::Yes_no] $forward_agent = undef,
  Optional[Ssh::Yes_no] $forward_x11 = undef,
  Variant[Undef, String[1], Integer[0]] $forward_x11_timeout = undef,
  Optional[Ssh::Yes_no] $forward_x11_trusted = undef,
  Optional[Ssh::Yes_no] $gateway_ports = undef,
  Variant[Undef, String[1], Array[String[1]]] $global_known_hosts_file = undef,
  Optional[Ssh::Yes_no] $gss_api_authentication = undef,
  Optional[Ssh::Yes_no] $gss_api_delegate_credentials = undef,
  Optional[Ssh::Yes_no] $hash_known_hosts = undef,
  Optional[Ssh::Yes_no] $hostbased_authentication = undef,
  Optional[Array[String[1]]] $hostbased_key_types = undef,
  Optional[Array[String[1]]] $host_key_algorithms = undef,
  Optional[String[1]] $host_key_alias = undef,
  Optional[String[1]] $host_name = undef,
  Optional[Ssh::Yes_no] $identities_only = undef,
  Optional[String[1]] $identity_agent = undef,
  Optional[Array[String[1]]] $identity_file = undef,
  Optional[Array[String[1]]] $ignore_unknown = undef,
  Optional[String[1]] $include = undef,
  Optional[String[1]] $ip_qos = undef,
  Optional[Ssh::Yes_no] $kbd_interactive_authentication = undef,
  Optional[Array[String[1]]] $kbd_interactive_devices = undef,
  Optional[Array[String[1]]] $kex_algorithms = undef,
  Optional[String[1]] $local_command = undef,
  Optional[String[1]] $local_forward = undef,
  Optional[Ssh::Log_level] $log_level = undef,
  Optional[Ssh::Yes_no] $no_host_authentication_for_localhost = undef,
  Optional[Integer] $number_of_password_prompts = undef,
  Optional[Ssh::Yes_no] $password_authentication = undef,
  Optional[Ssh::Yes_no] $permit_local_command = undef,
  Optional[String[1]] $pkcs11_provider = undef,
  Optional[Stdlib::Port] $port = undef,
  Optional[Array[String[1]]] $preferred_authentications = undef,
  Optional[String[1]] $proxy_command = undef,
  Optional[Array[String[1]]] $proxy_jump = undef,
  Optional[Ssh::Yes_no] $proxy_use_fdpass = undef,
  Optional[Array[String[1]]] $pubkey_accepted_key_types = undef,
  Optional[Ssh::Yes_no] $pubkey_authentication = undef,
  Optional[String[1]] $rekey_limit = undef,
  Optional[String[1]] $remote_command = undef,
  Optional[String[1]] $remote_forward = undef,
  Optional[Enum['no', 'yes', 'force', 'auto']] $request_tty = undef,
  Optional[String[1]] $revoked_host_keys = undef,
  Optional[Array[String[1]]] $send_env = undef,
  Variant[Undef, String[1], Integer[0]] $server_alive_count_max = undef,
  Variant[Undef, String[1], Integer[0]] $server_alive_interval = undef,
  Optional[Array[String[1]]] $set_env = undef,
  Optional[Pattern[/^[0-7]{4}$/]] $stream_local_bind_mask = undef,
  Optional[Ssh::Yes_no] $stream_local_bind_unlink = undef,
  Optional[Enum['yes', 'no', 'accept-new', 'off', 'ask']] $strict_host_key_checking = undef,
  Optional[Ssh::Syslog_facility] $syslog_facility = undef,
  Optional[Ssh::Yes_no] $tcp_keep_alive = undef,
  Optional[Enum['yes', 'no', 'point-to-point', 'ethernet']] $tunnel = undef,
  Optional[String[1]] $tunnel_device = undef,
  Optional[Enum['yes', 'no', 'ask']] $update_host_keys = undef,
  Optional[String[1]] $user = undef,
  Optional[Array[String[1]]] $user_known_hosts_file = undef,
  Optional[Enum['yes', 'no', 'ask']] $verify_host_key_dns = undef,
  Optional[Ssh::Yes_no] $visual_host_key = undef,
  Optional[String[1]] $xauth_location = undef,
  # custom is a string that allows for multiple lines to be appended to end of
  # the sshd_config file.
  Optional[String[1]] $custom = undef,
) {

  # TODO: This huge case statement is getting transitioned to hiera
  case $facts['os']['family'] {
    'RedHat': {}
    'Suse': {
      $default_packages                        = 'openssh'
      $default_service_name                    = 'sshd'
      $default_ssh_config_hash_known_hosts     = 'no'
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
      $default_ssh_sendenv                     = true
      $default_ssh_config_forward_x11_trusted  = 'yes'
      $default_sshd_config_mode                = '0600'
      $default_sshd_config_use_dns             = 'yes'
      $default_sshd_config_xauth_location      = '/usr/bin/xauth'
      $default_sshd_use_pam                    = 'yes'
      $default_sshd_gssapikeyexchange          = undef
      $default_sshd_pamauthenticationviakbdint = undef
      $default_sshd_gssapicleanupcredentials   = 'yes'
      $default_sshd_acceptenv                  = true
      $default_service_hasstatus               = true
      $default_sshd_config_serverkeybits       = '1024'
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = 'any'
      $default_sshd_config_tcp_keepalive       = 'yes'
      $default_sshd_config_permittunnel        = 'no'
      case $::architecture {
        'x86_64': {
          if ($::operatingsystem == 'SLES') and ($::operatingsystemrelease =~ /^12\./) {
            $default_sshd_config_subsystem_sftp = '/usr/lib/ssh/sftp-server'
          } else {
            $default_sshd_config_subsystem_sftp = '/usr/lib64/ssh/sftp-server'
          }
        }
        'i386' : {
          $default_sshd_config_subsystem_sftp = '/usr/lib/ssh/sftp-server'
      }
        default: {
          fail("ssh supports architectures x86_64 and i386 for Suse. Detected architecture is <${::architecture}>.")
        }
      }
    }
    'Debian': {
      # common for debian and ubuntu
      $default_packages                        = ['openssh-server',
                                                  'openssh-client']
      $default_service_name                    = 'ssh'

      case $::operatingsystemrelease {
        '16.04': {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_dsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_ssh_config_hash_known_hosts        = 'yes'
          $default_sshd_config_xauth_location         = undef
          $default_ssh_config_forward_x11_trusted     = 'yes'
          $default_ssh_package_source                 = undef
          $default_ssh_package_adminfile              = undef
          $default_ssh_sendenv                        = true
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_acceptenv                     = true
          $default_service_hasstatus                  = true
          $default_sshd_config_serverkeybits          = '1024'
          $default_sshd_addressfamily                 = 'any'
          $default_sshd_config_tcp_keepalive          = 'yes'
          $default_sshd_config_permittunnel           = 'no'
        }
        '18.04': {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_dsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_ssh_config_hash_known_hosts        = 'yes'
          $default_sshd_config_xauth_location         = undef
          $default_ssh_config_forward_x11_trusted     = 'yes'
          $default_ssh_package_source                 = undef
          $default_ssh_package_adminfile              = undef
          $default_ssh_sendenv                        = true
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_acceptenv                     = true
          $default_service_hasstatus                  = true
          $default_sshd_config_serverkeybits          = '1024'
          $default_sshd_addressfamily                 = 'any'
          $default_sshd_config_tcp_keepalive          = 'yes'
          $default_sshd_config_permittunnel           = 'no'
        }
        /^9.*/: {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_mode                = '0600'
          $default_sshd_use_pam                    = 'yes'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_sshd_acceptenv                  = true
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_ssh_config_hash_known_hosts     = 'yes'
          $default_ssh_sendenv                     = true
          $default_sshd_addressfamily              = undef
          $default_sshd_config_serverkeybits       = undef
          $default_sshd_gssapicleanupcredentials   = undef
          $default_sshd_config_use_dns             = undef
          $default_sshd_config_xauth_location      = undef
          $default_sshd_config_permittunnel        = undef
          $default_sshd_config_tcp_keepalive       = undef
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_service_hasstatus               = true
        }
        /^7.*/: {
          $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
          $default_ssh_config_hash_known_hosts     = 'no'
          $default_sshd_config_xauth_location      = '/usr/bin/xauth'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
          $default_ssh_sendenv                     = true
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                = '0600'
          $default_sshd_config_use_dns             = 'yes'
          $default_sshd_use_pam                    = 'yes'
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_sshd_gssapicleanupcredentials   = 'yes'
          $default_sshd_acceptenv                  = true
          $default_service_hasstatus               = true
          $default_sshd_config_serverkeybits       = '1024'
          $default_sshd_addressfamily              = 'any'
          $default_sshd_config_tcp_keepalive       = 'yes'
          $default_sshd_config_permittunnel        = 'no'
        }
        /^8.*/: {

          $default_ssh_config_hash_known_hosts     = 'yes'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
          $default_ssh_sendenv                     = true
          $default_sshd_config_hostkey = [
          '/etc/ssh/ssh_host_rsa_key',
          '/etc/ssh/ssh_host_dsa_key',
          '/etc/ssh/ssh_host_ecdsa_key',
          '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                = '0600'
          $default_sshd_config_use_dns             = 'yes'
          $default_sshd_use_pam                    = 'yes'
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_sshd_gssapicleanupcredentials   = undef
          $default_sshd_acceptenv                  = true
          $default_sshd_config_xauth_location      = undef
          $default_sshd_config_serverkeybits       = '1024'
          $default_sshd_addressfamily              = 'any'
          $default_sshd_config_tcp_keepalive       = 'yes'
          $default_sshd_config_permittunnel        = 'no'
          $default_service_hasstatus               = true
        }
        default: { fail ("Operating System : ${::operatingsystemrelease} not supported") }
      }
    }
    'Solaris': {
      $default_ssh_config_hash_known_hosts     = undef
      $default_ssh_sendenv                     = false
      $default_ssh_config_forward_x11_trusted  = undef
      $default_sshd_config_subsystem_sftp      = '/usr/lib/ssh/sftp-server'
      $default_sshd_config_mode                = '0644'
      $default_sshd_config_use_dns             = undef
      $default_sshd_config_xauth_location      = '/usr/openwin/bin/xauth'
      $default_sshd_use_pam                    = undef
      $default_sshd_gssapikeyexchange          = 'yes'
      $default_sshd_pamauthenticationviakbdint = 'yes'
      $default_sshd_gssapicleanupcredentials   = undef
      $default_sshd_acceptenv                  = false
      $default_sshd_config_serverkeybits       = '768'
      $default_ssh_package_adminfile           = undef
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = undef
      $default_sshd_config_tcp_keepalive       = undef
      $default_sshd_config_permittunnel        = undef
      case $::kernelrelease {
        '5.11': {
          $default_packages                      = ['network/ssh',
                                                    'network/ssh/ssh-key',
                                                    'service/network/ssh']
          $default_service_name                  = 'ssh'
          $default_service_hasstatus             = true
          $default_ssh_package_source            = undef
        }
        '5.10': {
          $default_packages                      = ['SUNWsshcu',
                                                    'SUNWsshdr',
                                                    'SUNWsshdu',
                                                    'SUNWsshr',
                                                    'SUNWsshu']
          $default_service_name                  = 'ssh'
          $default_service_hasstatus             = true
          $default_ssh_package_source            = '/var/spool/pkg'
        }
        '5.9' : {
          $default_packages                      = ['SUNWsshcu',
                                                    'SUNWsshdr',
                                                    'SUNWsshdu',
                                                    'SUNWsshr',
                                                    'SUNWsshu']
          $default_service_name                  = 'sshd'
          $default_service_hasstatus             = false
          $default_ssh_package_source            = '/var/spool/pkg'
        }
        default: {
          fail('ssh module supports Solaris kernel release 5.9, 5.10 and 5.11.')
        }
      }
    }
    default: {
      fail("ssh supports osfamilies RedHat, Suse, Debian and Solaris. Detected os family is <${facts['os']['family']}>.")
    }
  }

  case type_of($global_known_hosts_file) {
    string:  { $global_known_hosts_file_array = [ $global_known_hosts_file ] }
    default: { $global_known_hosts_file_array = $global_known_hosts_file }
  }


  if "${::ssh_version}" =~ /^OpenSSH/  { # lint:ignore:only_variable_string
    $ssh_version_array = split($::ssh_version_numeric, '\.')
    $ssh_version_maj_int = 0 + $ssh_version_array[0]
    $ssh_version_min_int = 0 + $ssh_version_array[1]
    if $ssh_version_maj_int > 5 {
      $default_ssh_config_use_roaming = 'no'
    } elsif $ssh_version_maj_int == 5 and $ssh_version_min_int >= 4 {
      $default_ssh_config_use_roaming = 'no'
    } else {
      $default_ssh_config_use_roaming = 'unset'
    }
  } else {
      $default_ssh_config_use_roaming = 'unset'
  }

  package { $packages:
    ensure    => installed,
    source    => $package_source,
    adminfile => $package_adminfile,
  }

  file  { 'ssh_config' :
    ensure  => file,
    path    => $config_path,
    owner   => $config_owner,
    group   => $config_group,
    mode    => $config_mode,
    content => template('ssh/ssh_config.erb'),
    require => Package[$packages],
  }

  if $manage_root_ssh_config == true {

    exec { "mkdir_p-${::root_home}/.ssh":
      command => "mkdir -p ${::root_home}/.ssh",
      unless  => "test -d ${::root_home}/.ssh",
      path    => '/bin:/usr/bin',
    }

    file { 'root_ssh_dir':
      ensure  => directory,
      path    => "${::root_home}/.ssh",
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
      require => Exec["mkdir_p-${::root_home}/.ssh"],
    }

    file { 'root_ssh_config':
      ensure  => file,
      path    => "${::root_home}/.ssh/config",
      content => $root_ssh_config_content,
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
    }
  }

  # If either IPv4 or IPv6 stack is not configured on the agent, the
  # corresponding $::ipaddress(6)? fact is not present. So, we cannot assume
  # these variables are defined. Getvar (Stdlib 4.13+, ruby 1.8.7+) handles
  # this correctly.
  if getvar('::ipaddress') and getvar('::ipaddress6') { $host_aliases = [$::hostname, $::ipaddress, $::ipaddress6] }
  elsif getvar('::ipaddress6') { $host_aliases = [$::hostname, $::ipaddress6] }
  else { $host_aliases = [$::hostname, $::ipaddress] }

  # export each node's ssh key
  if $key_export == true {
    # ssh_key_type might start with 'ssh-' though facter stores them without
    # the 'ssh-' prefix.
    #$key_type = delete_regex($ssh_key_type, '^ssh-')
    $key_type = 'rsa'
    @@sshkey { $::fqdn :
      ensure       => $ssh_key_ensure,
      host_aliases => $host_aliases,
      type         => $ssh_key_type,
      key          => $facts['ssh'][$key_type]['key'],
    }
  }

  file { 'ssh_known_hosts':
    ensure  => file,
    path    => $global_known_hosts,
    owner   => $global_known_hosts_owner,
    group   => $global_known_hosts_group,
    mode    => $global_known_hosts_mode,
    require => Package[$packages],
  }

  # import all nodes' ssh keys
  if $ssh_key_import == true {
    Sshkey <<||>> {
      target => $global_known_hosts,
    }
  }

  # remove ssh key's not managed by puppet
  resources  { 'sshkey':
    purge => $purge_keys,
  }

  # manage users' ssh config entries if present
  $config_entries.each |$key,$value| {
    ssh::config_entry { $key:
      * => $value,
    }
  }

  # manage users' ssh authorized keys if present
  if $keys.empty == false {
    $keys.each |$key,$value| {
      ssh_authorized_key { $key:
        * => $value,
      }
    }
  }

  if $manage_server == true {
    include ssh::server
  }
}
