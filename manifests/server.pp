# @summary Class to manage SSH server
#
# Notes: `Match` attribute is not directly supported as multiple match blocks can
# exist. Use the `custom` parameter for that.
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
# @param banner_path
#
# @param banner_content
#
# @param banner_owner
#
# @param banner_group
#
# @param banner_mode
#
# @param manage_service
#
# @param service_ensure
#
# @param service_name
#
# @param service_enable
#
# @param service_hasrestart
#
# @param service_hasstatus
#
# @param accept_env
#
# @param address_family
#
# @param allow_agent_forwarding
#
# @param allow_groups
#
# @param allow_stream_local_forwarding
#
# @param allow_tcp_forwarding
#
# @param allow_users
#
# @param authentication_methods
#
# @param authorized_keys_command
#
# @param authorized_keys_command_user
#
# @param authorized_keys_file
#
# @param authorized_principals_command
#
# @param authorized_principals_command_user
#
# @param authorized_principals_file
#
# @param banner
#
# @param ca_signature_algorithms
#
# @param challenge_response_authentication
#
# @param chroot_directory
#
# @param ciphers
#
# @param client_alive_count_max
#
# @param client_alive_interval
#
# @param compression
#
# @param deny_groups
#
# @param deny_users
#
# @param disable_forwarding
#
# @param expose_auth_info
#
# @param fingerprint_hash
#
# @param force_command
#
# @param gateway_ports
#
# @param gss_api_authentication
#
# @param gss_api_cleanup_credentials
#
# @param gss_api_strict_acceptor_check
#
# @param hostbased_accepted_key_types
#
# @param hostbased_authentication
#
# @param hostbased_uses_name_from_packet_only
#
# @param host_certificate
#
# @param host_key
#
# @param host_key_agent
#
# @param host_key_algorithms
#
# @param ignore_rhosts
#
# @param ignore_user_known_hosts
#
# @param include
#
# @param ip_qos
#
# @param kbd_interactive_authentication
#
# @param kerberos_authentication
#
# @param kerberos_get_afs_token
#
# @param kerberos_or_local_passwd
#
# @param kerberos_ticket_cleanup
#
# @param kex_algorithms
#
# @param listen_address
#
# @param login_grace_time
#
# @param log_level
#
# @param macs
#
# @param max_auth_tries
#
# @param max_sessions
#
# @param max_startups
#
# @param password_authentication
#
# @param permit_empty_passwords
#
# @param permit_listen
#
# @param permit_root_login
#
# @param permit_tty
#
# @param permit_tunnel
#
# @param permit_user_environment
#
# @param permit_user_rc
#
# @param pid_file
#
# @param port
#
# @param print_last_log
#
# @param print_motd
#
# @param pubkey_accepted_key_types
#
# @param pubkey_authentication
#
# @param rekey_limit
#
# @param revoked_keys
#
# @param rdomain
#
# @param set_env
#
# @param stream_local_bind_mask
#
# @param stream_local_bind_unlink
#
# @param strict_modes
#
# @param subsystem
#
# @param syslog_facility
#
# @param tcp_keep_alive
#
# @param trusted_user_ca_keys
#
# @param use_dns
#
# @param use_pam
#
# @param version_addendum
#
# @param x11_display_offset
#
# @param x11_forwarding
#
# @param x11_use_localhost
#
# @param xauth_location
#
# @param custom
#
class ssh::server (
  Variant[String[1], Array[String[1]]] $packages = 'openssh-server',
  Optional[Stdlib::Absolutepath] $package_source = undef,
  Optional[Stdlib::Absolutepath] $package_adminfile = undef,
  Stdlib::Absolutepath $config_path = '/etc/ssh/sshd_config',
  String[1] $config_owner = 'root',
  String[1] $config_group = 'root',
  Stdlib::Filemode $config_mode = '0600',
  Stdlib::Absolutepath $banner_path = '/etc/sshd_banner',
  Optional[String[1]] $banner_content = undef,
  String[1] $banner_owner = 'root',
  String[1] $banner_group = 'root',
  Stdlib::Filemode $banner_mode = '0644',
  Boolean $manage_service = true,
  Stdlib::Ensure::Service $service_ensure = 'running',
  String[1] $service_name = 'sshd',
  Boolean $service_enable = true,
  Boolean $service_hasrestart = true,
  Boolean $service_hasstatus = true,
  # all paramters below this line are for sshd_config
  Optional[Array[String[1]]] $accept_env = undef,
  Optional[Enum['any', 'inet', 'inet6']] $address_family = undef,
  Optional[Ssh::Yes_no] $allow_agent_forwarding = undef,
  Variant[Undef, String[1], Array[String[1]]] $allow_groups = undef,
  Optional[Enum['yes', 'all', 'no', 'local', 'remote']] $allow_stream_local_forwarding = undef,
  Optional[Enum['yes', 'no', 'local', 'remote']] $allow_tcp_forwarding = undef,
  Variant[Undef, String[1], Array[String[1]]] $allow_users = undef,
  Optional[Array[String[1]]] $authentication_methods = undef,
  Optional[String[1]] $authorized_keys_command = undef,
  Optional[String[1]] $authorized_keys_command_user = undef,
  Variant[Undef, String[1], Array[String[1]]] $authorized_keys_file = undef,
  Optional[String[1]] $authorized_principals_command = undef,
  Optional[String[1]] $authorized_principals_command_user = undef,
  Optional[String[1]] $authorized_principals_file = undef,
  Optional[String[1]] $banner = undef,
  Optional[Array[String[1]]] $ca_signature_algorithms = undef,
  Optional[Ssh::Yes_no] $challenge_response_authentication = undef,
  Optional[String[1]] $chroot_directory = undef,
  Optional[Array[String[1]]] $ciphers = undef,
  Optional[Integer[0]] $client_alive_count_max = undef,
  Optional[Integer[0]] $client_alive_interval = undef,
  Optional[Enum['yes', 'delayed', 'no']] $compression = undef,
  Variant[Undef, String[1], Array[String[1]]] $deny_groups = undef,
  Variant[Undef, String[1], Array[String[1]]] $deny_users = undef,
  Optional[Ssh::Yes_no] $disable_forwarding = undef,
  Optional[Ssh::Yes_no] $expose_auth_info = undef,
  Optional[Enum['md5', 'sha256']] $fingerprint_hash = undef,
  Optional[String[1]] $force_command = undef,
  Optional[Enum['no', 'yes', 'clientspecified']] $gateway_ports = undef,
  Optional[Ssh::Yes_no] $gss_api_authentication = undef,
  Optional[Ssh::Yes_no] $gss_api_cleanup_credentials = undef,
  Optional[Ssh::Yes_no] $gss_api_strict_acceptor_check = undef,
  Optional[Array[String[1]]] $hostbased_accepted_key_types = undef,
  Optional[Ssh::Yes_no] $hostbased_authentication = undef,
  Optional[Ssh::Yes_no] $hostbased_uses_name_from_packet_only = undef,
  Optional[String[1]] $host_certificate = undef,
  Optional[Array[String[1]]] $host_key = undef,
  Optional[String[1]] $host_key_agent = undef,
  Optional[Array[String[1]]] $host_key_algorithms = undef,
  Optional[Ssh::Yes_no] $ignore_rhosts = undef,
  Optional[Ssh::Yes_no] $ignore_user_known_hosts = undef,
  Optional[String[1]] $include = undef,
  Optional[String[1]] $ip_qos = undef,
  Optional[Ssh::Yes_no] $kbd_interactive_authentication = undef,
  Optional[Ssh::Yes_no] $kerberos_authentication = undef,
  Optional[Ssh::Yes_no] $kerberos_get_afs_token = undef,
  Optional[Ssh::Yes_no] $kerberos_or_local_passwd = undef,
  Optional[Ssh::Yes_no] $kerberos_ticket_cleanup = undef,
  Optional[Array[String[1]]] $kex_algorithms = undef,
  Optional[Array[String[1]]] $listen_address = undef,
  Optional[Integer[0]] $login_grace_time = undef,
  Optional[Ssh::Log_level] $log_level = undef,
  Optional[Array[String[1]]] $macs = undef,
  Optional[Integer[2]] $max_auth_tries = undef,
  Optional[Integer[0]] $max_sessions = undef,
  Optional[String[1]] $max_startups = undef,
  Optional[Ssh::Yes_no] $password_authentication = undef,
  Optional[Ssh::Yes_no] $permit_empty_passwords = undef,
  Variant[Undef, String[1], Array[String[1]]] $permit_listen = undef,
  Optional[Ssh::Permit_root_login] $permit_root_login = undef,
  Optional[Ssh::Yes_no] $permit_tty = undef,
  Optional[Enum['yes', 'point-to-point', 'ethernet', 'no']] $permit_tunnel = undef,
  Optional[String[1]] $permit_user_environment = undef,
  Optional[Ssh::Yes_no] $permit_user_rc = undef,
  Optional[String[1]] $pid_file = undef,
  Optional[Array[Stdlib::Port]] $port = undef,
  Optional[Ssh::Yes_no] $print_last_log = undef,
  Optional[Ssh::Yes_no] $print_motd = undef,
  Optional[Array[String[1]]] $pubkey_accepted_key_types = undef,
  Optional[Ssh::Yes_no] $pubkey_authentication = undef,
  Optional[String[1]] $rekey_limit = undef,
  Optional[String[1]] $revoked_keys = undef,
  Optional[String[1]] $rdomain = undef,
  Optional[Array[String[1]]] $set_env = undef,
  Optional[Pattern[/^[0-7]{4}$/]] $stream_local_bind_mask = undef,
  Optional[Ssh::Yes_no] $stream_local_bind_unlink = undef,
  Optional[Ssh::Yes_no] $strict_modes = undef,
  Optional[String[1]] $subsystem = undef,
  Optional[Ssh::Syslog_facility] $syslog_facility = undef,
  Optional[Ssh::Yes_no] $tcp_keep_alive = undef,
  Optional[String[1]] $trusted_user_ca_keys = undef,
  Optional[Ssh::Yes_no] $use_dns = undef,
  Optional[Ssh::Yes_no] $use_pam = undef,
  Optional[String[1]] $version_addendum = undef,
  Optional[Integer[0]] $x11_display_offset = undef,
  Optional[Ssh::Yes_no] $x11_forwarding = undef,
  Optional[Ssh::Yes_no] $x11_use_localhost = undef,
  Optional[String[1]] $xauth_location = undef,
  # custom is a string that allows for multiple lines to be appended to end of
  # the sshd_config file.
  Optional[Array[String[1]]] $custom = undef,
) {

# lint:ignore:140chars
#  if $authorized_keys_command_user != undef and $authorized_keys_command == undef {
#    fail("If AuthorizedKeysCommand is specified but AuthorizedKeysCommandUser is not, then sshd(8) will refuse to start. authorized_keys_command_user = <${authorized_keys_command_user}> and authorized_keys_command = <${authorized_keys_command}>")
#  }
#
#  if $authorized_principals_command_user != undef and $authorized_principals_command == undef {
#    fail("If AuthorizedPrincipalsCommand is specified but AuthorizedPrincipalsCommandUser is not, then sshd(8) will refuse to start. authorized_principals_command_user = <${authorized_principals_command_user}> and authorized_principals_command = <${authorized_principals_command}>")
#  }
# lint:endignore

# TODO: This huge case statement is getting transitioned to hiera
  case $facts['os']['family'] {
    'RedHat': {
      $default_packages                        = ['openssh-server']
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
      $default_service_name                    = 'sshd'
      $default_sshd_config_subsystem_sftp      = '/usr/libexec/openssh/sftp-server'
      $default_sshd_config_mode                = '0600'
      $default_sshd_config_use_dns             = 'yes'
      $default_sshd_config_xauth_location      = '/usr/bin/xauth'
      $default_sshd_use_pam                    = 'yes'
      $default_sshd_gssapikeyexchange          = undef
      $default_sshd_pamauthenticationviakbdint = undef
      $default_sshd_gssapicleanupcredentials   = 'yes'
      $default_sshd_acceptenv                  = true
      $default_service_hasstatus               = true
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = 'any'
      $default_sshd_config_tcp_keepalive       = 'yes'
      $default_sshd_config_permittunnel        = 'no'
      $default_sshd_config_include             = undef
      if versioncmp($::operatingsystemrelease, '7.4') < 0 {
        $default_sshd_config_serverkeybits = '1024'
      } else {
        $default_sshd_config_serverkeybits = undef
      }
    }
    'Suse': {
      $default_packages                        = 'openssh'
      $default_service_name                    = 'sshd'
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
      $default_sshd_config_mode                = '0600'
      $default_sshd_config_use_dns             = 'yes'
      $default_sshd_config_xauth_location      = '/usr/bin/xauth'
      $default_sshd_use_pam                    = 'yes'
      $default_sshd_gssapikeyexchange          = undef
      $default_sshd_pamauthenticationviakbdint = undef
      $default_sshd_gssapicleanupcredentials   = 'yes'
      $default_sshd_acceptenv                  = true
      $default_service_hasstatus               = true
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = 'any'
      $default_sshd_config_tcp_keepalive       = 'yes'
      $default_sshd_config_permittunnel        = 'no'
      $default_sshd_config_include             = undef
      case $::architecture {
        'x86_64': {
          if ($::operatingsystem == 'SLES') {
            case $::operatingsystemrelease {
              /15\./: {
                $default_sshd_config_subsystem_sftp = '/usr/lib/ssh/sftp-server'
                $default_sshd_config_serverkeybits  = undef
              }
              default: {
                $default_sshd_config_subsystem_sftp = '/usr/lib64/ssh/sftp-server'
                $default_sshd_config_serverkeybits  = '1024'
              }
            }
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
      $default_packages                        = ['openssh-server']
      $default_service_name                    = 'ssh'

      case $::operatingsystemrelease {
        '14.04': {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
          ]
          $default_sshd_config_xauth_location         = '/usr/bin/xauth'
          $default_ssh_package_source                 = undef
          $default_ssh_package_adminfile              = undef
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
          $default_sshd_config_include                = undef
        }
        '16.04': {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_dsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_xauth_location         = undef
          $default_ssh_package_source                 = undef
          $default_ssh_package_adminfile              = undef
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_acceptenv                     = true
          $default_service_hasstatus                  = true
          $default_sshd_addressfamily                 = 'any'
          $default_sshd_config_tcp_keepalive          = 'yes'
          $default_sshd_config_permittunnel           = 'no'
          $default_sshd_config_include                = undef
        }
        '18.04': {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_dsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_xauth_location         = undef
          $default_ssh_package_source                 = undef
          $default_ssh_package_adminfile              = undef
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
          $default_sshd_config_include                = undef
        }
        '20.04': {
          $default_service_hasstatus                  = true
          $default_ssh_package_adminfile              = undef
          $default_ssh_package_source                 = undef
          $default_sshd_acceptenv                     = true
          $default_sshd_addressfamily                 = 'any'
          $default_sshd_config_hostkey                = []
          $default_sshd_config_include                = '/etc/ssh/sshd_config.d/*.conf'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_permittunnel           = undef
          $default_sshd_config_print_motd             = 'no'
          $default_sshd_config_serverkeybits          = undef
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_tcp_keepalive          = undef
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_config_xauth_location         = undef
          $default_sshd_gssapiauthentication          = 'yes'
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_x11_forwarding                = 'yes'
        }
        /^7.*/: {
          $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
          $default_sshd_config_xauth_location      = '/usr/bin/xauth'
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
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
          $default_sshd_config_include             = undef
        }
        /^8.*/: {
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
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
          $default_sshd_config_include             = undef
        }
        /^9.*/: {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_mode                = '0600'
          $default_sshd_use_pam                    = 'yes'
          $default_sshd_acceptenv                  = true
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
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
          $default_sshd_config_include             = undef
          $default_service_hasstatus               = true
        }

        /^10.*/: {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_mode                = '0600'
          $default_sshd_use_pam                    = 'yes'
          $default_sshd_acceptenv                  = true
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
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
          $default_sshd_config_include             = undef
        }
        default: { fail ("Operating System : ${::operatingsystemrelease} not supported") }
      }
    }
    'Solaris': {
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
      $default_sshd_config_include             = undef
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
    'UnitTesting': {} # fake OS for easier testing only
    default: {
      fail("ssh supports osfamilies RedHat, Suse, Debian and Solaris. Detected os.family is <${facts['os']['family']}>.")
    }
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

  file  { 'sshd_config' :
    ensure  => file,
    path    => $config_path,
    mode    => $config_mode,
    owner   => $config_owner,
    group   => $config_group,
    content => template('ssh/sshd_config.erb'),
    require => Package[$packages],
  }

  if $banner_content != undef {
    file { 'sshd_banner' :
      ensure  => file,
      path    => $banner_path,
      owner   => $banner_owner,
      group   => $banner_group,
      mode    => $banner_mode,
      content => $banner_content,
      require => Package[$packages],
    }
  }

  if $manage_service {
    service { 'sshd_service' :
      ensure     => $service_ensure,
      name       => $service_name,
      enable     => $service_enable,
      hasrestart => $service_hasrestart,
      hasstatus  => $service_hasstatus,
      subscribe  => File['sshd_config'],
    }
  }

  # TODO: remove and document that the code will not check these types of
  # things. It introduces too much complexity here and in the testing. Anyone
  # using this would test their own custom options to ensure they work anyhow.
  if $address_family != undef {
    if $facts['os']['family'] == 'Solaris' {
      fail("address_family is not supported on Solaris and is set to <${address_family}>.")
    }
  }
}
