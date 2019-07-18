define ssh::sshd_config(
  $permit_root_login                      = 'yes',
  $sshd_config_path                       = '/etc/ssh/sshd_config',
  $sshd_config_owner                      = 'root',
  $sshd_config_group                      = 'root',
  $sshd_config_loglevel                   = 'INFO',
  $sshd_config_mode                       = 'USE_DEFAULTS',
  $sshd_config_permitemptypasswords       = undef,
  $sshd_config_permituserenvironment      = undef,
  $sshd_config_compression                = undef,
  $sshd_config_port                       = '22',
  $sshd_config_syslog_facility            = 'AUTH',
  $sshd_config_template                   = 'ssh/sshd_config.erb',
  $sshd_config_login_grace_time           = '120',
  $sshd_config_challenge_resp_auth        = 'yes',
  $sshd_config_print_motd                 = 'yes',
  $sshd_config_print_last_log             = undef,
  $sshd_config_use_dns                    = 'USE_DEFAULTS',
  $sshd_config_authkey_location           = undef,
  $sshd_config_strictmodes                = undef,
  $sshd_config_serverkeybits              = 'USE_DEFAULTS',
  $sshd_config_banner                     = 'none',
  $sshd_config_ciphers                    = undef,
  $sshd_config_kexalgorithms              = undef,
  $sshd_config_macs                       = undef,
  $sshd_config_allowgroups                = [],
  $sshd_config_allowusers                 = [],
  $sshd_config_denygroups                 = [],
  $sshd_config_denyusers                  = [],
  $sshd_config_maxauthtries               = undef,
  $sshd_config_maxstartups                = undef,
  $sshd_config_maxsessions                = undef,
  $sshd_config_chrootdirectory            = undef,
  $sshd_config_forcecommand               = undef,
  $sshd_config_match                      = undef,
  $sshd_authorized_keys_command           = undef,
  $sshd_authorized_keys_command_user      = undef,
  $sshd_banner_content                    = undef,
  $sshd_banner_owner                      = 'root',
  $sshd_banner_group                      = 'root',
  $sshd_banner_mode                       = '0644',
  $sshd_config_xauth_location             = 'USE_DEFAULTS',
  $sshd_config_subsystem_sftp             = 'USE_DEFAULTS',
  $sshd_kerberos_authentication           = undef,
  $sshd_password_authentication           = 'yes',
  $sshd_allow_tcp_forwarding              = 'yes',
  $sshd_x11_forwarding                    = 'yes',
  $sshd_x11_use_localhost                 = 'yes',
  $sshd_use_pam                           = 'USE_DEFAULTS',
  $sshd_client_alive_count_max            = '3',
  $sshd_client_alive_interval             = '0',
  $sshd_gssapiauthentication              = 'yes',
  $sshd_gssapikeyexchange                 = 'USE_DEFAULTS',
  $sshd_pamauthenticationviakbdint        = 'USE_DEFAULTS',
  $sshd_gssapicleanupcredentials          = 'USE_DEFAULTS',
  $sshd_acceptenv                         = 'USE_DEFAULTS',
  $sshd_config_hostkey                    = 'USE_DEFAULTS',
  $sshd_listen_address                    = undef,
  $sshd_hostbasedauthentication           = 'no',
  $sshd_pubkeyacceptedkeytypes            = undef,
  $sshd_pubkeyauthentication              = 'yes',
  $sshd_ignoreuserknownhosts              = 'no',
  $sshd_ignorerhosts                      = 'yes',
  $sshd_config_authenticationmethods      = undef,
  $sshd_config_tcp_keepalive              = undef,
  $sshd_config_use_privilege_separation   = undef,
  $sshd_config_permittunnel               = undef,
  $sshd_config_hostcertificate            = undef,
  $sshd_config_trustedusercakeys          = undef,
  $sshd_config_key_revocation_list        = undef,
  $sshd_config_authorized_principals_file = undef,
  $sshd_config_allowagentforwarding       = undef,
) {

  case $::osfamily {
    'RedHat': {
      $default_sshd_config_subsystem_sftp      = '/usr/libexec/openssh/sftp-server'
      $default_sshd_config_mode                = '0600'
      $default_sshd_config_use_dns             = 'yes'
      $default_sshd_config_xauth_location      = '/usr/bin/xauth'
      $default_sshd_use_pam                    = 'yes'
      $default_sshd_gssapikeyexchange          = undef
      $default_sshd_pamauthenticationviakbdint = undef
      $default_sshd_gssapicleanupcredentials   = 'yes'
      $default_sshd_acceptenv                  = true
      if versioncmp($::operatingsystemrelease, '7.4') < 0 {
        $default_sshd_config_serverkeybits = '1024'
      } else {
        $default_sshd_config_serverkeybits = undef
      }
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = 'any'
      $default_sshd_config_tcp_keepalive       = 'yes'
      $default_sshd_config_permittunnel        = 'no'
    }
    'Suse': {
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
      case $::operatingsystemrelease {
        '16.04': {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_dsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_xauth_location         = undef
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_acceptenv                     = true
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
          $default_sshd_config_xauth_location         = undef
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
          $default_sshd_acceptenv                  = true
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_sshd_addressfamily              = undef
          $default_sshd_config_serverkeybits       = undef
          $default_sshd_gssapicleanupcredentials   = undef
          $default_sshd_config_use_dns             = undef
          $default_sshd_config_xauth_location      = undef
          $default_sshd_config_permittunnel        = undef
          $default_sshd_config_tcp_keepalive       = undef
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_service_hasstatus               = true
        }
        /^7.*/: {
          $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
          $default_sshd_config_xauth_location      = '/usr/bin/xauth'
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                = '0600'
          $default_sshd_config_use_dns             = 'yes'
          $default_sshd_use_pam                    = 'yes'
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_sshd_gssapicleanupcredentials   = 'yes'
          $default_sshd_acceptenv                  = true
          $default_sshd_config_serverkeybits       = '1024'
          $default_sshd_addressfamily              = 'any'
          $default_sshd_config_tcp_keepalive       = 'yes'
          $default_sshd_config_permittunnel        = 'no'
        }
        /^8.*/: {
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
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily              = undef
      $default_sshd_config_tcp_keepalive       = undef
      $default_sshd_config_permittunnel        = undef
    }
    default: {
      fail("ssh supports osfamilies RedHat, Suse, Debian and Solaris. Detected osfamily is <${::osfamily}>.")
    }
  }

  if $sshd_config_subsystem_sftp == 'USE_DEFAULTS' {
    $sshd_config_subsystem_sftp_real = $default_sshd_config_subsystem_sftp
  } else {
    $sshd_config_subsystem_sftp_real = $sshd_config_subsystem_sftp
  }

  if $sshd_config_mode    == 'USE_DEFAULTS' {
    $sshd_config_mode_real = $default_sshd_config_mode
  } else {
    $sshd_config_mode_real = $sshd_config_mode
  }

  if $sshd_config_xauth_location == 'USE_DEFAULTS' {
    $sshd_config_xauth_location_real = $default_sshd_config_xauth_location
  } else {
    $sshd_config_xauth_location_real = $sshd_config_xauth_location
  }

  if $sshd_config_xauth_location_real != undef {
    validate_absolute_path($sshd_config_xauth_location_real)
  }

  if $sshd_config_use_dns == 'USE_DEFAULTS' {
    $sshd_config_use_dns_real = $default_sshd_config_use_dns
  } else {
    $sshd_config_use_dns_real = $sshd_config_use_dns
  }

  if $sshd_use_pam == 'USE_DEFAULTS' {
    $sshd_use_pam_real = $default_sshd_use_pam
  } else {
    $sshd_use_pam_real = $sshd_use_pam
  }

  if $sshd_config_serverkeybits == 'USE_DEFAULTS' {
    $sshd_config_serverkeybits_real = $default_sshd_config_serverkeybits
  } else {
    $sshd_config_serverkeybits_real = $sshd_config_serverkeybits
  }

  if $sshd_gssapikeyexchange == 'USE_DEFAULTS' {
    $sshd_gssapikeyexchange_real = $default_sshd_gssapikeyexchange
  } else {
    $sshd_gssapikeyexchange_real = $sshd_gssapikeyexchange
  }

  if $sshd_pamauthenticationviakbdint == 'USE_DEFAULTS' {
    $sshd_pamauthenticationviakbdint_real = $default_sshd_pamauthenticationviakbdint
  } else {
    $sshd_pamauthenticationviakbdint_real = $sshd_pamauthenticationviakbdint
  }

  if $sshd_gssapicleanupcredentials == 'USE_DEFAULTS' {
    $sshd_gssapicleanupcredentials_real = $default_sshd_gssapicleanupcredentials
  } else {
    $sshd_gssapicleanupcredentials_real = $sshd_gssapicleanupcredentials
  }

  if $sshd_acceptenv == 'USE_DEFAULTS' {
    $sshd_acceptenv_real = $default_sshd_acceptenv
  } else {
    case type3x($sshd_acceptenv) {
      'string': {
        validate_re($sshd_acceptenv, '^(true|false)$', "ssh::sshd_acceptenv may be either 'true' or 'false' and is set to <${sshd_acceptenv}>.")
        $sshd_acceptenv_real = str2bool($sshd_acceptenv)
      }
      'boolean': {
        $sshd_acceptenv_real = $sshd_acceptenv
      }
      default: {
        fail('ssh::sshd_acceptenv type must be true or false.')
      }
    }
  }

  if $sshd_config_hostkey == 'USE_DEFAULTS' {
    $sshd_config_hostkey_real = $default_sshd_config_hostkey
  } else {
    validate_array($sshd_config_hostkey)
    validate_absolute_path($sshd_config_hostkey)
    $sshd_config_hostkey_real = $sshd_config_hostkey
  }

  if $sshd_listen_address {
    validate_array($sshd_listen_address)
  }

  if $sshd_addressfamily == 'USE_DEFAULTS' {
    $sshd_addressfamily_real = $default_sshd_addressfamily
  } else {
    $sshd_addressfamily_real = $sshd_addressfamily
  }

  case $sshd_config_maxsessions {
    'unset', undef: { $sshd_config_maxsessions_integer = undef }
    default:        { $sshd_config_maxsessions_integer = floor($sshd_config_maxsessions) }
  }

  case $sshd_config_tcp_keepalive {
    'unset': { $sshd_config_tcp_keepalive_real = undef }
    undef:   { $sshd_config_tcp_keepalive_real = $default_sshd_config_tcp_keepalive }
    default: { $sshd_config_tcp_keepalive_real = $sshd_config_tcp_keepalive }
  }

  case $sshd_config_permittunnel {
    'unset': { $sshd_config_permittunnel_real = undef }
    undef:   { $sshd_config_permittunnel_real = $default_sshd_config_permittunnel }
    default: { $sshd_config_permittunnel_real = $sshd_config_permittunnel }
  }

  case $sshd_config_hostcertificate {
    'unset', undef: { $sshd_config_hostcertificate_real = undef }
    default: { $sshd_config_hostcertificate_real = $sshd_config_hostcertificate }
  }

  case $sshd_config_trustedusercakeys {
    'unset', undef: { $sshd_config_trustedusercakeys_real = undef }
    default: { $sshd_config_trustedusercakeys_real = $sshd_config_trustedusercakeys }
  }

  case $sshd_config_key_revocation_list {
    'unset', undef: { $sshd_config_key_revocation_list_real = undef }
    default: { $sshd_config_key_revocation_list_real = $sshd_config_key_revocation_list }
  }

  case $sshd_config_authorized_principals_file {
    'unset', undef: { $sshd_config_authorized_principals_file_real = undef }
    default: { $sshd_config_authorized_principals_file_real = $sshd_config_authorized_principals_file }
  }

  if $sshd_config_ciphers != undef {
    validate_array($sshd_config_ciphers)
  }

  if $sshd_config_kexalgorithms != undef {
    validate_array($sshd_config_kexalgorithms)
  }

  if $sshd_config_macs != undef {
    validate_array($sshd_config_macs)
  }

  if $sshd_config_permitemptypasswords != undef {
    validate_re($sshd_config_permitemptypasswords, '^(yes|no)$', "ssh::sshd_config_permitemptypasswords may be either 'yes' or 'no' and is set to <${sshd_config_permitemptypasswords}>.")
  }
  if $sshd_config_permituserenvironment != undef {
    validate_re($sshd_config_permituserenvironment, '^(yes|no)$', "ssh::sshd_config_permituserenvironment may be either 'yes' or 'no' and is set to <${sshd_config_permituserenvironment}>.")
  }
  if $sshd_config_compression != undef {
    validate_re($sshd_config_compression, '^(yes|no|delayed)$', "ssh::sshd_config_compression may be either 'yes', 'no' or 'delayed' and is set to <${sshd_config_compression}>.")
  }
  case type3x($sshd_config_port) {
    'string': {
      validate_re($sshd_config_port, '^\d+$', "ssh::sshd_config_port must be a valid number and is set to <${sshd_config_port}>.")
      $sshd_config_port_array = [ str2num($sshd_config_port) ]
    }
    'array': {
      $sshd_config_port_array = $sshd_config_port
    }
    'integer': {
      $sshd_config_port_array = [ $sshd_config_port ]
    }
    default: {
      fail('ssh:sshd_config_port must be a string, an integer or an array. ')
    }
  }
  validate_numeric($sshd_config_port_array, 65535, 1)
  if $sshd_kerberos_authentication != undef {
    validate_re($sshd_kerberos_authentication, '^(yes|no)$', "ssh::sshd_kerberos_authentication may be either 'yes' or 'no' and is set to <${sshd_kerberos_authentication}>.")
  }
  validate_re($sshd_password_authentication, '^(yes|no)$', "ssh::sshd_password_authentication may be either 'yes' or 'no' and is set to <${sshd_password_authentication}>.")
  validate_re($sshd_allow_tcp_forwarding, '^(yes|no)$', "ssh::sshd_allow_tcp_forwarding may be either 'yes' or 'no' and is set to <${sshd_allow_tcp_forwarding}>.")
  validate_re($sshd_x11_forwarding, '^(yes|no)$', "ssh::sshd_x11_forwarding may be either 'yes' or 'no' and is set to <${sshd_x11_forwarding}>.")
  validate_re($sshd_x11_use_localhost, '^(yes|no)$', "ssh::sshd_x11_use_localhost may be either 'yes' or 'no' and is set to <${sshd_x11_use_localhost}>.")
  if $sshd_config_print_last_log != undef {
    validate_re($sshd_config_print_last_log, '^(yes|no)$', "ssh::sshd_config_print_last_log may be either 'yes' or 'no' and is set to <${sshd_config_print_last_log}>.")
  }
  if $sshd_use_pam_real != undef {
    validate_re($sshd_use_pam_real, '^(yes|no)$', "ssh::sshd_use_pam may be either 'yes' or 'no' and is set to <${sshd_use_pam_real}>.")
  }
  if $sshd_config_serverkeybits_real != undef {
    if is_integer($sshd_config_serverkeybits_real) == false { fail("ssh::sshd_config_serverkeybits must be an integer and is set to <${sshd_config_serverkeybits}>.") }
  }

  if is_integer($sshd_client_alive_interval) == false { fail("ssh::sshd_client_alive_interval must be an integer and is set to <${sshd_client_alive_interval}>.") }
  if is_integer($sshd_client_alive_count_max) == false { fail("ssh::sshd_client_alive_count_max must be an integer and is set to <${sshd_client_alive_count_max}>.") }

  if $sshd_config_banner != 'none' {
    validate_absolute_path($sshd_config_banner)
  }
  if $sshd_banner_content != undef and $sshd_config_banner == 'none' {
    fail('ssh::sshd_config_banner must be set to be able to use sshd_banner_content.')
  }

  validate_re($sshd_gssapiauthentication, '^(yes|no)$', "ssh::sshd_gssapiauthentication may be either 'yes' or 'no' and is set to <${sshd_gssapiauthentication}>.")

  if $sshd_gssapikeyexchange_real != undef {
    validate_re($sshd_gssapikeyexchange_real, '^(yes|no)$', "ssh::sshd_gssapikeyexchange may be either 'yes' or 'no' and is set to <${sshd_gssapikeyexchange_real}>.")
  }

  if $sshd_pamauthenticationviakbdint_real != undef {
    validate_re($sshd_pamauthenticationviakbdint_real, '^(yes|no)$', "ssh::sshd_pamauthenticationviakbdint may be either 'yes' or 'no' and is set to <${sshd_pamauthenticationviakbdint_real}>.")
  }

  if $sshd_gssapicleanupcredentials_real != undef {
    validate_re($sshd_gssapicleanupcredentials_real, '^(yes|no)$', "ssh::sshd_gssapicleanupcredentials may be either 'yes' or 'no' and is set to <${sshd_gssapicleanupcredentials_real}>.")
  }

  if $sshd_config_authkey_location != undef {
    validate_string($sshd_config_authkey_location)
  }

  if $sshd_config_maxauthtries != undef {
    if is_integer($sshd_config_maxauthtries) == false {
      fail("ssh::sshd_config_maxauthtries must be a valid number and is set to <${sshd_config_maxauthtries}>.")
    }
  }

  if $sshd_config_maxstartups != undef {
    validate_re($sshd_config_maxstartups,'^((\d+)|(\d+?:\d+?:\d+)?)$',
      "ssh::sshd_config_maxstartups may be either an integer or three integers separated with colons, such as 10:30:100. Detected value is <${sshd_config_maxstartups}>.")
  }

  if $sshd_config_chrootdirectory != undef {
    validate_absolute_path($sshd_config_chrootdirectory)
  }

  if $sshd_config_forcecommand != undef {
    validate_string($sshd_config_forcecommand)
  }

  if $sshd_authorized_keys_command != undef {
    validate_absolute_path($sshd_authorized_keys_command)
  }

  if $sshd_authorized_keys_command_user != undef {
    validate_string($sshd_authorized_keys_command_user)
  }

  if $sshd_config_match != undef {
    validate_hash($sshd_config_match)
  }

  if $sshd_config_strictmodes != undef {
    validate_re($sshd_config_strictmodes, '^(yes|no)$', "ssh::sshd_config_strictmodes may be either 'yes' or 'no' and is set to <${sshd_config_strictmodes}>.")
  }

  validate_re($sshd_hostbasedauthentication, '^(yes|no)$', "ssh::sshd_hostbasedauthentication may be either 'yes' or 'no' and is set to <${sshd_hostbasedauthentication}>.")

  if $sshd_pubkeyacceptedkeytypes != undef {
    validate_array($sshd_pubkeyacceptedkeytypes)
  }

  if $sshd_config_authenticationmethods != undef {
    validate_array($sshd_config_authenticationmethods)
  }

  validate_re($sshd_pubkeyauthentication, '^(yes|no)$', "ssh::sshd_pubkeyauthentication may be either 'yes' or 'no' and is set to <${sshd_pubkeyauthentication}>.")

  validate_re($sshd_ignoreuserknownhosts, '^(yes|no)$', "ssh::sshd_ignoreuserknownhosts may be either 'yes' or 'no' and is set to <${sshd_ignoreuserknownhosts}>.")

  validate_re($sshd_ignorerhosts, '^(yes|no)$', "ssh::sshd_ignorerhosts may be either 'yes' or 'no' and is set to <${sshd_ignorerhosts}>.")

  case $permit_root_login {
    'no', 'yes', 'without-password', 'forced-commands-only': {
      # noop
    }
    default: {
      fail("ssh::permit_root_login may be either 'yes', 'without-password', 'forced-commands-only' or 'no' and is set to <${permit_root_login}>.")
    }
  }

  #sshd_config template
  validate_string($sshd_config_template)

  #loglevel
  $supported_loglevel_vals=['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE']
  validate_re($sshd_config_loglevel, $supported_loglevel_vals)

  #enable hiera merging for groups, users, and config_entries
  if $hiera_merge_real == true {
    $sshd_config_allowgroups_real = hiera_array('ssh::sshd_config_allowgroups',[])
    $sshd_config_allowusers_real  = hiera_array('ssh::sshd_config_allowusers',[])
    $sshd_config_denygroups_real  = hiera_array('ssh::sshd_config_denygroups',[])
    $sshd_config_denyusers_real   = hiera_array('ssh::sshd_config_denyusers',[])
  } else {
    $sshd_config_allowgroups_real = $sshd_config_allowgroups
    $sshd_config_allowusers_real  = $sshd_config_allowusers
    $sshd_config_denygroups_real  = $sshd_config_denygroups
    $sshd_config_denyusers_real   = $sshd_config_denyusers
  }

  if $sshd_config_denyusers_real != [] {
    validate_array($sshd_config_denyusers_real)
  }

  if $sshd_config_denygroups_real != [] {
    validate_array($sshd_config_denygroups_real)
  }

  if $sshd_config_allowusers_real != [] {
    validate_array($sshd_config_allowusers_real)
  }

  if $sshd_config_allowgroups_real != [] {
    validate_array($sshd_config_allowgroups_real)
  }


  if $sshd_config_tcp_keepalive_real != undef {
    validate_re($sshd_config_tcp_keepalive_real, '^(yes|no)$', "ssh::sshd_config_tcp_keepalive may be either 'yes', 'no' or 'unset' and is set to <${sshd_config_tcp_keepalive_real}>.")
  }

  if $sshd_config_use_privilege_separation != undef {
    validate_re($sshd_config_use_privilege_separation, '^(yes|no|sandbox)$', "ssh::sshd_config_use_privilege_separation may be either 'yes', 'no' or 'sandbox' and is set to <${sshd_config_use_privilege_separation}>.")
  }

  if $sshd_config_permittunnel_real != undef {
    validate_re($sshd_config_permittunnel_real, '^(yes|no|point-to-point|ethernet|unset)$', "ssh::sshd_config_permittunnel may be either 'yes', 'point-to-point', 'ethernet', 'no' or 'unset' and is set to <${sshd_config_permittunnel_real}>.")
  }

  if $sshd_config_hostcertificate_real != undef {
    if is_array($sshd_config_hostcertificate_real) {
      validate_array($sshd_config_hostcertificate_real)
    }
    validate_absolute_path($sshd_config_hostcertificate_real)
  }

  if $sshd_config_trustedusercakeys_real != undef {
    # TrustedUserCAKeys may be a path to the keys or 'none'
    if $sshd_config_trustedusercakeys_real != 'none' {
      validate_absolute_path($sshd_config_trustedusercakeys_real)
    }
  }
  if $sshd_config_key_revocation_list_real != undef {
    # RevokedKeys may be a path to the key revocation list or 'none'
    if $sshd_config_key_revocation_list_real != 'none' {
      validate_absolute_path($sshd_config_key_revocation_list)
    }
  }

  if $sshd_config_authorized_principals_file_real != undef {
    validate_string($sshd_config_authorized_principals_file_real)
  }

  if $sshd_config_allowagentforwarding != undef {
    validate_re($sshd_config_allowagentforwarding, '^(yes|no)$', "ssh::sshd_config_allowagentforwarding may be either 'yes' or 'no' and is set to <${sshd_config_allowagentforwarding}>.")
  }

  if $sshd_addressfamily_real != undef {
    if $::osfamily == 'Solaris' {
      fail("ssh::sshd_addressfamily is not supported on Solaris and is set to <${sshd_addressfamily}>.")
    } else {
      validate_re($sshd_addressfamily_real, '^(any|inet|inet6)$',
        "ssh::sshd_addressfamily can be undef, 'any', 'inet' or 'inet6' and is set to ${sshd_addressfamily_real}.")
    }
  }

  file  { $title:
  ensure  => file,
    path    => $sshd_config_path,
    mode    => $sshd_config_mode_real,
    owner   => $sshd_config_owner,
    group   => $sshd_config_group,
    content => template($sshd_config_template),
  }

  if $sshd_config_banner != 'none' and $sshd_banner_content != undef {
    file { 'sshd_banner' :
      ensure  => file,
      path    => $sshd_config_banner,
      owner   => $sshd_banner_owner,
      group   => $sshd_banner_group,
      mode    => $sshd_banner_mode,
      content => $sshd_banner_content,
      require => Package[$packages_real],
    }
  }
}