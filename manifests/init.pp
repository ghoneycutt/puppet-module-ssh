# == Class: ssh
#
# Manage ssh client and server
#
class ssh (
  $hiera_merge                         = false,
  $packages                            = 'USE_DEFAULTS',
  $permit_root_login                   = 'yes',
  $purge_keys                          = 'true',
  $manage_firewall                     = false,
  $ssh_package_source                  = 'USE_DEFAULTS',
  $ssh_package_adminfile               = 'USE_DEFAULTS',
  $ssh_config_hash_known_hosts         = 'USE_DEFAULTS',
  $ssh_config_path                     = '/etc/ssh/ssh_config',
  $ssh_config_owner                    = 'root',
  $ssh_config_group                    = 'root',
  $ssh_config_mode                     = '0644',
  $ssh_config_forward_x11              = undef,
  $ssh_config_forward_x11_trusted      = 'USE_DEFAULTS',
  $ssh_config_forward_agent            = undef,
  $ssh_config_server_alive_interval    = undef,
  $ssh_config_sendenv_xmodifiers       = false,
  $ssh_config_ciphers                  = undef,
  $ssh_config_macs                     = undef,
  $ssh_config_template                 = 'ssh/ssh_config.erb',
  $ssh_sendenv                         = 'USE_DEFAULTS',
  $ssh_gssapidelegatecredentials       = undef,
  $sshd_config_path                    = '/etc/ssh/sshd_config',
  $sshd_config_owner                   = 'root',
  $sshd_config_group                   = 'root',
  $sshd_config_loglevel                = 'INFO',
  $sshd_config_mode                    = 'USE_DEFAULTS',
  $sshd_config_port                    = '22',
  $sshd_config_syslog_facility         = 'AUTH',
  $sshd_config_template                = 'ssh/sshd_config.erb',
  $sshd_config_login_grace_time        = '120',
  $sshd_config_challenge_resp_auth     = 'yes',
  $sshd_config_print_motd              = 'yes',
  $sshd_config_use_dns                 = 'USE_DEFAULTS',
  $sshd_config_authkey_location        = undef,
  $sshd_config_strictmodes             = undef,
  $sshd_config_serverkeybits           = 'USE_DEFAULTS',
  $sshd_config_banner                  = 'none',
  $sshd_config_ciphers                 = undef,
  $sshd_config_macs                    = undef,
  $sshd_config_denyusers               = undef,
  $sshd_config_denygroups              = undef,
  $sshd_config_allowusers              = undef,
  $sshd_config_allowgroups             = undef,
  $sshd_config_maxstartups             = undef,
  $sshd_config_maxsessions             = undef,
  $sshd_banner_content                 = undef,
  $sshd_banner_owner                   = 'root',
  $sshd_banner_group                   = 'root',
  $sshd_banner_mode                    = '0644',
  $sshd_config_xauth_location          = 'USE_DEFAULTS',
  $sshd_config_subsystem_sftp          = 'USE_DEFAULTS',
  $sshd_password_authentication        = 'yes',
  $sshd_allow_tcp_forwarding           = 'yes',
  $sshd_x11_forwarding                 = 'yes',
  $sshd_use_pam                        = 'USE_DEFAULTS',
  $sshd_client_alive_count_max         = '3',
  $sshd_client_alive_interval          = '0',
  $sshd_gssapiauthentication           = 'yes',
  $sshd_gssapikeyexchange              = 'USE_DEFAULTS',
  $sshd_pamauthenticationviakbdint     = 'USE_DEFAULTS',
  $sshd_gssapicleanupcredentials       = 'USE_DEFAULTS',
  $sshd_acceptenv                      = 'USE_DEFAULTS',
  $sshd_config_hostkey                 = 'USE_DEFAULTS',
  $sshd_listen_address                 = undef,
  $service_ensure                      = 'running',
  $service_name                        = 'USE_DEFAULTS',
  $service_enable                      = 'true',
  $service_hasrestart                  = 'true',
  $service_hasstatus                   = 'USE_DEFAULTS',
  $ssh_key_ensure                      = 'present',
  $ssh_key_import                      = 'true',
  $ssh_key_type                        = 'ssh-rsa',
  $ssh_config_global_known_hosts_file  = '/etc/ssh/ssh_known_hosts',
  $ssh_config_global_known_hosts_owner = 'root',
  $ssh_config_global_known_hosts_group = 'root',
  $ssh_config_global_known_hosts_mode  = '0644',
  $keys                                = undef,
  $manage_root_ssh_config              = 'false',
  $root_ssh_config_content             = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
) {

  case $::osfamily {
    'RedHat': {
      $default_packages                        = ['openssh-server',
                                                  'openssh-clients']
      $default_service_name                    = 'sshd'
      $default_ssh_config_hash_known_hosts     = 'no'
      $default_ssh_config_forward_x11_trusted  = 'yes'
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
      $default_ssh_sendenv                     = true
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
      $default_sshd_config_serverkeybits       = '1024'
      $default_sshd_config_hostkey             = [ '/etc/ssh/ssh_host_rsa_key' ]
    }
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
      case $::architecture {
        'x86_64': {
          $default_sshd_config_subsystem_sftp = '/usr/lib64/ssh/sftp-server'
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
      $default_packages                        = ['openssh-server',
                                                  'openssh-client']
      $default_service_name                    = 'ssh'
      $default_ssh_config_forward_x11_trusted  = 'yes'
      $default_ssh_config_hash_known_hosts     = 'no'
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
      $default_ssh_sendenv                     = true
      $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
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
      fail("ssh supports osfamilies RedHat, Suse, Debian and Solaris. Detected osfamily is <${::osfamily}>.")
    }
  }

  if $packages == 'USE_DEFAULTS' {
    $packages_real = $default_packages
  } else {
    $packages_real = $packages
  }

  if $ssh_config_hash_known_hosts == 'USE_DEFAULTS' {
    $ssh_config_hash_known_hosts_real = $default_ssh_config_hash_known_hosts
  } else {
    $ssh_config_hash_known_hosts_real = $ssh_config_hash_known_hosts
  }

  if $service_name == 'USE_DEFAULTS' {
    $service_name_real = $default_service_name
  } else {
    $service_name_real = $service_name
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

  if $ssh_package_source == 'USE_DEFAULTS' {
    $ssh_package_source_real = $default_ssh_package_source
  } else {
    $ssh_package_source_real = $ssh_package_source
  }

  if $ssh_package_adminfile == 'USE_DEFAULTS' {
    $ssh_package_adminfile_real = $default_ssh_package_adminfile
  } else {
    $ssh_package_adminfile_real = $ssh_package_adminfile
  }

  if $ssh_package_adminfile_real != undef {
    validate_absolute_path($ssh_package_adminfile_real)
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

  if $ssh_config_forward_x11_trusted == 'USE_DEFAULTS' {
    $ssh_config_forward_x11_trusted_real = $default_ssh_config_forward_x11_trusted
  } else {
    $ssh_config_forward_x11_trusted_real = $ssh_config_forward_x11_trusted
  }
  if $ssh_config_forward_x11_trusted_real != undef {
    validate_re($ssh_config_forward_x11_trusted_real, '^(yes|no)$', "ssh::ssh_config_forward_x11_trusted may be either 'yes' or 'no' and is set to <${ssh_config_forward_x11_trusted_real}>.")
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

  if $ssh_sendenv == 'USE_DEFAULTS' {
    $ssh_sendenv_real = $default_ssh_sendenv
  } else {
    case type($ssh_sendenv) {
      'string': {
        validate_re($ssh_sendenv, '^(true|false)$', "ssh::ssh_sendenv may be either 'true' or 'false' and is set to <${ssh_sendenv}>.")
        $ssh_sendenv_real = str2bool($ssh_sendenv)
      }
      'boolean': {
        $ssh_sendenv_real = $ssh_sendenv
      }
      default: {
        fail('ssh::ssh_sendenv type must be true or false.')
      }
    }
  }

  if $sshd_acceptenv == 'USE_DEFAULTS' {
    $sshd_acceptenv_real = $default_sshd_acceptenv
  } else {
    case type($sshd_acceptenv) {
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
    validate_absolute_path(join($sshd_config_hostkey))
    $sshd_config_hostkey_real = $sshd_config_hostkey
  }

  if $sshd_listen_address {
    validate_array($sshd_listen_address)
  }

  if $service_hasstatus == 'USE_DEFAULTS' {
    $service_hasstatus_real = $default_service_hasstatus
  } else {
    case type($service_hasstatus) {
      'string': {
        validate_re($service_hasstatus, '^(true|false)$', "ssh::service_hasstatus must be 'true' or 'false' and is set to <${service_hasstatus}>.")
        $service_hasstatus_real = str2bool($service_hasstatus)
      }
      'boolean': {
        $service_hasstatus_real = $service_hasstatus
      }
      default: {
        fail('ssh::service_hasstatus must be true or false.')
      }
    }
  }

  # validate params
  if $ssh_config_ciphers != undef {
    validate_array($ssh_config_ciphers)
  }

  if $sshd_config_ciphers != undef {
    validate_array($sshd_config_ciphers)
  }

  if $ssh_config_macs != undef {
    validate_array($ssh_config_macs)
  }

  if $sshd_config_macs != undef {
    validate_array($sshd_config_macs)
  }

  if $ssh_config_hash_known_hosts_real != undef {
    validate_re($ssh_config_hash_known_hosts_real, '^(yes|no)$', "ssh::ssh_config_hash_known_hosts may be either 'yes' or 'no' and is set to <${ssh_config_hash_known_hosts_real}>.")
  }
  validate_re($sshd_config_port, '^\d+$', "ssh::sshd_config_port must be a valid number and is set to <${sshd_config_port}>.")
  validate_re($sshd_password_authentication, '^(yes|no)$', "ssh::sshd_password_authentication may be either 'yes' or 'no' and is set to <${sshd_password_authentication}>.")
  validate_re($sshd_allow_tcp_forwarding, '^(yes|no)$', "ssh::sshd_allow_tcp_forwarding may be either 'yes' or 'no' and is set to <${sshd_allow_tcp_forwarding}>.")
  validate_re($sshd_x11_forwarding, '^(yes|no)$', "ssh::sshd_x11_forwarding may be either 'yes' or 'no' and is set to <${sshd_x11_forwarding}>.")
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

  if $ssh_gssapidelegatecredentials != undef {
    validate_re($ssh_gssapidelegatecredentials, '^(yes|no)$', "ssh::ssh_gssapidelegatecredentials may be either 'yes' or 'no' and is set to <${ssh_gssapidelegatecredentials}>.")
  }

  if $sshd_gssapiauthentication != undef {
    validate_re($sshd_gssapiauthentication, '^(yes|no)$', "ssh::sshd_gssapiauthentication may be either 'yes' or 'no' and is set to <${sshd_gssapiauthentication}>.")
  }

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

  if $sshd_config_maxstartups != undef {
    validate_re($sshd_config_maxstartups,'^(\d+)+(\d+?:\d+?:\d+)?$',
      "ssh::sshd_config_maxstartups may be either an integer or three integers separated with colons, such as 10:30:100. Detected value is <${sshd_config_maxstartups}>.")
  }

  if $sshd_config_maxsessions != undef {
    $is_int_sshd_config_maxsessions = is_integer($sshd_config_maxsessions)
    if $is_int_sshd_config_maxsessions == false {
      fail("sshd_config_maxsessions must be an integer. Detected value is ${sshd_config_maxsessions}.")
    }
  }

  if $sshd_config_strictmodes != undef {
    validate_re($sshd_config_strictmodes, '^(yes|no)$', "ssh::sshd_config_strictmodes may be either 'yes' or 'no' and is set to <${sshd_config_strictmodes}>.")
  }

  case type($hiera_merge) {
    'string': {
      validate_re($hiera_merge, '^(true|false)$', "ssh::hiera_merge may be either 'true' or 'false' and is set to <${hiera_merge}>.")
      $hiera_merge_real = str2bool($hiera_merge)
    }
    'boolean': {
      $hiera_merge_real = $hiera_merge
    }
    default: {
      fail('ssh::hiera_merge type must be true or false.')
    }
  }

  case type($ssh_key_import) {
    'string': {
      validate_re($ssh_key_import, '^(true|false)$', "ssh::ssh_key_import may be either 'true' or 'false' and is set to <${ssh_key_import}>.")
      $ssh_key_import_real = str2bool($ssh_key_import)
    }
    'boolean': {
      $ssh_key_import_real = $ssh_key_import
    }
    default: {
      fail('ssh::ssh_key_import type must be true or false.')
    }
  }

  case type($ssh_config_sendenv_xmodifiers) {
    'string': {
      $ssh_config_sendenv_xmodifiers_real = str2bool($ssh_config_sendenv_xmodifiers)
    }
    'boolean': {
      $ssh_config_sendenv_xmodifiers_real = $ssh_config_sendenv_xmodifiers
    }
    default: {
      fail('ssh::ssh_config_sendenv_xmodifiers type must be true or false.')
    }
  }

  case $permit_root_login {
    'no', 'yes', 'without-password', 'forced-commands-only': {
      # noop
    }
    default: {
      fail("ssh::permit_root_login may be either 'yes', 'without-password', 'forced-commands-only' or 'no' and is set to <${permit_root_login}>.")
    }
  }

  case $ssh_key_type {
    'ssh-rsa','rsa': {
      $key = $::sshrsakey
    }
    'ssh-dsa','dsa': {
      $key = $::sshdsakey
    }
    default: {
      fail("ssh::ssh_key_type must be 'ssh-rsa', 'rsa', 'ssh-dsa', or 'dsa' and is <${ssh_key_type}>.")
    }
  }

  validate_absolute_path($ssh_config_global_known_hosts_file)
  validate_string($ssh_config_global_known_hosts_owner)
  validate_string($ssh_config_global_known_hosts_group)
  validate_re($ssh_config_global_known_hosts_mode, '^[0-7]{4}$',
    "ssh::ssh_config_global_known_hosts_mode must be a valid 4 digit mode in octal notation. Detected value is <${ssh_config_global_known_hosts_mode}>.")

  case $purge_keys {
    'true','false': {
      # noop
    }
    default: {
      fail("ssh::purge_keys must be 'true' or 'false' and is <${purge_keys}>.")
    }
  }

  #ssh_config template
  validate_string($ssh_config_template)

  #sshd_config template
  validate_string($sshd_config_template)

  #loglevel
  $supported_loglevel_vals=['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE']
  validate_re($sshd_config_loglevel, $supported_loglevel_vals)

  #enable hiera merging for allow groups and allow users
  if $hiera_merge_real == true {
    $sshd_config_denygroups_real  = hiera_array('ssh::sshd_config_denygroups',  undef)
    $sshd_config_denyusers_real   = hiera_array('ssh::sshd_config_denyusers',  undef)
    $sshd_config_allowgroups_real = hiera_array('ssh::sshd_config_allowgroups',  undef)
    $sshd_config_allowusers_real  = hiera_array('ssh::sshd_config_allowusers',  undef)
  } else {
    $sshd_config_denygroups_real  = $sshd_config_denygroups
    $sshd_config_denyusers_real   = $sshd_config_denyusers
    $sshd_config_allowgroups_real = $sshd_config_allowgroups
    $sshd_config_allowusers_real  = $sshd_config_allowusers
  }

  if $real_sshd_config_denyusers != undef {
    validate_array($real_sshd_config_denyusers)
  }

  if $real_sshd_config_denygroups != undef {
    validate_array($real_sshd_config_denygroups)
  }

  if $real_sshd_config_allowusers != undef {
    validate_array($real_sshd_config_allowusers)
  }

  if $real_sshd_config_allowgroups != undef {
    validate_array($real_sshd_config_allowgroups)
  }

  package { $packages_real:
    ensure    => installed,
    source    => $ssh_package_source_real,
    adminfile => $ssh_package_adminfile_real,
  }

  file  { 'ssh_config' :
    ensure  => file,
    path    => $ssh_config_path,
    owner   => $ssh_config_owner,
    group   => $ssh_config_group,
    mode    => $ssh_config_mode,
    content => template($ssh_config_template),
    require => Package[$packages_real],
  }

  file  { 'sshd_config' :
    ensure  => file,
    path    => $sshd_config_path,
    mode    => $sshd_config_mode_real,
    owner   => $sshd_config_owner,
    group   => $sshd_config_group,
    content => template($sshd_config_template),
    require => Package[$packages_real],
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

  case $manage_root_ssh_config {
    'true': {

      include common

      common::mkdir_p { "${::root_home}/.ssh": }

      file { 'root_ssh_dir':
        ensure  => directory,
        path    => "${::root_home}/.ssh",
        owner   => 'root',
        group   => 'root',
        mode    => '0700',
        require => Common::Mkdir_p["${::root_home}/.ssh"],
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
    'false': {
      # noop
    }
    default: {
      fail("ssh::manage_root_ssh_config is <${manage_root_ssh_config}> and must be \'true\' or \'false\'.")
    }
  }

  service { 'sshd_service' :
    ensure     => $service_ensure,
    name       => $service_name_real,
    enable     => $service_enable,
    hasrestart => $service_hasrestart,
    hasstatus  => $service_hasstatus_real,
    subscribe  => File['sshd_config'],
  }

  if $manage_firewall == true {
    firewall { '22 open port 22 for SSH':
      action => 'accept',
      dport  => 22,
      proto  => 'tcp',
    }
  }

  # export each node's ssh key
  @@sshkey { $::fqdn :
    ensure => $ssh_key_ensure,
    type   => $ssh_key_type,
    key    => $key,
  }

  file { 'ssh_known_hosts':
    ensure => file,
    path   => $ssh_config_global_known_hosts_file,
    owner  => $ssh_config_global_known_hosts_owner,
    group  => $ssh_config_global_known_hosts_group,
    mode   => $ssh_config_global_known_hosts_mode,
  }

  # import all nodes' ssh keys
  if $ssh_key_import_real == true {
    Sshkey <<||>> {
      target => $ssh_config_global_known_hosts_file,
    }
  }

  # remove ssh key's not managed by puppet
  resources  { 'sshkey':
    purge => $purge_keys,
  }

  # manage users' ssh authorized keys if present
  if $keys != undef {
    if $hiera_merge_real == true {
      $keys_real = hiera_hash('ssh::keys')
    } else {
      $keys_real = $keys
      notice('Future versions of the ssh module will default ssh::hiera_merge_real to true')
    }
    validate_hash($keys_real)
    create_resources('ssh_authorized_key', $keys_real)
  }
}
