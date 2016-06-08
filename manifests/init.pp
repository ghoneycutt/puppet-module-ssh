# == Class: ssh
#
# Manage ssh client and server
#
class ssh (
  $hiera_merge                         = false,
  $packages                            = 'USE_DEFAULTS',
  $permit_root_login                   = 'yes',
  $purge_keys                          = true,
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
  $ssh_hostbasedauthentication         = undef,
  $ssh_strict_host_key_checking        = undef,
  $ssh_config_ciphers                  = undef,
  $ssh_config_macs                     = undef,
  $ssh_config_use_roaming              = 'USE_DEFAULTS',
  $ssh_config_template                 = 'ssh/ssh_config.erb',
  $ssh_sendenv                         = 'USE_DEFAULTS',
  $ssh_gssapiauthentication            = 'yes',
  $ssh_gssapidelegatecredentials       = undef,
  $sshd_config_path                    = '/etc/ssh/sshd_config',
  $sshd_config_owner                   = 'root',
  $sshd_config_group                   = 'root',
  $sshd_config_loglevel                = 'INFO',
  $sshd_config_mode                    = 'USE_DEFAULTS',
  $sshd_config_permitemptypasswords    = undef,
  $sshd_config_permituserenvironment   = undef,
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
  $ssh_enable_ssh_keysign              = undef,
  $sshd_config_allowgroups             = [],
  $sshd_config_allowusers              = [],
  $sshd_config_denygroups              = [],
  $sshd_config_denyusers               = [],
  $sshd_config_maxauthtries            = undef,
  $sshd_config_maxstartups             = undef,
  $sshd_config_maxsessions             = undef,
  $sshd_config_chrootdirectory         = undef,
  $sshd_config_forcecommand            = undef,
  $sshd_config_match                   = undef,
  $sshd_authorized_keys_command        = undef,
  $sshd_authorized_keys_command_user   = undef,
  $sshd_banner_content                 = undef,
  $sshd_banner_owner                   = 'root',
  $sshd_banner_group                   = 'root',
  $sshd_banner_mode                    = '0644',
  $sshd_config_xauth_location          = 'USE_DEFAULTS',
  $sshd_config_subsystem_sftp          = 'USE_DEFAULTS',
  $sshd_kerberos_authentication        = undef,
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
  $sshd_hostbasedauthentication        = 'no',
  $sshd_pubkeyauthentication           = 'yes',
  $sshd_ignoreuserknownhosts           = 'no',
  $sshd_ignorerhosts                   = 'yes',
  $manage_service                      = true,
  $sshd_addressfamily                  = 'USE_DEFAULTS',
  $service_ensure                      = 'running',
  $service_name                        = 'USE_DEFAULTS',
  $service_enable                      = true,
  $service_hasrestart                  = true,
  $service_hasstatus                   = 'USE_DEFAULTS',
  $ssh_key_ensure                      = 'present',
  $ssh_key_import                      = true,
  $ssh_key_type                        = 'ssh-rsa',
  $ssh_config_global_known_hosts_file  = '/etc/ssh/ssh_known_hosts',
  $ssh_config_global_known_hosts_list  = undef,
  $ssh_config_global_known_hosts_owner = 'root',
  $ssh_config_global_known_hosts_group = 'root',
  $ssh_config_global_known_hosts_mode  = '0644',
  $ssh_config_user_known_hosts_file    = undef,
  $keys                                = undef,
  $manage_root_ssh_config              = false,
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
      $default_sshd_addressfamily              = 'any'
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
      $default_sshd_addressfamily              = 'any'
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
      $default_sshd_addressfamily              = 'any'
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

  if $sshd_config_xauth_location_real != undef {
    validate_absolute_path($sshd_config_xauth_location_real)
  }

  if $ssh_package_source == 'USE_DEFAULTS' {
    $ssh_package_source_real = $default_ssh_package_source
  } else {
    $ssh_package_source_real = $ssh_package_source
  }

  if $ssh_package_source_real != undef {
    validate_absolute_path($ssh_package_source_real)
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

  if $ssh_config_use_roaming == 'USE_DEFAULTS' {
    $ssh_config_use_roaming_real = $default_ssh_config_use_roaming
  } else {
    $ssh_config_use_roaming_real = $ssh_config_use_roaming
  }

  if $ssh_sendenv == 'USE_DEFAULTS' {
    $ssh_sendenv_real = $default_ssh_sendenv
  } else {
    case type3x($ssh_sendenv) {
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
    validate_absolute_path(join($sshd_config_hostkey))
    $sshd_config_hostkey_real = $sshd_config_hostkey
  }

  if $sshd_listen_address {
    validate_array($sshd_listen_address)
  }

  if $service_hasstatus == 'USE_DEFAULTS' {
    $service_hasstatus_real = $default_service_hasstatus
  } else {
    case type3x($service_hasstatus) {
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

  if $sshd_addressfamily == 'USE_DEFAULTS' {
    $sshd_addressfamily_real = $default_sshd_addressfamily
  } else {
    $sshd_addressfamily_real = $sshd_addressfamily
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
  if $sshd_config_permitemptypasswords != undef {
    validate_re($sshd_config_permitemptypasswords, '^(yes|no)$', "ssh::sshd_config_permitemptypasswords may be either 'yes' or 'no' and is set to <${sshd_config_permitemptypasswords}>.")
  }
  if $sshd_config_permituserenvironment != undef {
    validate_re($sshd_config_permituserenvironment, '^(yes|no)$', "ssh::sshd_config_permituserenvironment may be either 'yes' or 'no' and is set to <${sshd_config_permituserenvironment}>.")
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
  if $sshd_use_pam_real != undef {
    validate_re($sshd_use_pam_real, '^(yes|no)$', "ssh::sshd_use_pam may be either 'yes' or 'no' and is set to <${sshd_use_pam_real}>.")
  }
  if $sshd_config_serverkeybits_real != undef {
    if is_integer($sshd_config_serverkeybits_real) == false { fail("ssh::sshd_config_serverkeybits must be an integer and is set to <${sshd_config_serverkeybits}>.") }
  }
  if $ssh_config_use_roaming_real != undef {
    validate_re($ssh_config_use_roaming_real, '^(yes|no|unset)$', "ssh::ssh_config_use_roaming may be either 'yes', 'no' or 'unset' and is set to <${$ssh_config_use_roaming}>.")
  }
  if is_integer($sshd_client_alive_interval) == false { fail("ssh::sshd_client_alive_interval must be an integer and is set to <${sshd_client_alive_interval}>.") }
  if is_integer($sshd_client_alive_count_max) == false { fail("ssh::sshd_client_alive_count_max must be an integer and is set to <${sshd_client_alive_count_max}>.") }

  if $sshd_config_banner != 'none' {
    validate_absolute_path($sshd_config_banner)
  }
  if $sshd_banner_content != undef and $sshd_config_banner == 'none' {
    fail('ssh::sshd_config_banner must be set to be able to use sshd_banner_content.')
  }

  validate_re($ssh_gssapiauthentication, '^(yes|no)$', "ssh::ssh_gssapiauthentication may be either 'yes' or 'no' and is set to <${ssh_gssapiauthentication}>.")

  if $ssh_gssapidelegatecredentials != undef {
    validate_re($ssh_gssapidelegatecredentials, '^(yes|no)$', "ssh::ssh_gssapidelegatecredentials may be either 'yes' or 'no' and is set to <${ssh_gssapidelegatecredentials}>.")
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

  if $ssh_strict_host_key_checking != undef {
    validate_re($ssh_strict_host_key_checking, '^(yes|no|ask)$', "ssh::ssh_strict_host_key_checking may be 'yes', 'no' or 'ask' and is set to <${ssh_strict_host_key_checking}>.")
  }

  if $ssh_enable_ssh_keysign != undef {
    validate_re($ssh_enable_ssh_keysign, '^(yes|no)$', "ssh::ssh_enable_ssh_keysign may be either 'yes' or 'no' and is set to <${ssh_enable_ssh_keysign}>.")
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
    validate_re($sshd_config_maxstartups,'^(\d+)+(\d+?:\d+?:\d+)?$',
      "ssh::sshd_config_maxstartups may be either an integer or three integers separated with colons, such as 10:30:100. Detected value is <${sshd_config_maxstartups}>.")
  }

  if $sshd_config_maxsessions != undef {
    $is_int_sshd_config_maxsessions = is_integer($sshd_config_maxsessions)
    if $is_int_sshd_config_maxsessions == false {
      fail("sshd_config_maxsessions must be an integer. Detected value is ${sshd_config_maxsessions}.")
    }
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
  if $ssh_hostbasedauthentication != undef {
    validate_re($ssh_hostbasedauthentication, '^(yes|no)$', "ssh::ssh_hostbasedauthentication may be either 'yes' or 'no' and is set to <${ssh_hostbasedauthentication}>.")
  }

  validate_re($sshd_hostbasedauthentication, '^(yes|no)$', "ssh::sshd_hostbasedauthentication may be either 'yes' or 'no' and is set to <${sshd_hostbasedauthentication}>.")

  validate_re($sshd_pubkeyauthentication, '^(yes|no)$', "ssh::sshd_pubkeyauthentication may be either 'yes' or 'no' and is set to <${sshd_pubkeyauthentication}>.")

  validate_re($sshd_ignoreuserknownhosts, '^(yes|no)$', "ssh::sshd_ignoreuserknownhosts may be either 'yes' or 'no' and is set to <${sshd_ignoreuserknownhosts}>.")

  validate_re($sshd_ignorerhosts, '^(yes|no)$', "ssh::sshd_ignorerhosts may be either 'yes' or 'no' and is set to <${sshd_ignorerhosts}>.")

  case type3x($hiera_merge) {
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

  case type3x($ssh_key_import) {
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
  validate_bool($ssh_key_import_real)

  case type3x($ssh_config_sendenv_xmodifiers) {
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
    'ecdsa-sha2-nistp256': {
          $key = $::sshecdsakey
    }
    default: {
      fail("ssh::ssh_key_type must be 'ecdsa-sha2-nistp256', 'ssh-rsa', 'rsa', 'ssh-dsa', or 'dsa' and is <${ssh_key_type}>.")
    }
  }

  validate_absolute_path($ssh_config_global_known_hosts_file)
  $ssh_config_global_known_hosts_file_real = any2array($ssh_config_global_known_hosts_file)

  if $ssh_config_global_known_hosts_list != undef {
    validate_array($ssh_config_global_known_hosts_list)
    validate_absolute_path($ssh_config_global_known_hosts_list)
    $ssh_config_global_known_hosts_list_real = concat($ssh_config_global_known_hosts_file_real, $ssh_config_global_known_hosts_list)
  } else {
    $ssh_config_global_known_hosts_list_real = $ssh_config_global_known_hosts_file_real
  }

  if $ssh_config_user_known_hosts_file != undef {
    validate_array($ssh_config_user_known_hosts_file)
  }

  validate_string($ssh_config_global_known_hosts_owner)
  validate_string($ssh_config_global_known_hosts_group)
  validate_re($ssh_config_global_known_hosts_mode, '^[0-7]{4}$',
    "ssh::ssh_config_global_known_hosts_mode must be a valid 4 digit mode in octal notation. Detected value is <${ssh_config_global_known_hosts_mode}>.")

  if type3x($purge_keys) == 'string' {
    $purge_keys_real = str2bool($purge_keys)
  } else {
    $purge_keys_real = $purge_keys
  }
  validate_bool($purge_keys_real)

  if type3x($manage_service) == 'string' {
    $manage_service_real = str2bool($manage_service)
  } else {
    $manage_service_real = $manage_service
  }
  validate_bool($manage_service_real)

  if type3x($service_enable) == 'string' {
    $service_enable_real = str2bool($service_enable)
  } else {
    $service_enable_real = $service_enable
  }
  validate_bool($service_enable_real)

  if type3x($service_hasrestart) == 'string' {
    $service_hasrestart_real = str2bool($service_hasrestart)
  } else {
    $service_hasrestart_real = $service_hasrestart
  }
  validate_bool($service_hasrestart_real)

  if type3x($manage_root_ssh_config) == 'string' {
    $manage_root_ssh_config_real = str2bool($manage_root_ssh_config)
  } else {
    $manage_root_ssh_config_real = $manage_root_ssh_config
  }
  validate_bool($manage_root_ssh_config_real)

  #ssh_config template
  validate_string($ssh_config_template)

  #sshd_config template
  validate_string($sshd_config_template)

  #loglevel
  $supported_loglevel_vals=['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE']
  validate_re($sshd_config_loglevel, $supported_loglevel_vals)

  #enable hiera merging for groups and users
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

  if $manage_root_ssh_config_real == true {

    include ::common

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

  if $manage_service_real {
    service { 'sshd_service' :
      ensure     => $service_ensure,
      name       => $service_name_real,
      enable     => $service_enable_real,
      hasrestart => $service_hasrestart_real,
      hasstatus  => $service_hasstatus_real,
      subscribe  => File['sshd_config'],
    }
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
    ensure       => $ssh_key_ensure,
    host_aliases => [$::hostname, $::ipaddress],
    type         => $ssh_key_type,
    key          => $key,
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
    purge => $purge_keys_real,
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

  if $sshd_addressfamily_real != undef {
    if $::osfamily == 'Solaris' {
      fail("ssh::sshd_addressfamily is not supported on Solaris and is set to <${sshd_addressfamily}>.")
    } else {
      validate_re($sshd_addressfamily_real, '^(any|inet|inet6)$',
        "ssh::sshd_addressfamily can be undef, 'any', 'inet' or 'inet6' and is set to ${sshd_addressfamily_real}.")
    }
  }
}
