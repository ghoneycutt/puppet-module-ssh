# == Class: ssh
#
# Manage ssh client and server
#
class ssh (
  $hiera_merge                            = false,
  $packages                               = 'USE_DEFAULTS',
  $permit_root_login                      = 'yes',
  $purge_keys                             = true,
  $manage_firewall                        = false,
  $ssh_package_source                     = 'USE_DEFAULTS',
  $ssh_package_adminfile                  = 'USE_DEFAULTS',
  $ssh_config_hash_known_hosts            = 'USE_DEFAULTS',
  $ssh_config_path                        = '/etc/ssh/ssh_config',
  $ssh_config_owner                       = 'root',
  $ssh_config_group                       = 'root',
  $ssh_config_mode                        = '0644',
  $ssh_config_forward_x11                 = undef,
  $ssh_config_forward_x11_trusted         = 'USE_DEFAULTS',
  $ssh_config_forward_agent               = undef,
  $ssh_config_server_alive_interval       = undef,
  $ssh_config_sendenv_xmodifiers          = false,
  $ssh_hostbasedauthentication            = undef,
  $ssh_config_proxy_command               = undef,
  $ssh_strict_host_key_checking           = undef,
  $ssh_config_ciphers                     = undef,
  $ssh_config_kexalgorithms               = undef,
  $ssh_config_macs                        = undef,
  $ssh_config_use_roaming                 = 'USE_DEFAULTS',
  $ssh_config_template                    = 'ssh/ssh_config.erb',
  $ssh_sendenv                            = 'USE_DEFAULTS',
  $ssh_gssapiauthentication               = 'yes',
  $ssh_gssapidelegatecredentials          = undef,
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
  $ssh_enable_ssh_keysign                 = undef,
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
  $manage_service                         = true,
  $sshd_addressfamily                     = 'USE_DEFAULTS',
  $service_ensure                         = 'running',
  $service_name                           = 'USE_DEFAULTS',
  $service_enable                         = true,
  $service_hasrestart                     = true,
  $service_hasstatus                      = 'USE_DEFAULTS',
  $ssh_key_ensure                         = 'present',
  $ssh_key_import                         = true,
  $ssh_key_type                           = 'ssh-rsa',
  $ssh_config_global_known_hosts_file     = '/etc/ssh/ssh_known_hosts',
  $ssh_config_global_known_hosts_list     = undef,
  $ssh_config_global_known_hosts_owner    = 'root',
  $ssh_config_global_known_hosts_group    = 'root',
  $ssh_config_global_known_hosts_mode     = '0644',
  $ssh_config_user_known_hosts_file       = undef,
  $config_entries                         = {},
  $keys                                   = undef,
  $manage_root_ssh_config                 = false,
  $root_ssh_config_content                = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
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
      $default_ssh_config_hash_known_hosts     = 'no'
      $default_ssh_config_forward_x11_trusted  = 'yes'
      $default_ssh_sendenv                     = true
    }
    'Suse': {
      $default_ssh_config_hash_known_hosts     = 'no'
      $default_ssh_sendenv                     = true
      $default_ssh_config_forward_x11_trusted  = 'yes'
    }
    'Debian': {
      # common for debian and ubuntu
      case $::operatingsystemrelease {
        '16.04': {
          $default_ssh_config_hash_known_hosts        = 'yes'
          $default_ssh_config_forward_x11_trusted     = 'yes'
          $default_ssh_sendenv                        = true
        }
        '18.04': {
          $default_ssh_config_hash_known_hosts        = 'yes'
          $default_ssh_config_forward_x11_trusted     = 'yes'
          $default_ssh_sendenv                        = true
        }
        /^9.*/: {
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_ssh_config_hash_known_hosts     = 'yes'
          $default_ssh_sendenv                     = true
        }
        /^7.*/: {
          $default_ssh_config_hash_known_hosts     = 'no'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_ssh_sendenv                     = true
        }
        /^8.*/: {

          $default_ssh_config_hash_known_hosts     = 'yes'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_ssh_sendenv                     = true
        }
        default: { fail ("Operating System : ${::operatingsystemrelease} not supported") }
      }
    }
    'Solaris': {
      $default_ssh_config_hash_known_hosts     = undef
      $default_ssh_sendenv                     = false
      $default_ssh_config_forward_x11_trusted  = undef
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

  case $ssh_config_hash_known_hosts {
    'unset':        { $ssh_config_hash_known_hosts_real = undef }
    'USE_DEFAULTS': { $ssh_config_hash_known_hosts_real = $default_ssh_config_hash_known_hosts }
    default:        { $ssh_config_hash_known_hosts_real = $ssh_config_hash_known_hosts }
  }

  if $ssh_config_forward_x11_trusted == 'USE_DEFAULTS' {
    $ssh_config_forward_x11_trusted_real = $default_ssh_config_forward_x11_trusted
  } else {
    $ssh_config_forward_x11_trusted_real = $ssh_config_forward_x11_trusted
  }
  if $ssh_config_forward_x11_trusted_real != undef {
    validate_re($ssh_config_forward_x11_trusted_real, '^(yes|no)$', "ssh::ssh_config_forward_x11_trusted may be either 'yes' or 'no' and is set to <${ssh_config_forward_x11_trusted_real}>.")
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

  # validate params
  if $ssh_config_ciphers != undef {
    validate_array($ssh_config_ciphers)
  }

  if $ssh_config_kexalgorithms != undef {
    validate_array($ssh_config_kexalgorithms)
  }

  if $ssh_config_macs != undef {
    validate_array($ssh_config_macs)
  }

  if $ssh_config_hash_known_hosts_real != undef {
    validate_re($ssh_config_hash_known_hosts_real, '^(yes|no)$', "ssh::ssh_config_hash_known_hosts may be either 'yes', 'no' or 'unset' and is set to <${ssh_config_hash_known_hosts_real}>.")
  }
  if $ssh_config_use_roaming_real != undef {
    validate_re($ssh_config_use_roaming_real, '^(yes|no|unset)$', "ssh::ssh_config_use_roaming may be either 'yes', 'no' or 'unset' and is set to <${$ssh_config_use_roaming}>.")
  }

  validate_re($ssh_gssapiauthentication, '^(yes|no)$', "ssh::ssh_gssapiauthentication may be either 'yes' or 'no' and is set to <${ssh_gssapiauthentication}>.")

  if $ssh_gssapidelegatecredentials != undef {
    validate_re($ssh_gssapidelegatecredentials, '^(yes|no)$', "ssh::ssh_gssapidelegatecredentials may be either 'yes' or 'no' and is set to <${ssh_gssapidelegatecredentials}>.")
  }

  if $ssh_strict_host_key_checking != undef {
    validate_re($ssh_strict_host_key_checking, '^(yes|no|ask)$', "ssh::ssh_strict_host_key_checking may be 'yes', 'no' or 'ask' and is set to <${ssh_strict_host_key_checking}>.")
  }

  if $ssh_config_proxy_command != undef {
    validate_string($ssh_config_proxy_command)
  }

  if $ssh_enable_ssh_keysign != undef {
    validate_re($ssh_enable_ssh_keysign, '^(yes|no)$', "ssh::ssh_enable_ssh_keysign may be either 'yes' or 'no' and is set to <${ssh_enable_ssh_keysign}>.")
  }

  if $ssh_hostbasedauthentication != undef {
    validate_re($ssh_hostbasedauthentication, '^(yes|no)$', "ssh::ssh_hostbasedauthentication may be either 'yes' or 'no' and is set to <${ssh_hostbasedauthentication}>.")
  }

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

  if type3x($manage_root_ssh_config) == 'string' {
    $manage_root_ssh_config_real = str2bool($manage_root_ssh_config)
  } else {
    $manage_root_ssh_config_real = $manage_root_ssh_config
  }
  validate_bool($manage_root_ssh_config_real)

  #ssh_config template
  validate_string($ssh_config_template)

  #enable hiera merging for groups, users, and config_entries
  if $hiera_merge_real == true {
    $config_entries_real          = hiera_hash('ssh::config_entries',{})
  } else {
    $config_entries_real          = $config_entries
  }
  validate_hash($config_entries_real)

  class{'ssh::package':
    packages              => $packages,
    ssh_package_source    => $ssh_package_source,
    ssh_package_adminfile => $ssh_package_adminfile,

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

  ssh::sshd_config{'sshd_config' :
    sshd_config_path                       => $sshd_config_path,
    sshd_config_owner                      => $sshd_config_owner,
    sshd_config_group                      => $sshd_config_group,
    sshd_config_loglevel                   => $sshd_config_loglevel,
    sshd_config_mode                       => $sshd_config_mode,
    sshd_config_permitemptypasswords       => $sshd_config_permitemptypasswords,
    sshd_config_permituserenvironment      => $sshd_config_permituserenvironment,
    sshd_config_compression                => $sshd_config_compression,
    sshd_config_port                       => $sshd_config_port,
    sshd_config_syslog_facility            => $sshd_config_syslog_facility,
    sshd_config_template                   => $sshd_config_template,
    sshd_config_login_grace_time           => $sshd_config_login_grace_time,
    sshd_config_challenge_resp_auth        => $sshd_config_challenge_resp_auth,
    sshd_config_print_motd                 => $sshd_config_print_motd,
    sshd_config_print_last_log             => $sshd_config_print_last_log,
    sshd_config_use_dns                    => $sshd_config_use_dns,
    sshd_config_authkey_location           => $sshd_config_authkey_location,
    sshd_config_strictmodes                => $sshd_config_strictmodes,
    sshd_config_serverkeybits              => $sshd_config_serverkeybits,
    sshd_config_banner                     => $sshd_config_banner,
    sshd_config_ciphers                    => $sshd_config_ciphers,
    sshd_config_kexalgorithms              => $sshd_config_kexalgorithms,
    sshd_config_macs                       => $sshd_config_macs,
    sshd_config_allowgroups                => $sshd_config_allowgroups,
    sshd_config_allowusers                 => $sshd_config_allowusers,
    sshd_config_denygroups                 => $sshd_config_denygroups,
    sshd_config_denyusers                  => $sshd_config_denyusers,
    sshd_config_maxauthtries               => $sshd_config_maxauthtries,
    sshd_config_maxstartups                => $sshd_config_maxstartups,
    sshd_config_maxsessions                => $sshd_config_maxsessions,
    sshd_config_chrootdirectory            => $sshd_config_chrootdirectory,
    sshd_config_forcecommand               => $sshd_config_forcecommand,
    sshd_config_match                      => $sshd_config_match,
    sshd_authorized_keys_command           => $sshd_authorized_keys_command,
    sshd_authorized_keys_command_user      => $sshd_authorized_keys_command_user,
    sshd_banner_content                    => $sshd_banner_content,
    sshd_banner_owner                      => $sshd_banner_owner,
    sshd_banner_group                      => $sshd_banner_group,
    sshd_banner_mode                       => $sshd_banner_mode,
    sshd_config_xauth_location             => $sshd_config_xauth_location,
    sshd_config_subsystem_sftp             => $sshd_config_subsystem_sftp,
    sshd_kerberos_authentication           => $sshd_kerberos_authentication,
    sshd_password_authentication           => $sshd_password_authentication,
    sshd_allow_tcp_forwarding              => $sshd_allow_tcp_forwarding,
    sshd_x11_forwarding                    => $sshd_x11_forwarding,
    sshd_x11_use_localhost                 => $sshd_x11_use_localhost,
    sshd_use_pam                           => $sshd_use_pam,
    sshd_client_alive_count_max            => $sshd_client_alive_count_max,
    sshd_client_alive_interval             => $sshd_client_alive_interval,
    sshd_gssapiauthentication              => $sshd_gssapiauthentication,
    sshd_gssapikeyexchange                 => $sshd_gssapikeyexchange,
    sshd_pamauthenticationviakbdint        => $sshd_pamauthenticationviakbdint,
    sshd_gssapicleanupcredentials          => $sshd_gssapicleanupcredentials,
    sshd_acceptenv                         => $sshd_acceptenv,
    sshd_config_hostkey                    => $sshd_config_hostkey,
    sshd_listen_address                    => $sshd_listen_address,
    sshd_hostbasedauthentication           => $sshd_hostbasedauthentication,
    sshd_pubkeyacceptedkeytypes            => $sshd_pubkeyacceptedkeytypes,
    sshd_pubkeyauthentication              => $sshd_pubkeyauthentication,
    sshd_ignoreuserknownhosts              => $sshd_ignoreuserknownhosts,
    sshd_ignorerhosts                      => $sshd_ignorerhosts,
    sshd_config_authenticationmethods      => $sshd_config_authenticationmethods,
    sshd_config_tcp_keepalive              => $sshd_config_tcp_keepalive,
    sshd_config_use_privilege_separation   => $sshd_config_use_privilege_separation,
    sshd_config_permittunnel               => $sshd_config_permittunnel,
    sshd_config_hostcertificate            => $sshd_config_hostcertificate,
    sshd_config_trustedusercakeys          => $sshd_config_trustedusercakeys,
    sshd_config_key_revocation_list        => $sshd_config_key_revocation_list,
    sshd_config_authorized_principals_file => $sshd_config_authorized_principals_file,
    sshd_config_allowagentforwarding       => $sshd_config_allowagentforwarding,
    require                                => Package[$packages_real],
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
    ssh::service { 'sshd_service':
      service_ensure     => $service_ensure,
      service_name       => $service_name,
      service_enable     => $service_enable,
      service_hasrestart => $service_hasrestart,
      service_hasstatus  => $service_hasstatus,
      service_subscribe  => File['sshd_config'],
      require            => Ssh::Sshd_config['sshd_config'],
    }
  }

  if $manage_firewall == true {
    firewall { '22 open port 22 for SSH':
      action => 'accept',
      dport  => 22,
      proto  => 'tcp',
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
  @@sshkey { $::fqdn :
    ensure       => $ssh_key_ensure,
    host_aliases => $host_aliases,
    type         => $ssh_key_type,
    key          => $key,
  }

  file { 'ssh_known_hosts':
    ensure  => file,
    path    => $ssh_config_global_known_hosts_file,
    owner   => $ssh_config_global_known_hosts_owner,
    group   => $ssh_config_global_known_hosts_group,
    mode    => $ssh_config_global_known_hosts_mode,
    require => Package[$packages_real],
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

  # manage users' ssh config entries if present
  create_resources('ssh::config_entry',$config_entries_real)

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
