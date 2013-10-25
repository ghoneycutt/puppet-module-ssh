# == Class: ssh
#
# Manage ssh client and server
#
class ssh (
  $packages                         = 'USE_DEFAULTS',
  $permit_root_login                = 'no',
  $purge_keys                       = 'true',
  $manage_firewall                  = false,
  $ssh_config_path                  = '/etc/ssh/ssh_config',
  $ssh_config_owner                 = 'root',
  $ssh_config_group                 = 'root',
  $ssh_config_mode                  = '0644',
  $ssh_config_forward_x11           = undef,
  $ssh_config_forward_agent         = undef,
  $ssh_config_server_alive_interval = undef,
  $sshd_config_path                 = '/etc/ssh/sshd_config',
  $sshd_config_owner                = 'root',
  $sshd_config_group                = 'root',
  $sshd_config_mode                 = '0600',
  $sshd_config_syslog_facility      = 'AUTH',
  $sshd_config_login_grace_time     = '120',
  $sshd_config_challenge_resp_auth  = 'no',
  $sshd_config_print_motd           = 'yes',
  $sshd_config_use_dns              = 'yes',
  $sshd_config_banner               = 'none',
  $sshd_config_xauth_location       = '/usr/bin/xauth',
  $sshd_config_subsystem_sftp       = 'USE_DEFAULTS',
  $service_ensure                   = 'running',
  $service_name                     = 'USE_DEFAULTS',
  $service_enable                   = 'true',
  $service_hasrestart               = 'true',
  $service_hasstatus                = 'true',
  $ssh_key_ensure                   = 'present',
  $ssh_key_type                     = 'ssh-rsa',
  $keys                             = undef,
  $manage_root_ssh_config           = 'false',
  $root_ssh_config_content          = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
) {

  # <validating variables>
#  validate_re($manage_firewall, '^(true|false)$', "manage_firewall may be either 'true' or 'false' and is set to '${manage_firewall}'")
  validate_re($manage_root_ssh_config, '^(true|false)$', "manage_root_ssh_config may be either 'true' or 'false' and is set to '${manage_root_ssh_config}'")
  validate_re($permit_root_login, '^(yes|no|without-password|forced-commands-only)$', "permit_root_login may be either 'yes', 'no' 'without-password' and 'forced-commands-only' and is set to '${permit_root_login}'")
  validate_re($purge_keys, '^(true|false)$', "purge_keys may be either 'true' or 'false' and is set to '${purge_keys}'")
  validate_re($service_enable, '^(true|false)$', "service_enable may be either 'true' or 'false' and is set to '${service_enable}'")
  validate_re($service_ensure, '^(running|stopped)$', "service_ensure may be either 'running' or 'stopped' and is set to '${service_ensure}'")
  validate_re($service_hasrestart, '^(true|false)$', "service_hasrestart may be either 'true' or 'false' and is set to '${service_hasrestart}'")
  validate_re($service_hasstatus, '^(true|false)$', "service_hasstatus may be either 'true' or 'false' and is set to '${service_hasstatus}'")
  validate_absolute_path($ssh_config_path)
  validate_re($sshd_allow_tcp_forwarding, '^(yes|no)$', "sshd_allow_tcp_forwarding may be either 'yes' or 'no' and is set to '${sshd_allow_tcp_forwarding}'")
  validate_re($sshd_challenge_response_authentication, '^(yes|no)$', "sshd_challenge_response_authentication may be either 'yes' or 'no' and is set to '${sshd_challenge_response_authentication}'")
  if is_integer($sshd_client_alive_interval) == false { fail("sshd_client_alive_interval must be an integer and is set to '${sshd_client_alive_interval}'") }
  validate_absolute_path($sshd_config_path)
  if is_integer($sshd_login_grace_time) == false { fail("sshd_login_grace_time must be an integer and is set to '${sshd_login_grace_time}'") }
  validate_re($sshd_password_authentication, '^(yes|no)$', "sshd_password_authentication may be either 'yes' or 'no' and is set to '${sshd_password_authentication}'")
  validate_re($sshd_print_motd, '^(yes|no)$', "sshd_print_motd may be either 'yes' or 'no' and is set to '${sshd_print_motd}'")
  if is_integer($sshd_server_key_bits) == false { fail("sshd_server_key_bits must be an integer and is set to '${sshd_server_key_bits}'") }
  if $sshd_server_key_bits < '512' { fail("sshd_server_key_bits needs a minimum value of 512 and is set to '${sshd_server_key_bits}'") }
  validate_re($sshd_syslog_facility, '^(DAEMON|USER|AUTH|LOCAL[0-7])$', "sshd_syslog_facility may be either 'DAEMIN', 'USER', 'AUTH' or 'LOCAL[0-7]' and is set to '${sshd_syslog_facility}'")
  validate_re($sshd_use_dns, '^(yes|no)$', "sshd_use_dns may be either 'yes' or 'no' and is set to '${sshd_use_dns}'")
  validate_re($sshd_use_pam, '^(yes|no)$', "sshd_use_pam may be either 'yes' or 'no' and is set to '${sshd_use_pam}'")
  validate_re($sshd_x11_forwarding, '^(yes|no)$', "sshd_x11_forwarding may be either 'yes' or 'no' and is set to '${sshd_x11_forwarding}'")
  validate_absolute_path($sshd_x_auth_location)
  if empty($ssh_forward_agent) == false { validate_re($ssh_forward_agent, '^(yes|no)$', "ssh_forward_agent may be either 'yes' or 'no' and is set to '${ssh_forward_agent}'") }
  if empty($ssh_forward_x11) == false { validate_re($ssh_forward_x11, '^(yes|no)$', "ssh_forward_x11 may be either 'yes' or 'no' and is set to '${ssh_forward_x11}'") }
  validate_re($ssh_key_ensure, '^(present|absent)$', "ssh_key_ensure may be either 'present' or 'absent' and is set to '${ssh_key_ensure}'")
  case $ssh_key_type {
    'ssh-rsa','rsa': {
      $key = $::sshrsakey
    }
    'ssh-dsa','dsa': {
      $key = $::sshdsakey
    }
    default: {
      fail("ssh_key_type must be 'ssh-rsa', 'rsa', 'ssh-dsa', or 'dsa' and is ${ssh_key_type}")
    }
  }
  if is_integer($ssh_server_alive_interval) == false { fail("ssh_server_alive_interval must be an integer and is set to '${ssh_server_alive_interval}'") }
  # </validating variables>

  case $::osfamily {
    'RedHat': {
      $default_packages                   = ['openssh-server',
                                              'openssh-clients']
      $default_sshd_config_subsystem_sftp = '/usr/libexec/openssh/sftp-server'
      $default_service_name               = 'sshd'
    }
    'Suse': {
      $default_packages     = 'openssh'
      $default_service_name = 'sshd'
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
      case $::operatingsystem {
        'Ubuntu': {
          $default_packages                   = [ 'openssh-server',
                                                  'openssh-client']
          $default_sshd_config_subsystem_sftp = '/usr/lib/openssh/sftp-server'
          $default_service_name               = 'ssh'
        }
        default: {
          fail("ssh supports Debian variant Ubuntu. Your osfamily is <${::osfamily}> and operatingsystem is <${::operatingsystem}>.")
        }
      }
    }
    default: {
      fail("ssh supports osfamilies RedHat, Suse and Debian. Detected osfamily is <${::osfamily}>.")
    }
  }

  if $packages == 'USE_DEFAULTS' {
    $packages_real = $default_packages
  } else {
    $packages_real = $packages
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

  package { 'ssh_packages':
    ensure => installed,
    name   => $packages_real,
  }

  file  { 'ssh_config' :
    ensure  => file,
    path    => $ssh_config_path,
    owner   => $ssh_config_owner,
    group   => $ssh_config_group,
    mode    => $ssh_config_mode,
    content => template('ssh/ssh_config.erb'),
    require => Package['ssh_packages'],
  }

  file  { 'sshd_config' :
    ensure  => file,
    path    => $sshd_config_path,
    mode    => $sshd_config_mode,
    owner   => $sshd_config_owner,
    group   => $sshd_config_group,
    content => template('ssh/sshd_config.erb'),
    require => Package['ssh_packages'],
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
      fail("manage_root_ssh_config is <${manage_root_ssh_config}> and must be \'true\' or \'false\'.")
    }
  }

  service { 'sshd_service' :
    ensure     => $service_ensure,
    name       => $service_name_real,
    enable     => $service_enable,
    hasrestart => $service_hasrestart,
    hasstatus  => $service_hasstatus,
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
    ensure  => $ssh_key_ensure,
    type    => $ssh_key_type,
    key     => $key,
    require => Package['ssh_packages'],
  }

  # import all nodes' ssh keys
  Sshkey <<||>>

  # remove ssh key's not managed by puppet
  resources  { 'sshkey':
    purge => $purge_keys,
  }

  # manage users' ssh authorized keys if present
  if $keys != undef {
    $keys_type = type($keys)
    if $keys_type == 'hash' {
      create_resources(ssh_authorized_key, $keys)
    }
  }
}
