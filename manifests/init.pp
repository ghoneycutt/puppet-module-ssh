# == Class: ssh
#
# Manage ssh client and server
#
class ssh (
  $packages                         = 'USE_DEFAULTS',
  $permit_root_login                = 'yes',
  $purge_keys                       = 'true',
  $manage_firewall                  = false,
  $ssh_config_path                  = '/etc/ssh/ssh_config',
  $ssh_config_owner                 = 'root',
  $ssh_config_group                 = 'root',
  $ssh_config_mode                  = '0644',
  $ssh_config_forward_x11           = undef,
  $ssh_config_forward_agent         = undef,
  $ssh_config_server_alive_interval = undef,
  $ssh_config_sendenv_xmodifiers    = false,
  $sshd_config_path                 = '/etc/ssh/sshd_config',
  $sshd_config_owner                = 'root',
  $sshd_config_group                = 'root',
  $sshd_config_mode                 = '0600',
  $sshd_config_port                 = '22',
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
  $sshd_password_authentication     = 'yes',
  $sshd_allow_tcp_forwarding        = 'yes',
  $sshd_x11_forwarding              = 'yes',
  $sshd_use_pam                     = 'yes',
  $sshd_client_alive_interval       = '0',
) {

  # validate params
  validate_re($sshd_config_port, '^\d+$', "sshd_config_port must be a valid number and is set to <${sshd_config_port}>")
  validate_re($sshd_password_authentication, '^(yes|no)$', "sshd_password_authentication may be either 'yes' or 'no' and is set to <${sshd_password_authentication}>.")
  validate_re($sshd_allow_tcp_forwarding, '^(yes|no)$', "sshd_allow_tcp_forwarding may be either 'yes' or 'no' and is set to <${sshd_allow_tcp_forwarding}>.")
  validate_re($sshd_x11_forwarding, '^(yes|no)$', "sshd_x11_forwarding may be either 'yes' or 'no' and is set to <${sshd_x11_forwarding}>.")
  validate_re($sshd_use_pam, '^(yes|no)$', "sshd_use_pam may be either 'yes' or 'no' and is set to <${sshd_use_pam}>.")
  if is_integer($sshd_client_alive_interval) == false { fail("sshd_client_alive_interval must be an integer and is set to <${sshd_client_alive_interval}>.") }

  case type($ssh_config_sendenv_xmodifiers) {
    'string': {
      $ssh_config_sendenv_xmodifiers_real = str2bool($ssh_config_sendenv_xmodifiers)
    }
    'boolean': {
      $ssh_config_sendenv_xmodifiers_real = $ssh_config_sendenv_xmodifiers
    }
    default: {
      fail("ssh_config_sendenv_xmodifiers type must be true or false.")
    }
  }

  case $permit_root_login {
    'no', 'yes', 'without-password', 'forced-commands-only': {
      # noop
    }
    default: {
      fail("permit_root_login may be either 'yes', 'without-password', 'forced-commands-only' or 'no' and is set to <${permit_root_login}>")
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
      fail("ssh_key_type must be 'ssh-rsa', 'rsa', 'ssh-dsa', or 'dsa' and is <${ssh_key_type}>")
    }
  }

  case $purge_keys {
    'true','false': {
      # noop
    }
    default: {
      fail("purge_keys must be 'true' or 'false' and is <${purge_keys}>")
    }
  }

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
      $default_packages                   = [ 'openssh-server',
                                              'openssh-client']
      $default_sshd_config_subsystem_sftp = '/usr/lib/openssh/sftp-server'
      $default_service_name               = 'ssh'
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
