# == Class: ssh
#
# Manage ssh client and server.
#
# Sample usage:
# # Push authorized key "root_for_userX" and remove key "root_for_userY" with hiera
#
# ssh::keys:
#   root_for_userX:
#     ensure: present
#     user: root
#     type: dsa
#     key: AAAA...==
#   root_for_userY:
#     ensure: absent
#     user: root
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
  $sshd_config_passwordauth         = 'yes',
  $sshd_config_allowtcpforwarding   = 'yes',
  $sshd_config_x11forwarding        = 'yes',
  $sshd_config_usepam               = 'yes',
  $sshd_config_clientaliveinterval  = '0',
  $sshd_config_serverkeybits        = '768',
  $service_ensure                   = 'running',
  $service_name                     = 'sshd',
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
  validate_re($permit_root_login, '^(yes|no|without-password|forced-commands-only)$', "permit_root_login may be either 'yes', 'no' 'without-password' and 'forced-commands-only' and is set to '${permit_root_login}'")
  validate_re($purge_keys, '^(true|false)$', "purge_keys may be either 'true' or 'false' and is set to '${purge_keys}'")
  validate_re($sshd_config_allowtcpforwarding, '^(yes|no)$', "sshd_config_allowtcpforwarding may be either 'yes' or 'no' and is set to '${sshd_config_allowtcpforwarding}'")
  validate_re($sshd_config_passwordauth, '^(yes|no)$', "sshd_config_passwordauth may be either 'yes' or 'no' and is set to '${sshd_config_passwordauth}'")
  validate_re($sshd_config_usepam, '^(yes|no)$', "sshd_config_usepam may be either 'yes' or 'no' and is set to '${sshd_config_usepam}'")
  validate_re($sshd_config_x11forwarding, '^(yes|no)$', "sshd_config_x11forwarding may be either 'yes' or 'no' and is set to '${sshd_config_x11forwarding}'")

  if is_integer($sshd_config_serverkeybits) == false {
    fail("sshd_config_serverkeybits must be an integer and is set to '${sshd_config_serverkeybits}'")
  }
  if $sshd_config_serverkeybits < '512' {
    fail("sshd_config_serverkeybits needs a minimum value of 512 and is set to '${sshd_config_serverkeybits}'")
  }

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
  # </validating variables>

  case $::osfamily {
    'RedHat': {
      $default_packages                   = ['openssh-server',
                                              'openssh-server',
                                              'openssh-clients']
      $default_sshd_config_subsystem_sftp = '/usr/libexec/openssh/sftp-server'
    }
    default: {
      fail("ssh supports osfamily RedHat. Detected osfamily is <${::osfamily}>.")
    }
  }

  if $packages == 'USE_DEFAULTS' {
    $packages_real = $default_packages
  } else {
    $packages_real = $packages
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
    name       => $service_name,
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
