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
  $keys                                   = undef,
  $manage_firewall                        = false,
  $manage_root_ssh_config                 = 'false',
  $packages                               = 'USE_DEFAULTS',
  $purge_keys                             = 'true',
  $root_ssh_config_content                = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
  $service_enable                         = 'true',
  $service_ensure                         = 'running',
  $service_hasrestart                     = 'true',
  $service_hasstatus                      = 'true',
  $service_name                           = 'sshd',
  $ssh_config_group                       = 'root',
  $ssh_config_mode                        = '0644',
  $ssh_config_owner                       = 'root',
  $ssh_config_path                        = '/etc/ssh/ssh_config',
  $sshd_allow_tcp_forwarding              = 'yes',
  $sshd_banner                            = 'none',
  $sshd_challenge_response_authentication = 'no',
  $sshd_client_alive_interval             = '0',
  $sshd_config_group                      = 'root',
  $sshd_config_mode                       = '0600',
  $sshd_config_owner                      = 'root',
  $sshd_config_path                       = '/etc/ssh/sshd_config',
  $sshd_login_grace_time                  = '120',
  $sshd_password_authentication           = 'yes',
  $sshd_permit_root_login                 = 'no',
  $sshd_print_motd                        = 'yes',
  $sshd_server_key_bits                   = '768',
  $sshd_subsystem_sftp                    = 'USE_DEFAULTS',
  $sshd_syslog_facility                   = 'AUTH',
  $sshd_use_dns                           = 'yes',
  $sshd_use_pam                           = 'yes',
  $sshd_x11_forwarding                    = 'yes',
  $sshd_x_auth_location                   = '/usr/bin/xauth',
  $ssh_forward_agent                      = undef,
  $ssh_forward_x11                        = undef,
  $ssh_key_ensure                         = 'present',
  $ssh_key_type                           = 'ssh-rsa',
  $ssh_server_alive_interval              = undef,
) {

  # <validating variables>
  validate_re($sshd_permit_root_login, '^(yes|no|without-password|forced-commands-only)$', "sshd_permit_root_login may be either 'yes', 'no' 'without-password' and 'forced-commands-only' and is set to '${sshd_permit_root_login}'")
  validate_re($purge_keys, '^(true|false)$', "purge_keys may be either 'true' or 'false' and is set to '${purge_keys}'")
  validate_re($sshd_allow_tcp_forwarding, '^(yes|no)$', "sshd_allow_tcp_forwarding may be either 'yes' or 'no' and is set to '${sshd_allow_tcp_forwarding}'")
  validate_re($sshd_password_authentication, '^(yes|no)$', "sshd_password_authentication may be either 'yes' or 'no' and is set to '${sshd_password_authentication}'")
  validate_re($sshd_use_pam, '^(yes|no)$', "sshd_use_pam may be either 'yes' or 'no' and is set to '${sshd_use_pam}'")
  validate_re($sshd_x11_forwarding, '^(yes|no)$', "sshd_x11_forwarding may be either 'yes' or 'no' and is set to '${sshd_x11_forwarding}'")

  if is_integer($sshd_server_key_bits) == false {
    fail("sshd_server_key_bits must be an integer and is set to '${sshd_server_key_bits}'")
  }
  if $sshd_server_key_bits < '512' {
    fail("sshd_server_key_bits needs a minimum value of 512 and is set to '${sshd_server_key_bits}'")
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
      $default_sshd_subsystem_sftp = '/usr/libexec/openssh/sftp-server'
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

  if $sshd_subsystem_sftp == 'USE_DEFAULTS' {
    $sshd_subsystem_sftp_real = $default_sshd_subsystem_sftp
  } else {
    $sshd_subsystem_sftp_real = $sshd_subsystem_sftp
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
