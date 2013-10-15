# ## Class: ssh ##
#
# Manage ssh client and server.
#
class ssh (
  $packages                = ['openssh-server',
                              'openssh-server',
                              'openssh-clients'],
  $permit_root_login       = 'no',
  $purge_keys              = 'true',
  $manage_firewall         = false,
  $ssh_config_path         = '/etc/ssh/ssh_config',
  $ssh_config_owner        = 'root',
  $ssh_config_group        = 'root',
  $ssh_config_mode         = '0644',
  $sshd_config_path        = '/etc/ssh/sshd_config',
  $sshd_config_owner       = 'root',
  $sshd_config_group       = 'root',
  $sshd_config_mode        = '0600',
  $service_ensure          = 'running',
  $service_name            = 'sshd',
  $service_enable          = 'true',
  $service_hasrestart      = 'true',
  $service_hasstatus       = 'true',
  $ssh_key_ensure          = 'present',
  $ssh_key_type            = 'ssh-rsa',
  $manage_root_ssh_config  = 'false',
  $root_ssh_config_content = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
  $keys                    = undef,
) {

  case $permit_root_login {
    'no', 'yes', 'without-password', 'forced-commands-only': {
      # noop
    }
    default: {
      fail("permit_root_login may be either 'yes', 'without-password', 'forced-commands-only' or 'no' and is set to ${permit_root_login}")
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
      fail("ssh_key_type must be 'ssh-rsa', 'rsa', 'ssh-dsa', or 'dsa' and is ${ssh_key_type}")
    }
  }

  case $purge_keys {
    'true','false': {
      # noop
    }
    default: {
      fail("purge_keys must be 'true' or 'false' and is ${purge_keys}")
    }
  }

  package { 'ssh_packages':
    ensure => installed,
    name   => $packages,
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
