#  ## Class: ssh ##
#
# Manage ssh client and server.
#
# ### Parameters ###
#
# packages
# --------
# Array of package names used for installation.
#
# - *Default*: 'openssh-server', 'openssh-server', 'openssh-clients'
#
# permit_root_login
# -----------------
# Allow root login. Valid values are 'yes', 'without-password', 'forced-commands-only', 'no'.
#
# - *Default*: no
#
# purge_keys
# ----------
# Remove keys not managed by puppet.
#
# - *Default*: 'true'
#
# manage_firewall
# ---------------
# Open firewall for SSH service.
#
# - *Default*: false
#
# ssh_config_path
# ---------------
# Path to ssh_config.
#
# - *Default*: '/etc/ssh/ssh_config'
#
# ssh_config_owner
# ----------------
# ssh_config's owner.
#
# - *Default*: 'root'
#
# ssh_config_group
# ----------------
# ssh_config's group.
#
# - *Default*: 'root'
#
# ssh_config_mode
# ---------------
# ssh_config's mode.
#
# - *Default*: '0644'
#
# sshd_config_path
# ----------------
# Path to sshd_config.
#
# - *Default*: '/etc/ssh/sshd_config
#
# sshd_config_owner
# -----------------
# sshd_config's owner.
#
# - *Default*: 'root'
#
# sshd_config_group
# ----------------
# sshd_config's group.
#
# - *Default*: 'root'
#
# sshd_config_mode
# ---------------
# sshd_config's mode.
#
# - *Default*: '0600'
#
# service_ensure
# --------------
# Ensure SSH service is running. Valid values are 'stopped' and 'running'.
#
# - *Default*: 'running'
#
# service_name
# ------------
# Name of the SSH service.
#
# - *Default*: 'sshd'
#
# service_enable
# --------------
# Start SSH at boot. Valid values are 'true', 'false' and 'manual'.
#
# - *Default*: 'true'
#
# service_hasrestart
# ------------------
# Specify that the init script has a restart command. Valid values are 'true' and 'false'.
#
# - *Default*: 'true'
#
# service_hasstatus
# -----------------
# Declare whether the service's init script has a functional status command. Valid values are 'true' and 'false'
#
# - *Default*: 'true'
#
# ssh_key_ensure
# --------------
# Export node SSH key. Valid values are 'present' and 'absent'.
#
# - *Default*: 'present'
#
# ssh_key_type
# ------------
# Encryption type for SSH key. Valid values are 'rsa', 'dsa', 'ssh-dss' and 'ssh-rsa'
#
# - *Default*: 'ssh-rsa'
#
# manage_root_ssh_config
# ----------------------
# Manage SSH config of root. Valid values are 'true' and 'false'.
#
# - *Default*: 'false'
#
# root_ssh_config_content
# -----------------------
# Content of root's ~/.ssh/config.
#
# - *Default*: "# This file is being maintained by Puppet.\n# DO NOT EDIT\n"
#
class ssh (
  $packages                         = ['openssh-server',
                                        'openssh-server',
                                        'openssh-clients'],
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
  $sshd_config_subsystem_sftp       = '/usr/libexec/openssh/sftp-server',
  $service_ensure                   = 'running',
  $service_name                     = 'sshd',
  $service_enable                   = 'true',
  $service_hasrestart               = 'true',
  $service_hasstatus                = 'true',
  $ssh_key_ensure                   = 'present',
  $ssh_key_type                     = 'ssh-rsa',
  $manage_root_ssh_config           = 'false',
  $root_ssh_config_content          = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
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
}
