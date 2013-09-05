# puppet-module-ssh #

Manage ssh client and server.

The module uses exported resources to manage ssh keys and removes ssh keys that are not managed by puppet. This behavior is managed by the parameters ssh_key_ensure and purge_keys.

# Compatability #

This module has been tested to work on the following systems.

 * EL 5
 * EL 6

# Parameters #

packages
--------
Array of package names used for installation.

- *Default*: 'openssh-server', 'openssh-server', 'openssh-clients'

permit_root_login
-----------------
Allow root login. Valid values are 'yes', 'without-password', 'forced-commands-only', 'no'.

- *Default*: no

purge_keys
----------
Remove keys not managed by puppet.

- *Default*: 'true'

manage_firewall
---------------
Open firewall for SSH service.

- *Default*: false

ssh_config_path
---------------
Path to ssh_config.

- *Default*: '/etc/ssh/ssh_config'

ssh_config_owner
----------------
ssh_config's owner.

- *Default*: 'root'

ssh_config_group
----------------
ssh_config's group.

- *Default*: 'root'

ssh_config_mode
---------------
ssh_config's mode.

- *Default*: '0644'

ssh_config_forward_x11
----------------------
ForwardX11 option in ssh_config. Not set by default.

- *Default*: undef

ssh_config_forward_agent
------------------------
ForwardAgent option in ssh_config. Not set by default.

- *Default*: undef

ssh_config_server_alive_interval
--------------------------------
ServerAliveInterval option in ssh_config. Not set by default.

- *Default*: undef

sshd_config_path
----------------
Path to sshd_config.

- *Default*: '/etc/ssh/sshd_config

sshd_config_owner
-----------------
sshd_config's owner.

- *Default*: 'root'

sshd_config_group
----------------
sshd_config's group.

- *Default*: 'root'

sshd_config_mode
---------------
sshd_config's mode.

- *Default*: '0600'

sshd_config_syslog_facility
---------------------------
SyslogFacility option in sshd_config.

- *Default*: 'AUTH'

sshd_config_login_grace_time
----------------------------
LoginGraceTime option in sshd_config.

- *Default*: '120'

sshd_config_challenge_resp_auth
-------------------------------
ChallengeResponseAuthentication option in sshd_config.

- *Default*: 'no'

sshd_config_print_motd
----------------------
PrintMotd option in sshd_config.

- *Default*: 'yes'

sshd_config_use_dns
-------------------
UseDNS option in sshd_config.

- *Default*: 'yes'

sshd_config_banner
------------------
Banner option in sshd_config.

- *Default*: 'none'

sshd_config_xauth_location
--------------------------
XAuthLocation option in sshd_config.

- *Default*: '/usr/bin/xauth'

sshd_config_subsystem_sftp
--------------------------
Path to sftp file transfer subsystem in sshd_config.

- *Default*: '/usr/libexec/openssh/sftp-server'

service_ensure
--------------
Ensure SSH service is running. Valid values are 'stopped' and 'running'.

- *Default*: 'running'

service_name
------------
Name of the SSH service.

- *Default*: 'sshd'

service_enable
--------------
Start SSH at boot. Valid values are 'true', 'false' and 'manual'.

- *Default*: 'true'

service_hasrestart
------------------
Specify that the init script has a restart command. Valid values are 'true' and 'false'.

- *Default*: 'true'

service_hasstatus
-----------------
Declare whether the service's init script has a functional status command. Valid values are 'true' and 'false'

- *Default*: 'true'

ssh_key_ensure
--------------
Export node SSH key. Valid values are 'present' and 'absent'.

- *Default*: 'present'

ssh_key_type
------------
Encryption type for SSH key. Valid values are 'rsa', 'dsa', 'ssh-dss' and 'ssh-rsa'

- *Default*: 'ssh-rsa'

manage_root_ssh_config
----------------------
Manage SSH config of root. Valid values are 'true' and 'false'.

- *Default*: 'false'

root_ssh_config_content
-----------------------
Content of root's ~/.ssh/config.

- *Default*: "# This file is being maintained by Puppet.\n# DO NOT EDIT\n"
