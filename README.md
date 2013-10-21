# puppet-module-ssh #

Manage ssh client and server.

The module uses exported resources to manage ssh keys and removes ssh keys that are not managed by puppet. This behavior is managed by the parameters ssh_key_ensure and purge_keys.

===

# Compatability #

This module has been tested to work on the following systems.

 * EL 5
 * EL 6

===

# Parameters #

keys
----
Hash of keys for user's ~/.ssh/authorized_keys

- *Default*: undefined

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

sshd_config_passwordauth
------------------------
PasswordAuthentication in sshd_config.

- *Default*: 'yes'

sshd_config_allowtcpforwarding
------------------------
AllowTcpForwarding in sshd_config.

- *Default*: 'yes'

sshd_config_x11forwarding
------------------------
X11Forwarding in sshd_config.
Specifies whether X11 forwarding is permitted. The default is 'no'.
- *Default*: 'no'

sshd_config_usepam
------------------------
UsePam in  sshd_config.

- *Default*: 'yes'

sshd_config_clientaliveinterval
------------------------
ClientAliveInterval in sshd_config.

- *Default*: '0'

sshd_config_serverkeybits
------------------------
ServerKeyBits in sshd_config.
Defines the number of bits in the ephemeral protocol version 1 server key.
The minimum value is 512, and the OpenSSH default is 1024.
- *Default*: '768'

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

===

# Manage user's ssh_authorized_keys
This works by passing the ssh::keys hash to the ssh_authorized_keys type with create_resources(). Because of this, you may specify any valid parameter for ssh_authorized_key. See the [Type Reference](http://docs.puppetlabs.com/references/stable/type.html#ssh_authorized_key) for a complete list.

## Sample usage:
Push authorized key "root_for_userX" and remove key "root_for_userY" through Hiera.

<pre>
ssh::keys:
  root_for_userX:
    ensure: present
    user: root
    type: dsa
    key: AAAA...==
  root_for_userY:
    ensure: absent
    user: root
</pre>
