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

ssh_forward_x11
---------------
ForwardX11 option in ssh_config:
Specifies whether X11 connections will be automatically redirected over the secure
channel and DISPLAY set. The default is 'no'.

X11 forwarding should be enabled with caution. Users with the ability to bypass file
permissions on the remote host (for the user's X11 authorization database) can access
the local X11 display through the forwarded connection. An attacker may then be able
to perform activities such as keystroke monitoring if the ForwardX11Trusted option is
also enabled.
- *Default*: undef

ssh_forward_agent
-----------------
ForwardAgent option in ssh_config:
Specifies whether the connection to the authentication agent (if any) will be forwarded
to the remote machine. The default is 'no'.

Agent forwarding should be enabled with caution. Users with the ability to bypass file
permissions on the remote host (for the agent's Unix-domain socket) can access the local
agent through the forwarded connection. An attacker cannot obtain key material from the
agent, however they can perform operations on the keys that enable them to authenticate
using the identities loaded into the agent.
- *Default*: undef

ssh_server_alive_interval
-------------------------
ServerAliveInterval option in ssh_config:
Sets a timeout interval in seconds after which if no data has been received from the server,
ssh(1) will send a message through the encrypted channel to request a response from the server.
The default is 0, indicating that these messages will not be sent to the server, or 300 if the
BatchMode option is set. This option applies to protocol version 2 only.
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

sshd_syslog_facility
--------------------
SyslogFacility option in sshd_config:
Gives the facility code that is used when logging messages from sshd(8).  The possible values are:
DAEMON, USER, AUTH, LOCAL0, LOCAL1, LOCAL2, LOCAL3, LOCAL4, LOCAL5, LOCAL6, LOCAL7.
- *Default*: 'AUTH'

sshd_login_grace_time
---------------------
LoginGraceTime option in sshd_config:
The server disconnects after this time if the user has not successfully logged in.
If the value is 0, there is no time limit.
- *Default*: '120'

sshd_challenge_response_authentication
--------------------------------------
ChallengeResponseAuthentication option in sshd_config:
Specifies whether challenge-response authentication is allowed (e.g. via PAM).
The OpenSSH default is 'yes'.
- *Default*: 'no'

sshd_print_motd
---------------
PrintMotd option in sshd_config:
Specifies whether sshd(8) should print /etc/motd when a user logs in interactively.
(On some systems it is also printed by the shell, /etc/profile, or equivalent.)
- *Default*: 'yes'

sshd_use_dns
------------
UseDNS option in sshd_config:
Specifies whether sshd(8) should look up the remote host name and check that the resolved
host name for the remote IP address maps back to the very same IP address.
- *Default*: 'yes'

sshd_banner
-----------
Banner option in sshd_config:
The contents of the specified file are sent to the remote user before authentication is allowed.
If the argument is “none” then no banner is displayed. This option is only available for protocol
version 2.

- *Default*: 'none'

sshd_x_auth_location
--------------------
XAuthLocation option in sshd_config:
Specifies the full pathname of the xauth(1) program.
- *Default*: '/usr/bin/xauth'

sshd_subsystem_sftp
-------------------
Subsystem in sshd_config:
Configures an external subsystem (e.g. file transfer daemon). Arguments should be a subsystem
name and a command (with optional arguments) to execute upon subsystem request.
The command sftp-server(8) implements the “sftp” file transfer subsystem.
- *Default*: '/usr/libexec/openssh/sftp-server'

$sshd_password_authentication
-----------------------------
PasswordAuthentication in sshd_config:
Specifies whether password authentication is allowed.
- *Default*: 'yes'

sshd_allow_tcp_forwarding
-------------------------
AllowTcpForwarding in sshd_config:
Specifies whether TCP forwarding is permitted.
- *Default*: 'yes'

sshd_x11_forwarding
-------------------
X11Forwarding in sshd_config.
Specifies whether X11 forwarding is permitted.
- *Default*: 'no'

sshd_use_pam
------------
UsePam in sshd_config:
Enables the Pluggable Authentication Module interface.  If set to 'yes' this will enable PAM
authentication using ChallengeResponseAuthentication and PasswordAuthentication in addition
to PAM account and session module processing for all authentication types.
- *Default*: 'no'

sshd_client_alive_interval
--------------------------
ClientAliveInterval in sshd_config:
Sets a timeout interval in seconds after which if no data has been received from the client,
sshd(8) will send a message through the encrypted channel to request a response from the
client.  The default is 0, indicating that these messages will not be sent to the client.
This option applies to protocol version 2 only.
- *Default*: '0'

sshd_server_key_bits
--------------------
ServerKeyBits in sshd_config:
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
