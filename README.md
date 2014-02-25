# puppet-module-ssh #

Manage ssh client and server.

The module uses exported resources to manage ssh keys and removes ssh keys that are not managed by puppet. This behavior is managed by the parameters ssh_key_ensure and purge_keys.

===

# Compatability #

This module has been tested to work on the following systems with Puppet v3 and Ruby versions 1.8.7, 1.9.3 and 2.0.0.

 * Debian 7
 * EL 5
 * EL 6
 * SLES 11
 * Ubuntu 12.04 LTS
 * Solaris 10

===

# Parameters #

hiera_merge
-----------
Boolean to merges all found instances of ssh::keys in Hiera. This is useful for specifying
SSH keys at different levels of the hierarchy and having them all included in the catalog.

This will default to 'true' in future versions.

- *Default*: false

ssh_config_hash_known_hosts
---------------------------
HashKnownHosts in ssh_config.
Indicates that ssh should hash host names and addresses when they are added to ~/.ssh/known_hosts.
These hashed names may be used normally by ssh and sshd, but they do not reveal identifying
information should the file's contents be disclosed.  The default is 'no' on Linux OS.

Note that existing names and addresses in known hosts files will not be converted automatically,
but may be manually hashed using ssh-keygen. Use of this option may break facilities such as
tab-completion that rely on being able to read unhashed host names from ~/.ssh/known_hosts.

- *Default*: based on OS platform.

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

ssh_config_sendenv_xmodifiers
-----------------------
Boolean to set 'SendEnv XMODIFIERS' in ssh_config. This option is only valid on Linux OS.

- *Default*: false

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
sshd_config's mode. The default is '0600' on Linux OS and '0644' on Solaris OS.

- *Default*: based on OS platform.

sshd_config_port
---------------------------
String to specify listen port for sshd. Port option in sshd_config.

- *Default*: 22

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

- *Default*: 'yes'

sshd_config_print_motd
----------------------
PrintMotd option in sshd_config.

- *Default*: 'yes'

sshd_config_use_dns
-------------------
UseDNS option in sshd_config. The default is 'yes' on Linux OS.

- *Default*: based on OS platform. (Only valid on Linux OS.)

sshd_config_banner
------------------
Banner option in sshd_config.

- *Default*: 'none'

sshd_banner_content
-------------------
content parameter for file specified in sshd_config_banner

- *Default*: undef

sshd_banner_owner
-----------------
owner parameter for file specified in sshd_config_banner

- *Default*: 'root'

sshd_banner_group
-----------------
group parameter for file specified in sshd_config_banner

- *Default*: 'root'

sshd_banner_mode
----------------
mode parameter for file specified in sshd_config_banner

- *Default*: '0644'

sshd_config_xauth_location
--------------------------
XAuthLocation option in sshd_config.

- *Default*: based on OS platform.

sshd_config_subsystem_sftp
--------------------------
Path to sftp file transfer subsystem in sshd_config.

- *Default*: based on OS platform.


sshd_password_authentication
-----------------------------
PasswordAuthentication in sshd_config.
Specifies whether password authentication is allowed.

- *Default*: 'yes'

sshd_allow_tcp_forwarding
-------------------------
AllowTcpForwarding in sshd_config.
Specifies whether TCP forwarding is permitted.

- *Default*: 'yes'

sshd_x11_forwarding
-------------------
X11Forwarding in sshd_config.
Specifies whether X11 forwarding is permitted. Module sets this option to 'yes'. Future release will update the default to be based on OS platform.

- *Default*: 'yes'

sshd_use_pam
------------
UsePam in sshd_config.
Enables the Pluggable Authentication Module interface. If set to 'yes' this will enable PAM
authentication using ChallengeResponseAuthentication and PasswordAuthentication in addition
to PAM account and session module processing for all authentication types.
This module sets this option to 'yes' on Linux OS and undef on Solaris OS.

- *Default*: based on OS platform. (Valid only on Linux OS)

sshd_client_alive_interval
--------------------------
ClientAliveInterval in sshd_config.
Sets a timeout interval in seconds after which if no data has been received from the client,
sshd(8) will send a message through the encrypted channel to request a response from the
client. The default is 0, indicating that these messages will not be sent to the client.
This option applies to protocol version 2 only.

- *Default*: '0'

keys
----
Hash of keys for user's ~/.ssh/authorized_keys

- *Default*: undefined

packages
--------
Array of package names used for installation.

- *Default*: Based on OS

permit_root_login
-----------------
Allow root login. Valid values are 'yes', 'without-password', 'forced-commands-only', and 'no'.

- *Default*: yes

ssh_config_forward_x11_trusted
------------------------------
ForwardX11Trusted. Determine remote X11 client access to the original X11 display.
The option is set to 'yes' on Linux OS.

- *Default*: based on OS platform. (Not valid on Solaris OS.)

ssh_package_source
------------------
Source to SSH packages.

- *Default*: based on OS platform. (used on Solaris)

ssh_package_adminfile
---------------------
Path to admin file for SSH packages.

- *Default*: based on OS platform. (used on Solaris)

sshd_gssapiauthentication
-------------------------
GSSAPIAuthentication: Enables/disables GSS-API user authentication.

- *Default*: based on OS platform.

sshd_gssapikeyexchange
----------------------
GSSAPIKeyExchange: Enables/disables GSS-API-authenticated key exchanges.

- *Default*: based on OS platform.

sshd_pamauthenticationviakbdint
-------------------------------
PAMAuthenticationViaKBDInt: Use PAM via keyboard interactive method for authentication.

- *Default*: based on OS platform. (valid on Solaris OS)

sshd_gssapicleanupcredentials
-----------------------------
GSSAPICleanupCredentials: Specifies whether to automatically destroy the user's credentials on logout.
Default is 'yes' on Linux OS.

- *Default*: based on OS platform. (Only valid on Linux OS)

ssh_acceptenv
-------------
Boolean to enable AcceptEnv and SendEnv options for specifying environment variables.
Default is set to 'true' on Linux OS.

- *Default*: based on OS platform. (Only valid on Linux OS)

purge_keys
----------
Remove keys not managed by puppet.

- *Default*: 'true'

manage_firewall
---------------
Open firewall for SSH service. Not used on Solaris OS.

- *Default*: false

service_ensure
--------------
Ensure SSH service is running. Valid values are 'stopped' and 'running'.

- *Default*: 'running'

service_name
------------
Name of the SSH service.

- *Default*: Based on OS

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
  apachehup:
    ensure: present
    user: apachehup
    type: rsa
    key: 'AAAA...=='
    options: 'command="/sbin/service httpd restart"'
  root_for_userY:
    ensure: absent
    user: root
</pre>
