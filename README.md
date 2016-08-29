# puppet-module-ssh

Manage ssh client and server.

The module uses exported resources to manage ssh keys and removes ssh keys that
are not managed by puppet. This behavior is managed by the parameters
ssh_key_ensure and purge_keys.

This module may be used with a simple `include ::ssh`

===

### Table of Contents
1. [Compatibility](#compatibility)
1. [Parameters](#parameters)
1. [Examples](#sample-usage)

===

# Compatibility

This module has been tested to work on the following systems with Puppet
versions v3, v3 with future parser and v4 with  Ruby versions 1.8.7 (Puppet v3
only), 1.9.3, 2.0.0, 2.1.0 and 2.3.1 (Puppet v4 only).

 * Debian 7
 * EL 5
 * EL 6
 * EL 7
 * SLES 10
 * SLES 11
 * SLES 12
 * Ubuntu 12.04 LTS
 * Ubuntu 14.04 LTS
 * Ubuntu 16.04 LTS
 * Solaris 9
 * Solaris 10
 * Solaris 11

===

# Parameters
A value of `'USE_DEFAULTS'` will use the defaults specified by the module.


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
information should the file's contents be disclosed. The default is 'no' on Linux.

Note that existing names and addresses in known hosts files will not be converted automatically,
but may be manually hashed using ssh-keygen. Use of this option may break facilities such as
tab-completion that rely on being able to read unhashed host names from ~/.ssh/known_hosts.

- *Default*: 'USE_DEFAULTS'

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
Boolean to set 'SendEnv XMODIFIERS' in ssh_config. This option is only valid on Linux.

- *Default*: false

ssh_config_template
--------------------
*string* The template used to generate ssh_config.

- *Default*: 'ssh/ssh_config.erb'

ssh_config_ciphers
------------------
Array of ciphers to be used with the Ciphers option in ssh_config.

- *Default*: undef

ssh_config_macs
---------------
Array of ciphers to be used with the MACs option in ssh_config.

- *Default*: undef

ssh_sendenv
-------------
Boolean to enable SendEnv options for specifying environment variables. Default is set to true on Linux.

- *Default*: 'USE_DEFAULTS'

ssh_gssapiauthentication
-------------------------
GSSAPIAuthentication: Enables/disables GSS-API user authentication in ssh_config. Valid values are 'yes' and 'no'.

- *Default*: 'yes'

ssh_gssapidelegatecredentials
-----------------------------
*string* For GSSAPIDelegateCredentials setting in ssh_config. Valid values are
'yes' and 'no' or to leave undef which will ensure the setting is not present
in ssh_config.

- *Default*: undef

ssh_hostbasedauthentication
-------------------------
String for HostbasedAuthentication option in ssh_config. Valid values are 'yes' and 'no'.

- *Default*: undef


ssh_strict_host_key_checking
-----------------------------
*string* For StrictHostKeyChecking setting in ssh_config. Valid values are
'yes', 'no' or 'ask'.

- *Default*: undef

ssh_enable_ssh_keysign
-----------------------------
*string* For EnableSSHKeysign setting in ssh_config. Valid values are
'yes' and 'no' or to leave undef which will ensure the setting is not present
in ssh_config.

- *Default*: undef

sshd_addressfamily
----------------
Specifies the value of the AddressFamily setting in sshd_config. Valid values are 'any', 'inet' (IPv4 only), 'inet6' (IPv6 only) and undef. A value of undef will ensure that AddressFamily is not in the configuration.

- *Default*: 'any'

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

sshd_config_loglevel
---------------------------
LogLevel option in sshd_config. Acceptable values are QUIET, FATAL, ERROR, INFO, VERBOSE.

*DEBUG, DEBUG1, DEBUG2, and DEBUG3* are permitted values for sshd, however [setting the logging level to DEBUG or higher violates the privacy of users](http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man5/sshd_config.5?query=sshd_config) and should not be done unless manually debugging.

- *Default*: 'INFO'

sshd_config_maxauthtries
---------------
MaxAuthTries option in sshd_config.  Specifies the maximum number of authentication attempts permitted per connection.  Once the number of failures reaches half this value, additional failures are logged.

- *Default*: '6'

sshd_config_mode
---------------
sshd_config's mode. The default is '0600' on Linux and '0644' on Solaris.

- *Default*: 'USE_DEFAULTS'

sshd_listen_address
-------------------
String or Array to specify address(es) for which sshd will bind. Corresponds to ListenAddress in sshd_config.

- *Default*: undef

sshd_config_permitemptypasswords
--------------------------------
PermitEmptyPasswords option in sshd_config.  When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings.
Valid values are 'yes' and 'no'.

- *Default*: undef

sshd_config_permituserenvironment
---------------------------------
PermitUserEnvironment option in sshd_config.  Specifies whether ~/.ssh/environment and environment= options in ~/.ssh/authorized_keys are processed by sshd(8).  The default is “no”.  Enabling environment processing may enable users to bypass access restrictions in some configurations using mechanisms such as LD_PRELOAD.
Valid values are 'yes' and 'no'.


- *Default*: undef

sshd_config_port
---------------------------
String, Integer or Array to specify listen port[s] for sshd. Port option in sshd_config.

- *Default*: '22'

sshd_config_syslog_facility
---------------------------
SyslogFacility option in sshd_config.

- *Default*: 'AUTH'

sshd_config_template
--------------------
*string* The template used to generate sshd_config.

- *Default*: 'ssh/sshd_config.erb'

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
UseDNS option in sshd_config. The default is 'yes' on Linux.

- *Default*: 'USE_DEFAULTS'

sshd_config_authkey_location
----------------------------
Specify location of authorized_keys file. Default is to not specify.

- *Default*: undef

sshd_config_hostkey
----------------------------
Specify an array of server side HostKey files to use. Default is to use only /etc/ssh/ssh_host_rsa_key

- *Default*: /etc/ssh/ssh_host_rsa_key

sshd_config_strictmodes
----------------------------
Specifies whether sshd should check file modes and ownership of the user's files and home directory before accepting login. Valid values are yes and no.

- *Default*: undef

sshd_config_serverkeybits
----------------------------
Defines the number of bits in the ephemeral protocol version 1 server key.  The minimum value is 512, and the default is 1024 except for Solaris default value is 768.

- *Default*: '1024' except for Solaris which is '768'

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

- *Default*: 'USE_DEFAULTS'

sshd_config_subsystem_sftp
--------------------------
Path to sftp file transfer subsystem in sshd_config.

- *Default*: 'USE_DEFAULTS'

sshd_password_authentication
-----------------------------
PasswordAuthentication in sshd_config. Specifies whether password authentication is allowed.

- *Default*: 'yes'

sshd_allow_tcp_forwarding
-------------------------
AllowTcpForwarding in sshd_config. Specifies whether TCP forwarding is permitted.

- *Default*: 'yes'

sshd_authorized_keys_command
----------------------------
Fully qualified path to command for AuthorizedKeysCommand in sshd_config.

- *Default*: undef

sshd_authorized_keys_command_user
---------------------------------
String of user for AuthorizedKeysCommandUser in sshd_config.

- *Default*: undef

sshd_x11_forwarding
-------------------
X11Forwarding in sshd_config. Specifies whether X11 forwarding is permitted.

- *Default*: 'yes'

sshd_use_pam
------------
UsePam in sshd_config.
Enables the Pluggable Authentication Module interface. If set to 'yes' this will enable PAM
authentication using ChallengeResponseAuthentication and PasswordAuthentication in addition
to PAM account and session module processing for all authentication types.
This module sets this option to 'yes' on Linux and undef on Solaris.

- *Default*: 'USE_DEFAULTS'

ssh_config_use_roaming
----------------------
String to enable or disable UseRoaming in client configuration ssh_config.
Valid values are 'yes', 'no' and 'unset'. Using 'unset' will not use (print)
this configuration parameter at all. Default is set to 'no' on Linux and
'unset' on Solaris. If you have OpenSSH >= version 5.4, this should be set to
'no' to mitigate CVE-2016-0777 and CVE-2016-0778.

- *Default*: 'USE_DEFAULTS'

sshd_client_alive_interval
--------------------------
ClientAliveInterval in sshd_config.
Sets a timeout interval in seconds after which if no data has been received from the client,
sshd(8) will send a message through the encrypted channel to request a response from the
client. The default is 0, indicating that these messages will not be sent to the client.
This option applies to protocol version 2 only.

- *Default*: '0'

sshd_client_alive_count_max
--------------------------
ClientAliveCountMax in sshd_config.
Sets the number of client alive messages (see below) which may be sent without sshd(8)
receiving any messages back from the client. If this threshold is reached while client alive
messages are being sent, sshd will disconnect the client, terminating the session.  It is
important to note that the use of client alive messages is very different from TCPKeepAlive
(below).  The client alive messages are sent through the encrypted channel and therefore will
not be spoofable.  The TCP keepalive option enabled by TCPKeepAlive is spoofable.  The client
alive mechanism is valuable when the client or server depend on knowing when a connection has
become inactive. The default value is 3.  If ClientAliveInterval (see below) is set to 15,
and ClientAliveCountMax is left at the default, unresponsive SSH clients will be disconnected
after approximately 45 seconds.  This option applies to protocol version 2 only.

- *Default*: '3'

sshd_config_tcp_keepalive
------------------------
TCPKeepAlive in sshd_config.
Specifies  whether the system should send TCP keepalive messages to the other side.  If they
are sent, death of the connection or crash of one of the machines will be properly noticed.
However, this means that connections will die if the route is down temporarily, and some
people find it annoying.  On the other hand, if TCP keepalives are not sent, sessions may
hang indefinitely on the server, leaving ``ghost'' users and consuming server resources.
The default is ``yes'' (to send TCP keepalive messages), and the server will notice if the
network goes down or the client host crashes.  This avoids infinitely hanging sessions.

- *Default*: 'yes'

sshd_config_ciphers
-------------------
Array of ciphers for the Ciphers setting in sshd_config.

- *Default*: undef

sshd_config_macs
----------------
Array of macs for the MACs setting in sshd_config.

- *Default*: undef

sshd_config_denyusers
---------------------
Array of users for the DenyUsers setting in sshd_config.

- *Default*: undef

sshd_config_denygroups
---------------------
Array of groups for the DenyGroups setting in sshd_config.

- *Default*: undef

sshd_config_allowgroups
-----------------------
Array of users for the AllowGroups setting in sshd_config.

- *Default*: undef

sshd_config_allowusers
-----------------------
Array of users for the AllowUsers setting in sshd_config.

- *Default*: undef

sshd_config_maxstartups
-----------------------
Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon.

- *Default*: undef

sshd_config_maxsessions
-----------------------
Specifies the maximum number of open sessions permitted per network connection.

- *Default*: undef

sshd_config_chrootdirectory
---------------------------
String with absolute path for the ChrootDirectory directive for the SSH daemon.

- *Default*: undef

sshd_config_forcecommand
---------------------------
String with command for the ForceCommand directive for the SSH daemon.

- *Default*: undef

sshd_config_match
-----------------
Hash for matches with nested arrays for options for the Match directive for the SSH daemon.
Match directive is supported on SSH >= 5.x.

- *Default*: undef

- *Hiera example*:

``` yaml
ssh::sshd_config_match:
  'User JohnDoe':
    - 'AllowTcpForwarding yes'
  'Address 2.4.2.0':
    - 'X11Forwarding yes'
    - 'PasswordAuthentication no'
```

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
ForwardX11Trusted. Determine remote X11 client access to the original X11 display. The option is set to 'yes' on Linux. Valid values are 'yes', 'no', and undef.

- *Default*: 'USE_DEFAULTS' (Not valid on Solaris.)

ssh_package_source
------------------
Source to SSH packages.

- *Default*: 'USE_DEFAULTS'

ssh_package_adminfile
---------------------
Path to admin file for SSH packages.

- *Default*: 'USE_DEFAULTS'

sshd_gssapiauthentication
-------------------------
GSSAPIAuthentication: Enables/disables GSS-API user authentication. Valid values are 'yes' and 'no'.

- *Default*: 'yes'

sshd_gssapikeyexchange
----------------------
GSSAPIKeyExchange: Enables/disables GSS-API-authenticated key exchanges. Valid values are 'yes', 'no', and undef.

- *Default*: 'USE_DEFAULTS'

sshd_pamauthenticationviakbdint
-------------------------------
PAMAuthenticationViaKBDInt: Use PAM via keyboard interactive method for authentication. Valid values are 'yes', 'no', and undef.

- *Default*: 'USE_DEFAULTS'

sshd_gssapicleanupcredentials
-----------------------------
GSSAPICleanupCredentials: Specifies whether to automatically destroy the user's credentials on logout. Default is 'yes' on Linux. Valid values are 'yes', 'no', and undef.

- *Default*: 'USE_DEFAULTS'

sshd_acceptenv
-------------
Boolean to enable AcceptEnv options for specifying environment variables. Default is set to true on Linux.

- *Default*: 'USE_DEFAULTS'

sshd_hostbasedauthentication
-------------------------
String for HostbasedAuthentication option in sshd_config. Valid values are 'yes' and 'no'. Specifies whether rhosts or /etc/hosts.equiv authentication together with successful public key client host authentication is allowed (host-based authentication). This option is similar to RhostsRSAAuthentication and applies to protocol version 2 only.

- *Default*: 'no'

sshd_pubkeyauthentication
-------------------------
String for PubkeyAuthentication option in sshd_config. Valid values are 'yes' and 'no'.

- *Default*: 'yes'

sshd_ignoreuserknownhosts
-------------------------
String for IgnoreUserKnownHosts option in sshd_config. Valid values are 'yes' and 'no'. Specifies whether sshd(8) should ignore the user's ~/.ssh/known_hosts during RhostsRSAAuthentication or HostbasedAuthentication.

- *Default*: 'no'

sshd_ignorerhosts
-------------------------
String for IgnoreRhosts option in sshd_config. Valid values are 'yes' and 'no'. Specifies that .rhosts and .shosts files will not be used in RhostsRSAAuthentication or HostbasedAuthentication though /etc/hosts.equiv and /etc/ssh/shosts.equiv are still used.

- *Default*: 'yes'

purge_keys
----------
Remove keys not managed by puppet.

- *Default*: 'true'

manage_firewall
---------------
Open firewall for SSH service. Not used on Solaris.

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
Boolean to declare whether the service's init script has a functional status command.

- *Default*: 'USE_DEFAULTS'

ssh_key_ensure
--------------
Export node SSH key. Valid values are 'present' and 'absent'.

- *Default*: 'present'

ssh_key_import
--------------
Import all exported node SSH keys. Valid values are 'true' and 'false'.

- *Default*: 'true'

ssh_key_type
------------
Encryption type for SSH key. Valid values are 'ecdsa-sha2-nistp256', 'rsa', 'dsa', 'ssh-dss' and 'ssh-rsa'

- *Default*: 'ssh-rsa'

ssh_config_global_known_hosts_file
----------------------------------
File of the global known_hosts file

- *Default*: '/etc/ssh/ssh_known_hosts'

ssh_config_global_known_hosts_list
----------------------------------
Array of additional known_hosts files to be added to GlobalKnownHostsFile
option together with `ssh_config_global_known_hosts_file`.

- *Default*: undef

ssh_config_global_known_hosts_owner
----------------------------------
Owner of the global known_hosts file

- *Default*: 'root'

ssh_config_global_known_hosts_group
----------------------------------
Group of the global known_hosts file

- *Default*: 'root'

ssh_config_global_known_hosts_mode
----------------------------------
File mode of the global known_hosts file

- *Default*: '0644'

ssh_config_user_known_hosts_file
--------------------------------
Array of user's known_hosts files used in the ssh config option
UserKnownHostsFile.

- *Default*: undef

manage_root_ssh_config
----------------------
Manage SSH config of root. Valid values are 'true' and 'false'.

- *Default*: 'false'

root_ssh_config_content
-----------------------
Content of root's ~/.ssh/config.

- *Default*: "# This file is being maintained by Puppet.\n# DO NOT EDIT\n"

manage_service
--------------
Manage the sshd service through this module or not.  Valid values are 'true' and 'false'.

- *Default*: 'true'

===
# Manage user's ssh_authorized_keys
This works by passing the ssh::keys hash to the ssh_authorized_keys type with create_resources(). Because of this, you may specify any valid parameter for ssh_authorized_key. See the [Type Reference](http://docs.puppetlabs.com/references/stable/type.html#ssh_authorized_key) for a complete list.

## Sample usage:
Push authorized key "root_for_userX" and remove key "root_for_userY" through Hiera.

``` yaml
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
```
