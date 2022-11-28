# puppet-module-ssh

Manage ssh client and server.

This module is based on the OpenSSH v7.0 implementation. All parameters that are described in the
man pages are available to this module with the exception of the Match parameter. Some SSH
implementations do provide extra features and use additional parameters. These deviations can
still be managed with the help of the `$custom` parameter. This freetext parameter allows you to add
any lines to ssh_config and sshd_config that you wish to.

This module may be used with a simple `include ::ssh`

The `ssh::config_entry` defined type may be used directly and is used to manage
Host entries in a personal `~/.ssh/config` file.

#### Table of Contents
1. [Compatibility](#compatibility)
1. [Parameters](#parameters)
1. [Examples](#sample-usage)
1. [Upgrading](#upgrading)
1. [Contributing](#contributing)


## Compatibility

This module officially supports the platforms listed in the
`metadata.json`. It does not fail on unsupported platforms and has been
known to work on many, many platforms since its creation in 2010.

### Known to work

 * Debian 10
 * Debian 11
 * EL 7
 * EL 8
 * Ubuntu 18.04 LTS
 * Ubuntu 20.04 LTS
 * Solaris 10
 * Solaris 11


### SunSSH
If you use the Sun Solaris SSH, please keep in mind that not all parameters can be used.

Unsupported parameters for ssh_config:
AddressFamily, Tunnel, TunnelDevice, PermitLocalCommand, HashKnownHosts

Unsupported parameters for sshd_config:
KerberosOrLocalPasswd, KerberosTicketCleanup, KerberosGetAFSToken, TCPKeepAlive, ShowPatchLevel,
MaxSessions, PermitTunnel


# Parameters
A value of `undef` will use the defaults specified by the module. See `data/os/` for the actual
default settings for supported operating systems.

Please keep in mind that this module does not include any sanity checks. Depending on the set
parameters or values and the running version of SSH the resulting configuration could stop SSH
from working.


See [REFERENCE.md](REFERENCE.md) for a list of all parameters.

# Manage user's ssh_authorized_keys
The hash ssh::keys is passed to ssh_authorized_key type. Because of this, you may specify any valid
parameter for ssh_authorized_key.
See the [Type Reference](https://github.com/puppetlabs/puppetlabs-sshkeys_core/blob/main/REFERENCE.md#ssh_authorized_key)
for a complete list.

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

Manage config entries in a personal ssh/config file.

```
Ssh::Config_entry {
  ensure => present,
  path   => '/home/jenkins/.ssh/config',
  owner  => 'jenkins',
  group  => 'jenkins',
}


ssh::config_entry { 'jenkins *':
  host  => '*',
  lines => [
    '  ForwardX11 no',
    '  StrictHostKeyChecking no',
  ],
  order => '10',
}

ssh::config_entry { 'jenkins github.com':
  host  => 'github.com',
  lines => ["  IdentityFile /home/jenkins/.ssh/jenkins-gihub.key"],
  order => '20',
}
```


## Upgrading

The SSH module v4 was completely rewritten. In this process all parameters for the SSH configuration
files have been renamed. Users that want to upgrade need to change their running configuration.
To make your upgrade easier there is a list of old and new parameter names.
Consult [UPGRADING.md](UPGRADING.md)


## Contributing

Please check [CONTRIBUTING.md](CONTRIBUTING.md)
