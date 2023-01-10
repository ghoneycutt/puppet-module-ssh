# sshd_config configuration file parameters
type Ssh::Sshd_Config = Struct[
  {
    Optional['AcceptEnv']                       => String[1],
    Optional['AddressFamily']                   => Enum['any', 'inet', 'inet6'],
    Optional['AllowAgentForwarding']            => Ssh::Yes_no,
    Optional['AllowGroups']                     => String[1],
    Optional['AllowStreamLocalForwarding']      => Enum['yes', 'all', 'no', 'local', 'remote'],
    Optional['AllowTcpForwarding']              => Enum['yes', 'no', 'local', 'remote'],
    Optional['AllowUsers']                      => String[1],
    Optional['AuthenticationMethods']           => String[1],
    Optional['AuthorizedKeysCommand']           => String[1],
    Optional['AuthorizedKeysCommandUser']       => String[1],
    Optional['AuthorizedKeysFile']              => String[1],
    Optional['AuthorizedPrincipalsCommand']     => String[1],
    Optional['AuthorizedPrincipalsCommandUser'] => String[1],
    Optional['AuthorizedPrincipalsFile']        => String[1],
    Optional['Banner']                          => String[1],
    Optional['CASignatureAlgorithms']           => String[1],
    Optional['ChannelTimeout']                  => String[1],
    Optional['ChrootDirectory']                 => String[1],
    Optional['Ciphers']                         => String[1],
    Optional['ClientAliveCountMax']             => Integer[0],
    Optional['ClientAliveInterval']             => Integer[0],
    Optional['Compression']                     => Enum['yes', 'delayed', 'no'],
    Optional['DenyGroups']                      => String[1],
    Optional['DenyUsers']                       => String[1],
    Optional['DisableForwarding']               => Ssh::Yes_no,
    Optional['ExposeAuthInfo']                  => Ssh::Yes_no,
    Optional['FingerprintHash']                 => Enum['md5', 'sha256'],
    Optional['ForceCommand']                    => String[1],
    Optional['GatewayPorts']                    => Enum['no', 'yes', 'clientspecified'],
    Optional['GSSAPIAuthentication']            => Ssh::Yes_no,
    Optional['GSSAPICleanupCredentials']        => Ssh::Yes_no,
    Optional['GSSAPIStrictAcceptorCheck']       => Ssh::Yes_no,
    Optional['HostbasedAcceptedAlgorithms']     => String[1],
    Optional['HostbasedAuthentication']         => Ssh::Yes_no,
    Optional['HostbasedUsesNameFromPacketOnly'] => Ssh::Yes_no,
    Optional['HostCertificate']                 => String[1],
    Optional['HostKey']                         => String[1],
    Optional['HostKeyAgent']                    => String[1],
    Optional['HostKeyAlgorithms']               => String[1],
    Optional['IgnoreRhosts']                    => Ssh::Yes_no,
    Optional['IgnoreUserKnownHosts']            => Ssh::Yes_no,
    Optional['Include']                         => String[1],
    Optional['IPQoS']                           => String[1],
    Optional['KbdInteractiveAuthentication']    => Ssh::Yes_no,
    Optional['KerberosAuthentication']          => Ssh::Yes_no,
    Optional['KerberosGetAFSToken']             => Ssh::Yes_no,
    Optional['KerberosOrLocalPasswd']           => Ssh::Yes_no,
    Optional['KerberosTicketCleanup']           => Ssh::Yes_no,
    Optional['KexAlgorithms']                   => String[1],
    Optional['ListenAddress']                   => String[1],
    Optional['LoginGraceTime']                  => Integer[0],
    Optional['LogLevel']                        => Ssh::Log_level,
    Optional['LogVerbose']                      => String[1],
    Optional['MACs']                            => String[1],
    Optional['Match']                           => String[1],
    Optional['MaxAuthTries']                    => Integer[2],
    Optional['MaxSessions']                     => Integer[0],
    Optional['MaxStartups']                     => String[1],
    Optional['ModuliFile']                      => Stdlib::Absolutepath,
    Optional['PasswordAuthentication']          => Ssh::Yes_no,
    Optional['PermitEmptyPasswords']            => Ssh::Yes_no,
    Optional['PermitListen']                    => String[1],
    Optional['PermitOpen']                      => String[1],
    Optional['PermitRootLogin']                 => Ssh::Permit_root_login,
    Optional['PermitTTY']                       => Ssh::Yes_no,
    Optional['PermitTunnel']                    => Enum['yes', 'point-to-point', 'ethernet', 'no'],
    Optional['PermitUserEnvironmen']            => String[1],
    Optional['PermitUserRC']                    => Ssh::Yes_no,
    Optional['PerSourceMaxStartups']            => String[1],
    Optional['PerSourceNetBlockSize']           => String[1],
    Optional['PidFile']                         => String[1],
    Optional['Port']                            => Stdlib::Port,
    Optional['PrintLastLog']                    => Ssh::Yes_no,
    Optional['PrintMotd']                       => Ssh::Yes_no,
    Optional['PubkeyAcceptedAlgorithms']        => String[1],
    Optional['PubkeyAuthOptions']               => Enum['none', 'touch-required', 'verify-required'],
    Optional['PubkeyAuthentication']            => Ssh::Yes_no,
    Optional['RekeyLimit']                      => String[1],
    Optional['RequiredRSASize']                 => Integer[0],
    Optional['RevokedKeys']                     => String[1],
    Optional['RDomain']                         => String[1],
    Optional['SecurityKeyProvider']             => Stdlib::Absolutepath,
    Optional['SetEnv']                          => String[1],
    Optional['StreamLocalBindMask']             => Stdlib::Filemode,
    Optional['StreamLocalBindUnlink']           => Ssh::Yes_no,
    Optional['StrictModes']                     => Ssh::Yes_no,
    Optional['Subsystem']                       => String[1],
    Optional['SyslogFacility']                  => Ssh::Syslog_facility,
    Optional['TCPKeepAlive']                    => Ssh::Yes_no,
    Optional['TrustedUserCAKeys']               => String[1],
    Optional['UseDNS']                          => Ssh::Yes_no,
    Optional['VersionAddendum']                 => String[1],
    Optional['X11DisplayOffset']                => Integer[0],
    Optional['X11Forwarding']                   => Ssh::Yes_no,
    Optional['X11UseLocalhost']                 => Ssh::Yes_no,
    Optional['XAuthLocation']                   => String[1],
    Optional['custom']                          => Array,
  }
]
