# Upgrading from v3 to v4

In v4 of this module all the configuration file related parameters have been renamed to follow a
simple naming scheme. In SSH configuration files CamelCase is used to name the parameters. Puppet
does not support CamelCase, instead these names have been transfered to all lowercase names with
underscores whenever a new word starts.

Please also take notice that all SSH server related actions and configurations have been moved to
the ssh::server class. Therefore client related configuration paramaters now use the `ssh::` prefix
while server related configuration paramaters now uses the `ssh::server::` prefix as namespace
(eg: `ssh::send_env` vs `ssh::server::accept_env`).

To make your life a little bit easier while upgrading from v3 to v4 of this module here is a list
with the names that are used by OpenSSH and the names used in v3 and v4 of this module.


Client configuration file related parameters:

|ssh_config name                   |v3 name                                 |v4 name                               |
|----------------------------------|----------------------------------------|--------------------------------------|
|AddKeysToAgent                    |                                        |add_keys_to_agent                     |
|AddressFamily                     |                                        |address_family                        |
|BatchMode                         |                                        |batch_mode                            |
|BindAddress                       |                                        |bind_address                          |
|BindInterface                     |                                        |bind_interface                        |
|CanonicalDomains                  |                                        |canonical_domains                     |
|CanonicalizeFallbackLocal         |                                        |canonicalize_fallback_local           |
|CanonicalizeHostname              |                                        |canonicalize_hostname                 |
|CanonicalizeMaxDots               |                                        |canonicalize_max_dots                 |
|CanonicalizePermittedCNAMEs       |                                        |canonicalize_permitted_cnames         |
|CASignatureAlgorithms             |                                        |ca_signature_algorithms               |
|CertificateFile                   |                                        |certificate_file                      |
|CheckHostIP                       |                                        |check_host_ip                         |
|Ciphers                           |ssh_config_ciphers                      |ciphers                               |
|ClearAllForwardings               |                                        |clear_all_forwardings                 |
|Compression                       |                                        |compression                           |
|ConnectionAttempts                |                                        |connection_attempts                   |
|ConnectTimeout                    |                                        |connect_timeout                       |
|ControlMaster                     |                                        |control_master                        |
|ControlPath                       |                                        |control_path                          |
|ControlPersist                    |                                        |control_persist                       |
|DynamicForward                    |                                        |dynamic_forward                       |
|EnableSSHKeysign                  |ssh_enable_ssh_keysign                  |enable_ssh_keysign                    |
|EscapeChar                        |                                        |escape_char                           |
|ExitOnForwardFailure              |                                        |exit_on_forward_failure               |
|FingerprintHash                   |                                        |fingerprint_hash                      |
|ForkAfterAuthentication           |                                        |fork_after_authentication             |
|ForwardAgent                      |ssh_config_forward_agent                |forward_agent                         |
|ForwardX11                        |ssh_config_forward_x11                  |forward_x11                           |
|ForwardX11Timeout                 |                                        |forward_x11_timeout                   |
|ForwardX11Trusted                 |ssh_config_forward_x11_trusted          |forward_x11_trusted                   |
|GatewayPorts                      |                                        |gateway_ports                         |
|GlobalKnownHostsFile              |ssh_config_global_known_hosts_list      |global_known_hosts_file               |
|GSSAPIAuthentication              |ssh_gssapiauthentication                |gss_api_authentication                |
|GSSAPIDelegateCredentials         |ssh_gssapidelegatecredentials           |gss_api_delegate_credentials          |
|HashKnownHosts                    |ssh_config_hash_known_hosts             |hash_known_hosts                      |
|Host                              |                                        |host                                  |
|HostbasedAcceptedAlgorithms       |                                        |hostbased_accepted_algorithms         |
|HostbasedAuthentication           |ssh_hostbasedauthentication             |hostbased_authentication              |
|HostKeyAlgorithms                 |                                        |host_key_algorithms                   |
|HostKeyAlias                      |                                        |host_key_alias                        |
|Hostname                          |                                        |hostname                              |
|IdentitiesOnly                    |                                        |identities_only                       |
|IdentityAgent                     |                                        |identity_agent                        |
|IdentityFile                      |                                        |identity_file                         |
|IgnoreUnknown                     |                                        |ignore_unknown                        |
|Include                           |ssh_config_include                      |include                               |
|IPQoS                             |                                        |ip_qos                                |
|KbdInteractiveAuthentication      |                                        |kbd_interactive_authentication        |
|KbdInteractiveDevices             |                                        |kbd_interactive_devices               |
|KexAlgorithms                     |ssh_config_kexalgorithms                |kex_algorithms                        |
|KnownHostsCommand                 |                                        |kown_hosts_command                    |
|LocalCommand                      |                                        |local_command                         |
|LocalForward                      |                                        |local_forward                         |
|LogLevel                          |                                        |log_level                             |
|LogVerbose                        |                                        |log_verbose                           |
|MACs                              |ssh_config_macs                         |macs                                  |
|NoHostAuthenticationForLocalhost  |                                        |no_host_authentication_for_localhost  |
|NumberOfPasswordPrompts           |                                        |number_of_password_prompts            |
|PasswordAuthentication            |                                        |password_authentication               |
|PermitLocalCommand                |                                        |permit_local_command                  |
|PermitRemoteOpen                  |                                        |permit_remote_open                    |
|PKCS11Provider                    |                                        |pkcs11_provider                       |
|Port                              |                                        |port                                  |
|PreferredAuthentications          |                                        |preferred_authentications             |
|ProxyCommand                      |ssh_config_proxy_command                |proxy_command                         |
|ProxyJump                         |                                        |proxy_jump                            |
|ProxyUseFdpass                    |                                        |proxy_use_fdpass                      |
|PubkeyAcceptedAlgorithms          |                                        |pubkey_accepted_algorithms            |
|PubkeyAuthentication              |                                        |pubkey_authentication                 |
|RekeyLimit                        |                                        |rekey_limit                           |
|RemoteCommand                     |                                        |remote_command                        |
|RemoteForward                     |                                        |remote_forward                        |
|RequestTTY                        |                                        |request_tty                           |
|RevokedHostKeys                   |                                        |revoked_host_keys                     |
|SecurityKeyProvider               |                                        |security_key_provider                 |
|SendEnv                           |ssh_sendenv                             |send_env                              |
|ServerAliveCountMax               |                                        |server_alive_count_max                |
|ServerAliveInterval               |ssh_config_server_alive_interval        |server_alive_interval                 |
|SessionType                       |                                        |session_type                          |
|SetEnv                            |                                        |set_env                               |
|StdinNull                         |                                        |stdin_null                            |
|StreamLocalBindMask               |                                        |stream_local_bind_mask                |
|StreamLocalBindUnlink             |                                        |stream_local_bind_unlink              |
|StrictHostKeyChecking             |ssh_strict_host_key_checking            |strict_host_key_checking              |
|SyslogFacility                    |                                        |syslog_facility                       |
|TCPKeepAlive                      |                                        |tcp_keep_alive                        |
|Tunnel                            |                                        |tunnel                                |
|TunnelDevice                      |                                        |tunnel_device                         |
|UpdateHostKeys                    |                                        |update_host_keys                      |
|User                              |                                        |user                                  |
|UserKnownHostsFile                |ssh_config_user_known_hosts_file        |user_known_hosts_file                 |
|VerifyHostKeyDNS                  |                                        |verify_host_key_dns                   |
|VisualHostKey                     |                                        |visual_host_key                       |
|XAuthLocation                     |                                        |xauth_location                        |
|**removed**                       |                                        |                                      |
|Protocol                          |                                        |use $custom instead                   |
|UseRoaming                        |ssh_config_use_roaming                  |use $custom instead                   |


Server configuration file related parameters:

|sshd_config name                  |v3 name                                 |v4 name                               |
|----------------------------------|----------------------------------------|--------------------------------------|
|AcceptEnv                         |sshd_acceptenv                          |accept_env                            |
|AddressFamily                     |sshd_addressfamily                      |address_family                        |
|AllowAgentForwarding              |sshd_config_allowagentforwarding        |allow_agent_forwarding                |
|AllowGroups                       |sshd_config_allowgroups                 |allow_groups                          |
|AllowStreamLocalForwarding        |                                        |allow_stream_local_forwarding         |
|AllowTcpForwarding                |sshd_allow_tcp_forwarding               |allow_tcp_forwarding                  |
|AllowUsers                        |sshd_config_allowusers                  |allow_users                           |
|AuthenticationMethods             |sshd_config_authenticationmethods       |authentication_methods                |
|AuthorizedKeysCommand             |sshd_authorized_keys_command            |authorized_keys_command               |
|AuthorizedKeysCommandUser         |sshd_authorized_keys_command_user       |authorized_keys_command_user          |
|AuthorizedKeysFile                |sshd_config_authkey_location            |authorized_keys_file                  |
|AuthorizedPrincipalsCommand       |                                        |authorized_principals_command         |
|AuthorizedPrincipalsCommandUser   |                                        |authorized_principals_command_user    |
|AuthorizedPrincipalsFile          |sshd_config_authorized_principals_file  |authorized_principals_file            |
|Banner                            |sshd_config_banner                      |banner                                |
|CASignatureAlgorithms             |                                        |ca_signature_algorithms               |
|ChallengeResponseAuthentication   |sshd_config_challenge_resp_auth         |challenge_response_authentication     |
|ChrootDirectory                   |sshd_config_chrootdirectory             |chroot_directory                      |
|Ciphers                           |sshd_config_ciphers                     |ciphers                               |
|ClientAliveCountMax               |sshd_client_alive_count_max             |client_alive_count_max                |
|ClientAliveInterval               |sshd_client_alive_interval              |client_alive_interval                 |
|Compression                       |sshd_config_compression                 |compression                           |
|DenyGroups                        |sshd_config_denygroups                  |deny_groups                           |
|DenyUsers                         |sshd_config_denyusers                   |deny_users                            |
|DisableForwarding                 |                                        |disable_forwarding                    |
|ExposeAuthInfo                    |                                        |expose_auth_info                      |
|FingerprintHash                   |                                        |fingerprint_hash                      |
|ForceCommand                      |sshd_config_forcecommand                |force_command                         |
|GatewayPorts                      |                                        |gateway_ports                         |
|GSSAPIAuthentication              |sshd_gssapiauthentication               |gss_api_authentication                |
|GSSAPICleanupCredentials          |sshd_gssapicleanupcredentials           |gss_api_cleanup_credentials           |
|GSSAPIStrictAcceptorCheck         |                                        |gss_api_strict_acceptor_check         |
|HostbasedAcceptedAlgorithms       |                                        |hostbased_accepted_algorithms         |
|HostbasedAuthentication           |sshd_hostbasedauthentication            |hostbased_authentication              |
|HostbasedUsesNameFromPacketOnly   |                                        |hostbased_uses_name_from_packet_only  |
|HostCertificate                   |sshd_config_hostcertificate             |host_certificate                      |
|HostKey                           |sshd_config_hostkey                     |host_key                              |
|HostKeyAgent                      |                                        |host_key_agent                        |
|HostKeyAlgorithms                 |                                        |host_key_algorithms                   |
|IgnoreRhosts                      |sshd_ignorerhosts                       |ignore_rhosts                         |
|IgnoreUserKnownHosts              |sshd_ignoreuserknownhosts               |ignore_user_known_hosts               |
|Include                           |sshd_config_include                     |include                               |
|IPQoS                             |                                        |ip_qos                                |
|KbdInteractiveAuthentication      |                                        |kbd_interactive_authentication        |
|KerberosAuthentication            |sshd_kerberos_authentication            |kerberos_authentication               |
|KerberosGetAFSToken               |                                        |kerberos_get_afs_token                |
|KerberosOrLocalPasswd             |                                        |kerberos_or_local_passwd              |
|KerberosTicketCleanup             |                                        |kerberos_ticket_cleanup               |
|KexAlgorithms                     |sshd_config_kexalgorithms               |kex_algorithms                        |
|ListenAddress                     |sshd_listen_address                     |listen_address                        |
|LoginGraceTime                    |sshd_config_login_grace_time            |login_grace_time                      |
|LogLevel                          |sshd_config_loglevel                    |log_level                             |
|LogVerbose                        |                                        |log_verbose                           |
|MACs                              |sshd_config_macs                        |macs                                  |
|MaxAuthTries                      |sshd_config_maxauthtries                |max_auth_tries                        |
|MaxSessions                       |sshd_config_maxsessions                 |max_sessions                          |
|MaxStartups                       |sshd_config_maxstartups                 |max_startups                          |
|ModuliFile                        |                                        |moduli_file                           |
|PasswordAuthentication            |sshd_password_authentication            |password_authentication               |
|PermitEmptyPasswords              |sshd_config_permitemptypasswords        |permit_empty_passwords                |
|PermitListen                      |                                        |permit_listen                         |
|PermitOpen                        |                                        |permit_open                           |
|PermitRootLogin                   |permit_root_login                       |permit_root_login                     |
|PermitTTY                         |                                        |permit_tty                            |
|PermitTunnel                      |sshd_config_permittunnel                |permit_tunnel                         |
|PermitUserEnvironment             |sshd_config_permituserenvironment       |permit_user_environment               |
|PermitUserRC                      |                                        |permit_user_rc                        |
|PerSourceMaxStartups              |                                        |per_source_max_startups               |
|PerSourceNetBlockSize             |                                        |per_source_net_block_size             |
|PidFile                           |                                        |pid_file                              |
|Port                              |sshd_config_port                        |port                                  |
|PrintLastLog                      |sshd_config_print_last_log              |print_last_log                        |
|PrintMotd                         |sshd_config_print_motd                  |print_motd                            |
|PubkeyAcceptedAlgorithms          |sshd_pubkeyacceptedkeytypes             |pubkey_accepted_algorithms            |
|PubkeyAuthentication              |sshd_pubkeyauthentication               |pubkey_authentication                 |
|PubkeyAuthOptions                 |                                        |pubkey_auth_options                   |
|RekeyLimit                        |                                        |rekey_limit                           |
|RevokedKeys                       |sshd_config_key_revocation_list         |revoked_keys                          |
|RDomain                           |                                        |rdomain                               |
|SecurityKeyProvider               |                                        |security_key_provider                 |
|SetEnv                            |                                        |set_env                               |
|StreamLocalBindMask               |                                        |stream_local_bind_mask                |
|StreamLocalBindUnlink             |                                        |stream_local_bind_unlink              |
|StrictModes                       |sshd_config_strictmodes                 |strict_modes                          |
|Subsystem sftp                    |sshd_config_subsystem_sftp              |subsystem (in v3 'sftp' was included) |
|SyslogFacility                    |sshd_config_syslog_facility             |syslog_facility                       |
|TCPKeepAlive                      |sshd_config_tcp_keepalive               |tcp_keep_alive                        |
|TrustedUserCAKeys                 |sshd_config_trustedusercakeys           |trusted_user_ca_keys                  |
|UseDNS                            |sshd_config_use_dns                     |use_dns                               |
|UsePAM                            |sshd_use_pam                            |use_pam                               |
|VersionAddendum                   |                                        |version_addendum                      |
|X11DisplayOffset                  |                                        |x11_display_offset                    |
|X11Forwarding                     |sshd_x11_forwarding                     |x11_forwarding                        |
|X11UseLocalhost                   |sshd_x11_use_localhost                  |x11_use_localhost                     |
|XAuthLocation                     |sshd_config_xauth_location              |xauth_location                        |
|**removed**                       |                                        |                                      |
|Match                             |sshd_config_match                       |use $custom instead                   |
|UsePrivilegeSeparation            |sshd_config_use_privilege_separation    |use $custom instead                   |
|GSSAPIKeyExchange                 |sshd_gssapikeyexchange                  |use $custom instead                   |
|PAMAuthenticationViaKBDInt        |sshd_pamauthenticationviakbdint         |use $custom instead                   |
|ServerKeyBits                     |sshd_config_serverkeybits               |use $custom instead                   |
