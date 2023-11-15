# @summary Class to manage SSH server
#
# Notes: `Match` attribute is not directly supported as multiple match blocks can
# exist. Use the `custom` parameter for that.
#
# @param banner_content
#   Content of SSHd banner file.
#
# @param banner_group
#   User group used for SSHd banner file.
#
# @param banner_mode
#   File mode used for SSHd banner file.
#
# @param banner_owner
#   User/Owner used for SSHd banner file.
#
# @param banner_path
#   Absolute path to SSHd banner file.
#
# @param config_group
#   User group used for sshd_config file.
#
# @param config_mode
#   File mode used for sshd_config file.
#
# @param config_owner
#   User/Owner used for sshd_config file.
#
# @param config_path
#   Absolute path to sshd_config file.
#
# @param manage_service
#   Boolean to choose if the SSH daemon should be managed.
#
# @param manage_packages
#   Boolean to choose if SSH client packages should be managed.
#
# @param packages
#   Installation package(s) for the SSH server. Leave empty if the client package(s) also
#   include the server binaries (eg: Suse SLES and SLED).
#
# @param packages_ensure
#   Ensure parameter to SSH server package(s).
#
# @param packages_adminfile
#   Path to adminfile for SSH server package(s) installation. Needed for Solaris.
#
# @param packages_source
#   Source to SSH server package(s). Needed for Solaris.
#
# @param service_enable
#   enable attribure for SSH daemon.
#
# @param service_ensure
#   ensure attribute for SSH daemon.
#
# @param service_hasrestart
#   hasrestart attribute for SSH daemon.
#
# @param service_hasstatus
#   hasstatus attribute for SSH daemon.
#
# @param config_files
#   Hash of configuration entries passed to ssh::config_file_server define.
#   Please check the docs for ssh::config_file_client and the type Ssh::Sshd_Config
#   for a list and details of the parameters usable here.
#
# @param service_name
#   Name of the SSH daemon.
#
# @param accept_env
#   Value(s) passed to AcceptEnv parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AcceptEnv for possible values.
#
# @param address_family
#   Value(s) passed to AddressFamily parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AddressFamily for possible values.
#
# @param allow_agent_forwarding
#   Value(s) passed to AllowAgentForwarding parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AllowAgentForwarding for possible values.
#
# @param allow_groups
#   Value(s) passed to AllowGroups parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AllowGroups for possible values.
#
# @param allow_stream_local_forwarding
#   Value(s) passed to AllowStreamLocalForwarding parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AllowStreamLocalForwarding for possible values.
#
# @param allow_tcp_forwarding
#   Value(s) passed to AllowTcpForwarding parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AllowTcpForwarding for possible values.
#
# @param allow_users
#   Value(s) passed to AllowUsers parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AllowUsers for possible values.
#
# @param authentication_methods
#   Value(s) passed to AuthenticationMethods parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AuthenticationMethods for possible values.
#
# @param authorized_keys_command
#   Value(s) passed to AuthorizedKeysCommand parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AuthorizedKeysCommand for possible values.
#
# @param authorized_keys_command_user
#   Value(s) passed to AuthorizedKeysCommandUser parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AuthorizedKeysCommandUser for possible values.
#
# @param authorized_keys_file
#   Value(s) passed to AuthorizedKeysFile parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AuthorizedKeysFile for possible values.
#
# @param authorized_principals_command
#   Value(s) passed to AuthorizedPrincipalsCommand parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AuthorizedPrincipalsCommand for possible values.
#
# @param authorized_principals_command_user
#   Value(s) passed to AuthorizedPrincipalsCommandUser parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AuthorizedPrincipalsCommandUser for possible values.
#
# @param authorized_principals_file
#   Value(s) passed to AuthorizedPrincipalsFile parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#AuthorizedPrincipalsFile for possible values.
#
# @param banner
#   Value(s) passed to Banner parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#Banner for possible values.
#
# @param ca_signature_algorithms
#   Value(s) passed to CASignatureAlgorithms parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#CASignatureAlgorithms for possible values.
#
# @param challenge_response_authentication
#   Value(s) passed to ChallengeResponseAuthentication parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#KbdInteractiveAuthentication for possible values.
#
# @param chroot_directory
#   Value(s) passed to ChrootDirectory parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#ChrootDirectory for possible values.
#
# @param ciphers
#   Value(s) passed to Ciphers parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#Ciphers for possible values.
#
# @param client_alive_count_max
#   Value(s) passed to ClientAliveCountMax parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#ClientAliveCountMax for possible values.
#
# @param client_alive_interval
#   Value(s) passed to ClientAliveInterval parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#ClientAliveInterval for possible values.
#
# @param compression
#   Value(s) passed to Compression parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#Compression for possible values.
#
# @param deny_groups
#   Value(s) passed to DenyGroups parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#DenyGroups for possible values.
#
# @param deny_users
#   Value(s) passed to DenyUsers parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#DenyUsers for possible values.
#
# @param disable_forwarding
#   Value(s) passed to DisableForwarding parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#DisableForwarding for possible values.
#
# @param expose_auth_info
#   Value(s) passed to ExposeAuthInfo parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#ExposeAuthInfo for possible values.
#
# @param fingerprint_hash
#   Value(s) passed to FingerprintHash parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#FingerprintHash for possible values.
#
# @param force_command
#   Value(s) passed to ForceCommand parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#ForceCommand for possible values.
#
# @param gateway_ports
#   Value(s) passed to GatewayPorts parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#GatewayPorts for possible values.
#
# @param gss_api_authentication
#   Value(s) passed to GSSAPIAuthentication parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#GSSAPIAuthentication for possible values.
#
# @param gss_api_cleanup_credentials
#   Value(s) passed to GSSAPICleanupCredentials parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#GSSAPICleanupCredentials for possible values.
#
# @param gss_api_strict_acceptor_check
#   Value(s) passed to GSSAPIStrictAcceptorCheck parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#GSSAPIStrictAcceptorCheck for possible values.
#
# @param hostbased_accepted_algorithms
#   Value(s) passed to HostbasedAcceptedAlgorithms parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#HostbasedAcceptedAlgorithms for possible values.
#
# @param hostbased_authentication
#   Value(s) passed to HostbasedAuthentication parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#HostbasedAuthentication for possible values.
#
# @param hostbased_uses_name_from_packet_only
#   Value(s) passed to HostbasedUsesNameFromPacketOnly parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#HostbasedUsesNameFromPacketOnly for possible values.
#
# @param host_certificate
#   Value(s) passed to HostCertificate parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#HostCertificate for possible values.
#
# @param host_key
#   Value(s) passed to HostKey parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#HostKey for possible values.
#
# @param host_key_agent
#   Value(s) passed to HostKeyAgent parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#HostKeyAgent for possible values.
#
# @param host_key_algorithms
#   Value(s) passed to HostKeyAlgorithms parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#HostKeyAlgorithms for possible values.
#
# @param ignore_rhosts
#   Value(s) passed to IgnoreRhosts parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#IgnoreRhosts for possible values.
#
# @param ignore_user_known_hosts
#   Value(s) passed to IgnoreUserKnownHosts parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#IgnoreUserKnownHosts for possible values.
#
# @param include
#   Value(s) passed to Include parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#Include for possible values.
#
# @param include_dir_owner
#   The owner of the include directory
#
# @param include_dir_group
#   The group of the include directory
#
# @param include_dir_mode
#   The mode of the include directory
#
# @param include_dir_purge
#   Sets whether to purge the include_dir of unmanaged files
#
# @param ip_qos
#   Value(s) passed to IPQoS parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#IPQoS for possible values.
#
# @param kbd_interactive_authentication
#   Value(s) passed to KbdInteractiveAuthentication parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#KbdInteractiveAuthentication for possible values.
#
# @param kerberos_authentication
#   Value(s) passed to KerberosAuthentication parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#KerberosAuthentication for possible values.
#
# @param kerberos_get_afs_token
#   Value(s) passed to KerberosGetAFSToken parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#KerberosGetAFSToken for possible values.
#
# @param kerberos_or_local_passwd
#   Value(s) passed to KerberosOrLocalPasswd parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#KerberosOrLocalPasswd for possible values.
#
# @param kerberos_ticket_cleanup
#   Value(s) passed to KerberosTicketCleanup parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#KerberosTicketCleanup for possible values.
#
# @param kex_algorithms
#   Value(s) passed to KexAlgorithms parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#KexAlgorithms for possible values.
#
# @param listen_address
#   Value(s) passed to ListenAddress parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#ListenAddress for possible values.
#
# @param login_grace_time
#   Value(s) passed to LoginGraceTime parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#LoginGraceTime for possible values.
#
# @param log_level
#   Value(s) passed to LogLevel parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#LogLevel for possible values.
#
# @param log_verbose
#   Value(s) passed to LogVerbose parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#LogVerbose for possible values.
#
# @param macs
#   Value(s) passed to MACs parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#MACs for possible values.
#
# @param max_auth_tries
#   Value(s) passed to MaxAuthTries parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#MaxAuthTries for possible values.
#
# @param max_sessions
#   Value(s) passed to MaxSessions parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#MaxSessions for possible values.
#
# @param max_startups
#   Value(s) passed to MaxStartups parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#MaxStartups for possible values.
#
# @param moduli_file
#   Value(s) passed to ModuliFile parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#ModuliFile for possible values.
#
# @param password_authentication
#   Value(s) passed to PasswordAuthentication parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PasswordAuthentication for possible values.
#
# @param permit_empty_passwords
#   Value(s) passed to PermitEmptyPasswords parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PermitEmptyPasswords for possible values.
#
# @param permit_listen
#   Value(s) passed to PermitListen parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PermitListen for possible values.
#
# @param permit_open
#   Value(s) passed to PermitOpen parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PermitOpen for possible values.
#
# @param permit_root_login
#   Value(s) passed to PermitRootLogin parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PermitRootLogin for possible values.
#
# @param permit_tty
#   Value(s) passed to PermitTTY parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PermitTTY for possible values.
#
# @param permit_tunnel
#   Value(s) passed to PermitTunnel parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PermitTunnel for possible values.
#
# @param permit_user_environment
#   Value(s) passed to PermitUserEnvironment parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PermitUserEnvironment for possible values.
#
# @param permit_user_rc
#   Value(s) passed to PermitUserRC parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PermitUserRC for possible values.
#
# @param per_source_max_startups
#   Value(s) passed to PerSourceMaxStartups parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PerSourceMaxStartups for possible values.
#
# @param per_source_net_block_size
#   Value(s) passed to PerSourceNetBlockSize parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PerSourceNetBlockSize for possible values.
#
# @param pid_file
#   Value(s) passed to PidFile parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PidFile for possible values.
#
# @param port
#   Value(s) passed to Port parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#Port for possible values.
#
# @param print_last_log
#   Value(s) passed to PrintLastLog parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PrintLastLog for possible values.
#
# @param print_motd
#   Value(s) passed to PrintMotd parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PrintMotd for possible values.
#
# @param pubkey_accepted_algorithms
#   Value(s) passed to PubkeyAcceptedAlgorithms parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PubkeyAcceptedAlgorithms for possible values.
#
# @param pubkey_auth_options
#   Value(s) passed to PubkeyAuthOptions parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PubkeyAuthOptions for possible values.
#
# @param pubkey_authentication
#   Value(s) passed to PubkeyAuthentication parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#PubkeyAuthentication for possible values.
#
# @param rekey_limit
#   Value(s) passed to RekeyLimit parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#RekeyLimit for possible values.
#
# @param revoked_keys
#   Value(s) passed to RevokedKeys parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#RevokedKeys for possible values.
#
# @param rdomain
#   Value(s) passed to RDomain parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#RDomain for possible values.
#
# @param security_key_provider
#   Value(s) passed to SecurityKeyProvider parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#SecurityKeyProvider for possible values.
#
# @param set_env
#   Value(s) passed to SetEnv parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#SetEnv for possible values.
#
# @param stream_local_bind_mask
#   Value(s) passed to StreamLocalBindMask parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#StreamLocalBindMask for possible values.
#
# @param stream_local_bind_unlink
#   Value(s) passed to StreamLocalBindUnlink parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#StreamLocalBindUnlink for possible values.
#
# @param strict_modes
#   Value(s) passed to StrictModes parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#StrictModes for possible values.
#
# @param subsystem
#   Value(s) passed to Subsystem parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#Subsystem for possible values.
#
# @param syslog_facility
#   Value(s) passed to SyslogFacility parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#SyslogFacility for possible values.
#
# @param tcp_keep_alive
#   Value(s) passed to TCPKeepAlive parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#TCPKeepAlive for possible values.
#
# @param trusted_user_ca_keys
#   Value(s) passed to TrustedUserCAKeys parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#TrustedUserCAKeys for possible values.
#
# @param use_dns
#   Value(s) passed to UseDNS parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#UseDNS for possible values.
#
# @param use_pam
#   Value(s) passed to UsePAM parameter in sshd_config. Unused if empty.
#   Possible values are 'yes' and 'no'.
#   There is no mentioning of this parameter in the current man pages of OpenSSH v7.
#   But it is mentioned in the release notes of OpenSSH v8. https://www.openssh.com/txt/release-8.0
#
# @param version_addendum
#   Value(s) passed to VersionAddendum parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#VersionAddendum for possible values.
#
# @param x11_display_offset
#   Value(s) passed to X11DisplayOffset parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#X11DisplayOffset for possible values.
#
# @param x11_forwarding
#   Value(s) passed to X11Forwarding parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#X11Forwarding for possible values.
#
# @param x11_use_localhost
#   Value(s) passed to X11UseLocalhost parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#X11UseLocalhost for possible values.
#
# @param xauth_location
#   Value(s) passed to XAuthLocation parameter in sshd_config. Unused if empty.
#   Check https://man.openbsd.org/sshd_config#XAuthLocation for possible values.
#
# @param custom
#   Array of custom lines to be added to server configuration file sshd_config.
#   Uses one array item per line to be added.
#
class ssh::server (
  Boolean $manage_packages = true,
  Array[String[1]] $packages = [],
  Variant[Enum['present', 'absent', 'purged', 'disabled', 'installed', 'latest'], String[1]] $packages_ensure = 'installed',
  Optional[Stdlib::Absolutepath] $packages_adminfile = undef,
  Optional[Stdlib::Absolutepath] $packages_source = undef,
  Stdlib::Absolutepath $config_path = '/etc/ssh/sshd_config',
  String[1] $config_owner = 'root',
  String[1] $config_group = 'root',
  Stdlib::Filemode $config_mode = '0600',
  Stdlib::Absolutepath $banner_path = '/etc/sshd_banner',
  Optional[String[1]] $banner_content = undef,
  String[1] $banner_owner = 'root',
  String[1] $banner_group = 'root',
  Stdlib::Filemode $banner_mode = '0644',
  Boolean $manage_service = true,
  Stdlib::Ensure::Service $service_ensure = 'running',
  String[1] $service_name = 'sshd',
  Boolean $service_enable = true,
  Boolean $service_hasrestart = true,
  Boolean $service_hasstatus = true,
  Hash $config_files = {},
  # all paramters below this line are for sshd_config
  Optional[Array[String[1]]] $accept_env = undef,
  Optional[Enum['any', 'inet', 'inet6']] $address_family = undef,
  Optional[Ssh::Yes_no] $allow_agent_forwarding = undef,
  Optional[Array[String[1]]] $allow_groups = undef,
  Optional[Enum['yes', 'all', 'no', 'local', 'remote']] $allow_stream_local_forwarding = undef,
  Optional[Enum['yes', 'no', 'local', 'remote']] $allow_tcp_forwarding = undef,
  Optional[Array[String[1]]] $allow_users = undef,
  Optional[Array[String[1]]] $authentication_methods = undef,
  Optional[String[1]] $authorized_keys_command = undef,
  Optional[String[1]] $authorized_keys_command_user = undef,
  Optional[Array[String[1]]] $authorized_keys_file = undef,
  Optional[String[1]] $authorized_principals_command = undef,
  Optional[String[1]] $authorized_principals_command_user = undef,
  Optional[String[1]] $authorized_principals_file = undef,
  Optional[String[1]] $banner = undef,
  Optional[Array[String[1]]] $ca_signature_algorithms = undef,
  Optional[Ssh::Yes_no] $challenge_response_authentication = undef,
  Optional[String[1]] $chroot_directory = undef,
  Optional[Array[String[1]]] $ciphers = undef,
  Optional[Integer[0]] $client_alive_count_max = undef,
  Optional[Integer[0]] $client_alive_interval = undef,
  Optional[Enum['yes', 'delayed', 'no']] $compression = undef,
  Optional[Array[String[1]]] $deny_groups = undef,
  Optional[Array[String[1]]] $deny_users = undef,
  Optional[Ssh::Yes_no] $disable_forwarding = undef,
  Optional[Ssh::Yes_no] $expose_auth_info = undef,
  Optional[Enum['md5', 'sha256']] $fingerprint_hash = undef,
  Optional[String[1]] $force_command = undef,
  Optional[Enum['no', 'yes', 'clientspecified']] $gateway_ports = undef,
  Optional[Ssh::Yes_no] $gss_api_authentication = undef,
  Optional[Ssh::Yes_no] $gss_api_cleanup_credentials = undef,
  Optional[Ssh::Yes_no] $gss_api_strict_acceptor_check = undef,
  Optional[Array[String[1]]] $hostbased_accepted_algorithms = undef,
  Optional[Ssh::Yes_no] $hostbased_authentication = undef,
  Optional[Ssh::Yes_no] $hostbased_uses_name_from_packet_only = undef,
  Optional[Array[String[1]]] $host_certificate = undef,
  Optional[Array[String[1]]] $host_key = undef,
  Optional[String[1]] $host_key_agent = undef,
  Optional[Array[String[1]]] $host_key_algorithms = undef,
  Optional[Ssh::Yes_no] $ignore_rhosts = undef,
  Optional[Ssh::Yes_no] $ignore_user_known_hosts = undef,
  Optional[Stdlib::Absolutepath] $include = undef,
  String[1] $include_dir_owner = 'root',
  String[1] $include_dir_group = 'root',
  Stdlib::Filemode $include_dir_mode = '0700',
  Boolean $include_dir_purge = true,
  Optional[String[1]] $ip_qos = undef,
  Optional[Ssh::Yes_no] $kbd_interactive_authentication = undef,
  Optional[Ssh::Yes_no] $kerberos_authentication = undef,
  Optional[Ssh::Yes_no] $kerberos_get_afs_token = undef,
  Optional[Ssh::Yes_no] $kerberos_or_local_passwd = undef,
  Optional[Ssh::Yes_no] $kerberos_ticket_cleanup = undef,
  Optional[Array[String[1]]] $kex_algorithms = undef,
  Optional[Array[String[1]]] $listen_address = undef,
  Optional[Integer[0]] $login_grace_time = undef,
  Optional[Ssh::Log_level] $log_level = undef,
  Optional[String[1]] $log_verbose = undef,
  Optional[Array[String[1]]] $macs = undef,
  Optional[Integer[2]] $max_auth_tries = undef,
  Optional[Integer[0]] $max_sessions = undef,
  Optional[String[1]] $max_startups = undef,
  Optional[Stdlib::Absolutepath] $moduli_file = undef,
  Optional[Ssh::Yes_no] $password_authentication = undef,
  Optional[Ssh::Yes_no] $permit_empty_passwords = undef,
  Optional[Array[String[1]]] $permit_listen = undef,
  Optional[Array[String[1]]] $permit_open = undef,
  Optional[Ssh::Permit_root_login] $permit_root_login = undef,
  Optional[Ssh::Yes_no] $permit_tty = undef,
  Optional[Enum['yes', 'point-to-point', 'ethernet', 'no']] $permit_tunnel = undef,
  Optional[String[1]] $permit_user_environment = undef,
  Optional[Ssh::Yes_no] $permit_user_rc = undef,
  Optional[String[1]] $per_source_max_startups = undef,
  Optional[String[1]] $per_source_net_block_size = undef,
  Optional[String[1]] $pid_file = undef,
  Optional[Array[Stdlib::Port]] $port = undef,
  Optional[Ssh::Yes_no] $print_last_log = undef,
  Optional[Ssh::Yes_no] $print_motd = undef,
  Optional[Array[String[1]]] $pubkey_accepted_algorithms = undef,
  Optional[Enum['none', 'touch-required', 'verify-required']] $pubkey_auth_options = undef,
  Optional[Ssh::Yes_no] $pubkey_authentication = undef,
  Optional[String[1]] $rekey_limit = undef,
  Optional[String[1]] $revoked_keys = undef,
  Optional[String[1]] $rdomain = undef,
  Optional[Stdlib::Absolutepath] $security_key_provider = undef,
  Optional[Array[String[1]]] $set_env = undef,
  Optional[Pattern[/^[0-7]{4}$/]] $stream_local_bind_mask = undef,
  Optional[Ssh::Yes_no] $stream_local_bind_unlink = undef,
  Optional[Ssh::Yes_no] $strict_modes = undef,
  Optional[String[1]] $subsystem = undef,
  Optional[Ssh::Syslog_facility] $syslog_facility = undef,
  Optional[Ssh::Yes_no] $tcp_keep_alive = undef,
  Optional[String[1]] $trusted_user_ca_keys = undef,
  Optional[Ssh::Yes_no] $use_dns = undef,
  Optional[Ssh::Yes_no] $use_pam = undef,
  Optional[String[1]] $version_addendum = undef,
  Optional[Integer[0]] $x11_display_offset = undef,
  Optional[Ssh::Yes_no] $x11_forwarding = undef,
  Optional[Ssh::Yes_no] $x11_use_localhost = undef,
  Optional[String[1]] $xauth_location = undef,
  # custom is a string that allows for multiple lines to be appended to end of
  # the sshd_config file.
  Optional[Array[String[1]]] $custom = undef,
) {
  if $manage_packages {
    package { $packages:
      ensure    => $packages_ensure,
      source    => $packages_source,
      adminfile => $packages_adminfile,
      before    => 'File[sshd_config]',
    }
    $packages_require = Package[$packages]
  } else {
    $packages_require = undef
  }

  if $manage_service {
    $notify_service = Service['sshd_service']
  } else {
    $notify_service = undef
  }

  file { 'sshd_config' :
    ensure  => file,
    path    => $config_path,
    mode    => $config_mode,
    owner   => $config_owner,
    group   => $config_group,
    content => template('ssh/sshd_config.erb'),
  }

  if $include {
    $include_dir = dirname($include)
    file { 'sshd_config_include_dir':
      ensure  => 'directory',
      path    => $include_dir,
      owner   => $include_dir_owner,
      group   => $include_dir_group,
      mode    => $include_dir_mode,
      purge   => $include_dir_purge,
      recurse => $include_dir_purge,
      force   => $include_dir_purge,
      require => $packages_require,
      notify  => $notify_service,
    }
  } else {
    $include_dir = undef
  }

  if $banner_content != undef {
    file { 'sshd_banner' :
      ensure  => file,
      path    => $banner_path,
      owner   => $banner_owner,
      group   => $banner_group,
      mode    => $banner_mode,
      content => $banner_content,
      require => 'File[sshd_config]',
    }
  }

  if $manage_service {
    service { 'sshd_service' :
      ensure     => $service_ensure,
      name       => $service_name,
      enable     => $service_enable,
      hasrestart => $service_hasrestart,
      hasstatus  => $service_hasstatus,
      subscribe  => File['sshd_config'],
    }
  }

  $config_files.each |$file, $lines| {
    ssh::config_file_server { $file:
      * => $lines,
    }
  }
}
