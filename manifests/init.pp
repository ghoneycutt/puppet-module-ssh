# @summary Class to manage SSH client
#
# Notes: `Match` and `Host` attributes are not directly supported as multiple
# match/host blocks can exist. Use the `custom` parameter for that.
#
# @param config_entries
#   Hash of configuration entries passed to ssh::config_entries define.
#   Please check the docs for ssh::config_entries for a list and details
#   of the parameters usable here.
#
# @param config_group
#   User group used for ssh_config file.
#
# @param config_mode
#   File mode used for ssh_config file.
#
# @param config_owner
#   User/Owner used for ssh_config file.
#
# @param config_path
#   Absolute path to ssh_config file.
#
# @param global_known_hosts_group
#   User group used for global used known_hosts file.
#
# @param global_known_hosts_mode
#   File mode used for global used known_hosts file.
#
# @param global_known_hosts_owner
#   User/Owner used for global used known_hosts file.
#
# @param global_known_hosts_path
#   Absolute path to global used known_hosts file.
#
# @param keys
#   Hash of keys to be added to ~/.ssh/authorized_keys for users.
#
# @param manage_global_known_hosts
#   Boolean to choose if the global used known hosts file should be managed.
#
# @param manage_root_ssh_config
#   Boolean to choose if the ssh_config file of root should be managed.
#
# @param manage_server
#   Boolean to choose if the SSH daemon and its configuration should be managed.
#
# @param manage_sshkey
#   Boolean to choose if SSH keys should be managed. Also see $purge_keys.
#
# @param packages
#   Installation package(s) for the SSH client.
#
# @param packages_adminfile
#   Path to adminfile for SSH client package(s) installation. Needed for Solaris.
#
# @param packages_source
#   Source to SSH client package(s). Needed for Solaris.
#
# @param purge_keys
#   If SSH keys not managed by Puppet should get removed. Also see $manage_sshkey.
#
# @param root_ssh_config_content
#   Content of the ssh_config file of root.
#
# @param host
#   Value(s) passed to Host parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#Host for possible values.
#
# @param add_keys_to_agent
#   Value(s) passed to AddKeysToAgent parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#AddKeysToAgent for possible values.
#
# @param address_family
#   Value(s) passed to AddressFamily parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#AddressFamily for possible values.
#
# @param batch_mode
#   Value(s) passed to BatchMode parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#BatchMode for possible values.
#
# @param bind_address
#   Value(s) passed to BindAddress parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#BindAddress for possible values.
#
# @param bind_interface
#   Value(s) passed to BindInterface parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#BindInterface for possible values.
#
# @param canonical_domains
#   Value(s) passed to CanonicalDomains parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#CanonicalDomains for possible values.
#
# @param canonicalize_fallback_local
#   Value(s) passed to CanonicalizeFallbackLocal parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#CanonicalizeFallbackLocal for possible values.
#
# @param canonicalize_hostname
#   Value(s) passed to CanonicalizeHostname parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#CanonicalizeHostname for possible values.
#
# @param canonicalize_max_dots
#   Value(s) passed to CanonicalizeMaxDots parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#CanonicalizeMaxDots for possible values.
#
# @param canonicalize_permitted_cnames
#   Value(s) passed to CanonicalizePermittedCNAMEs parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#CanonicalizePermittedCNAMEs for possible values.
#
# @param ca_signature_algorithms
#   Value(s) passed to CASignatureAlgorithms parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#CASignatureAlgorithms for possible values.
#
# @param certificate_file
#   Value(s) passed to CertificateFile parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#CertificateFile for possible values.
#
# @param check_host_ip
#   Value(s) passed to CheckHostIP parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#CheckHostIP for possible values.
#
# @param ciphers
#   Value(s) passed to Ciphers parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#Ciphers for possible values.
#
# @param clear_all_forwardings
#   Value(s) passed to ClearAllForwardings parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ClearAllForwardings for possible values.
#
# @param compression
#   Value(s) passed to Compression parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#Compression for possible values.
#
# @param connection_attempts
#   Value(s) passed to ConnectionAttempts parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ConnectionAttempts for possible values.
#
# @param connect_timeout
#   Value(s) passed to ConnectTimeout parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ConnectTimeout for possible values.
#
# @param control_master
#   Value(s) passed to ControlMaster parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ControlMaster for possible values.
#
# @param control_path
#   Value(s) passed to ControlPath parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ControlPath for possible values.
#
# @param control_persist
#   Value(s) passed to ControlPersist parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ControlPersist for possible values.
#
# @param dynamic_forward
#   Value(s) passed to DynamicForward parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#DynamicForward for possible values.
#
# @param enable_ssh_keysign
#   Value(s) passed to EnableSSHKeysign parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#EnableSSHKeysign for possible values.
#
# @param escape_char
#   Value(s) passed to EscapeChar parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#EscapeChar for possible values.
#
# @param exit_on_forward_failure
#   Value(s) passed to ExitOnForwardFailure parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ExitOnForwardFailure for possible values.
#
# @param fingerprint_hash
#   Value(s) passed to FingerprintHash parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#FingerprintHash for possible values.
#
# @param fork_after_authentication
#   Value(s) passed to ForkAfterAuthentication parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ForkAfterAuthentication for possible values.
#
# @param forward_agent
#   Value(s) passed to ForwardAgent parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ForwardAgent for possible values.
#
# @param forward_x11
#   Value(s) passed to ForwardX11 parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ForwardX11 for possible values.
#
# @param forward_x11_timeout
#   Value(s) passed to ForwardX11Timeout parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ForwardX11Timeout for possible values.
#
# @param forward_x11_trusted
#   Value(s) passed to ForwardX11Trusted parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ForwardX11Trusted for possible values.
#
# @param gateway_ports
#   Value(s) passed to GatewayPorts parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#GatewayPorts for possible values.
#
# @param global_known_hosts_file
#   Value(s) passed to GlobalKnownHostsFile parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#GlobalKnownHostsFile for possible values.
#
# @param gss_api_authentication
#   Value(s) passed to GSSAPIAuthentication parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#GSSAPIAuthentication for possible values.
#
# @param gss_api_delegate_credentials
#   Value(s) passed to GSSAPIDelegateCredentials parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#GSSAPIDelegateCredentials for possible values.
#
# @param hash_known_hosts
#   Value(s) passed to HashKnownHosts parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#HashKnownHosts for possible values.
#
# @param hostbased_accepted_algorithms
#   Value(s) passed to HostbasedAcceptedAlgorithms parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#HostbasedAcceptedAlgorithms for possible values.
#
# @param hostbased_authentication
#   Value(s) passed to HostbasedAuthentication parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#HostbasedAuthentication for possible values.
#
# @param host_key_algorithms
#   Value(s) passed to HostKeyAlgorithms parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#HostKeyAlgorithms for possible values.
#
# @param host_key_alias
#   Value(s) passed to HostKeyAlias parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#HostKeyAlias for possible values.
#
# @param hostname
#   Value(s) passed to Hostname parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#Hostname for possible values.
#
# @param identities_only
#   Value(s) passed to IdentitiesOnly parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#IdentitiesOnly for possible values.
#
# @param identity_agent
#   Value(s) passed to IdentityAgent parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#IdentityAgent for possible values.
#
# @param identity_file
#   Value(s) passed to IdentityFile parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#IdentityFile for possible values.
#
# @param ignore_unknown
#   Value(s) passed to IgnoreUnknown parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#IgnoreUnknown for possible values.
#
# @param include
#   Value(s) passed to Include parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#Include for possible values.
#
# @param ip_qos
#   Value(s) passed to IPQoS parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#IPQoS for possible values.
#
# @param kbd_interactive_authentication
#   Value(s) passed to KbdInteractiveAuthentication parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#KbdInteractiveAuthentication for possible values.
#
# @param kbd_interactive_devices
#   Value(s) passed to KbdInteractiveDevices parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#KbdInteractiveDevices for possible values.
#
# @param kex_algorithms
#   Value(s) passed to KexAlgorithms parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#KexAlgorithms for possible values.
#
# @param kown_hosts_command
#   Value(s) passed to KnownHostsCommand parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#KnownHostsCommand for possible values.
#
# @param local_command
#   Value(s) passed to LocalCommand parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#LocalCommand for possible values.
#
# @param local_forward
#   Value(s) passed to LocalForward parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#LocalForward for possible values.
#
# @param log_level
#   Value(s) passed to LogLevel parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#LogLevel for possible values.
#
# @param log_verbose
#   Value(s) passed to LogVerbose parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#LogVerbose for possible values.
#
# @param macs
#   Value(s) passed to MACs parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#MACs for possible values.
#
# @param no_host_authentication_for_localhost
#   Value(s) passed to NoHostAuthenticationForLocalhost parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#NoHostAuthenticationForLocalhost for possible values.
#
# @param number_of_password_prompts
#   Value(s) passed to NumberOfPasswordPrompts parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#NumberOfPasswordPrompts for possible values.
#
# @param password_authentication
#   Value(s) passed to PasswordAuthentication parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#PasswordAuthentication for possible values.
#
# @param permit_local_command
#   Value(s) passed to PermitLocalCommand parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#PermitLocalCommand for possible values.
#
# @param permit_remote_open
#   Value(s) passed to PermitRemoteOpen parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#PermitRemoteOpen for possible values.
#
# @param pkcs11_provider
#   Value(s) passed to PKCS11Provider parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#PKCS11Provider for possible values.
#
# @param port
#   Value(s) passed to Port parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#Port for possible values.
#
# @param preferred_authentications
#   Value(s) passed to PreferredAuthentications parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#PreferredAuthentications for possible values.
#
# @param proxy_command
#   Value(s) passed to ProxyCommand parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ProxyCommand for possible values.
#
# @param proxy_jump
#   Value(s) passed to ProxyJump parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ProxyJump for possible values.
#
# @param proxy_use_fdpass
#   Value(s) passed to ProxyUseFdpass parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ProxyUseFdpass for possible values.
#
# @param pubkey_accepted_algorithms
#   Value(s) passed to PubkeyAcceptedAlgorithms parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#PubkeyAcceptedAlgorithms for possible values.
#
# @param pubkey_authentication
#   Value(s) passed to PubkeyAuthentication parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#PubkeyAuthentication for possible values.
#
# @param rekey_limit
#   Value(s) passed to RekeyLimit parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#RekeyLimit for possible values.
#
# @param remote_command
#   Value(s) passed to RemoteCommand parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#RemoteCommand for possible values.
#
# @param remote_forward
#   Value(s) passed to RemoteForward parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#RemoteForward for possible values.
#
# @param request_tty
#   Value(s) passed to RequestTTY parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#RequestTTY for possible values.
#
# @param revoked_host_keys
#   Value(s) passed to RevokedHostKeys parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#RevokedHostKeys for possible values.
#
# @param security_key_provider
#   Value(s) passed to SecurityKeyProvider parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#SecurityKeyProvider for possible values.
#
# @param send_env
#   Value(s) passed to SendEnv parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#SendEnv for possible values.
#
# @param server_alive_count_max
#   Value(s) passed to ServerAliveCountMax parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ServerAliveCountMax for possible values.
#
# @param server_alive_interval
#   Value(s) passed to ServerAliveInterval parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#ServerAliveInterval for possible values.
#
# @param session_type
#   Value(s) passed to SessionType parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#SessionType for possible values.
#
# @param set_env
#   Value(s) passed to SetEnv parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#SetEnv for possible values.
#
# @param stdin_null
#   Value(s) passed to StdinNull parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#StdinNull for possible values.
#
# @param stream_local_bind_mask
#   Value(s) passed to StreamLocalBindMask parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#StreamLocalBindMask for possible values.
#
# @param stream_local_bind_unlink
#   Value(s) passed to StreamLocalBindUnlink parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#StreamLocalBindUnlink for possible values.
#
# @param strict_host_key_checking
#   Value(s) passed to StrictHostKeyChecking parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#StrictHostKeyChecking for possible values.
#
# @param syslog_facility
#   Value(s) passed to SyslogFacility parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#SyslogFacility for possible values.
#
# @param tcp_keep_alive
#   Value(s) passed to TCPKeepAlive parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#TCPKeepAlive for possible values.
#
# @param tunnel
#   Value(s) passed to Tunnel parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#Tunnel for possible values.
#
# @param tunnel_device
#   Value(s) passed to TunnelDevice parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#TunnelDevice for possible values.
#
# @param update_host_keys
#   Value(s) passed to UpdateHostKeys parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#UpdateHostKeys for possible values.
#
# @param user
#   Value(s) passed to User parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#User for possible values.
#
# @param user_known_hosts_file
#   Value(s) passed to UserKnownHostsFile parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#UserKnownHostsFile for possible values.
#
# @param use_roaming
#   Value(s) passed to the UseRoaming parameter in ssh_config. Unused if empty.
#
# @param verify_host_key_dns
#   Value(s) passed to VerifyHostKeyDNS parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#VerifyHostKeyDNS for possible values.
#
# @param visual_host_key
#   Value(s) passed to VisualHostKey parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#VisualHostKey for possible values.
#
# @param xauth_location
#   Value(s) passed to XAuthLocation parameter in ssh_config. Unused if empty.
#   Check https://man.openbsd.org/ssh_config#XAuthLocation for possible values.
#
# @param custom
#   Array of custom lines to be added to client configuration file ssh_config.
#   Uses one array item per line to be added.
#
class ssh (
  Hash $config_entries = {},
  String[1] $config_group = 'root',
  Stdlib::Filemode $config_mode = '0644',
  String[1] $config_owner = 'root',
  Stdlib::Absolutepath $config_path = '/etc/ssh/ssh_config',
  String[1] $global_known_hosts_group = 'root',
  Stdlib::Filemode $global_known_hosts_mode = '0644',
  String[1] $global_known_hosts_owner = 'root',
  Stdlib::Absolutepath $global_known_hosts_path = '/etc/ssh/ssh_known_hosts',
  Hash $keys = {},
  Boolean $manage_global_known_hosts = true,
  Boolean $manage_root_ssh_config = false,
  Boolean $manage_server = true,
  Boolean $manage_sshkey = true,
  Array[String[1]] $packages = [],
  Optional[Stdlib::Absolutepath] $packages_adminfile = undef,
  Optional[Stdlib::Absolutepath] $packages_source = undef,
  Boolean $purge_keys = true,
  String[1] $root_ssh_config_content = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
  # class parameters below this line directly correlate with ssh_config parameters
  String[1] $host = '*',
  Optional[Enum['yes', 'no', 'ask', 'confirm']] $add_keys_to_agent = undef,
  Optional[Enum['any', 'inet', 'inet6']] $address_family = undef,
  Optional[Ssh::Yes_no] $batch_mode = undef,
  Optional[String[1]] $bind_address = undef,
  Optional[String[1]] $bind_interface = undef,
  Optional[Array[String[1]]] $canonical_domains = undef,
  Optional[Ssh::Yes_no] $canonicalize_fallback_local = undef,
  Optional[Enum['yes', 'no', 'always']] $canonicalize_hostname = undef,
  Optional[Integer[0]] $canonicalize_max_dots = undef,
  Optional[Array[String[1]]] $canonicalize_permitted_cnames = undef,
  Optional[Array[String[1]]] $ca_signature_algorithms = undef,
  Optional[Array[String[1]]] $certificate_file = undef,
  Optional[Ssh::Yes_no] $check_host_ip = undef,
  Optional[Array[String[1]]] $ciphers = undef,
  Optional[Ssh::Yes_no] $clear_all_forwardings = undef,
  Optional[Ssh::Yes_no] $compression = undef,
  Optional[Integer[0]] $connection_attempts = undef,
  Optional[Integer[0]] $connect_timeout = undef,
  Optional[Enum['yes', 'no', 'ask', 'auto', 'autoask']] $control_master = undef,
  Optional[String[1]] $control_path = undef,
  Optional[String[1]] $control_persist = undef,
  Optional[String[1]] $dynamic_forward = undef,
  Optional[Ssh::Yes_no] $enable_ssh_keysign = undef,
  Optional[String[1]] $escape_char = undef,
  Optional[Ssh::Yes_no] $exit_on_forward_failure = undef,
  Optional[Enum['sha256', 'md5']] $fingerprint_hash = undef,
  Optional[Ssh::Yes_no] $fork_after_authentication = undef,
  Optional[Ssh::Yes_no] $forward_agent = undef,
  Optional[Ssh::Yes_no] $forward_x11 = undef,
  Variant[Undef, String[1], Integer[0]] $forward_x11_timeout = undef,
  Optional[Ssh::Yes_no] $forward_x11_trusted = undef,
  Optional[Ssh::Yes_no] $gateway_ports = undef,
  Optional[Array[String[1]]] $global_known_hosts_file = undef,
  Optional[Ssh::Yes_no] $gss_api_authentication = undef,
  Optional[Ssh::Yes_no] $gss_api_delegate_credentials = undef,
  Optional[Ssh::Yes_no] $hash_known_hosts = undef,
  Optional[Array[String[1]]] $hostbased_accepted_algorithms = undef,
  Optional[Ssh::Yes_no] $hostbased_authentication = undef,
  Optional[Array[String[1]]] $host_key_algorithms = undef,
  Optional[String[1]] $host_key_alias = undef,
  Optional[String[1]] $hostname = undef,
  Optional[Ssh::Yes_no] $identities_only = undef,
  Optional[String[1]] $identity_agent = undef,
  Optional[Array[String[1]]] $identity_file = undef,
  Optional[Array[String[1]]] $ignore_unknown = undef,
  Optional[String[1]] $include = undef,
  Optional[String[1]] $ip_qos = undef,
  Optional[Ssh::Yes_no] $kbd_interactive_authentication = undef,
  Optional[Array[String[1]]] $kbd_interactive_devices = undef,
  Optional[Array[String[1]]] $kex_algorithms = undef,
  Optional[String[1]] $kown_hosts_command = undef,
  Optional[String[1]] $local_command = undef,
  Optional[String[1]] $local_forward = undef,
  Optional[Ssh::Log_level] $log_level = undef,
  Optional[String[1]] $log_verbose = undef,
  Optional[Array[String[1]]] $macs = undef,
  Optional[Ssh::Yes_no] $no_host_authentication_for_localhost = undef,
  Optional[Integer] $number_of_password_prompts = undef,
  Optional[Ssh::Yes_no] $password_authentication = undef,
  Optional[Ssh::Yes_no] $permit_local_command = undef,
  Optional[Array[String[1]]] $permit_remote_open = undef,
  Optional[String[1]] $pkcs11_provider = undef,
  Optional[Stdlib::Port] $port = undef,
  Optional[Array[String[1]]] $preferred_authentications = undef,
  Optional[String[1]] $proxy_command = undef,
  Optional[Array[String[1]]] $proxy_jump = undef,
  Optional[Ssh::Yes_no] $proxy_use_fdpass = undef,
  Optional[Array[String[1]]] $pubkey_accepted_algorithms = undef,
  Optional[Ssh::Yes_no] $pubkey_authentication = undef,
  Optional[String[1]] $rekey_limit = undef,
  Optional[String[1]] $remote_command = undef,
  Optional[String[1]] $remote_forward = undef,
  Optional[Enum['no', 'yes', 'force', 'auto']] $request_tty = undef,
  Optional[String[1]] $revoked_host_keys = undef,
  Optional[String[1]] $security_key_provider = undef,
  Optional[Array[String[1]]] $send_env = undef,
  Variant[Undef, String[1], Integer[0]] $server_alive_count_max = undef,
  Variant[Undef, String[1], Integer[0]] $server_alive_interval = undef,
  Optional[Enum['default', 'none', 'subsystem']] $session_type = undef,
  Optional[Array[String[1]]] $set_env = undef,
  Optional[Ssh::Yes_no] $stdin_null = undef,
  Optional[Pattern[/^[0-7]{4}$/]] $stream_local_bind_mask = undef,
  Optional[Ssh::Yes_no] $stream_local_bind_unlink = undef,
  Optional[Enum['yes', 'no', 'accept-new', 'off', 'ask']] $strict_host_key_checking = undef,
  Optional[Ssh::Syslog_facility] $syslog_facility = undef,
  Optional[Ssh::Yes_no] $tcp_keep_alive = undef,
  Optional[Enum['yes', 'no', 'point-to-point', 'ethernet']] $tunnel = undef,
  Optional[String[1]] $tunnel_device = undef,
  Optional[Enum['yes', 'no', 'ask']] $update_host_keys = undef,
  Optional[String[1]] $user = undef,
  Optional[Array[String[1]]] $user_known_hosts_file = undef,
  Optional[Ssh::Yes_no] $use_roaming = undef,
  Optional[Enum['yes', 'no', 'ask']] $verify_host_key_dns = undef,
  Optional[Ssh::Yes_no] $visual_host_key = undef,
  Optional[String[1]] $xauth_location = undef,
  # custom is a string that allows for multiple lines to be appended to end of
  # the ssh_config file.
  Optional[Array[String[1]]] $custom = undef
) {

  package { $packages:
    ensure    => installed,
    source    => $packages_source,
    adminfile => $packages_adminfile,
    before    => 'File[ssh_config]',
  }

  file { 'ssh_config' :
    ensure  => file,
    path    => $config_path,
    owner   => $config_owner,
    group   => $config_group,
    mode    => $config_mode,
    content => template('ssh/ssh_config.erb'),
  }

  if $manage_root_ssh_config == true {
    exec { "mkdir_p-${facts['root_home']}/.ssh":
      command => "mkdir -p ${facts['root_home']}/.ssh",
      unless  => "test -d ${facts['root_home']}/.ssh",
      path    => '/bin:/usr/bin',
    }

    file { 'root_ssh_dir':
      ensure  => directory,
      path    => "${facts['root_home']}/.ssh",
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
      require => Exec["mkdir_p-${facts['root_home']}/.ssh"],
    }

    file { 'root_ssh_config':
      ensure  => file,
      path    => "${facts['root_home']}/.ssh/config",
      content => $root_ssh_config_content,
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
    }
  }

  if $manage_global_known_hosts == true {
    file { 'global_known_hosts':
      ensure  => file,
      path    => $global_known_hosts_path,
      owner   => $global_known_hosts_owner,
      group   => $global_known_hosts_group,
      mode    => $global_known_hosts_mode,
      require => 'File[ssh_config]',
    }
  }

  # remove ssh key's not managed by puppet
  if $manage_sshkey == true {
    resources { 'sshkey':
      purge => $purge_keys,
    }
  }

  # manage users' ssh config entries if present
  $config_entries.each |$key,$values| {
    ssh::config_entry { $key:
      * => $values,
    }
  }

  # manage users' ssh authorized keys if present
  $keys.each |$key,$values| {
    ssh_authorized_key { $key:
      * => $values,
    }
  }

  if $manage_server == true {
    include ssh::server
  }
}
