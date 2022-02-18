# == Class: ssh
#
<<<<<<< HEAD
# Manage ssh client and server
=======
# Notes: `Match` and `Host` attributes are not directly supported as multiple
# match/host blocks can exist. Use the `custom` parameter for that.
#
# @param config_entries
#
# @param config_group
#
# @param config_mode
#
# @param config_owner
#
# @param config_path
#
# @param global_known_hosts_group
#
# @param global_known_hosts_mode
#
# @param global_known_hosts_owner
#
# @param global_known_hosts_path
#
# @param keys
#
# @param manage_global_known_hosts
#
# @param manage_root_ssh_config
#
# @param manage_server
#
# @param manage_sshkey
#
# @param package_adminfile
#
# @param packages
#
# @param package_source
#
# @param purge_keys
#
# @param root_ssh_config_content
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
#   TODO: missing in docs
#   Value(s) passed to  parameter in ssh_config. Unused if empty.
#   Check  for possible values.
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
>>>>>>> 2510367 (Use new variable names for ssh_config related params)
#
class ssh (
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
  $hiera_merge                                = false,
  $packages                                   = 'USE_DEFAULTS',
  $permit_root_login                          = 'yes',
  $purge_keys                                 = true,
  $manage_firewall                            = false,
  $ssh_package_source                         = 'USE_DEFAULTS',
  $ssh_package_adminfile                      = 'USE_DEFAULTS',
  $ssh_config_hash_known_hosts                = 'USE_DEFAULTS',
  $ssh_config_path                            = '/etc/ssh/ssh_config',
  $ssh_config_owner                           = 'root',
  $ssh_config_group                           = 'root',
  $ssh_config_mode                            = '0644',
  $ssh_config_forward_x11                     = undef,
  $ssh_config_forward_x11_trusted             = 'USE_DEFAULTS',
  $ssh_config_forward_agent                   = undef,
  $ssh_config_server_alive_interval           = undef,
  $ssh_config_sendenv_xmodifiers              = false,
  $ssh_hostbasedauthentication                = undef,
  $ssh_config_proxy_command                   = undef,
  $ssh_strict_host_key_checking               = undef,
  $ssh_config_ciphers                         = undef,
  $ssh_config_kexalgorithms                   = undef,
  $ssh_config_macs                            = undef,
  $ssh_config_use_roaming                     = 'USE_DEFAULTS',
  $ssh_config_template                        = 'ssh/ssh_config.erb',
  $ssh_sendenv                                = 'USE_DEFAULTS',
  $ssh_gssapiauthentication                   = 'yes',
  $ssh_gssapidelegatecredentials              = undef,
  $sshd_config_path                           = '/etc/ssh/sshd_config',
  $sshd_config_owner                          = 'root',
  $sshd_config_group                          = 'root',
  $sshd_config_loglevel                       = 'INFO',
  $sshd_config_mode                           = 'USE_DEFAULTS',
  $sshd_config_permitemptypasswords           = undef,
  $sshd_config_permituserenvironment          = undef,
  $sshd_config_compression                    = undef,
  $sshd_config_port                           = '22',
  $sshd_config_syslog_facility                = 'AUTH',
  $sshd_config_template                       = 'ssh/sshd_config.erb',
  $sshd_config_login_grace_time               = '120',
  $sshd_config_challenge_resp_auth            = 'yes',
  $sshd_config_print_motd                     = 'yes',
  $sshd_config_print_last_log                 = undef,
  $sshd_config_use_dns                        = 'USE_DEFAULTS',
  $sshd_config_authkey_location               = undef,
  $sshd_config_strictmodes                    = undef,
  $sshd_config_serverkeybits                  = 'USE_DEFAULTS',
  $sshd_config_banner                         = 'none',
  $sshd_config_ciphers                        = undef,
  $sshd_config_kexalgorithms                  = undef,
  $sshd_config_macs                           = undef,
  $ssh_enable_ssh_keysign                     = undef,
  $sshd_config_allowgroups                    = [],
  $sshd_config_allowusers                     = [],
  $sshd_config_denygroups                     = [],
  $sshd_config_denyusers                      = [],
  $sshd_config_maxauthtries                   = undef,
  $sshd_config_maxstartups                    = undef,
  $sshd_config_maxsessions                    = undef,
  $sshd_config_chrootdirectory                = undef,
  $sshd_config_forcecommand                   = undef,
  $sshd_config_match                          = undef,
  $sshd_authorized_keys_command               = undef,
  $sshd_authorized_keys_command_user          = undef,
  $sshd_banner_content                        = undef,
  $sshd_banner_owner                          = 'root',
  $sshd_banner_group                          = 'root',
  $sshd_banner_mode                           = '0644',
  $sshd_config_xauth_location                 = 'USE_DEFAULTS',
  $sshd_config_subsystem_sftp                 = 'USE_DEFAULTS',
  $sshd_kerberos_authentication               = undef,
  $sshd_password_authentication               = 'yes',
  $sshd_allow_tcp_forwarding                  = 'yes',
  $sshd_x11_forwarding                        = 'yes',
  $sshd_x11_use_localhost                     = 'yes',
  $sshd_use_pam                               = 'USE_DEFAULTS',
  $sshd_client_alive_count_max                = '3',
  $sshd_client_alive_interval                 = '0',
  $sshd_gssapiauthentication                  = 'yes',
  $sshd_gssapikeyexchange                     = 'USE_DEFAULTS',
  $sshd_pamauthenticationviakbdint            = 'USE_DEFAULTS',
  $sshd_gssapicleanupcredentials              = 'USE_DEFAULTS',
  $sshd_acceptenv                             = 'USE_DEFAULTS',
  $sshd_config_hostkey                        = 'USE_DEFAULTS',
  $sshd_listen_address                        = undef,
  $sshd_hostbasedauthentication               = 'no',
  $sshd_pubkeyacceptedkeytypes                = undef,
  $sshd_pubkeyauthentication                  = 'yes',
  $sshd_ignoreuserknownhosts                  = 'no',
  $sshd_ignorerhosts                          = 'yes',
  $sshd_config_authenticationmethods          = undef,
  $manage_service                             = true,
  $sshd_addressfamily                         = 'USE_DEFAULTS',
  $service_ensure                             = 'running',
  $service_name                               = 'USE_DEFAULTS',
  $service_enable                             = true,
  $service_hasrestart                         = true,
  $service_hasstatus                          = 'USE_DEFAULTS',
  $ssh_key_ensure                             = 'present',
  $ssh_key_export                             = true,
  $ssh_key_import                             = true,
  $ssh_key_type                               = 'ssh-rsa',
  $ssh_config_global_known_hosts_file         = '/etc/ssh/ssh_known_hosts',
  $ssh_config_global_known_hosts_list         = undef,
  $ssh_config_global_known_hosts_owner        = 'root',
  $ssh_config_global_known_hosts_group        = 'root',
  $ssh_config_global_known_hosts_mode         = '0644',
  $ssh_config_user_known_hosts_file           = undef,
  $ssh_config_include                         = 'USE_DEFAULTS',
  $config_entries                             = {},
  $keys                                       = undef,
  $manage_root_ssh_config                     = false,
  $root_ssh_config_content                    = "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
  $sshd_config_tcp_keepalive                  = undef,
  $sshd_config_use_privilege_separation       = undef,
  $sshd_config_permittunnel                   = undef,
  $sshd_config_hostcertificate                = undef,
  $sshd_config_trustedusercakeys              = undef,
  $sshd_config_key_revocation_list            = undef,
  $sshd_config_authorized_principals_file     = undef,
  $sshd_config_allowagentforwarding           = undef,
  $sshd_config_include                        = 'USE_DEFAULTS',
=======
  Variant[String[1], Array[String[1]]] $packages = 'openssh-clients',
=======
  Optional[Array[String[1]]] $packages = undef,
>>>>>>> c2b2b69 (Refactor package related params in main class)
=======
  Optional[Array[String[1]]] $packages = [],
>>>>>>> db859ce (Move data from main class to hiera)
  Optional[Stdlib::Absolutepath] $package_source = undef,
  Optional[Stdlib::Absolutepath] $package_adminfile = undef,
  Stdlib::Absolutepath $config_path = '/etc/ssh/ssh_config',
  String[1] $config_owner = 'root',
=======
  Hash $config_entries = {},
>>>>>>> 4bd4f3a (Sort parameters in main class alphabetically)
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
  Optional[Stdlib::Absolutepath] $package_adminfile = undef,
  Optional[Array[String[1]]] $packages = [],
  Optional[Stdlib::Absolutepath] $package_source = undef,
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
  # the sshd_config file.
  Optional[Array[String[1]]] $custom = undef
>>>>>>> f9cb674 (Change data type for $custom to array in main class)
) {

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
  case $::osfamily {
=======
  # TODO: This huge case statement is getting transitioned to hiera
  case $facts['os']['family'] {
>>>>>>> 879e814 (Adopt default settings from release 3.62.0)
    'RedHat': {
      $packages_default             = ['openssh-clients']
      $package_source_default       = undef
      $hash_known_hosts_default     = 'no'
      $forward_x11_trusted_default  = 'yes'
      $gss_api_authentication_default = 'yes'
      $send_env_default = ['LANG', 'LANGUAGE', 'LC_ADDRESS', 'LC_ALL', 'LC_COLLATE', 'LC_CTYPE', 'LC_IDENTIFICATION', 'LC_MEASUREMENT',
                            'LC_MESSAGES', 'LC_MONETARY', 'LC_NAME', 'LC_NUMERIC', 'LC_PAPER', 'LC_TELEPHONE', 'LC_TIME']
      $include_default              = undef
    }
    'Suse': {
      $packages_default                        = ['openssh']
      $package_source_default                  = undef
      $default_service_name                    = 'sshd'
      $hash_known_hosts_default     = 'no'
      $gss_api_authentication_default = 'yes'
      $send_env_default = ['LANG', 'LANGUAGE', 'LC_ADDRESS', 'LC_ALL', 'LC_COLLATE', 'LC_CTYPE', 'LC_IDENTIFICATION', 'LC_MEASUREMENT',
                            'LC_MESSAGES', 'LC_MONETARY', 'LC_NAME', 'LC_NUMERIC', 'LC_PAPER', 'LC_TELEPHONE', 'LC_TIME']
      $forward_x11_trusted_default  = 'yes'
      $include_default              = undef
    }
    'Debian': {
      case $::operatingsystemrelease {
        '14.04': {
          $packages_default                 = ['openssh-client']
          $package_source_default           = undef
          $hash_known_hosts_default        = 'no'
          $forward_x11_trusted_default     = 'yes'
          $include_default                 = undef
          $gss_api_authentication_default = 'yes'
          $send_env_default = ['LANG', 'LANGUAGE', 'LC_ADDRESS', 'LC_ALL', 'LC_COLLATE', 'LC_CTYPE', 'LC_IDENTIFICATION', 'LC_MEASUREMENT',
                                'LC_MESSAGES', 'LC_MONETARY', 'LC_NAME', 'LC_NUMERIC', 'LC_PAPER', 'LC_TELEPHONE', 'LC_TIME']
        }
        '16.04': {
          $packages_default                 = ['openssh-client']
          $package_source_default           = undef
          $hash_known_hosts_default        = 'yes'
          $gss_api_authentication_default = 'yes'
          $forward_x11_trusted_default     = 'yes'
          $send_env_default = ['LANG', 'LANGUAGE', 'LC_ADDRESS', 'LC_ALL', 'LC_COLLATE', 'LC_CTYPE', 'LC_IDENTIFICATION', 'LC_MEASUREMENT',
                                'LC_MESSAGES', 'LC_MONETARY', 'LC_NAME', 'LC_NUMERIC', 'LC_PAPER', 'LC_TELEPHONE', 'LC_TIME']
          $include_default                 = undef
        }
        '18.04': {
          $packages_default             = ['openssh-client']
          $package_source_default       = undef
          $hash_known_hosts_default        = 'yes'
          $gss_api_authentication_default = 'yes'
          $forward_x11_trusted_default     = 'yes'
          $send_env_default = ['LANG', 'LANGUAGE', 'LC_ADDRESS', 'LC_ALL', 'LC_COLLATE', 'LC_CTYPE', 'LC_IDENTIFICATION', 'LC_MEASUREMENT',
                                'LC_MESSAGES', 'LC_MONETARY', 'LC_NAME', 'LC_NUMERIC', 'LC_PAPER', 'LC_TELEPHONE', 'LC_TIME']
          $include_default                 = undef
<<<<<<< HEAD
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_acceptenv                     = true
          $default_service_hasstatus                  = true
          $default_sshd_config_serverkeybits          = '1024'
          $default_sshd_addressfamily                 = 'any'
          $default_sshd_config_tcp_keepalive          = 'yes'
          $default_sshd_config_permittunnel           = 'no'
          $default_sshd_config_include                = undef
<<<<<<< HEAD
=======
=======
>>>>>>> 4ae8446 (Remove server related data from main class)
        }
        '20.04': {
          $packages_default             = ['openssh-client']
          $package_source_default       = undef
          $forward_x11_trusted_default     = 'yes'
          $gss_api_authentication_default = 'yes'
          $hash_known_hosts_default        = 'yes'
          $include_default                 = '/etc/ssh/ssh_config.d/*.conf'
          $send_env_default = ['LANG', 'LANGUAGE', 'LC_ADDRESS', 'LC_ALL', 'LC_COLLATE', 'LC_CTYPE', 'LC_IDENTIFICATION', 'LC_MEASUREMENT',
                                'LC_MESSAGES', 'LC_MONETARY', 'LC_NAME', 'LC_NUMERIC', 'LC_PAPER', 'LC_TELEPHONE', 'LC_TIME']
<<<<<<< HEAD
          $default_sshd_acceptenv                     = true
          $default_sshd_addressfamily                 = 'any'
          $default_sshd_config_hostkey                = []
          $default_sshd_config_include                = '/etc/ssh/sshd_config.d/*.conf'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_permittunnel           = undef
          $default_sshd_config_print_motd             = 'no'
          $default_sshd_config_serverkeybits          = undef
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_tcp_keepalive          = undef
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_config_xauth_location         = undef
#          $default_sshd_gssapiauthentication          = 'yes'
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_x11_forwarding                = 'yes'
>>>>>>> 879e814 (Adopt default settings from release 3.62.0)
        }
        '20.04': {
          $default_service_hasstatus                  = true
          $default_ssh_config_forward_x11_trusted     = 'yes'
          $default_ssh_config_hash_known_hosts        = 'yes'
          $default_ssh_config_include                 = '/etc/ssh/ssh_config.d/*.conf'
          $default_ssh_gssapiauthentication           = 'yes'
          $default_ssh_package_adminfile              = undef
          $default_ssh_package_source                 = undef
          $default_ssh_sendenv                        = true
          $default_sshd_acceptenv                     = true
          $default_sshd_addressfamily                 = 'any'
          $default_sshd_config_hostkey                = []
          $default_sshd_config_include                = '/etc/ssh/sshd_config.d/*.conf'
          $default_sshd_config_mode                   = '0600'
          $default_sshd_config_permittunnel           = undef
          $default_sshd_config_print_motd             = 'no'
          $default_sshd_config_serverkeybits          = undef
          $default_sshd_config_subsystem_sftp         = '/usr/lib/openssh/sftp-server'
          $default_sshd_config_tcp_keepalive          = undef
          $default_sshd_config_use_dns                = 'yes'
          $default_sshd_config_xauth_location         = undef
          $default_sshd_gssapiauthentication          = 'yes'
          $default_sshd_gssapicleanupcredentials      = 'yes'
          $default_sshd_gssapikeyexchange             = undef
          $default_sshd_pamauthenticationviakbdint    = undef
          $default_sshd_use_pam                       = 'yes'
          $default_sshd_x11_forwarding                = 'yes'
        }
        /^10.*/: {
          $default_sshd_config_hostkey = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key',
          ]
          $default_sshd_config_mode                = '0600'
          $default_sshd_use_pam                    = 'yes'
          $default_ssh_config_forward_x11_trusted  = 'yes'
          $default_ssh_config_include              = undef
          $default_sshd_acceptenv                  = true
          $default_sshd_config_subsystem_sftp      = '/usr/lib/openssh/sftp-server'
          $default_ssh_config_hash_known_hosts     = 'yes'
          $default_ssh_sendenv                     = true
          $default_ssh_config_include              = undef
          $default_sshd_addressfamily              = undef
          $default_sshd_config_serverkeybits       = undef
          $default_sshd_gssapicleanupcredentials   = undef
          $default_sshd_config_use_dns             = undef
          $default_sshd_config_xauth_location      = undef
          $default_sshd_config_permittunnel        = undef
          $default_sshd_config_tcp_keepalive       = undef
          $default_ssh_package_source              = undef
          $default_ssh_package_adminfile           = undef
          $default_sshd_gssapikeyexchange          = undef
          $default_sshd_pamauthenticationviakbdint = undef
          $default_sshd_config_include             = undef
          $default_service_hasstatus               = true
          $default_sshd_config_include             = undef
=======
>>>>>>> 4ae8446 (Remove server related data from main class)
        }
        /^7.*/: {
          $packages_default             = ['openssh-client']
          $package_source_default       = undef
          $gss_api_authentication_default = 'yes'
          $hash_known_hosts_default     = 'no'
          $forward_x11_trusted_default  = 'yes'
          $send_env_default = ['LANG', 'LANGUAGE', 'LC_ADDRESS', 'LC_ALL', 'LC_COLLATE', 'LC_CTYPE', 'LC_IDENTIFICATION', 'LC_MEASUREMENT',
                                'LC_MESSAGES', 'LC_MONETARY', 'LC_NAME', 'LC_NUMERIC', 'LC_PAPER', 'LC_TELEPHONE', 'LC_TIME']
          $include_default              = undef
        }
        /^8.*/: {
          $packages_default             = ['openssh-client']
          $package_source_default       = undef
          $gss_api_authentication_default = 'yes'
          $hash_known_hosts_default     = 'yes'
          $forward_x11_trusted_default  = 'yes'
          $send_env_default = ['LANG', 'LANGUAGE', 'LC_ADDRESS', 'LC_ALL', 'LC_COLLATE', 'LC_CTYPE', 'LC_IDENTIFICATION', 'LC_MEASUREMENT',
                                'LC_MESSAGES', 'LC_MONETARY', 'LC_NAME', 'LC_NUMERIC', 'LC_PAPER', 'LC_TELEPHONE', 'LC_TIME']
          $include_default              = undef
        }
        /^9.*/: {
          $packages_default             = ['openssh-client']
          $package_source_default       = undef
          $forward_x11_trusted_default  = 'yes'
          $gss_api_authentication_default = 'yes'
          $hash_known_hosts_default     = 'yes'
          $send_env_default = ['LANG', 'LANGUAGE', 'LC_ADDRESS', 'LC_ALL', 'LC_COLLATE', 'LC_CTYPE', 'LC_IDENTIFICATION', 'LC_MEASUREMENT',
                                'LC_MESSAGES', 'LC_MONETARY', 'LC_NAME', 'LC_NUMERIC', 'LC_PAPER', 'LC_TELEPHONE', 'LC_TIME']
          $include_default              = undef
        }
        /^10.*/: {
          $packages_default             = ['openssh-client']
          $package_source_default       = undef
          $forward_x11_trusted_default  = 'yes'
          $include_default              = undef
          $gss_api_authentication_default = 'yes'
          $hash_known_hosts_default     = 'yes'
          $send_env_default = ['LANG', 'LANGUAGE', 'LC_ADDRESS', 'LC_ALL', 'LC_COLLATE', 'LC_CTYPE', 'LC_IDENTIFICATION', 'LC_MEASUREMENT',
                                'LC_MESSAGES', 'LC_MONETARY', 'LC_NAME', 'LC_NUMERIC', 'LC_PAPER', 'LC_TELEPHONE', 'LC_TIME']
        }
        default: { fail ("Operating System : ${::operatingsystemrelease} not supported") }
      }
    }
    'Solaris': {
      $gss_api_authentication_default = 'yes'
      $hash_known_hosts_default     = undef
      $send_env_default             = undef
      $forward_x11_trusted_default  = undef
      $include_default              = undef
      case $::kernelrelease {
        '5.11': {
          $packages_default         = ['network/ssh', 'network/ssh/ssh-key']
          $package_source_default   = undef
        }
        '5.10': {
          $packages_default         = ['SUNWsshcu', 'SUNWsshr', 'SUNWsshu']
          $package_source_default   = '/var/spool/pkg'
        }
        '5.9' : {
          $packages_default         = ['SUNWsshcu', 'SUNWsshr', 'SUNWsshu']
          $package_source_default   = '/var/spool/pkg'
        }
        default: {
          fail('ssh module supports Solaris kernel release 5.9, 5.10 and 5.11.')
        }
      }
    }
    'UnitTesting': { # fake OS for easier testing only
      # TODO: These default values should only be needed while transitioning data to v4
      $hash_known_hosts_default = undef
      $forward_x11_trusted_default = undef
      $include_default = undef
      $send_env_default = undef
      $gss_api_authentication_default = undef
      $packages_default = []
      $package_source_default = undef
    }
    default: {
      fail("ssh supports osfamilies RedHat, Suse, Debian and Solaris. Detected osfamily is <${::osfamily}>.")
    }
  }

=======
>>>>>>> db859ce (Move data from main class to hiera)
  if "${::ssh_version}" =~ /^OpenSSH/  { # lint:ignore:only_variable_string
    $ssh_version_array = split($::ssh_version_numeric, '\.')
    $ssh_version_maj_int = 0 + $ssh_version_array[0]
    $ssh_version_min_int = 0 + $ssh_version_array[1]
    if $ssh_version_maj_int > 5 {
      $use_roaming_default = 'no'
    } elsif $ssh_version_maj_int == 5 and $ssh_version_min_int >= 4 {
      $use_roaming_default = 'no'
    } else {
      $use_roaming_default = undef
    }
=======
=======
  # UseRoaming should only be used if OpenSSH 5.4 is used on the client
>>>>>>> e82a3df (Add comment for $use_roaming handling)
  if $use_roaming != undef {
    $use_roaming_real = $use_roaming
>>>>>>> 5dd4eed (Refactor handling of $use_roaming)
  } else {
    if $::ssh_version =~ /^OpenSSH/ and versioncmp($::ssh_version_numeric, '5.3') == 1 {
      $use_roaming_real = 'no'
    } else {
      $use_roaming_real = undef
    }
  }

<<<<<<< HEAD
  case type_of($global_known_hosts_file) {
    string:  { $global_known_hosts_file_array = [ $global_known_hosts_file ] }
    default: { $global_known_hosts_file_array = $global_known_hosts_file }
  }

<<<<<<< HEAD
<<<<<<< HEAD
  if $packages == 'USE_DEFAULTS' {
    $packages_real = $default_packages
  } else {
    $packages_real = $packages
  }

  case $ssh_config_hash_known_hosts {
    'unset':        { $ssh_config_hash_known_hosts_real = undef }
    'USE_DEFAULTS': { $ssh_config_hash_known_hosts_real = $default_ssh_config_hash_known_hosts }
    default:        { $ssh_config_hash_known_hosts_real = $ssh_config_hash_known_hosts }
  }

  if $service_name == 'USE_DEFAULTS' {
    $service_name_real = $default_service_name
  } else {
    $service_name_real = $service_name
  }

  if $sshd_config_subsystem_sftp == 'USE_DEFAULTS' {
    $sshd_config_subsystem_sftp_real = $default_sshd_config_subsystem_sftp
  } else {
    $sshd_config_subsystem_sftp_real = $sshd_config_subsystem_sftp
  }

  if $sshd_config_mode    == 'USE_DEFAULTS' {
    $sshd_config_mode_real = $default_sshd_config_mode
  } else {
    $sshd_config_mode_real = $sshd_config_mode
  }

  if $sshd_config_xauth_location == 'USE_DEFAULTS' {
    $sshd_config_xauth_location_real = $default_sshd_config_xauth_location
  } else {
    $sshd_config_xauth_location_real = $sshd_config_xauth_location
  }

  if $sshd_config_xauth_location_real != undef {
    validate_absolute_path($sshd_config_xauth_location_real)
  }

  if $ssh_package_source == 'USE_DEFAULTS' {
    $ssh_package_source_real = $default_ssh_package_source
  } else {
    $ssh_package_source_real = $ssh_package_source
  }

  if $ssh_package_source_real != undef {
    validate_absolute_path($ssh_package_source_real)
  }

  if $ssh_package_adminfile == 'USE_DEFAULTS' {
    $ssh_package_adminfile_real = $default_ssh_package_adminfile
  } else {
    $ssh_package_adminfile_real = $ssh_package_adminfile
  }

  if $ssh_package_adminfile_real != undef {
    validate_absolute_path($ssh_package_adminfile_real)
  }

  if $sshd_config_use_dns == 'USE_DEFAULTS' {
    $sshd_config_use_dns_real = $default_sshd_config_use_dns
  } else {
    $sshd_config_use_dns_real = $sshd_config_use_dns
  }

  if $sshd_use_pam == 'USE_DEFAULTS' {
    $sshd_use_pam_real = $default_sshd_use_pam
  } else {
    $sshd_use_pam_real = $sshd_use_pam
  }

  if $sshd_config_serverkeybits == 'USE_DEFAULTS' {
    $sshd_config_serverkeybits_real = $default_sshd_config_serverkeybits
  } else {
    $sshd_config_serverkeybits_real = $sshd_config_serverkeybits
  }

  if $ssh_config_forward_x11_trusted == 'USE_DEFAULTS' {
    $ssh_config_forward_x11_trusted_real = $default_ssh_config_forward_x11_trusted
  } else {
    $ssh_config_forward_x11_trusted_real = $ssh_config_forward_x11_trusted
  }
  if $ssh_config_forward_x11_trusted_real != undef {
    validate_re($ssh_config_forward_x11_trusted_real, '^(yes|no)$', "ssh::ssh_config_forward_x11_trusted may be either 'yes' or 'no' and is set to <${ssh_config_forward_x11_trusted_real}>.")
  }

  if $sshd_gssapikeyexchange == 'USE_DEFAULTS' {
    $sshd_gssapikeyexchange_real = $default_sshd_gssapikeyexchange
  } else {
    $sshd_gssapikeyexchange_real = $sshd_gssapikeyexchange
  }

  if $sshd_pamauthenticationviakbdint == 'USE_DEFAULTS' {
    $sshd_pamauthenticationviakbdint_real = $default_sshd_pamauthenticationviakbdint
  } else {
    $sshd_pamauthenticationviakbdint_real = $sshd_pamauthenticationviakbdint
  }

  if $sshd_gssapicleanupcredentials == 'USE_DEFAULTS' {
    $sshd_gssapicleanupcredentials_real = $default_sshd_gssapicleanupcredentials
  } else {
    $sshd_gssapicleanupcredentials_real = $sshd_gssapicleanupcredentials
  }

  if $ssh_config_use_roaming == 'USE_DEFAULTS' {
    $ssh_config_use_roaming_real = $default_ssh_config_use_roaming
  } else {
    $ssh_config_use_roaming_real = $ssh_config_use_roaming
  }

  if $ssh_config_include == 'USE_DEFAULTS' {
    $ssh_config_include_real = $default_ssh_config_include
  } else {
    case type3x($ssh_config_include) {
      'array': {
        validate_array($ssh_config_include)
      }
      'string': {
        validate_string($ssh_config_include)
      }
      default: {
        fail('ssh::ssh_config_include type must be a strting or array.')
      }
    }
    $ssh_config_include_real = $ssh_config_include
  }

  if $ssh_sendenv == 'USE_DEFAULTS' {
    $ssh_sendenv_real = $default_ssh_sendenv
  } else {
    case type3x($ssh_sendenv) {
      'string': {
        validate_re($ssh_sendenv, '^(true|false)$', "ssh::ssh_sendenv may be either 'true' or 'false' and is set to <${ssh_sendenv}>.")
        $ssh_sendenv_real = str2bool($ssh_sendenv)
      }
      'boolean': {
        $ssh_sendenv_real = $ssh_sendenv
      }
      default: {
        fail('ssh::ssh_sendenv type must be true or false.')
      }
    }
  }

  if $sshd_acceptenv == 'USE_DEFAULTS' {
    $sshd_acceptenv_real = $default_sshd_acceptenv
  } else {
    case type3x($sshd_acceptenv) {
      'string': {
        validate_re($sshd_acceptenv, '^(true|false)$', "ssh::sshd_acceptenv may be either 'true' or 'false' and is set to <${sshd_acceptenv}>.")
        $sshd_acceptenv_real = str2bool($sshd_acceptenv)
      }
      'boolean': {
        $sshd_acceptenv_real = $sshd_acceptenv
      }
      default: {
        fail('ssh::sshd_acceptenv type must be true or false.')
      }
    }
  }

  if $sshd_config_hostkey == 'USE_DEFAULTS' {
    $sshd_config_hostkey_real = $default_sshd_config_hostkey
  } else {
    validate_array($sshd_config_hostkey)
    validate_absolute_path($sshd_config_hostkey)
    $sshd_config_hostkey_real = $sshd_config_hostkey
  }

  if $sshd_listen_address {
    validate_array($sshd_listen_address)
  }

  if $service_hasstatus == 'USE_DEFAULTS' {
    $service_hasstatus_real = $default_service_hasstatus
  } else {
    case type3x($service_hasstatus) {
      'string': {
        validate_re($service_hasstatus, '^(true|false)$', "ssh::service_hasstatus must be 'true' or 'false' and is set to <${service_hasstatus}>.")
        $service_hasstatus_real = str2bool($service_hasstatus)
      }
      'boolean': {
        $service_hasstatus_real = $service_hasstatus
      }
      default: {
        fail('ssh::service_hasstatus must be true or false.')
      }
    }
  }

  if $sshd_addressfamily == 'USE_DEFAULTS' {
    $sshd_addressfamily_real = $default_sshd_addressfamily
  } else {
    $sshd_addressfamily_real = $sshd_addressfamily
  }

  if $sshd_config_include == 'USE_DEFAULTS' {
    $sshd_config_include_real = $default_sshd_config_include
  } else {
    case type3x($sshd_config_include) {
      'array': {
        validate_array($sshd_config_include)
      }
      'string': {
        validate_string($sshd_config_include)
      }
      default: {
        fail('ssh::sshd_config_include type must be a strting or array.')
      }
    }
    $sshd_config_include_real = $sshd_config_include
  }

  case $sshd_config_maxsessions {
    'unset', undef: { $sshd_config_maxsessions_integer = undef }
    default:        { $sshd_config_maxsessions_integer = floor($sshd_config_maxsessions) }
  }

  case $sshd_config_tcp_keepalive {
    'unset': { $sshd_config_tcp_keepalive_real = undef }
    undef:   { $sshd_config_tcp_keepalive_real = $default_sshd_config_tcp_keepalive }
    default: { $sshd_config_tcp_keepalive_real = $sshd_config_tcp_keepalive }
  }

  case $sshd_config_permittunnel {
    'unset': { $sshd_config_permittunnel_real = undef }
    undef:   { $sshd_config_permittunnel_real = $default_sshd_config_permittunnel }
    default: { $sshd_config_permittunnel_real = $sshd_config_permittunnel }
  }

  case $sshd_config_hostcertificate {
    'unset', undef: { $sshd_config_hostcertificate_real = undef }
    default: { $sshd_config_hostcertificate_real = $sshd_config_hostcertificate }
  }

  case $sshd_config_trustedusercakeys {
    'unset', undef: { $sshd_config_trustedusercakeys_real = undef }
    default: { $sshd_config_trustedusercakeys_real = $sshd_config_trustedusercakeys }
  }

  case $sshd_config_key_revocation_list {
    'unset', undef: { $sshd_config_key_revocation_list_real = undef }
    default: { $sshd_config_key_revocation_list_real = $sshd_config_key_revocation_list }
  }

  case $sshd_config_authorized_principals_file {
    'unset', undef: { $sshd_config_authorized_principals_file_real = undef }
    default: { $sshd_config_authorized_principals_file_real = $sshd_config_authorized_principals_file }
  }

  # validate params
  if $ssh_config_ciphers != undef {
    validate_array($ssh_config_ciphers)
  }

  if $sshd_config_ciphers != undef {
    validate_array($sshd_config_ciphers)
  }

  if $ssh_config_kexalgorithms != undef {
    validate_array($ssh_config_kexalgorithms)
  }

  if $sshd_config_kexalgorithms != undef {
    validate_array($sshd_config_kexalgorithms)
  }

  if $ssh_config_macs != undef {
    validate_array($ssh_config_macs)
  }

  if $sshd_config_macs != undef {
    validate_array($sshd_config_macs)
  }

  if $ssh_config_hash_known_hosts_real != undef {
    validate_re($ssh_config_hash_known_hosts_real, '^(yes|no)$', "ssh::ssh_config_hash_known_hosts may be either 'yes', 'no' or 'unset' and is set to <${ssh_config_hash_known_hosts_real}>.")
  }
  if $sshd_config_permitemptypasswords != undef {
    validate_re($sshd_config_permitemptypasswords, '^(yes|no)$', "ssh::sshd_config_permitemptypasswords may be either 'yes' or 'no' and is set to <${sshd_config_permitemptypasswords}>.")
  }
  if $sshd_config_permituserenvironment != undef {
    validate_re($sshd_config_permituserenvironment, '^(yes|no)$', "ssh::sshd_config_permituserenvironment may be either 'yes' or 'no' and is set to <${sshd_config_permituserenvironment}>.")
  }
  if $sshd_config_compression != undef {
    validate_re($sshd_config_compression, '^(yes|no|delayed)$', "ssh::sshd_config_compression may be either 'yes', 'no' or 'delayed' and is set to <${sshd_config_compression}>.")
  }
  case type3x($sshd_config_port) {
    'string': {
      validate_re($sshd_config_port, '^\d+$', "ssh::sshd_config_port must be a valid number and is set to <${sshd_config_port}>.")
      $sshd_config_port_array = [ str2num($sshd_config_port) ]
    }
    'array': {
      $sshd_config_port_array = $sshd_config_port
    }
    'integer': {
      $sshd_config_port_array = [ $sshd_config_port ]
    }
    default: {
      fail('ssh:sshd_config_port must be a string, an integer or an array. ')
    }
  }
  validate_numeric($sshd_config_port_array, 65535, 1)
  if $sshd_kerberos_authentication != undef {
    validate_re($sshd_kerberos_authentication, '^(yes|no)$', "ssh::sshd_kerberos_authentication may be either 'yes' or 'no' and is set to <${sshd_kerberos_authentication}>.")
  }
  validate_re($sshd_password_authentication, '^(yes|no)$', "ssh::sshd_password_authentication may be either 'yes' or 'no' and is set to <${sshd_password_authentication}>.")
  validate_re($sshd_allow_tcp_forwarding, '^(yes|no)$', "ssh::sshd_allow_tcp_forwarding may be either 'yes' or 'no' and is set to <${sshd_allow_tcp_forwarding}>.")
  validate_re($sshd_x11_forwarding, '^(yes|no)$', "ssh::sshd_x11_forwarding may be either 'yes' or 'no' and is set to <${sshd_x11_forwarding}>.")
  validate_re($sshd_x11_use_localhost, '^(yes|no)$', "ssh::sshd_x11_use_localhost may be either 'yes' or 'no' and is set to <${sshd_x11_use_localhost}>.")
  if $sshd_config_print_last_log != undef {
    validate_re($sshd_config_print_last_log, '^(yes|no)$', "ssh::sshd_config_print_last_log may be either 'yes' or 'no' and is set to <${sshd_config_print_last_log}>.")
  }
  if $sshd_use_pam_real != undef {
    validate_re($sshd_use_pam_real, '^(yes|no)$', "ssh::sshd_use_pam may be either 'yes' or 'no' and is set to <${sshd_use_pam_real}>.")
  }
  if $sshd_config_serverkeybits_real != undef {
    if is_integer($sshd_config_serverkeybits_real) == false { fail("ssh::sshd_config_serverkeybits must be an integer and is set to <${sshd_config_serverkeybits}>.") }
  }
  if $ssh_config_use_roaming_real != undef {
    validate_re($ssh_config_use_roaming_real, '^(yes|no|unset)$', "ssh::ssh_config_use_roaming may be either 'yes', 'no' or 'unset' and is set to <${$ssh_config_use_roaming}>.")
  }
  if is_integer($sshd_client_alive_interval) == false { fail("ssh::sshd_client_alive_interval must be an integer and is set to <${sshd_client_alive_interval}>.") }
  if is_integer($sshd_client_alive_count_max) == false { fail("ssh::sshd_client_alive_count_max must be an integer and is set to <${sshd_client_alive_count_max}>.") }

  if $sshd_config_banner != 'none' {
    validate_absolute_path($sshd_config_banner)
  }
  if $sshd_banner_content != undef and $sshd_config_banner == 'none' {
    fail('ssh::sshd_config_banner must be set to be able to use sshd_banner_content.')
  }

  validate_re($ssh_gssapiauthentication, '^(yes|no)$', "ssh::ssh_gssapiauthentication may be either 'yes' or 'no' and is set to <${ssh_gssapiauthentication}>.")

  if $ssh_gssapidelegatecredentials != undef {
    validate_re($ssh_gssapidelegatecredentials, '^(yes|no)$', "ssh::ssh_gssapidelegatecredentials may be either 'yes' or 'no' and is set to <${ssh_gssapidelegatecredentials}>.")
  }

  validate_re($sshd_gssapiauthentication, '^(yes|no)$', "ssh::sshd_gssapiauthentication may be either 'yes' or 'no' and is set to <${sshd_gssapiauthentication}>.")

  if $sshd_gssapikeyexchange_real != undef {
    validate_re($sshd_gssapikeyexchange_real, '^(yes|no)$', "ssh::sshd_gssapikeyexchange may be either 'yes' or 'no' and is set to <${sshd_gssapikeyexchange_real}>.")
  }

  if $sshd_pamauthenticationviakbdint_real != undef {
    validate_re($sshd_pamauthenticationviakbdint_real, '^(yes|no)$', "ssh::sshd_pamauthenticationviakbdint may be either 'yes' or 'no' and is set to <${sshd_pamauthenticationviakbdint_real}>.")
  }

  if $sshd_gssapicleanupcredentials_real != undef {
    validate_re($sshd_gssapicleanupcredentials_real, '^(yes|no)$', "ssh::sshd_gssapicleanupcredentials may be either 'yes' or 'no' and is set to <${sshd_gssapicleanupcredentials_real}>.")
  }

  if $ssh_strict_host_key_checking != undef {
    validate_re($ssh_strict_host_key_checking, '^(yes|no|ask)$', "ssh::ssh_strict_host_key_checking may be 'yes', 'no' or 'ask' and is set to <${ssh_strict_host_key_checking}>.")
  }

  if $ssh_config_proxy_command != undef {
    validate_string($ssh_config_proxy_command)
  }

  if $ssh_enable_ssh_keysign != undef {
    validate_re($ssh_enable_ssh_keysign, '^(yes|no)$', "ssh::ssh_enable_ssh_keysign may be either 'yes' or 'no' and is set to <${ssh_enable_ssh_keysign}>.")
  }

  if $sshd_config_authkey_location != undef {
    validate_string($sshd_config_authkey_location)
  }

  if $sshd_config_maxauthtries != undef {
    if is_integer($sshd_config_maxauthtries) == false {
      fail("ssh::sshd_config_maxauthtries must be a valid number and is set to <${sshd_config_maxauthtries}>.")
    }
  }

  if $sshd_config_maxstartups != undef {
    validate_re($sshd_config_maxstartups,'^((\d+)|(\d+?:\d+?:\d+)?)$',
      "ssh::sshd_config_maxstartups may be either an integer or three integers separated with colons, such as 10:30:100. Detected value is <${sshd_config_maxstartups}>.")
  }

  if $sshd_config_chrootdirectory != undef {
    validate_absolute_path($sshd_config_chrootdirectory)
  }

  if $sshd_config_forcecommand != undef {
    validate_string($sshd_config_forcecommand)
  }

  if $sshd_authorized_keys_command != undef {
    validate_absolute_path($sshd_authorized_keys_command)
  }

  if $sshd_authorized_keys_command_user != undef {
    validate_string($sshd_authorized_keys_command_user)
  }

  if $sshd_config_match != undef {
    validate_hash($sshd_config_match)
  }

  if $sshd_config_strictmodes != undef {
    validate_re($sshd_config_strictmodes, '^(yes|no)$', "ssh::sshd_config_strictmodes may be either 'yes' or 'no' and is set to <${sshd_config_strictmodes}>.")
  }
  if $ssh_hostbasedauthentication != undef {
    validate_re($ssh_hostbasedauthentication, '^(yes|no)$', "ssh::ssh_hostbasedauthentication may be either 'yes' or 'no' and is set to <${ssh_hostbasedauthentication}>.")
  }

  validate_re($sshd_hostbasedauthentication, '^(yes|no)$', "ssh::sshd_hostbasedauthentication may be either 'yes' or 'no' and is set to <${sshd_hostbasedauthentication}>.")

  if $sshd_pubkeyacceptedkeytypes != undef {
    validate_array($sshd_pubkeyacceptedkeytypes)
  }

  if $sshd_config_authenticationmethods != undef {
    validate_array($sshd_config_authenticationmethods)
  }

  validate_re($sshd_pubkeyauthentication, '^(yes|no)$', "ssh::sshd_pubkeyauthentication may be either 'yes' or 'no' and is set to <${sshd_pubkeyauthentication}>.")

  validate_re($sshd_ignoreuserknownhosts, '^(yes|no)$', "ssh::sshd_ignoreuserknownhosts may be either 'yes' or 'no' and is set to <${sshd_ignoreuserknownhosts}>.")

  validate_re($sshd_ignorerhosts, '^(yes|no)$', "ssh::sshd_ignorerhosts may be either 'yes' or 'no' and is set to <${sshd_ignorerhosts}>.")

  case type3x($hiera_merge) {
    'string': {
      validate_re($hiera_merge, '^(true|false)$', "ssh::hiera_merge may be either 'true' or 'false' and is set to <${hiera_merge}>.")
      $hiera_merge_real = str2bool($hiera_merge)
    }
    'boolean': {
      $hiera_merge_real = $hiera_merge
    }
    default: {
      fail('ssh::hiera_merge type must be true or false.')
    }
  }

  case type3x($ssh_key_import) {
    'string': {
      validate_re($ssh_key_import, '^(true|false)$', "ssh::ssh_key_import may be either 'true' or 'false' and is set to <${ssh_key_import}>.")
      $ssh_key_import_real = str2bool($ssh_key_import)
    }
    'boolean': {
      $ssh_key_import_real = $ssh_key_import
    }
    default: {
      fail('ssh::ssh_key_import type must be true or false.')
    }
  }
  validate_bool($ssh_key_import_real)

  case type3x($ssh_config_sendenv_xmodifiers) {
    'string': {
      $ssh_config_sendenv_xmodifiers_real = str2bool($ssh_config_sendenv_xmodifiers)
    }
    'boolean': {
      $ssh_config_sendenv_xmodifiers_real = $ssh_config_sendenv_xmodifiers
    }
    default: {
      fail('ssh::ssh_config_sendenv_xmodifiers type must be true or false.')
    }
  }

  case $permit_root_login {
    'no', 'yes', 'without-password', 'forced-commands-only': {
      # noop
    }
    default: {
      fail("ssh::permit_root_login may be either 'yes', 'without-password', 'forced-commands-only' or 'no' and is set to <${permit_root_login}>.")
    }
  }

  case $ssh_key_type {
    'ssh-rsa','rsa': {
      $key = $::sshrsakey
    }
    'ssh-dsa','dsa': {
      $key = $::sshdsakey
    }
    'ecdsa-sha2-nistp256': {
          $key = $::sshecdsakey
    }
    default: {
      fail("ssh::ssh_key_type must be 'ecdsa-sha2-nistp256', 'ssh-rsa', 'rsa', 'ssh-dsa', or 'dsa' and is <${ssh_key_type}>.")
    }
  }

  validate_absolute_path($ssh_config_global_known_hosts_file)
  $ssh_config_global_known_hosts_file_real = any2array($ssh_config_global_known_hosts_file)

  if $ssh_config_global_known_hosts_list != undef {
    validate_array($ssh_config_global_known_hosts_list)
    validate_absolute_path($ssh_config_global_known_hosts_list)
    $ssh_config_global_known_hosts_list_real = concat($ssh_config_global_known_hosts_file_real, $ssh_config_global_known_hosts_list)
  } else {
    $ssh_config_global_known_hosts_list_real = $ssh_config_global_known_hosts_file_real
  }

  if $ssh_config_user_known_hosts_file != undef {
    validate_array($ssh_config_user_known_hosts_file)
  }

  validate_string($ssh_config_global_known_hosts_owner)
  validate_string($ssh_config_global_known_hosts_group)
  validate_re($ssh_config_global_known_hosts_mode, '^[0-7]{4}$',
    "ssh::ssh_config_global_known_hosts_mode must be a valid 4 digit mode in octal notation. Detected value is <${ssh_config_global_known_hosts_mode}>.")

  if type3x($purge_keys) == 'string' {
    $purge_keys_real = str2bool($purge_keys)
  } else {
    $purge_keys_real = $purge_keys
  }
  validate_bool($purge_keys_real)

  if type3x($manage_service) == 'string' {
    $manage_service_real = str2bool($manage_service)
  } else {
    $manage_service_real = $manage_service
  }
  validate_bool($manage_service_real)

  if type3x($service_enable) == 'string' {
    $service_enable_real = str2bool($service_enable)
  } else {
    $service_enable_real = $service_enable
  }
  validate_bool($service_enable_real)

  if type3x($service_hasrestart) == 'string' {
    $service_hasrestart_real = str2bool($service_hasrestart)
  } else {
    $service_hasrestart_real = $service_hasrestart
  }
  validate_bool($service_hasrestart_real)

  if type3x($manage_root_ssh_config) == 'string' {
    $manage_root_ssh_config_real = str2bool($manage_root_ssh_config)
  } else {
    $manage_root_ssh_config_real = $manage_root_ssh_config
  }
  validate_bool($manage_root_ssh_config_real)

  #ssh_config template
  validate_string($ssh_config_template)

  #sshd_config template
  validate_string($sshd_config_template)

  #loglevel
  $supported_loglevel_vals=['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE']
  validate_re($sshd_config_loglevel, $supported_loglevel_vals)

  #enable hiera merging for groups, users, and config_entries
  if $hiera_merge_real == true {
    $sshd_config_allowgroups_real = hiera_array('ssh::sshd_config_allowgroups',[])
    $sshd_config_allowusers_real  = hiera_array('ssh::sshd_config_allowusers',[])
    $sshd_config_denygroups_real  = hiera_array('ssh::sshd_config_denygroups',[])
    $sshd_config_denyusers_real   = hiera_array('ssh::sshd_config_denyusers',[])
    $config_entries_real          = hiera_hash('ssh::config_entries',{})
  } else {
    $sshd_config_allowgroups_real = $sshd_config_allowgroups
    $sshd_config_allowusers_real  = $sshd_config_allowusers
    $sshd_config_denygroups_real  = $sshd_config_denygroups
    $sshd_config_denyusers_real   = $sshd_config_denyusers
    $config_entries_real          = $config_entries
  }
  validate_hash($config_entries_real)

  if $sshd_config_denyusers_real != [] {
    validate_array($sshd_config_denyusers_real)
  }

  if $sshd_config_denygroups_real != [] {
    validate_array($sshd_config_denygroups_real)
  }

  if $sshd_config_allowusers_real != [] {
    validate_array($sshd_config_allowusers_real)
  }

  if $sshd_config_allowgroups_real != [] {
    validate_array($sshd_config_allowgroups_real)
  }


  if $sshd_config_tcp_keepalive_real != undef {
    validate_re($sshd_config_tcp_keepalive_real, '^(yes|no)$', "ssh::sshd_config_tcp_keepalive may be either 'yes', 'no' or 'unset' and is set to <${sshd_config_tcp_keepalive_real}>.")
  }

  if $sshd_config_use_privilege_separation != undef {
    validate_re($sshd_config_use_privilege_separation, '^(yes|no|sandbox)$', "ssh::sshd_config_use_privilege_separation may be either 'yes', 'no' or 'sandbox' and is set to <${sshd_config_use_privilege_separation}>.")
  }

  if $sshd_config_permittunnel_real != undef {
    validate_re($sshd_config_permittunnel_real, '^(yes|no|point-to-point|ethernet|unset)$', "ssh::sshd_config_permittunnel may be either 'yes', 'point-to-point', 'ethernet', 'no' or 'unset' and is set to <${sshd_config_permittunnel_real}>.")
  }

  if $sshd_config_hostcertificate_real != undef {
    if is_array($sshd_config_hostcertificate_real) {
      validate_array($sshd_config_hostcertificate_real)
    }
    validate_absolute_path($sshd_config_hostcertificate_real)
  }

  if $sshd_config_trustedusercakeys_real != undef {
    # TrustedUserCAKeys may be a path to the keys or 'none'
    if $sshd_config_trustedusercakeys_real != 'none' {
      validate_absolute_path($sshd_config_trustedusercakeys_real)
    }
  }
  if $sshd_config_key_revocation_list_real != undef {
    # RevokedKeys may be a path to the key revocation list or 'none'
    if $sshd_config_key_revocation_list_real != 'none' {
      validate_absolute_path($sshd_config_key_revocation_list)
    }
  }

  if $sshd_config_authorized_principals_file_real != undef {
    validate_string($sshd_config_authorized_principals_file_real)
  }

  if $sshd_config_allowagentforwarding != undef {
    validate_re($sshd_config_allowagentforwarding, '^(yes|no)$', "ssh::sshd_config_allowagentforwarding may be either 'yes' or 'no' and is set to <${sshd_config_allowagentforwarding}>.")
  }

  package { $packages_real:
    ensure    => installed,
    source    => $ssh_package_source_real,
    adminfile => $ssh_package_adminfile_real,
=======
  package { $packages_real:
=======
=======
>>>>>>> f628824 (Refactor parameters that allow multiple values to accept only arrays)
=======
>>>>>>> d56aa55 (Remove automatic choosing of UseRoaming by running SSH version)
  package { $packages:
>>>>>>> db859ce (Move data from main class to hiera)
    ensure    => installed,
    source    => $package_source,
    adminfile => $package_adminfile,
<<<<<<< HEAD
    before    => ['File[ssh_config]', 'File[ssh_known_hosts]'],
>>>>>>> c2b2b69 (Refactor package related params in main class)
=======
    before    => 'File[ssh_config]',
>>>>>>> 89a26da (Make global_known_hosts manageable)
  }

  file  { 'ssh_config' :
    ensure  => file,
<<<<<<< HEAD
    path    => $ssh_config_path,
    owner   => $ssh_config_owner,
    group   => $ssh_config_group,
    mode    => $ssh_config_mode,
    content => template($ssh_config_template),
    require => Package[$packages_real],
=======
    path    => $config_path,
    owner   => $config_owner,
    group   => $config_group,
    mode    => $config_mode,
    content => template('ssh/ssh_config.erb'),
>>>>>>> c2b2b69 (Refactor package related params in main class)
  }

<<<<<<< HEAD
  file  { 'sshd_config' :
    ensure  => file,
    path    => $sshd_config_path,
    mode    => $sshd_config_mode_real,
    owner   => $sshd_config_owner,
    group   => $sshd_config_group,
    content => template($sshd_config_template),
    require => Package[$packages_real],
  }

  if $sshd_config_banner != 'none' and $sshd_banner_content != undef {
    file { 'sshd_banner' :
      ensure  => file,
      path    => $sshd_config_banner,
      owner   => $sshd_banner_owner,
      group   => $sshd_banner_group,
      mode    => $sshd_banner_mode,
      content => $sshd_banner_content,
      require => Package[$packages_real],
=======
  if $manage_root_ssh_config == true {
    exec { "mkdir_p-${::root_home}/.ssh":
      command => "mkdir -p ${::root_home}/.ssh",
      unless  => "test -d ${::root_home}/.ssh",
      path    => '/bin:/usr/bin',
>>>>>>> 3d4f17a (Remove linebreak)
    }
  }

  if $manage_root_ssh_config_real == true {

    include ::common

    common::mkdir_p { "${::root_home}/.ssh": }

    file { 'root_ssh_dir':
      ensure  => directory,
      path    => "${::root_home}/.ssh",
      owner   => 'root',
      group   => 'root',
      mode    => '0700',
      require => Common::Mkdir_p["${::root_home}/.ssh"],
    }

    file { 'root_ssh_config':
      ensure  => file,
      path    => "${::root_home}/.ssh/config",
      content => $root_ssh_config_content,
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
    }
  }

<<<<<<< HEAD
<<<<<<< HEAD
  if $manage_service_real {
    service { 'sshd_service' :
      ensure     => $service_ensure,
      name       => $service_name_real,
      enable     => $service_enable_real,
      hasrestart => $service_hasrestart_real,
      hasstatus  => $service_hasstatus_real,
      subscribe  => File['sshd_config'],
    }
  }

  if $manage_firewall == true {
    firewall { '22 open port 22 for SSH':
      action => 'accept',
      dport  => 22,
      proto  => 'tcp',
    }
  }

  # If either IPv4 or IPv6 stack is not configured on the agent, the
  # corresponding $::ipaddress(6)? fact is not present. So, we cannot assume
  # these variables are defined. Getvar (Stdlib 4.13+, ruby 1.8.7+) handles
  # this correctly.
  if getvar('::ipaddress') and getvar('::ipaddress6') { $host_aliases = [$::hostname, $::ipaddress, $::ipaddress6] }
  elsif getvar('::ipaddress6') { $host_aliases = [$::hostname, $::ipaddress6] }
  else { $host_aliases = [$::hostname, $::ipaddress] }

  # export each node's ssh key
  if $ssh_key_export {
    @@sshkey { $::fqdn :
      ensure       => $ssh_key_ensure,
      host_aliases => $host_aliases,
      type         => $ssh_key_type,
      key          => $key,
    }
  }

=======
>>>>>>> d2f0ca6 (Remove code block that was used for exporting SSH keys)
  file { 'ssh_known_hosts':
<<<<<<< HEAD
    ensure  => file,
    path    => $ssh_config_global_known_hosts_file,
    owner   => $ssh_config_global_known_hosts_owner,
    group   => $ssh_config_global_known_hosts_group,
    mode    => $ssh_config_global_known_hosts_mode,
    require => Package[$packages_real],
  }

  # import all nodes' ssh keys
  if $ssh_key_import_real == true {
    Sshkey <<||>> {
      target => $ssh_config_global_known_hosts_file,
    }
=======
    ensure => file,
    path   => $global_known_hosts_path,
    owner  => $global_known_hosts_owner,
    group  => $global_known_hosts_group,
    mode   => $global_known_hosts_mode,
>>>>>>> c2b2b69 (Refactor package related params in main class)
=======
  if $manage_global_known_hosts == true {
    file { 'global_known_hosts':
      ensure  => file,
      path    => $global_known_hosts_path,
      owner   => $global_known_hosts_owner,
      group   => $global_known_hosts_group,
      mode    => $global_known_hosts_mode,
      require => 'File[ssh_config]',
    }
>>>>>>> 89a26da (Make global_known_hosts manageable)
  }

  # remove ssh key's not managed by puppet
<<<<<<< HEAD
  resources  { 'sshkey':
    purge => $purge_keys_real,
=======
  if $manage_sshkey == true {
    resources  { 'sshkey':
      purge => $purge_keys,
    }
>>>>>>> 7c9d49b (Make sshkey management manageable)
  }

  # manage users' ssh config entries if present
<<<<<<< HEAD
  create_resources('ssh::config_entry',$config_entries_real)

  # manage users' ssh authorized keys if present
  if $keys != undef {
    if $hiera_merge_real == true {
      $keys_real = hiera_hash('ssh::keys')
    } else {
      $keys_real = $keys
      notice('Future versions of the ssh module will default ssh::hiera_merge_real to true')
=======
  $config_entries.each |$key,$values| {
    ssh::config_entry { $key:
      * => $values,
    }
  }

  # manage users' ssh authorized keys if present
  $keys.each |$key,$values| {
    ssh_authorized_key { $key:
      * => $values,
>>>>>>> 3e07f34 (Remove unneeded check for $keys, adjust naming)
    }
    validate_hash($keys_real)
    create_resources('ssh_authorized_key', $keys_real)
  }

  if $sshd_addressfamily_real != undef {
    if $::osfamily == 'Solaris' {
      fail("ssh::sshd_addressfamily is not supported on Solaris and is set to <${sshd_addressfamily}>.")
    } else {
      validate_re($sshd_addressfamily_real, '^(any|inet|inet6)$',
        "ssh::sshd_addressfamily can be undef, 'any', 'inet' or 'inet6' and is set to ${sshd_addressfamily_real}.")
    }
  }
}
