# coding: utf-8

require 'spec_helper'

describe 'Ssh::Ssh_Config' do
  context 'Ssh::Log_level' do
    [
      'LogLevel',
    ].each do |directive|
      describe directive.inspect do
        [
          'QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context 'Ssh::Syslog_facility' do
    [
      'SyslogFacility',
    ].each do |directive|
      describe directive.inspect do
        [
          'DAEMON', 'USER', 'AUTH', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7', 'AUTHPRIV'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context 'Ssh::Yes_no' do
    [
      'BatchMode', 'CanonicalizeFallbackLocal', 'CheckHostIP', 'ClearAllForwardings', 'Compression', 'EnableEscapeCommandline',
      'EnableSSHKeysign', 'ExitOnForwardFailure', 'ForkAfterAuthentication', 'ForwardAgent', 'ForwardX11', 'ForwardX11Trusted',
      'GatewayPorts', 'GSSAPIAuthentication', 'GSSAPIDelegateCredentials', 'HashKnownHosts', 'HostbasedAuthentication',
      'IdentitiesOnly', 'KbdInteractiveAuthentication', 'NoHostAuthenticationForLocalhost', 'PasswordAuthentication',
      'PermitLocalCommand', 'ProxyUseFdpass', 'PubkeyAuthentication', 'StdinNull', 'StreamLocalBindUnlink', 'TCPKeepAlive',
      'UpdateHostKeys', 'VisualHostKey'
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'no'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context "Enum['yes', 'no', 'ask', 'confirm']" do
    [
      'AddKeysToAgent',
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'no', 'ask', 'confirm'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context "Enum['any', 'inet', 'inet6']" do
    [
      'AddressFamily',
    ].each do |directive|
      describe directive.inspect do
        [
          'any', 'inet', 'inet6'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context "Enum['yes', 'no', 'always']" do
    [
      'CanonicalizeHostname',
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'no', 'always'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context "Enum['yes', 'no', 'ask', 'auto', 'autoask']" do
    [
      'ControlMaster',
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'no', 'ask', 'auto', 'autoask'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context "Enum['sha256', 'md5']" do
    [
      'FingerprintHash',
    ].each do |directive|
      describe directive.inspect do
        [
          'sha256', 'md5'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context "Enum['no', 'yes', 'force', 'auto']" do
    [
      'RequestTTY',
    ].each do |directive|
      describe directive.inspect do
        [
          'no', 'yes', 'force', 'auto'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context "Enum['default', 'none', 'subsystem']" do
    [
      'SessionType',
    ].each do |directive|
      describe directive.inspect do
        [
          'default', 'none', 'subsystem'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context "Enum['yes', 'no', 'accept-new', 'off', 'ask']" do
    [
      'StrictHostKeyChecking',
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'no', 'accept-new', 'off', 'ask'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context "Enum['yes', 'no', 'point-to-point', 'ethernet']" do
    [
      'Tunnel',
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'no', 'point-to-point', 'ethernet'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context "Enum['yes', 'no', 'ask']" do
    [
      'VerifyHostKeyDNS',
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'no', 'ask'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context 'Integer[1]' do
    [
      'CanonicalizeMaxDots', 'ConnectionAttempts', 'ConnectTimeout', 'NumberOfPasswordPrompts', 'RequiredRSASize'
    ].each do |directive|
      describe directive.inspect do
        [
          242, 0x242
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context 'String[1]' do
    [
      'Match', 'BindAddress', 'BindInterface', 'CanonicalDomains',
      'CanonicalizePermittedCNAMEs', 'CASignatureAlgorithms',
      'CertificateFile', 'Ciphers', 'ControlPath', 'ControlPersist',
      'DynamicForward', 'EscapeChar', 'GlobalKnownHostsFile', 'Host',
      'HostbasedAcceptedAlgorithms', 'HostKeyAlgorithms', 'HostKeyAlias',
      'Hostname', 'IdentityAgent', 'IdentityFile', 'IgnoreUnknown', 'Include',
      'IPQoS', 'KbdInteractiveDevices', 'KexAlgorithms', 'KnownHostsCommand',
      'LocalCommand', 'LocalForward', 'LogVerbose', 'MACs', 'PermitRemoteOpen',
      'PKCS11Provider', 'PreferredAuthentications', 'ProxyCommand',
      'ProxyJump', 'PubkeyAcceptedAlgorithms', 'RekeyLimit', 'RemoteCommand',
      'RemoteForward', 'RevokedHostKeys', 'SecurityKeyProvider', 'SendEnv',
      'SetEnv', 'TunnelDevice', 'User', 'UserKnownHostsFile', 'XAuthLocation'
    ].each do |directive|
      describe directive.inspect do
        [
          'string', 'ネット', '242', nil, :keyword # FIXME: unsure why nil and :keyword are actually supported
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, [nil], [nil, nil]
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context 'Variant[String[1] }, Integer[0]]' do
    [
      'ForwardX11Timeout', 'ServerAliveCountMax', 'ServerAliveInterval'
    ].each do |directive|
      describe directive.inspect do
        [
          'string', 'ネット', '242', 242, 0x242, nil, :keyword # FIXME: unsure why nil and :keyword are actually supported
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          ['array'], { 'ha' => 'sh' }, [], '', true, false, [nil], [nil, nil]
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context 'Stdlib::Filemode' do
    [
      'StreamLocalBindMask',
    ].each do |directive|
      describe directive.inspect do
        [
          '242', '1666', 'a=Xr,g=w'
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          '0999', 'a=Xr,g=W', 'string', 'ネット', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end

  context 'Stdlib::Port' do
    [
      'Port',
    ].each do |directive|
      describe directive.inspect do
        [
          242, 0, 65_535, 0x242
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          -1, 65_536, 'string', 'ネット', '242', ['array'], { 'ha' => 'sh' }, [], '', true, false, nil, [nil], [nil, nil], :keyword
        ].each do |invalid|
          it { is_expected.not_to allow_value(directive => invalid) }
        end
      end
    end
  end
end
