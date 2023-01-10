# coding: utf-8

require 'spec_helper'

describe 'Ssh::Sshd_Config' do
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

  context 'Ssh::Permit_root_login' do
    [
      'PermitRootLogin',
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'prohibit-password', 'without-password', 'forced-commands-only', 'no'
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
      'AllowAgentForwarding', 'DisableForwarding', 'ExposeAuthInfo', 'GSSAPIAuthentication', 'GSSAPICleanupCredentials',
      'GSSAPIStrictAcceptorCheck', 'HostbasedAuthentication', 'HostbasedUsesNameFromPacketOnly', 'IgnoreRhosts',
      'IgnoreUserKnownHosts', 'KbdInteractiveAuthentication', 'KerberosAuthentication', 'KerberosGetAFSToken',
      'KerberosOrLocalPasswd', 'KerberosTicketCleanup', 'PasswordAuthentication', 'PermitEmptyPasswords',
      'PermitTTY', 'PermitUserRC', 'PrintLastLog', 'PrintMotd', 'PubkeyAuthentication', 'StreamLocalBindUnlink',
      'StrictModes', 'TCPKeepAlive', 'UseDNS', 'X11Forwarding', 'X11UseLocalhost'
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

  context "Enum['yes', 'all', 'no', 'local', 'remote']" do
    [
      'AllowStreamLocalForwarding',
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'all', 'no', 'local', 'remote'
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

  context "Enum['yes', 'no', 'local', 'remote']" do
    [
      'AllowTcpForwarding',
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'no', 'local', 'remote'
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

  context "Enum['yes', 'delayed', 'no']" do
    [
      'Compression',
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'delayed', 'no'
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

  context "Enum['no', 'yes', 'clientspecified']" do
    [
      'GatewayPorts',
    ].each do |directive|
      describe directive.inspect do
        [
          'no', 'yes', 'clientspecified'
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

  context "Enum['yes', 'point-to-point', 'ethernet', 'no']" do
    [
      'PermitTunnel',
    ].each do |directive|
      describe directive.inspect do
        [
          'yes', 'point-to-point', 'ethernet', 'no'
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

  context "Enum['none', 'touch-required', 'verify-required']" do
    [
      'PubkeyAuthOptions',
    ].each do |directive|
      describe directive.inspect do
        [
          'none', 'touch-required', 'verify-required'
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

  context 'Integer[2]' do
    [
      'MaxAuthTries',
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
      'AcceptEnv', 'AllowGroups', 'AllowUsers', 'AuthenticationMethods', 'AuthorizedKeysCommand', 'AuthorizedKeysCommandUser',
      'AuthorizedKeysFile', 'AuthorizedPrincipalsCommand', 'AuthorizedPrincipalsCommandUser', 'AuthorizedPrincipalsFile',
      'Banner', 'CASignatureAlgorithms', 'ChannelTimeout', 'ChrootDirectory', 'Ciphers', 'DenyGroups', 'DenyUsers',
      'ForceCommand', 'HostbasedAcceptedAlgorithms', 'HostCertificate', 'HostKey', 'HostKeyAgent', 'HostKeyAlgorithms',
      'Include', 'IPQoS', 'KexAlgorithms', 'ListenAddress', 'LogVerbose', 'MACs', 'Match', 'MaxStartups', 'PermitListen',
      'PermitOpen', 'PermitUserEnvironmen', 'PerSourceMaxStartups', 'PerSourceNetBlockSize', 'PidFile', 'PubkeyAcceptedAlgorithms',
      'RekeyLimit', 'RevokedKeys', 'RDomain', 'SetEnv', 'Subsystem', 'TrustedUserCAKeys', 'VersionAddendum', 'XAuthLocation'
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

  context 'Stdlib::Absolutepath' do
    [
      'ModuliFile', 'SecurityKeyProvider'
    ].each do |directive|
      describe directive.inspect do
        [
          '/abs/olute',
        ].each do |valid|
          it { is_expected.to allow_value(directive => valid) }
        end
        [
          'rela/tive', 'string', 'ネット', ['array'], { 'ha' => 'sh' }, [], '', 242, 0x242, true, false, nil, [nil], [nil, nil], :keyword
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
