require 'spec_helper'

describe 'ssh::server' do
  osfamily_matrix = {
    # 'Debian-7' => {
    #   architecture: 'x86_64',
    #   osfamily: 'Debian',
    #   operatingsystemrelease: '7',
    #   ssh_version: 'OpenSSH_6.0p1',
    #   ssh_version_numeric: '6.0',
    #   sshd_packages: ['openssh-server', 'openssh-client'],
    #   sshd_config_mode: '0600',
    #   sshd_service_name: 'ssh',
    #   sshd_service_hasstatus: true,
    #   sshd_config_fixture: 'sshd_config_debian',
    #   ssh_config_fixture: 'ssh_config_debian',
    # },
    'RedHat-5' => {
      architecture: 'x86_64',
      os: {
        family: 'RedHat',
        release: {
          major: '5',
        },
      },
      ssh_version: 'OpenSSH_4.3p2',
      ssh_version_numeric: '4.3',
      sshd_packages: ['openssh-server'],
      sshd_config_mode: '0600',
      sshd_service_name: 'sshd',
      sshd_service_hasstatus: true,
      sshd_config_fixture: 'sshd_config_el5',
    },
    'EL-6' => {
      architecture: 'x86_64',
      os: {
        family: 'RedHat',
        release: {
          major: '6',
        },
      },
      ssh_version: 'OpenSSH_5.3p1',
      ssh_version_numeric: '5.3',
      sshd_packages: ['openssh-server'],
      sshd_config_mode: '0600',
      sshd_service_name: 'sshd',
      sshd_service_hasstatus: true,
      sshd_config_fixture: 'sshd_config_el6',
    },
    'EL-7' => {
      architecture: 'x86_64',
      os: {
        family: 'RedHat',
        release: {
          major: '7',
        },
      },
      ssh_version: 'OpenSSH_7.4p1',
      ssh_version_numeric: '7.4',
      sshd_config_mode: '0600',
      sshd_service_name: 'sshd',
      sshd_service_hasstatus: true,
      sshd_packages: ['openssh-server'],
      sshd_config_fixture: 'sshd_config_el7',
    },
    # 'Suse-10-x86_64' => {
    #   architecture: 'x86_64',
    #   osfamily: 'Suse',
    #   operatingsystem: 'SLES',
    #   operatingsystemrelease: '10.4',
    #   ssh_version: 'OpenSSH_5.1p1',
    #   ssh_version_numeric: '5.1',
    #   sshd_packages: ['openssh'],
    #   sshd_config_mode: '0600',
    #   sshd_service_name: 'sshd',
    #   sshd_service_hasstatus: true,
    #   sshd_config_fixture: 'sshd_config_suse_x86_64',
    #   ssh_config_fixture: 'ssh_config_suse_old',
    # },
    # 'Suse-10-i386' => {
    #   architecture: 'i386',
    #   osfamily: 'Suse',
    #   operatingsystem: 'SLES',
    #   operatingsystemrelease: '10.4',
    #   ssh_version: 'OpenSSH_5.1p1',
    #   ssh_version_numeric: '5.1',
    #   sshd_packages: ['openssh'],
    #   sshd_config_mode: '0600',
    #   sshd_service_name: 'sshd',
    #   sshd_service_hasstatus: true,
    #   sshd_config_fixture: 'sshd_config_suse_i386',
    #   ssh_config_fixture: 'ssh_config_suse_old',
    # },
    # 'Suse-11-x86_64' => {
    #   architecture: 'x86_64',
    #   osfamily: 'Suse',
    #   operatingsystem: 'SLES',
    #   operatingsystemrelease: '11.4',
    #   ssh_version: 'OpenSSH_6.6.1p1',
    #   ssh_version_numeric: '6.6',
    #   sshd_packages: ['openssh'],
    #   sshd_config_mode: '0600',
    #   sshd_service_name: 'sshd',
    #   sshd_service_hasstatus: true,
    #   sshd_config_fixture: 'sshd_config_suse_x86_64',
    #   ssh_config_fixture: 'ssh_config_suse',
    # },
    # 'Suse-11-i386' => {
    #   architecture: 'i386',
    #   osfamily: 'Suse',
    #   operatingsystem: 'SLES',
    #   operatingsystemrelease: '11.4',
    #   ssh_version: 'OpenSSH_6.6.1p1',
    #   ssh_version_numeric: '6.6',
    #   sshd_packages: ['openssh'],
    #   sshd_config_mode: '0600',
    #   sshd_service_name: 'sshd',
    #   sshd_service_hasstatus: true,
    #   sshd_config_fixture: 'sshd_config_suse_i386',
    #   ssh_config_fixture: 'ssh_config_suse',
    # },
    # 'Suse-12-x86_64' => {
    #   architecture: 'x86_64',
    #   osfamily: 'Suse',
    #   operatingsystem: 'SLES',
    #   operatingsystemrelease: '12.0',
    #   ssh_version: 'OpenSSH_6.6.1p1',
    #   ssh_version_numeric: '6.6',
    #   sshd_packages: ['openssh'],
    #   sshd_config_mode: '0600',
    #   sshd_service_name: 'sshd',
    #   sshd_service_hasstatus: true,
    #   sshd_config_fixture: 'sshd_config_sles_12_x86_64',
    #   ssh_config_fixture: 'ssh_config_suse',
    # },
    # 'Solaris-5.11' => {
    #   architecture: 'i86pc',
    #   osfamily: 'Solaris',
    #   kernelrelease: '5.11',
    #   ssh_version: 'Sun_SSH_2.2',
    #   ssh_version_numeric: '2.2',
    #   sshd_packages: ['network/ssh', 'network/ssh/ssh-key', 'service/network/ssh'],
    #   sshd_config_mode: '0644',
    #   sshd_service_name: 'ssh',
    #   sshd_service_hasstatus: true,
    #   sshd_config_fixture: 'sshd_config_solaris',
    #   ssh_config_fixture: 'ssh_config_solaris',
    # },
    # 'Solaris-5.10' => {
    #   architecture: 'i86pc',
    #   osfamily: 'Solaris',
    #   kernelrelease: '5.10',
    #   ssh_version: 'Sun_SSH_2.2',
    #   ssh_version_numeric: '2.2',
    #   sshd_packages: ['SUNWsshcu', 'SUNWsshdr', 'SUNWsshdu', 'SUNWsshr', 'SUNWsshu'],
    #   sshd_config_mode: '0644',
    #   sshd_service_name: 'ssh',
    #   sshd_service_hasstatus: true,
    #   sshd_config_fixture: 'sshd_config_solaris',
    #   ssh_config_fixture: 'ssh_config_solaris',
    # },
    # 'Solaris-5.9' => {
    #   architecture: 'i86pc',
    #   osfamily: 'Solaris',
    #   kernelrelease: '5.9',
    #   ssh_version: 'Sun_SSH_2.2',
    #   ssh_version_numeric: '2.2',
    #   sshd_packages: ['SUNWsshcu', 'SUNWsshdr', 'SUNWsshdu', 'SUNWsshr', 'SUNWsshu'],
    #   sshd_config_mode: '0644',
    #   sshd_service_name: 'sshd',
    #   sshd_service_hasstatus: false,
    #   sshd_config_fixture: 'sshd_config_solaris',
    #   ssh_config_fixture: 'ssh_config_solaris',
    # },
    # 'Ubuntu-1604' => {
    #   architecture: 'x86_64',
    #   osfamily: 'Debian',
    #   operatingsystemrelease: '16.04',
    #   ssh_version: 'OpenSSH_7.2p2',
    #   ssh_version_numeric: '7.2',
    #   sshd_packages: ['openssh-server', 'openssh-client'],
    #   sshd_config_mode: '0600',
    #   sshd_service_name: 'ssh',
    #   sshd_service_hasstatus: true,
    #   sshd_config_fixture: 'sshd_config_ubuntu1604',
    #   ssh_config_fixture: 'ssh_config_ubuntu1604',
    # },
  }

  defaults = {
    fqdn: 'monkey.example.com',
    hostname: 'monkey',
    ipaddress: '127.0.0.1',
    root_home: '/root',
    specific: 'dummy',
    sshrsakey: 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ==', # rubocop:disable Layout/LineLength
  }

  #  defaults_solaris = {
  #    fqdn: 'monkey.example.com',
  #    hostname: 'monkey',
  #    ipaddress: '127.0.0.1',
  #    kernelrelease: '5.10',
  #    osfamily: 'Solaris',
  #    root_home: '/root',
  #    specific: 'dummy',
  #    ssh_version: 'Sun_SSH_2.2',
  #    ssh_version_numeric: '2.2',
  #    sshrsakey: 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ==', # rubocop:disable Layout/LineLength
  #  }

  default_facts = osfamily_matrix['EL-7'].merge(defaults)

  let(:facts) { default_facts }

  osfamily_matrix.each do |os, facts|
    context "with default params on osfamily #{os}" do
      let(:facts) { defaults.merge(facts) }

      # FIXME: first one fails. If you remove the duplicate, the first compile
      # fails, if you remove both compile lines, then contain class fails and so on. Get this error
      #
      # Evaluation Error: Error while evaluating a Resource Statement, Could not autoload puppet/type/service: Could not autoload puppet/provider/service/upstart: Could not autoload puppet/provider/service/debian: Could not autoload puppet/provider/service/init: undefined method `downcase' for nil:NilClass (file: /Users/gh/git/puppet-module-ssh/spec/fixtures/modules/ssh/manifests/server.pp, line: 332, column: 5) # rubocop:disable Layout/LineLength
      it { is_expected.to compile.with_all_deps }

      it { is_expected.to contain_class('ssh::server') }

      facts[:sshd_packages].each do |pkg|
        it {
          is_expected.to contain_package(pkg).with(
            {
              'ensure' => 'installed',
            },
          )
        }
      end

      it {
        is_expected.to contain_file('sshd_config').with(
          {
            'ensure'  => 'file',
            'path'    => '/etc/ssh/sshd_config',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => facts[:sshd_config_mode],
          },
        )
      }

      facts[:sshd_packages].each do |pkg|
        it {
          is_expected.to contain_file('sshd_config').that_requires("Package[#{pkg}]")
        }
      end

      sshd_config_fixture = File.read(fixtures("#{facts[:sshd_config_fixture]}_sorted"))
      it { is_expected.to contain_file('sshd_config').with_content(sshd_config_fixture) }

      it { is_expected.not_to contain_file('sshd_banner') }

      it {
        is_expected.to contain_service('sshd_service').with(
          {
            'ensure'     => 'running',
            'name'       => facts[:sshd_service_name],
            'enable'     => 'true',
            'hasrestart' => 'true',
            'hasstatus'  => facts[:sshd_service_hasstatus],
            'subscribe'  => 'File[sshd_config]',
          },
        )
      }
    end
  end

  # TODO: test failure on unsupported platforms
  #  context 'with default params on invalid osfamily' do
  #    let(:facts) { default_facts.merge({ osfamily: 'C64' }) }
  #
  #    it 'fail' do
  #      expect {
  #        is_expected.to contain_class('ssh')
  #      }.to raise_error(Puppet::Error,/ssh supports osfamilies RedHat, Suse, Debian and Solaris\. Detected osfamily is <C64>\./)
  #    end
  #  end
  #

  # TODO: test each param here
  #
  describe 'with parameter' do
    context 'syslog_facility' do
      context 'set to a valid facility' do
        let(:params) { { syslog_facility: 'LOCAL1' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^SyslogFacility LOCAL1$}) }
      end
    end

    context 'stream_local_bind_mask' do
      context 'set to a valid umask' do
        let(:params) { { stream_local_bind_mask: '0022' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^StreamLocalBindMask 0022$}) }
      end
    end

    context 'client_alive_count_max' do
      context 'set to a valid Integer' do
        let(:params) { { client_alive_count_max: 23 } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^ClientAliveCountMax 23$}) }
      end
    end

    context 'client_alive_interval' do
      context 'set to a valid Integer' do
        let(:params) { { client_alive_interval: 23 } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^ClientAliveInterval 23$}) }
      end
    end

    context 'login_grace_time' do
      context 'set to a valid Integer' do
        let(:params) { { login_grace_time: 23 } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^LoginGraceTime 23$}) }
      end
    end

    context 'max_auth_tries' do
      context 'set to a valid Integer' do
        let(:params) { { max_auth_tries: 23 } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^MaxAuthTries 23$}) }
      end
    end

    context 'max_sessions' do
      context 'set to a valid Integer' do
        let(:params) { { max_sessions: 23 } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^MaxSessions 23$}) }
      end
    end

    context 'x11_display_offset' do
      context 'set to a valid Integer' do
        let(:params) { { x11_display_offset: 23 } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^X11DisplayOffset 23$}) }
      end
    end

    context 'authorized_keys_command' do
      context "set to valid string 'test'" do
        let(:params) { { authorized_keys_command: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthorizedKeysCommand test$}) }
      end
    end

    context 'authorized_keys_command_user' do
      context "set to valid string 'test'" do
        let(:params) { { authorized_keys_command_user: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthorizedKeysCommandUser test$}) }
      end
    end

    context 'authorized_principals_command' do
      context "set to valid string 'test'" do
        let(:params) { { authorized_principals_command: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthorizedPrincipalsCommand test$}) }
      end
    end

    context 'authorized_principals_command_user' do
      context "set to valid string 'test'" do
        let(:params) { { authorized_principals_command_user: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthorizedPrincipalsCommandUser test$}) }
      end
    end

    context 'authorized_principals_file' do
      context "set to valid string 'test'" do
        let(:params) { { authorized_principals_file: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthorizedPrincipalsFile test$}) }
      end
    end

    context 'banner' do
      context "set to valid string 'test'" do
        let(:params) { { banner: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^Banner test$}) }
      end
    end

    context 'challenge_response_authentication' do
      context "set to valid string 'test'" do
        let(:params) { { challenge_response_authentication: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^ChallengeResponseAuthentication test$}) }
      end
    end

    context 'chroot_directory' do
      context "set to valid string 'test'" do
        let(:params) { { chroot_directory: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^ChrootDirectory test$}) }
      end
    end

    context 'force_command' do
      context "set to valid string 'test'" do
        let(:params) { { force_command: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^ForceCommand test$}) }
      end
    end

    context 'host_certificate' do
      context "set to valid string 'test'" do
        let(:params) { { host_certificate: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^HostCertificate test$}) }
      end
    end

    context 'host_key_agent' do
      context "set to valid string 'test'" do
        let(:params) { { host_key_agent: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^HostKeyAgent test$}) }
      end
    end

    context 'ip_qos' do
      context "set to valid string 'test'" do
        let(:params) { { ip_qos: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^IPQoS test$}) }
      end
    end

    context 'log_level' do
      context "set to valid string 'DEBUG1'" do
        let(:params) { { log_level: 'DEBUG1' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^LogLevel DEBUG1$}) }
      end
    end

    context 'max_startups' do
      context "set to valid string 'test'" do
        let(:params) { { max_startups: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^MaxStartups test$}) }
      end
    end

    context 'permit_user_environment' do
      context "set to valid string 'test'" do
        let(:params) { { permit_user_environment: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitUserEnvironment test$}) }
      end
    end

    context 'pid_file' do
      context "set to valid string 'test'" do
        let(:params) { { pid_file: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^PidFile test$}) }
      end
    end

    context 'rekey_limit' do
      context "set to valid string 'test'" do
        let(:params) { { rekey_limit: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^RekeyLimit test$}) }
      end
    end

    context 'revoked_keys' do
      context "set to valid string 'test'" do
        let(:params) { { revoked_keys: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^RevokedKeys test$}) }
      end
    end

    context 'rdomain' do
      context "set to valid string 'test'" do
        let(:params) { { rdomain: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^RDomain test$}) }
      end
    end

    context 'set_env' do
      context "set to valid string 'test'" do
        let(:params) { { set_env: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^SetEnv test$}) }
      end
    end

    context 'subsystem' do
      context "set to valid string 'test'" do
        let(:params) { { subsystem: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^Subsystem test$}) }
      end
    end

    context 'trusted_user_ca_keys' do
      context "set to valid string 'test'" do
        let(:params) { { trusted_user_ca_keys: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^TrustedUserCAKeys test$}) }
      end
    end

    context 'version_addendum' do
      context "set to valid string 'test'" do
        let(:params) { { version_addendum: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^VersionAddendum test$}) }
      end
    end

    context 'xauth_location' do
      context "set to valid string 'test'" do
        let(:params) { { xauth_location: 'test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^XAuthLocation test$}) }
      end
    end

    context 'custom' do
      context "set to valid string 'Foo test'" do
        let(:params) { { custom: 'Foo test' } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^Foo test$}) }
      end
    end

    context 'address_family' do
      ['any', 'inet', 'inet6'].each do |v|
        context "set to valid string #{v}" do
          let(:params) { { address_family: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^AddressFamily #{v}$}) }
        end
      end
    end

    context 'allow_stream_local_forwarding' do
      ['yes', 'all', 'no', 'local', 'remote'].each do |v|
        context "set to valid string #{v}" do
          let(:params) { { allow_stream_local_forwarding: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^AllowStreamLocalForwarding #{v}$}) }
        end
      end
    end

    context 'allow_tcp_forwarding' do
      ['yes', 'no', 'local', 'remote'].each do |v|
        context "set to valid string #{v}" do
          let(:params) { { allow_tcp_forwarding: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^AllowTcpForwarding #{v}$}) }
        end
      end
    end

    context 'compression' do
      ['yes', 'delayed', 'no'].each do |v|
        context "set to valid string #{v}" do
          let(:params) { { compression: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^Compression #{v}$}) }
        end
      end
    end

    context 'fingerprint_hash' do
      ['md5', 'sha256'].each do |v|
        context "set to valid string #{v}" do
          let(:params) { { fingerprint_hash: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^FingerprintHash #{v}$}) }
        end
      end
    end

    context 'gateway_ports' do
      ['no', 'yes', 'clientspecified'].each do |v|
        context "set to valid string #{v}" do
          let(:params) { { gateway_ports: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^GatewayPorts #{v}$}) }
        end
      end
    end

    context 'permit_tunnel' do
      ['yes', 'point-to-point', 'ethernet', 'no'].each do |v|
        context "set to valid string #{v}" do
          let(:params) { { permit_tunnel: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitTunnel #{v}$}) }
        end
      end
    end

    context 'allow_agent_forwarding' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { allow_agent_forwarding: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^AllowAgentForwarding #{v}$}) }
        end
      end
    end

    context 'disable_forwarding' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { disable_forwarding: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^DisableForwarding #{v}$}) }
        end
      end
    end

    context 'expose_auth_info' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { expose_auth_info: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^ExposeAuthInfo #{v}$}) }
        end
      end
    end

    context 'gss_api_authentication' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { gss_api_authentication: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^GSSAPIAuthentication #{v}$}) }
        end
      end
    end

    context 'gss_api_cleanup_credentials' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { gss_api_cleanup_credentials: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^GSSAPICleanupCredentials #{v}$}) }
        end
      end
    end

    context 'gss_api_strict_acceptor_check' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { gss_api_strict_acceptor_check: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^GSSAPIStrictAcceptorCheck #{v}$}) }
        end
      end
    end

    context 'hostbased_authentication' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { hostbased_authentication: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^HostbasedAuthentication #{v}$}) }
        end
      end
    end

    context 'hostbased_uses_name_from_packet_only' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { hostbased_uses_name_from_packet_only: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^HostbasedUsesNameFromPacketOnly #{v}$}) }
        end
      end
    end

    context 'ignore_rhosts' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { ignore_rhosts: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^IgnoreRhosts #{v}$}) }
        end
      end
    end

    context 'ignore_user_known_hosts' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { ignore_user_known_hosts: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^IgnoreUserKnownHosts #{v}$}) }
        end
      end
    end

    context 'kbd_interactive_authentication' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { kbd_interactive_authentication: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^KbdInteractiveAuthentication #{v}$}) }
        end
      end
    end

    context 'kerberos_authentication' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { kerberos_authentication: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^KerberosAuthentication #{v}$}) }
        end
      end
    end

    context 'kerberos_get_afs_token' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { kerberos_get_afs_token: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^KerberosGetAFSToken #{v}$}) }
        end
      end
    end

    context 'kerberos_or_local_passwd' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { kerberos_or_local_passwd: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^KerberosOrLocalPasswd #{v}$}) }
        end
      end
    end

    context 'kerberos_ticket_cleanup' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { kerberos_ticket_cleanup: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^KerberosTicketCleanup #{v}$}) }
        end
      end
    end

    context 'password_authentication' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { password_authentication: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PasswordAuthentication #{v}$}) }
        end
      end
    end

    context 'permit_empty_passwords' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { permit_empty_passwords: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitEmptyPasswords #{v}$}) }
        end
      end
    end

    context 'permit_tty' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { permit_tty: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitTTY #{v}$}) }
        end
      end
    end

    context 'permit_user_rc' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { permit_user_rc: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitUserRC #{v}$}) }
        end
      end
    end

    context 'print_last_log' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { print_last_log: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PrintLastLog #{v}$}) }
        end
      end
    end

    context 'print_motd' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { print_motd: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PrintMotd #{v}$}) }
        end
      end
    end

    context 'pubkey_authentication' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { pubkey_authentication: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^PubkeyAuthentication #{v}$}) }
        end
      end
    end

    context 'stream_local_bind_unlink' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { stream_local_bind_unlink: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^StreamLocalBindUnlink #{v}$}) }
        end
      end
    end

    context 'strict_modes' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { strict_modes: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^StrictModes #{v}$}) }
        end
      end
    end

    context 'tcp_keep_alive' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { tcp_keep_alive: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^TCPKeepAlive #{v}$}) }
        end
      end
    end

    context 'use_dns' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { use_dns: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^UseDNS #{v}$}) }
        end
      end
    end

    context 'use_pam' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { use_pam: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^UsePAM #{v}$}) }
        end
      end
    end

    context 'x11_forwarding' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { x11_forwarding: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^X11Forwarding #{v}$}) }
        end
      end
    end

    context 'x11_use_localhost' do
      ['yes', 'no'].each do |v|
        context "set to #{v}" do
          let(:params) { { x11_use_localhost: v } }

          it { is_expected.to contain_file('sshd_config').with_content(%r{^X11UseLocalhost #{v}$}) }
        end
      end
    end

    context 'accept_env' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { accept_env: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AcceptEnv test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { accept_env: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AcceptEnv one$}) }
        it { is_expected.to contain_file('sshd_config').with_content(%r{^AcceptEnv two$}) }
      end
    end

    context 'authentication_methods' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { authentication_methods: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthenticationMethods test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { authentication_methods: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthenticationMethods one,two$}) }
      end
    end

    context 'ca_signature_algorithms' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { ca_signature_algorithms: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^CASignatureAlgorithms test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { ca_signature_algorithms: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^CASignatureAlgorithms one,two$}) }
      end
    end

    context 'ciphers' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { ciphers: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^Ciphers test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { ciphers: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^Ciphers one,two$}) }
      end
    end

    context 'hostbased_accepted_key_types' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { hostbased_accepted_key_types: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^HostbasedAcceptedKeyTypes test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { hostbased_accepted_key_types: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^HostbasedAcceptedKeyTypes one,two$}) }
      end
    end

    context 'host_key' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { host_key: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^HostKey test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { host_key: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^HostKey one$}) }
        it { is_expected.to contain_file('sshd_config').with_content(%r{^HostKey two$}) }
      end
    end

    context 'host_key_algorithms' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { host_key_algorithms: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^HostKeyAlgorithms test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { host_key_algorithms: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^HostKeyAlgorithms one,two$}) }
      end
    end

    context 'kex_algorithms' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { kex_algorithms: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^KexAlgorithms test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { kex_algorithms: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^KexAlgorithms one,two$}) }
      end
    end

    context 'listen_address' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { listen_address: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^ListenAddress test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { listen_address: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^ListenAddress one$}) }
        it { is_expected.to contain_file('sshd_config').with_content(%r{^ListenAddress two$}) }
      end
    end

    context 'macs' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { macs: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^MACs test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { macs: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^MACs one,two$}) }
      end
    end

    context 'pubkey_accepted_key_types' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { pubkey_accepted_key_types: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^PubkeyAcceptedKeyTypes test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { pubkey_accepted_key_types: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^PubkeyAcceptedKeyTypes one,two$}) }
      end
    end

    context 'allow_groups' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { allow_groups: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AllowGroups test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { allow_groups: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AllowGroups one two$}) }
      end
    end

    context 'allow_users' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { allow_users: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AllowUsers test$}) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) { { allow_users: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AllowUsers one two$}) }
      end
    end

    context 'authorized_keys_file' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { authorized_keys_file: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthorizedKeysFile test$}) }
      end
      context "set to an array of strings with multiple elements ['one', 'two']" do
        let(:params) { { authorized_keys_file: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^AuthorizedKeysFile one two$}) }
      end
    end

    context 'deny_groups' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { deny_groups: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^DenyGroups test$}) }
      end
      context "set to an array of strings with multiple elements ['one', 'two']" do
        let(:params) { { deny_groups: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^DenyGroups one two$}) }
      end
    end

    context 'deny_users' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { deny_users: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^DenyUsers test$}) }
      end
      context "set to an array of strings with multiple elements ['one', 'two']" do
        let(:params) { { deny_users: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^DenyUsers one two$}) }
      end
    end

    context 'permit_listen' do
      context "set to an array of strings with one element ['test']" do
        let(:params) { { permit_listen: ['test'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitListen test$}) }
      end
      context "set to an array of strings with multiple elements ['one', 'two']" do
        let(:params) { { permit_listen: ['one', 'two'] } }

        it { is_expected.to contain_file('sshd_config').with_content(%r{^PermitListen one two$}) }
      end
    end
  end

  describe 'validate data types of parameters' do
    validations = {
      'Stdlib::Absolutepath (optional)' => {
        name:     ['package_adminfile', 'package_source'],
        valid:    ['/absolute/filepath', '/absolute/directory/', :undef],
        invalid:  ['../invalid', ['array'], { 'ha' => 'sh' }, 3, 2.42, false],
        message: 'expects a (match for|match for Stdlib::Absolutepath =|Stdlib::Absolutepath =) Variant\[Stdlib::Windowspath.*Stdlib::Unixpath',
      },
      'Stdlib::Absolutepath' => {
        name:     ['banner_path', 'config_path'],
        valid:    ['/absolute/filepath', '/absolute/directory/'],
        invalid:  ['../invalid', ['array'], { 'ha' => 'sh' }, 3, 2.42, false, nil],
        message: 'expects a (match for|match for Stdlib::Absolutepath =|Stdlib::Absolutepath =) Variant\[Stdlib::Windowspath.*Stdlib::Unixpath',
      },
      'Stdlib::Ensure::Service' => {
        name:     ['service_ensure'],
        valid:    ['running', 'stopped'],
        invalid:  ['present', 'absent', ['array'], { 'ha' => 'sh' }, 3, 2.42, false, nil],
        message: 'expects a match for Stdlib::Ensure::Service',
      },
      'Stdlib::Filemode' => {
        name:     ['banner_mode', 'config_mode'],
        valid:    ['0644', '0755', '0640', '1740'],
        invalid:  [2770, '0844', '00644', 'string', ['array'], { 'ha' => 'sh' }, 3, 2.42, false, nil],
        message: 'expects a match for Stdlib::Filemode|Error while evaluating a Resource Statement',
      },
      'Stdlib::Port (optional)' => {
        name:     ['port'],
        valid:    [0, 65_535, :undef],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, -1, 2.42, 65_536, false],
        message: 'expects a match for Stdlib::Port|Error while evaluating a Resource Statement',
      },
      'String or Array of strings' => {
        name:     ['packages'],
        valid:    ['string', ['array', 'of', 'strings']],
        invalid:  [{ 'ha' => 'sh' }, 3, 2.42, false, [0]],
        message: 'String or Array|expects a String value|Error while evaluating a Resource Statement',
      },
      'String or Array of strings (optional)' => {
        name:     ['allow_groups', 'allow_users', 'authorized_keys_file', 'deny_groups', 'deny_users', 'permit_listen'],
        valid:    ['string', ['array', 'of', 'strings'], :undef],
        invalid:  [{ 'ha' => 'sh' }, 3, 2.42, false, [0]],
        message: 'String or Array|expects a String value|Error while evaluating a Resource Statement',
      },
      'Array of strings (optional)' => {
        name:     ['accept_env', 'authentication_methods', 'ca_signature_algorithms', 'ciphers', 'host_key', 'host_key_algorithms',
                   'hostbased_accepted_key_types', 'kex_algorithms', 'listen_address', 'macs', 'pubkey_accepted_key_types'],
        valid:    [['array', 'of', 'strings'], :undef],
        invalid:  ['string', { 'ha' => 'sh' }, 3, 2.42, false, [0]],
        message: 'Undef or Array|expects a String value|Error while evaluating a Resource Statement',
      },
      'integer => 0 (optional)' => {
        name:     ['client_alive_count_max', 'client_alive_interval', 'login_grace_time', 'max_sessions', 'x11_display_offset'],
        valid:    [0, 1, 23, :undef],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'Undef or Integer|Error while evaluating a Resource Statement',
      },
      'integer => 2 (optional)' => {
        name:     ['max_auth_tries'],
        valid:    [2, 23, :undef],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, -1, 2.42, 0, 1, false],
        message: 'Undef or Integer|Error while evaluating a Resource Statement',
      },
      'four digit octal (optional) for umask' => {
        name:     ['stream_local_bind_mask'],
        valid:    ['0000', '1234', '7777', :undef],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, -1, 2.42, false, '00000', 'x234', '77e1', '011'],
        message: 'Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for permit_root_login (optional)' => {
        name:     ['permit_root_login'],
        valid:    ['yes', 'prohibit-password', 'without-password', 'forced-commands-only', 'no', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for syslog_facility (optional)' => {
        name:     ['syslog_facility'],
        valid:    ['DAEMON', 'USER', 'AUTH', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7', 'AUTHPRIV', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false, 'USER0', 'daemon'],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for fingerprint_hash (optional)' => {
        name:     ['fingerprint_hash'],
        valid:    ['md5', 'sha256', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for gateway_ports (optional)' => {
        name:     ['gateway_ports'],
        valid:    ['yes', 'no', 'clientspecified', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for allow_stream_local_forwarding (optional)' => {
        name:     ['allow_stream_local_forwarding'],
        valid:    ['yes', 'all', 'no', 'local', 'remote', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for compression (optional)' => {
        name:     ['compression'],
        valid:    ['yes', 'no', 'delayed', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for allow_tcp_forwarding (optional)' => {
        name:     ['allow_tcp_forwarding'],
        valid:    ['yes', 'no', 'local', 'remote', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for permit_tunnel (optional)' => {
        name:     ['permit_tunnel'],
        valid:    ['yes', 'point-to-point', 'ethernet', 'no', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for address_family (optional)' => {
        name:     ['address_family'],
        valid:    ['any', 'inet', 'inet6', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'yes or no (optional)' => {
        name:     ['allow_agent_forwarding', 'disable_forwarding', 'expose_auth_info', 'gss_api_authentication', 'gss_api_cleanup_credentials',
                   'gss_api_strict_acceptor_check', 'hostbased_authentication', 'hostbased_uses_name_from_packet_only', 'ignore_rhosts', 'ignore_user_known_hosts',
                   'kbd_interactive_authentication', 'kerberos_authentication', 'kerberos_get_afs_token', 'kerberos_or_local_passwd', 'kerberos_ticket_cleanup',
                   'password_authentication', 'permit_empty_passwords', 'permit_tty', 'permit_user_rc', 'print_last_log', 'print_motd', 'pubkey_authentication',
                   'stream_local_bind_unlink', 'strict_modes', 'tcp_keep_alive', 'use_dns', 'use_pam', 'x11_forwarding', 'x11_use_localhost'],
        valid:    ['yes', 'no', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false, 'YES', 'No'],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Ssh::Log_level (optional)' => {
        name:     ['log_level'],
        valid:    ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3', :undef],
        invalid:  ['invalid', ['array'], { 'ha' => 'sh' }, -1, 2.42, false, 'INFO1'],
        message: 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Boolean' => {
        name:     ['manage_service', 'service_enable', 'service_hasrestart', 'service_hasstatus'],
        valid:    [true, false],
        invalid:  ['string', ['array'], { 'ha' => 'sh' }, 3, 2.42, 'false', nil],
        message: 'expects a Boolean',
      },
      'String (optional)' => {
        name:     ['authorized_keys_command', 'authorized_keys_command_user',
                   'authorized_principals_command', 'authorized_principals_command_user',
                   'authorized_principals_file', 'banner', 'banner_content',
                   'challenge_response_authentication', 'chroot_directory', 'force_command',
                   'host_certificate', 'host_key_agent', 'ip_qos', 'max_startups',
                   'permit_user_environment', 'pid_file', 'rdomain', 'rekey_limit', 'revoked_keys',
                   'set_env', 'subsystem', 'trusted_user_ca_keys', 'version_addendum', 'xauth_location',
                   'custom'],
        valid:    ['string', :undef],
        invalid:  [['array'], { 'ha' => 'sh' }, 3, 2.42, false],
        message: 'expects a value of type Undef or String',
      },
    }

    validations.sort.each do |type, var|
      mandatory_params = {} if mandatory_params.nil?
      var[:name].each do |var_name|
        var[:params] = {} if var[:params].nil?
        var[:valid].each do |valid|
          context "when #{var_name} (#{type}) is set to valid #{valid} (as #{valid.class})" do
            let(:facts) { [mandatory_facts, var[:facts]].reduce(:merge) } unless var[:facts].nil?
            let(:params) { [mandatory_params, var[:params], { "#{var_name}": valid, }].reduce(:merge) }

            it { is_expected.to compile }
          end
        end

        var[:invalid].each do |invalid|
          context "when #{var_name} (#{type}) is set to invalid #{invalid} (as #{invalid.class})" do
            let(:params) { [mandatory_params, var[:params], { "#{var_name}": invalid, }].reduce(:merge) }

            it 'fail' do
              expect { is_expected.to contain_class(:subject) }.to raise_error(Puppet::Error, %r{#{var[:message]}})
            end
          end
        end
      end # var[:name].each
    end # validations.sort.each
  end # describe 'validate data types of parameters'
end
