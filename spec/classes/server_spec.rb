require 'spec_helper'

describe 'ssh::server' do

  osfamily_matrix = {
#    'Debian-7' => {
#      :architecture           => 'x86_64',
#      :osfamily               => 'Debian',
#      :operatingsystemrelease => '7',
#      :ssh_version            => 'OpenSSH_6.0p1',
#      :ssh_version_numeric    => '6.0',
#      :sshd_packages           => ['openssh-server', 'openssh-client'],
#      :sshd_config_mode       => '0600',
#      :sshd_service_name      => 'ssh',
#      :sshd_service_hasstatus => true,
#      :sshd_config_fixture    => 'sshd_config_debian',
#      :ssh_config_fixture     => 'ssh_config_debian',
#    },
    'RedHat-5' => {
      :architecture           => 'x86_64',
      :os                     => {
        :family  => 'RedHat',
        :release => {
          :major  => '5',
        },
      },
      :ssh_version            => 'OpenSSH_4.3p2',
      :ssh_version_numeric    => '4.3',
      :sshd_packages           => ['openssh-server'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_el5',
    },
    'EL-6' => {
      :architecture           => 'x86_64',
      :os                     => {
        :family  => 'RedHat',
        :release => {
          :major  => '6',
        },
      },
      :ssh_version            => 'OpenSSH_5.3p1',
      :ssh_version_numeric    => '5.3',
      :sshd_packages          => ['openssh-server'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_el6',
    },
    'EL-7' => {
      :architecture           => 'x86_64',
      :os                     => {
        :family  => 'RedHat',
        :release => {
          :major  => '7',
        },
      },
      :ssh_version            => 'OpenSSH_7.4p1',
      :ssh_version_numeric    => '7.4',
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_packages          => ['openssh-server'],
      :sshd_config_fixture    => 'sshd_config_el7',
    },
#    'Suse-10-x86_64' => {
#      :architecture           => 'x86_64',
#      :osfamily               => 'Suse',
#      :operatingsystem        => 'SLES',
#      :operatingsystemrelease => '10.4',
#      :ssh_version            => 'OpenSSH_5.1p1',
#      :ssh_version_numeric    => '5.1',
#      :sshd_packages           => ['openssh'],
#      :sshd_config_mode       => '0600',
#      :sshd_service_name      => 'sshd',
#      :sshd_service_hasstatus => true,
#      :sshd_config_fixture    => 'sshd_config_suse_x86_64',
#      :ssh_config_fixture     => 'ssh_config_suse_old',
#    },
#    'Suse-10-i386' => {
#      :architecture           => 'i386',
#      :osfamily               => 'Suse',
#      :operatingsystem        => 'SLES',
#      :operatingsystemrelease => '10.4',
#      :ssh_version            => 'OpenSSH_5.1p1',
#      :ssh_version_numeric    => '5.1',
#      :sshd_packages           => ['openssh'],
#      :sshd_config_mode       => '0600',
#      :sshd_service_name      => 'sshd',
#      :sshd_service_hasstatus => true,
#      :sshd_config_fixture    => 'sshd_config_suse_i386',
#      :ssh_config_fixture     => 'ssh_config_suse_old',
#    },
#    'Suse-11-x86_64' => {
#      :architecture           => 'x86_64',
#      :osfamily               => 'Suse',
#      :operatingsystem        => 'SLES',
#      :operatingsystemrelease => '11.4',
#      :ssh_version            => 'OpenSSH_6.6.1p1',
#      :ssh_version_numeric    => '6.6',
#      :sshd_packages           => ['openssh'],
#      :sshd_config_mode       => '0600',
#      :sshd_service_name      => 'sshd',
#      :sshd_service_hasstatus => true,
#      :sshd_config_fixture    => 'sshd_config_suse_x86_64',
#      :ssh_config_fixture     => 'ssh_config_suse',
#    },
#    'Suse-11-i386' => {
#      :architecture           => 'i386',
#      :osfamily               => 'Suse',
#      :operatingsystem        => 'SLES',
#      :operatingsystemrelease => '11.4',
#      :ssh_version            => 'OpenSSH_6.6.1p1',
#      :ssh_version_numeric    => '6.6',
#      :sshd_packages           => ['openssh'],
#      :sshd_config_mode       => '0600',
#      :sshd_service_name      => 'sshd',
#      :sshd_service_hasstatus => true,
#      :sshd_config_fixture    => 'sshd_config_suse_i386',
#      :ssh_config_fixture     => 'ssh_config_suse',
#    },
#    'Suse-12-x86_64' => {
#      :architecture           => 'x86_64',
#      :osfamily               => 'Suse',
#      :operatingsystem        => 'SLES',
#      :operatingsystemrelease => '12.0',
#      :ssh_version            => 'OpenSSH_6.6.1p1',
#      :ssh_version_numeric    => '6.6',
#      :sshd_packages           => ['openssh'],
#      :sshd_config_mode       => '0600',
#      :sshd_service_name      => 'sshd',
#      :sshd_service_hasstatus => true,
#      :sshd_config_fixture    => 'sshd_config_sles_12_x86_64',
#      :ssh_config_fixture     => 'ssh_config_suse',
#    },
#    'Solaris-5.11' => {
#      :architecture           => 'i86pc',
#      :osfamily               => 'Solaris',
#      :kernelrelease          => '5.11',
#      :ssh_version            => 'Sun_SSH_2.2',
#      :ssh_version_numeric    => '2.2',
#      :sshd_packages           => ['network/ssh', 'network/ssh/ssh-key', 'service/network/ssh'],
#      :sshd_config_mode       => '0644',
#      :sshd_service_name      => 'ssh',
#      :sshd_service_hasstatus => true,
#      :sshd_config_fixture    => 'sshd_config_solaris',
#      :ssh_config_fixture     => 'ssh_config_solaris',
#    },
#    'Solaris-5.10' => {
#      :architecture           => 'i86pc',
#      :osfamily               => 'Solaris',
#      :kernelrelease          => '5.10',
#      :ssh_version            => 'Sun_SSH_2.2',
#      :ssh_version_numeric    => '2.2',
#      :sshd_packages           => ['SUNWsshcu', 'SUNWsshdr', 'SUNWsshdu', 'SUNWsshr', 'SUNWsshu'],
#      :sshd_config_mode       => '0644',
#      :sshd_service_name      => 'ssh',
#      :sshd_service_hasstatus => true,
#      :sshd_config_fixture    => 'sshd_config_solaris',
#      :ssh_config_fixture     => 'ssh_config_solaris',
#    },
#    'Solaris-5.9' => {
#      :architecture           => 'i86pc',
#      :osfamily               => 'Solaris',
#      :kernelrelease          => '5.9',
#      :ssh_version            => 'Sun_SSH_2.2',
#      :ssh_version_numeric    => '2.2',
#      :sshd_packages           => ['SUNWsshcu', 'SUNWsshdr', 'SUNWsshdu', 'SUNWsshr', 'SUNWsshu'],
#      :sshd_config_mode       => '0644',
#      :sshd_service_name      => 'sshd',
#      :sshd_service_hasstatus => false,
#      :sshd_config_fixture    => 'sshd_config_solaris',
#      :ssh_config_fixture     => 'ssh_config_solaris',
#    },
#    'Ubuntu-1604' => {
#      :architecture           => 'x86_64',
#      :osfamily               => 'Debian',
#      :operatingsystemrelease => '16.04',
#      :ssh_version            => 'OpenSSH_7.2p2',
#      :ssh_version_numeric    => '7.2',
#      :sshd_packages           => ['openssh-server', 'openssh-client'],
#      :sshd_config_mode       => '0600',
#      :sshd_service_name      => 'ssh',
#      :sshd_service_hasstatus => true,
#      :sshd_config_fixture    => 'sshd_config_ubuntu1604',
#      :ssh_config_fixture     => 'ssh_config_ubuntu1604',
#    },
  }

  defaults = {
    :fqdn                   => 'monkey.example.com',
    :hostname               => 'monkey',
    :ipaddress              => '127.0.0.1',
    :root_home              => '/root',
    :specific               => 'dummy',
    :sshrsakey              => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ==',
  }

  defaults_solaris = {
    :fqdn                => 'monkey.example.com',
    :hostname            => 'monkey',
    :ipaddress           => '127.0.0.1',
    :kernelrelease       => '5.10',
    :osfamily            => 'Solaris',
    :root_home           => '/root',
    :specific            => 'dummy',
    :ssh_version         => 'Sun_SSH_2.2',
    :ssh_version_numeric => '2.2',
    :sshrsakey           => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ==',
  }

  default_facts = osfamily_matrix['EL-7'].merge(defaults)

  let(:facts) { default_facts }

  osfamily_matrix.each do |os, facts|
    context "with default params on osfamily #{os}" do
      let(:facts) { defaults.merge(facts)}

      # FIXME - first one fails. If you remove the duplicate, the first compile
      # fails, if you remove both compile lines, then contain class fails and so on. Get this error
      #
      # Evaluation Error: Error while evaluating a Resource Statement, Could not autoload puppet/type/service: Could not autoload puppet/provider/service/upstart: Could not autoload puppet/provider/service/debian: Could not autoload puppet/provider/service/init: undefined method `downcase' for nil:NilClass (file: /Users/gh/git/puppet-module-ssh/spec/fixtures/modules/ssh/manifests/server.pp, line: 332, column: 5)
      it { should compile.with_all_deps }
      it { should compile.with_all_deps }

      it { should contain_class('ssh::server')}

      facts[:sshd_packages].each do |pkg|
        it {
          should contain_package(pkg).with({
            'ensure' => 'installed',
          })
        }
      end

      it {
        should contain_file('sshd_config').with({
          'ensure'  => 'file',
          'path'    => '/etc/ssh/sshd_config',
          'owner'   => 'root',
          'group'   => 'root',
          'mode'    => facts[:sshd_config_mode],
        })
      }

      facts[:sshd_packages].each do |pkg|
        it {
          should contain_file('sshd_config').that_requires("Package[#{pkg}]")
        }
      end

      sshd_config_fixture = File.read(fixtures("#{facts[:sshd_config_fixture]}_sorted"))
      it { should contain_file('sshd_config').with_content(sshd_config_fixture) }

      it { should_not contain_file('sshd_banner') }

      it {
        should contain_service('sshd_service').with({
          'ensure'     => 'running',
          'name'       => facts[:sshd_service_name],
          'enable'     => 'true',
          'hasrestart' => 'true',
          'hasstatus'  => facts[:sshd_service_hasstatus],
          'subscribe'  => 'File[sshd_config]',
        })
      }
    end
  end

# TODO: test failure on unsupported platforms
#  context 'with default params on invalid osfamily' do
#    let(:facts) { default_facts.merge({ :osfamily => 'C64' }) }
#
#    it 'should fail' do
#      expect {
#        should contain_class('ssh')
#      }.to raise_error(Puppet::Error,/ssh supports osfamilies RedHat, Suse, Debian and Solaris\. Detected osfamily is <C64>\./)
#    end
#  end
#

  # TODO: test each param here
  #
  describe 'with parameter' do

    context 'syslog_facility' do
      context "set to a valid facility" do
        let(:params) do { :syslog_facility => 'LOCAL1' } end

        it { should contain_file('sshd_config').with_content(/^SyslogFacility LOCAL1$/) }
      end
    end

    context 'stream_local_bind_mask' do
      context "set to a valid umask" do
        let(:params) do { :stream_local_bind_mask => '0022' } end

        it { should contain_file('sshd_config').with_content(/^StreamLocalBindMask 0022$/) }
      end
    end

    context 'client_alive_count_max' do
      context "set to a valid Integer" do
        let(:params) do { :client_alive_count_max => 23 } end

        it { should contain_file('sshd_config').with_content(/^ClientAliveCountMax 23$/) }
      end
    end

    context 'client_alive_interval' do
      context "set to a valid Integer" do
        let(:params) do { :client_alive_interval => 23 } end

        it { should contain_file('sshd_config').with_content(/^ClientAliveInterval 23$/) }
      end
    end

    context 'login_grace_time' do
      context "set to a valid Integer" do
        let(:params) do { :login_grace_time => 23 } end

        it { should contain_file('sshd_config').with_content(/^LoginGraceTime 23$/) }
      end
    end

    context 'max_auth_tries' do
      context "set to a valid Integer" do
        let(:params) do { :max_auth_tries => 23 } end

        it { should contain_file('sshd_config').with_content(/^MaxAuthTries 23$/) }
      end
    end

    context 'max_sessions' do
      context "set to a valid Integer" do
        let(:params) do { :max_sessions => 23 } end

        it { should contain_file('sshd_config').with_content(/^MaxSessions 23$/) }
      end
    end

    context 'x11_display_offset' do
      context "set to a valid Integer" do
        let(:params) do { :x11_display_offset => 23 } end

        it { should contain_file('sshd_config').with_content(/^X11DisplayOffset 23$/) }
      end
    end

    context 'authorized_keys_command' do
      context "set to valid string 'test'" do
        let(:params) do { :authorized_keys_command => 'test' } end

        it { should contain_file('sshd_config').with_content(/^AuthorizedKeysCommand test$/) }
      end
    end

    context 'authorized_keys_command_user' do
      context "set to valid string 'test'" do
        let(:params) do { :authorized_keys_command_user => 'test' } end

        it { should contain_file('sshd_config').with_content(/^AuthorizedKeysCommandUser test$/) }
      end
    end

    context 'authorized_principals_command' do
      context "set to valid string 'test'" do
        let(:params) do { :authorized_principals_command => 'test' } end

        it { should contain_file('sshd_config').with_content(/^AuthorizedPrincipalsCommand test$/) }
      end
    end

    context 'authorized_principals_command_user' do
      context "set to valid string 'test'" do
        let(:params) do { :authorized_principals_command_user => 'test' } end

        it { should contain_file('sshd_config').with_content(/^AuthorizedPrincipalsCommandUser test$/) }
      end
    end

    context 'authorized_principals_file' do
      context "set to valid string 'test'" do
        let(:params) do { :authorized_principals_file => 'test' } end

        it { should contain_file('sshd_config').with_content(/^AuthorizedPrincipalsFile test$/) }
      end
    end

    context 'banner' do
      context "set to valid string 'test'" do
        let(:params) do { :banner => 'test' } end

        it { should contain_file('sshd_config').with_content(/^Banner test$/) }
      end
    end

    context 'challenge_response_authentication' do
      context "set to valid string 'test'" do
        let(:params) do { :challenge_response_authentication => 'test' } end

        it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication test$/) }
      end
    end

    context 'chroot_directory' do
      context "set to valid string 'test'" do
        let(:params) do { :chroot_directory => 'test' } end

        it { should contain_file('sshd_config').with_content(/^ChrootDirectory test$/) }
      end
    end

    context 'force_command' do
      context "set to valid string 'test'" do
        let(:params) do { :force_command => 'test' } end

        it { should contain_file('sshd_config').with_content(/^ForceCommand test$/) }
      end
    end

    context 'host_certificate' do
      context "set to valid string 'test'" do
        let(:params) do { :host_certificate => 'test' } end

        it { should contain_file('sshd_config').with_content(/^HostCertificate test$/) }
      end
    end

    context 'host_key_agent' do
      context "set to valid string 'test'" do
        let(:params) do { :host_key_agent => 'test' } end

        it { should contain_file('sshd_config').with_content(/^HostKeyAgent test$/) }
      end
    end

    context 'ip_qos' do
      context "set to valid string 'test'" do
        let(:params) do { :ip_qos => 'test' } end

        it { should contain_file('sshd_config').with_content(/^IPQoS test$/) }
      end
    end

    context 'log_level' do
      context "set to valid string 'DEBUG1'" do
        let(:params) do { :log_level => 'DEBUG1' } end

        it { should contain_file('sshd_config').with_content(/^LogLevel DEBUG1$/) }
      end
    end

    context 'max_startups' do
      context "set to valid string 'test'" do
        let(:params) do { :max_startups => 'test' } end

        it { should contain_file('sshd_config').with_content(/^MaxStartups test$/) }
      end
    end

    context 'permit_user_environment' do
      context "set to valid string 'test'" do
        let(:params) do { :permit_user_environment => 'test' } end

        it { should contain_file('sshd_config').with_content(/^PermitUserEnvironment test$/) }
      end
    end

    context 'pid_file' do
      context "set to valid string 'test'" do
        let(:params) do { :pid_file => 'test' } end

        it { should contain_file('sshd_config').with_content(/^PidFile test$/) }
      end
    end

    context 'rekey_limit' do
      context "set to valid string 'test'" do
        let(:params) do { :rekey_limit => 'test' } end

        it { should contain_file('sshd_config').with_content(/^RekeyLimit test$/) }
      end
    end

    context 'revoked_keys' do
      context "set to valid string 'test'" do
        let(:params) do { :revoked_keys => 'test' } end

        it { should contain_file('sshd_config').with_content(/^RevokedKeys test$/) }
      end
    end

    context 'rdomain' do
      context "set to valid string 'test'" do
        let(:params) do { :rdomain => 'test' } end

        it { should contain_file('sshd_config').with_content(/^RDomain test$/) }
      end
    end

    context 'set_env' do
      context "set to valid string 'test'" do
        let(:params) do { :set_env => 'test' } end

        it { should contain_file('sshd_config').with_content(/^SetEnv test$/) }
      end
    end

    context 'subsystem' do
      context "set to valid string 'test'" do
        let(:params) do { :subsystem => 'test' } end

        it { should contain_file('sshd_config').with_content(/^Subsystem test$/) }
      end
    end

    context 'trusted_user_ca_keys' do
      context "set to valid string 'test'" do
        let(:params) do { :trusted_user_ca_keys => 'test' } end

        it { should contain_file('sshd_config').with_content(/^TrustedUserCAKeys test$/) }
      end
    end

    context 'version_addendum' do
      context "set to valid string 'test'" do
        let(:params) do { :version_addendum => 'test' } end

        it { should contain_file('sshd_config').with_content(/^VersionAddendum test$/) }
      end
    end

    context 'xauth_location' do
      context "set to valid string 'test'" do
        let(:params) do { :xauth_location => 'test' } end

        it { should contain_file('sshd_config').with_content(/^XAuthLocation test$/) }
      end
    end

    context 'custom' do
      context "set to valid string 'Foo test'" do
        let(:params) do { :custom => 'Foo test' } end

        it { should contain_file('sshd_config').with_content(/^Foo test$/) }
      end
    end

    context 'address_family' do
      ['any','inet','inet6'].each do |v|
        context "set to valid string #{v}" do
          let(:params) do { :address_family => v } end

          it { should contain_file('sshd_config').with_content(/^AddressFamily #{v}$/) }
        end
      end
    end

    context 'allow_stream_local_forwarding' do
      ['yes','all','no','local','remote'].each do |v|
        context "set to valid string #{v}" do
          let(:params) do { :allow_stream_local_forwarding => v } end

          it { should contain_file('sshd_config').with_content(/^AllowStreamLocalForwarding #{v}$/) }
        end
      end
    end

    context 'allow_tcp_forwarding' do
      ['yes','no','local','remote'].each do |v|
        context "set to valid string #{v}" do
          let(:params) do { :allow_tcp_forwarding => v } end

          it { should contain_file('sshd_config').with_content(/^AllowTcpForwarding #{v}$/) }
        end
      end
    end

    context 'compression' do
      ['yes','delayed','no'].each do |v|
        context "set to valid string #{v}" do
          let(:params) do { :compression => v } end

          it { should contain_file('sshd_config').with_content(/^Compression #{v}$/) }
        end
      end
    end

    context 'fingerprint_hash' do
      ['md5','sha256'].each do |v|
        context "set to valid string #{v}" do
          let(:params) do { :fingerprint_hash => v } end

          it { should contain_file('sshd_config').with_content(/^FingerprintHash #{v}$/) }
        end
      end
    end

    context 'gateway_ports' do
      ['no','yes','clientspecified'].each do |v|
        context "set to valid string #{v}" do
          let(:params) do { :gateway_ports => v } end

          it { should contain_file('sshd_config').with_content(/^GatewayPorts #{v}$/) }
        end
      end
    end

    context 'permit_tunnel' do
      ['yes','point-to-point','ethernet','no'].each do |v|
        context "set to valid string #{v}" do
          let(:params) do { :permit_tunnel => v } end

          it { should contain_file('sshd_config').with_content(/^PermitTunnel #{v}$/) }
        end
      end
    end

    context 'allow_agent_forwarding' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :allow_agent_forwarding => v } end

          it { should contain_file('sshd_config').with_content(/^AllowAgentForwarding #{v}$/) }
        end
      end
    end

    context 'disable_forwarding' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :disable_forwarding => v } end

          it { should contain_file('sshd_config').with_content(/^DisableForwarding #{v}$/) }
        end
      end
    end

    context 'expose_auth_info' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :expose_auth_info => v } end

          it { should contain_file('sshd_config').with_content(/^ExposeAuthInfo #{v}$/) }
        end
      end
    end

    context 'gss_api_authentication' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :gss_api_authentication => v } end

          it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication #{v}$/) }
        end
      end
    end

    context 'gss_api_cleanup_credentials' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :gss_api_cleanup_credentials => v } end

          it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials #{v}$/) }
        end
      end
    end

    context 'gss_api_strict_acceptor_check' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :gss_api_strict_acceptor_check => v } end

          it { should contain_file('sshd_config').with_content(/^GSSAPIStrictAcceptorCheck #{v}$/) }
        end
      end
    end

    context 'hostbased_authentication' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :hostbased_authentication => v } end

          it { should contain_file('sshd_config').with_content(/^HostbasedAuthentication #{v}$/) }
        end
      end
    end

    context 'hostbased_uses_name_from_packet_only' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :hostbased_uses_name_from_packet_only => v } end

          it { should contain_file('sshd_config').with_content(/^HostbasedUsesNameFromPacketOnly #{v}$/) }
        end
      end
    end

    context 'ignore_rhosts' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :ignore_rhosts => v } end

          it { should contain_file('sshd_config').with_content(/^IgnoreRhosts #{v}$/) }
        end
      end
    end

    context 'ignore_user_known_hosts' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :ignore_user_known_hosts => v } end

          it { should contain_file('sshd_config').with_content(/^IgnoreUserKnownHosts #{v}$/) }
        end
      end
    end

    context 'kbd_interactive_authentication' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :kbd_interactive_authentication => v } end

          it { should contain_file('sshd_config').with_content(/^KbdInteractiveAuthentication #{v}$/) }
        end
      end
    end

    context 'kerberos_authentication' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :kerberos_authentication => v } end

          it { should contain_file('sshd_config').with_content(/^KerberosAuthentication #{v}$/) }
        end
      end
    end

    context 'kerberos_get_afs_token' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :kerberos_get_afs_token => v } end

          it { should contain_file('sshd_config').with_content(/^KerberosGetAFSToken #{v}$/) }
        end
      end
    end

    context 'kerberos_or_local_passwd' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :kerberos_or_local_passwd => v } end

          it { should contain_file('sshd_config').with_content(/^KerberosOrLocalPasswd #{v}$/) }
        end
      end
    end

    context 'kerberos_ticket_cleanup' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :kerberos_ticket_cleanup => v } end

          it { should contain_file('sshd_config').with_content(/^KerberosTicketCleanup #{v}$/) }
        end
      end
    end

    context 'password_authentication' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :password_authentication => v } end

          it { should contain_file('sshd_config').with_content(/^PasswordAuthentication #{v}$/) }
        end
      end
    end

    context 'permit_empty_passwords' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :permit_empty_passwords => v } end

          it { should contain_file('sshd_config').with_content(/^PermitEmptyPasswords #{v}$/) }
        end
      end
    end

    context 'permit_tty' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :permit_tty => v } end

          it { should contain_file('sshd_config').with_content(/^PermitTTY #{v}$/) }
        end
      end
    end

    context 'permit_user_rc' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :permit_user_rc => v } end

          it { should contain_file('sshd_config').with_content(/^PermitUserRC #{v}$/) }
        end
      end
    end

    context 'print_last_log' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :print_last_log => v } end

          it { should contain_file('sshd_config').with_content(/^PrintLastLog #{v}$/) }
        end
      end
    end

    context 'print_motd' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :print_motd => v } end

          it { should contain_file('sshd_config').with_content(/^PrintMotd #{v}$/) }
        end
      end
    end

    context 'pubkey_authentication' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :pubkey_authentication => v } end

          it { should contain_file('sshd_config').with_content(/^PubkeyAuthentication #{v}$/) }
        end
      end
    end

    context 'stream_local_bind_unlink' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :stream_local_bind_unlink => v } end

          it { should contain_file('sshd_config').with_content(/^StreamLocalBindUnlink #{v}$/) }
        end
      end
    end

    context 'strict_modes' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :strict_modes => v } end

          it { should contain_file('sshd_config').with_content(/^StrictModes #{v}$/) }
        end
      end
    end

    context 'tcp_keep_alive' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :tcp_keep_alive => v } end

          it { should contain_file('sshd_config').with_content(/^TCPKeepAlive #{v}$/) }
        end
      end
    end

    context 'use_dns' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :use_dns => v } end

          it { should contain_file('sshd_config').with_content(/^UseDNS #{v}$/) }
        end
      end
    end

    context 'use_pam' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :use_pam => v } end

          it { should contain_file('sshd_config').with_content(/^UsePAM #{v}$/) }
        end
      end
    end

    context 'x11_forwarding' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :x11_forwarding => v } end

          it { should contain_file('sshd_config').with_content(/^X11Forwarding #{v}$/) }
        end
      end
    end

    context 'x11_use_localhost' do
      ['yes','no'].each do |v|
        context "set to #{v}" do
          let(:params) do { :x11_use_localhost => v } end

          it { should contain_file('sshd_config').with_content(/^X11UseLocalhost #{v}$/) }
        end
      end
    end

    context 'accept_env' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :accept_env => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^AcceptEnv test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :accept_env => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^AcceptEnv one$/) }
        it { should contain_file('sshd_config').with_content(/^AcceptEnv two$/) }
      end
    end

    context 'authentication_methods' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :authentication_methods => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^AuthenticationMethods test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :authentication_methods => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^AuthenticationMethods one,two$/) }
      end
    end

    context 'ca_signature_algorithms' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :ca_signature_algorithms => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^CASignatureAlgorithms test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :ca_signature_algorithms => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^CASignatureAlgorithms one,two$/) }
      end
    end

    context 'ciphers' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :ciphers => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^Ciphers test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :ciphers => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^Ciphers one,two$/) }
      end
    end

    context 'hostbased_accepted_key_types' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :hostbased_accepted_key_types => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^HostbasedAcceptedKeyTypes test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :hostbased_accepted_key_types => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^HostbasedAcceptedKeyTypes one,two$/) }
      end
    end

    context 'host_key' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :host_key => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^HostKey test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :host_key => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^HostKey one$/) }
        it { should contain_file('sshd_config').with_content(/^HostKey two$/) }
      end
    end

    context 'host_key_algorithms' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :host_key_algorithms => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^HostKeyAlgorithms test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :host_key_algorithms => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^HostKeyAlgorithms one,two$/) }
      end
    end

    context 'kex_algorithms' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :kex_algorithms => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^KexAlgorithms test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :kex_algorithms => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^KexAlgorithms one,two$/) }
      end
    end

    context 'listen_address' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :listen_address => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^ListenAddress test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :listen_address => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^ListenAddress one$/) }
        it { should contain_file('sshd_config').with_content(/^ListenAddress two$/) }
      end
    end

    context 'macs' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :macs => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^MACs test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :macs => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^MACs one,two$/) }
      end
    end

    context 'pubkey_accepted_key_types' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :pubkey_accepted_key_types => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^PubkeyAcceptedKeyTypes test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :pubkey_accepted_key_types => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^PubkeyAcceptedKeyTypes one,two$/) }
      end
    end


    context 'allow_groups' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :allow_groups => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^AllowGroups test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :allow_groups => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^AllowGroups one two$/) }
      end
    end

    context 'allow_users' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :allow_users => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^AllowUsers test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :allow_users => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^AllowUsers one two$/) }
      end
    end

    context 'authorized_keys_file' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :authorized_keys_file => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^AuthorizedKeysFile test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :authorized_keys_file => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^AuthorizedKeysFile one two$/) }
      end
    end

    context 'deny_groups' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :deny_groups => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^DenyGroups test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :deny_groups => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^DenyGroups one two$/) }
      end
    end

    context 'deny_users' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :deny_users => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^DenyUsers test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :deny_users => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^DenyUsers one two$/) }
      end
    end

    context 'permit_listen' do
      context "set to an array of strings with one element ['test']" do
        let(:params) do { :permit_listen => ['test'] } end

        it { should contain_file('sshd_config').with_content(/^PermitListen test$/) }
      end
      context "set to an array of strings with multiple elements ['one','two']" do
        let(:params) do { :permit_listen => ['one','two'] } end

        it { should contain_file('sshd_config').with_content(/^PermitListen one two$/) }
      end
    end
  end

  describe 'validate data types of parameters' do
    validations = {
      'Stdlib::Absolutepath (optional)' => {
        :name    => %w(package_adminfile package_source),
        :valid   => ['/absolute/filepath', '/absolute/directory/', :undef],
        :invalid => ['../invalid', %w(array), { 'ha' => 'sh' }, 3, 2.42, false],
        :message => 'expects a (match for|match for Stdlib::Absolutepath =|Stdlib::Absolutepath =) Variant\[Stdlib::Windowspath.*Stdlib::Unixpath',
      },
      'Stdlib::Absolutepath' => {
        :name    => %w(banner_path config_path),
        :valid   => ['/absolute/filepath', '/absolute/directory/'],
        :invalid => ['../invalid', %w(array), { 'ha' => 'sh' }, 3, 2.42, false, nil],
        :message => 'expects a (match for|match for Stdlib::Absolutepath =|Stdlib::Absolutepath =) Variant\[Stdlib::Windowspath.*Stdlib::Unixpath',
      },
      'Stdlib::Ensure::Service' => {
        :name    => %w(service_ensure),
        :valid   => %w(running stopped),
        :invalid => ['present', 'absent', %w(array), { 'ha' => 'sh' }, 3, 2.42, false, nil],
        :message => 'expects a match for Stdlib::Ensure::Service',
      },
      'Stdlib::Filemode' => {
        :name    => %w(banner_mode config_mode),
        :valid   => %w(0644 0755 0640 1740),
        :invalid => [2770, '0844', '00644', 'string', %w(array), { 'ha' => 'sh' }, 3, 2.42, false, nil],
        :message => 'expects a match for Stdlib::Filemode|Error while evaluating a Resource Statement',
      },
      'Stdlib::Port (optional)' => {
        :name    => %w(port),
        :valid   => [0, 65535, :undef],
        :invalid => ['string', %w(array), { 'ha' => 'sh' }, -1, 2.42, 65536, false],
        :message => 'expects a match for Stdlib::Port|Error while evaluating a Resource Statement',
      },
      'String or Array of strings' => {
        :name    => %w(packages),
        :valid   => ['string', %w(array of strings)],
        :invalid => [{ 'ha' => 'sh' }, 3, 2.42, false, [0]],
        :message => 'String or Array|expects a String value|Error while evaluating a Resource Statement',
      },
      'String or Array of strings (optional)' => {
        :name    => %w(allow_groups allow_users authorized_keys_file deny_groups deny_users permit_listen),
        :valid   => ['string', %w(array of strings), :undef],
        :invalid => [{ 'ha' => 'sh' }, 3, 2.42, false, [0]],
        :message => 'String or Array|expects a String value|Error while evaluating a Resource Statement',
      },
      'Array of strings (optional)' => {
        :name    => %w(accept_env authentication_methods ca_signature_algorithms ciphers host_key host_key_algorithms
          hostbased_accepted_key_types kex_algorithms listen_address macs pubkey_accepted_key_types),
        :valid   => [%w(array of strings), :undef],
        :invalid => ['string', { 'ha' => 'sh' }, 3, 2.42, false, [0]],
        :message => 'Undef or Array|expects a String value|Error while evaluating a Resource Statement',
      },
      'integer => 0 (optional)' => {
        :name    => %w(client_alive_count_max client_alive_interval login_grace_time max_sessions x11_display_offset),
        :valid   => [0, 1, 23, :undef],
        :invalid => ['string', %w(array), { 'ha' => 'sh' }, -1, 2.42, false],
        :message => 'Undef or Integer|Error while evaluating a Resource Statement',
      },
      'integer => 2 (optional)' => {
        :name    => %w(max_auth_tries),
        :valid   => [2, 23, :undef],
        :invalid => ['string', %w(array), { 'ha' => 'sh' }, -1, 2.42, 0, 1, false],
        :message => 'Undef or Integer|Error while evaluating a Resource Statement',
      },
      'four digit octal (optional) for umask' => {
        :name    => %w(stream_local_bind_mask),
        :valid   => ['0000', '1234', '7777', :undef],
        :invalid => ['string', %w(array), { 'ha' => 'sh' }, -1, 2.42, false, '00000', 'x234', '77e1', '011'],
        :message => 'Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for permit_root_login (optional)' => {
        :name    => %w(permit_root_login),
        :valid   => ['yes', 'prohibit-password', 'without-password', 'forced-commands-only', 'no', :undef],
        :invalid => ['invalid', %w(array), { 'ha' => 'sh' }, -1, 2.42, false],
        :message => 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for syslog_facility (optional)' => {
        :name    => %w(syslog_facility),
        :valid   => ['DAEMON', 'USER', 'AUTH', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7', 'AUTHPRIV', :undef],
        :invalid => ['invalid', %w(array), { 'ha' => 'sh' }, -1, 2.42, false, 'USER0', 'daemon'],
        :message => 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for fingerprint_hash (optional)' => {
        :name    => %w(fingerprint_hash),
        :valid   => ['md5', 'sha256', :undef],
        :invalid => ['invalid', %w(array), { 'ha' => 'sh' }, -1, 2.42, false],
        :message => 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for gateway_ports (optional)' => {
        :name    => %w(gateway_ports),
        :valid   => ['yes', 'no', 'clientspecified', :undef],
        :invalid => ['invalid', %w(array), { 'ha' => 'sh' }, -1, 2.42, false],
        :message => 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for allow_stream_local_forwarding (optional)' => {
        :name    => %w(allow_stream_local_forwarding),
        :valid   => ['yes', 'all', 'no', 'local', 'remote', :undef],
        :invalid => ['invalid', %w(array), { 'ha' => 'sh' }, -1, 2.42, false],
        :message => 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for compression (optional)' => {
        :name    => %w(compression),
        :valid   => ['yes', 'no', 'delayed', :undef],
        :invalid => ['invalid', %w(array), { 'ha' => 'sh' }, -1, 2.42, false],
        :message => 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for allow_tcp_forwarding (optional)' => {
        :name    => %w(allow_tcp_forwarding),
        :valid   => ['yes', 'no', 'local', 'remote', :undef],
        :invalid => ['invalid', %w(array), { 'ha' => 'sh' }, -1, 2.42, false],
        :message => 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for permit_tunnel (optional)' => {
        :name    => %w(permit_tunnel),
        :valid   => ['yes', 'point-to-point', 'ethernet', 'no', :undef],
        :invalid => ['invalid', %w(array), { 'ha' => 'sh' }, -1, 2.42, false],
        :message => 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'enumeration of valid strings for address_family (optional)' => {
        :name    => %w(address_family),
        :valid   => ['any', 'inet', 'inet6', :undef],
        :invalid => ['invalid', %w(array), { 'ha' => 'sh' }, -1, 2.42, false],
        :message => 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'yes or no (optional)' => {
        :name    => %w(allow_agent_forwarding disable_forwarding expose_auth_info gss_api_authentication gss_api_cleanup_credentials
          gss_api_strict_acceptor_check hostbased_authentication hostbased_uses_name_from_packet_only ignore_rhosts ignore_user_known_hosts
          kbd_interactive_authentication kerberos_authentication kerberos_get_afs_token kerberos_or_local_passwd kerberos_ticket_cleanup
          password_authentication permit_empty_passwords permit_tty permit_user_rc print_last_log print_motd pubkey_authentication
          stream_local_bind_unlink strict_modes tcp_keep_alive use_dns use_pam x11_forwarding x11_use_localhost),
        :valid   => ['yes', 'no', :undef],
        :invalid => ['invalid', %w(array), { 'ha' => 'sh' }, -1, 2.42, false, 'YES', 'No'],
        :message => 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Ssh::Log_level (optional)' => {
        :name    => %w(log_level),
        :valid   => ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3', :undef],
        :invalid => ['invalid', %w(array), { 'ha' => 'sh' }, -1, 2.42, false, 'INFO1'],
        :message => 'expects an undef value or a match for Pattern|Error while evaluating a Resource Statement',
      },
      'Boolean' => {
        :name    => %w(manage_service service_enable service_hasrestart service_hasstatus),
        :valid   => [true, false],
        :invalid => ['string', %w(array), { 'ha' => 'sh' }, 3, 2.42, 'false', nil],
        :message => 'expects a Boolean',
      },
      'String (optional)' => {
        :name    => %w(authorized_keys_command authorized_keys_command_user
          authorized_principals_command authorized_principals_command_user
          authorized_principals_file banner banner_content
          challenge_response_authentication chroot_directory force_command
          host_certificate host_key_agent ip_qos max_startups
          permit_user_environment pid_file rdomain rekey_limit revoked_keys
          set_env subsystem trusted_user_ca_keys version_addendum xauth_location
          custom),
        :valid   => ['string', :undef],
        :invalid => [%w(array), { 'ha' => 'sh' }, 3, 2.42, false],
        :message => 'expects a value of type Undef or String',
      },
    }

    validations.sort.each do |type, var|
      mandatory_params = {} if mandatory_params.nil?
      var[:name].each do |var_name|
        var[:params] = {} if var[:params].nil?
        var[:valid].each do |valid|
          context "when #{var_name} (#{type}) is set to valid #{valid} (as #{valid.class})" do
            let(:facts) { [mandatory_facts, var[:facts]].reduce(:merge) } if ! var[:facts].nil?
            let(:params) { [mandatory_params, var[:params], { :"#{var_name}" => valid, }].reduce(:merge) }
            it { should compile }
          end
        end

        var[:invalid].each do |invalid|
          context "when #{var_name} (#{type}) is set to invalid #{invalid} (as #{invalid.class})" do
            let(:params) { [mandatory_params, var[:params], { :"#{var_name}" => invalid, }].reduce(:merge) }
            it 'should fail' do
              expect { should contain_class(subject) }.to raise_error(Puppet::Error, /#{var[:message]}/)
            end
          end
        end
      end # var[:name].each
    end # validations.sort.each
  end # describe 'validate data types of parameters'
end
