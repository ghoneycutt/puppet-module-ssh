require 'spec_helper'

describe 'ssh' do

  default_facts = {
    :fqdn                => 'monkey.example.com',
    :hostname            => 'monkey',
    :ipaddress           => '127.0.0.1',
    :lsbmajdistrelease   => '6',
    :osfamily            => 'RedHat',
    :root_home           => '/root',
    :specific            => 'dummy',
    :ssh_version         => 'OpenSSH_6.6p1',
    :ssh_version_numeric => '6.6',
    :sshrsakey           => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ==',
  }

  default_solaris_facts = {
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

  let(:facts) { default_facts }

  osfamily_matrix = {
    'Debian-7' => {
      :architecture           => 'x86_64',
      :osfamily               => 'Debian',
      :operatingsystemrelease => '7',
      :ssh_version            => 'OpenSSH_6.0p1',
      :ssh_version_numeric    => '6.0',
      :ssh_packages           => ['openssh-server', 'openssh-client'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'ssh',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_debian',
      :ssh_config_fixture     => 'ssh_config_debian',
    },
    'RedHat-5' => {
      :architecture           => 'x86_64',
      :osfamily               => 'RedHat',
      :operatingsystemrelease => '5.11',
      :ssh_version            => 'OpenSSH_4.3p2',
      :ssh_version_numeric    => '4.3',
      :ssh_packages           => ['openssh-server', 'openssh-clients'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_rhel',
      :ssh_config_fixture     => 'ssh_config_rhel_old',
    },
    'RedHat-6' => {
      :architecture           => 'x86_64',
      :osfamily               => 'RedHat',
      :operatingsystemrelease => '6.7',
      :ssh_version            => 'OpenSSH_5.3p1',
      :ssh_version_numeric    => '5.3',
      :ssh_packages           => ['openssh-server', 'openssh-clients'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_rhel',
      :ssh_config_fixture     => 'ssh_config_rhel_old',
    },
    'RedHat-7' => {
      :architecture           => 'x86_64',
      :osfamily               => 'RedHat',
      :operatingsystemrelease => '7.2',
      :ssh_version            => 'OpenSSH_6.6p1',
      :ssh_version_numeric    => '6.6',
      :ssh_packages           => ['openssh-server', 'openssh-clients'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_rhel',
      :ssh_config_fixture     => 'ssh_config_rhel',
    },
    'Suse-10-x86_64' => {
      :architecture           => 'x86_64',
      :osfamily               => 'Suse',
      :operatingsystem        => 'SLES',
      :operatingsystemrelease => '10.4',
      :ssh_version            => 'OpenSSH_5.1p1',
      :ssh_version_numeric    => '5.1',
      :ssh_packages           => ['openssh'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_suse_x86_64',
      :ssh_config_fixture     => 'ssh_config_suse_old',
    },
    'Suse-10-i386' => {
      :architecture           => 'i386',
      :osfamily               => 'Suse',
      :operatingsystem        => 'SLES',
      :operatingsystemrelease => '10.4',
      :ssh_version            => 'OpenSSH_5.1p1',
      :ssh_version_numeric    => '5.1',
      :ssh_packages           => ['openssh'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_suse_i386',
      :ssh_config_fixture     => 'ssh_config_suse_old',
    },
    'Suse-11-x86_64' => {
      :architecture           => 'x86_64',
      :osfamily               => 'Suse',
      :operatingsystem        => 'SLES',
      :operatingsystemrelease => '11.4',
      :ssh_version            => 'OpenSSH_6.6.1p1',
      :ssh_version_numeric    => '6.6',
      :ssh_packages           => ['openssh'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_suse_x86_64',
      :ssh_config_fixture     => 'ssh_config_suse',
    },
    'Suse-11-i386' => {
      :architecture           => 'i386',
      :osfamily               => 'Suse',
      :operatingsystem        => 'SLES',
      :operatingsystemrelease => '11.4',
      :ssh_version            => 'OpenSSH_6.6.1p1',
      :ssh_version_numeric    => '6.6',
      :ssh_packages           => ['openssh'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_suse_i386',
      :ssh_config_fixture     => 'ssh_config_suse',
    },
    'Suse-12-x86_64' => {
      :architecture           => 'x86_64',
      :osfamily               => 'Suse',
      :operatingsystem        => 'SLES',
      :operatingsystemrelease => '12.0',
      :ssh_version            => 'OpenSSH_6.6.1p1',
      :ssh_version_numeric    => '6.6',
      :ssh_packages           => ['openssh'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_sles_12_x86_64',
      :ssh_config_fixture     => 'ssh_config_suse',
    },
    'Solaris-5.11' => {
      :architecture           => 'i86pc',
      :osfamily               => 'Solaris',
      :kernelrelease          => '5.11',
      :ssh_version            => 'Sun_SSH_2.2',
      :ssh_version_numeric    => '2.2',
      :ssh_packages           => ['network/ssh', 'network/ssh/ssh-key', 'service/network/ssh'],
      :sshd_config_mode       => '0644',
      :sshd_service_name      => 'ssh',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_solaris',
      :ssh_config_fixture     => 'ssh_config_solaris',
    },
    'Solaris-5.10' => {
      :architecture           => 'i86pc',
      :osfamily               => 'Solaris',
      :kernelrelease          => '5.10',
      :ssh_version            => 'Sun_SSH_2.2',
      :ssh_version_numeric    => '2.2',
      :ssh_packages           => ['SUNWsshcu', 'SUNWsshdr', 'SUNWsshdu', 'SUNWsshr', 'SUNWsshu'],
      :sshd_config_mode       => '0644',
      :sshd_service_name      => 'ssh',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_solaris',
      :ssh_config_fixture     => 'ssh_config_solaris',
    },
    'Solaris-5.9' => {
      :architecture           => 'i86pc',
      :osfamily               => 'Solaris',
      :kernelrelease          => '5.9',
      :ssh_version            => 'Sun_SSH_2.2',
      :ssh_version_numeric    => '2.2',
      :ssh_packages           => ['SUNWsshcu', 'SUNWsshdr', 'SUNWsshdu', 'SUNWsshr', 'SUNWsshu'],
      :sshd_config_mode       => '0644',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => false,
      :sshd_config_fixture    => 'sshd_config_solaris',
      :ssh_config_fixture     => 'ssh_config_solaris',
    },
    'Ubuntu-1604' => {
      :architecture           => 'x86_64',
      :osfamily               => 'Debian',
      :operatingsystemrelease => '16.04',
      :ssh_version            => 'OpenSSH_7.2p2',
      :ssh_version_numeric    => '7.2',
      :ssh_packages           => ['openssh-server', 'openssh-client'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'ssh',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_ubuntu1604',
      :ssh_config_fixture     => 'ssh_config_ubuntu1604',
    },
  }

  osfamily_matrix.each do |os, facts|
    context "with default params on osfamily #{os}" do
      let(:facts) { default_facts.merge( facts )}

      it { should compile.with_all_deps }

      it { should contain_class('ssh')}

      it { should_not contain_class('common')}

      facts[:ssh_packages].each do |pkg|
        it {
          should contain_package(pkg).with({
            'ensure' => 'installed',
          })
        }
      end

      it {
        should contain_file('ssh_known_hosts').with({
          'ensure' => 'file',
          'path'   => '/etc/ssh/ssh_known_hosts',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0644',
        })
      }

      it {
        should contain_file('ssh_config').with({
          'ensure'  => 'file',
          'path'    => '/etc/ssh/ssh_config',
          'owner'   => 'root',
          'group'   => 'root',
          'mode'    => '0644',
        })
      }

      ssh_config_fixture = File.read(fixtures(facts[:ssh_config_fixture]))
      it { should contain_file('ssh_config').with_content(ssh_config_fixture) }

      facts[:ssh_packages].each do |pkg|
        it {
          should contain_file('ssh_config').that_requires("Package[#{pkg}]")
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

      facts[:ssh_packages].each do |pkg|
        it {
          should contain_file('sshd_config').that_requires("Package[#{pkg}]")
        }
      end

      sshd_config_fixture = File.read(fixtures(facts[:sshd_config_fixture]))
      it { should contain_file('sshd_config').with_content(sshd_config_fixture) }

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

      it {
        should contain_resources('sshkey').with({
          'purge' => 'true',
        })
      }
    end
  end

  context 'with default params on invalid osfamily' do
    let(:facts) { default_facts.merge({ :osfamily => 'C64' }) }
    let(:params) { { :manage_root_ssh_config => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh supports osfamilies RedHat, Suse, Debian and Solaris\. Detected osfamily is <C64>\./)
    end
  end

  context 'with optional params used in ssh_config set on valid osfamily' do
    let(:params) do
      {
        :ssh_config_hash_known_hosts        => 'yes',
        :ssh_config_forward_agent           => 'yes',
        :ssh_config_forward_x11             => 'yes',
        :ssh_config_use_roaming             => 'yes',
        :ssh_config_server_alive_interval   => '300',
        :ssh_config_sendenv_xmodifiers      => true,
        :ssh_config_ciphers                 => [ 'aes128-cbc',
                                                 '3des-cbc',
                                                 'blowfish-cbc',
                                                 'cast128-cbc',
                                                 'arcfour',
                                                 'aes192-cbc',
                                                 'aes256-cbc',
        ],
        :ssh_config_macs                    => [ 'hmac-md5-etm@openssh.com',
                                                 'hmac-sha1-etm@openssh.com',
        ],
        :ssh_config_global_known_hosts_file => '/etc/ssh/ssh_known_hosts2',
        :ssh_config_global_known_hosts_list => [ '/etc/ssh/ssh_known_hosts3',
					         '/etc/ssh/ssh_known_hosts4',
	],
        :ssh_config_user_known_hosts_file   => [ '.ssh/known_hosts1',
                                                 '.ssh/known_hosts2',
        ],
        :ssh_hostbasedauthentication        => 'yes',
        :ssh_strict_host_key_checking       => 'ask',
        :ssh_enable_ssh_keysign             => 'yes',
      }
    end

    it { should compile.with_all_deps }

    it {
      should contain_file('ssh_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => ['Package[openssh-server]', 'Package[openssh-clients]'],
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }
    it { should contain_file('ssh_config').with_content(/^   HashKnownHosts yes$/) }
    it { should contain_file('ssh_config').with_content(/^\s*SendEnv L.*$/) }
    it { should contain_file('ssh_config').with_content(/^  ForwardAgent yes$/) }
    it { should contain_file('ssh_config').with_content(/^  ForwardX11 yes$/) }
    it { should contain_file('ssh_config').with_content(/^\s*GSSAPIAuthentication yes$/) }
    it { should contain_file('ssh_config').with_content(/^\s*UseRoaming yes$/) }
    it { should contain_file('ssh_config').with_content(/^  ServerAliveInterval 300$/) }
    it { should contain_file('ssh_config').with_content(/^  SendEnv XMODIFIERS$/) }
    it { should contain_file('ssh_config').with_content(/^\s*Ciphers aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc$/) }
    it { should contain_file('ssh_config').with_content(/^\s*MACs hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com$/) }
    it { should contain_file('ssh_config').with_content(/^\s*GlobalKnownHostsFile \/etc\/ssh\/ssh_known_hosts2 \/etc\/ssh\/ssh_known_hosts3 \/etc\/ssh\/ssh_known_hosts4$/) }
    it { should contain_file('ssh_config').with_content(/^\s*UserKnownHostsFile \.ssh\/known_hosts1 \.ssh\/known_hosts2$/) }
    it { should contain_file('ssh_config').with_content(/^\s*HostbasedAuthentication yes$/) }
    it { should contain_file('ssh_config').with_content(/^\s*StrictHostKeyChecking ask$/) }
    it { should contain_file('ssh_config').with_content(/^\s*EnableSSHKeysign yes$/) }
  end

  context 'with params used in sshd_config set on valid osfamily' do
    let(:params) do
      {
        :sshd_config_port                  => '22222',
        :sshd_config_syslog_facility       => 'DAEMON',
        :sshd_config_login_grace_time      => '60',
        :permit_root_login                 => 'no',
        :sshd_config_chrootdirectory       => '/chrootdir',
        :sshd_config_forcecommand          => '/force/command --with-parameter 242',
        :sshd_config_match                 => { 'User JohnDoe' => [ 'AllowTcpForwarding yes', ], },
        :sshd_config_challenge_resp_auth   => 'no',
        :sshd_config_print_motd            => 'no',
        :sshd_config_use_dns               => 'no',
        :sshd_config_banner                => '/etc/sshd_banner',
        :sshd_authorized_keys_command      => '/path/to/command',
        :sshd_authorized_keys_command_user => 'asdf',
        :sshd_banner_content               => 'textinbanner',
        :sshd_config_xauth_location        => '/opt/ssh/bin/xauth',
        :sshd_config_subsystem_sftp        => '/opt/ssh/bin/sftp',
        :sshd_kerberos_authentication      => 'no',
        :sshd_password_authentication      => 'no',
        :sshd_config_permitemptypasswords  => 'no',
        :sshd_config_permituserenvironment => 'no',
        :sshd_pubkeyauthentication         => 'no',
        :sshd_allow_tcp_forwarding         => 'no',
        :sshd_x11_forwarding               => 'no',
        :sshd_use_pam                      => 'no',
        :sshd_client_alive_interval        => '242',
        :sshd_config_serverkeybits         => '1024',
        :sshd_client_alive_count_max       => '0',
        :sshd_config_authkey_location      => '.ssh/authorized_keys',
        :sshd_config_hostkey               => [ '/etc/ssh/ssh_host_rsa_key',
                                                '/etc/ssh/ssh_host_dsa_key',
        ],
        :sshd_config_strictmodes           => 'yes',
        :sshd_config_ciphers               => [ 'aes128-cbc',
                                                '3des-cbc',
                                                'blowfish-cbc',
                                                'cast128-cbc',
                                                'arcfour',
                                                'aes192-cbc',
                                                'aes256-cbc',
        ],
        :sshd_config_macs                  => [ 'hmac-md5-etm@openssh.com',
                                                'hmac-sha1-etm@openssh.com',
        ],
        :sshd_config_denyusers             => [ 'root',
                                                'lusers',
        ],
        :sshd_config_denygroups            => [ 'nossh',
                                                'wheel',
        ],
        :sshd_config_allowusers            => [ 'foo',
                                                'bar',
        ],
        :sshd_config_allowgroups           => [ 'ssh',
                                                'security',
        ],
        :sshd_listen_address               => [ '192.168.1.1',
                                                '2001:db8::dead:f00d',
        ],
        :sshd_config_tcp_keepalive         => 'yes',
      }
    end

    it { should compile.with_all_deps }

    it {
      should contain_file('sshd_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0600',
        'require' => ['Package[openssh-server]', 'Package[openssh-clients]'],
      })
    }

    it { should contain_file('sshd_config').with_content(/^Port 22222$/) }
    it { should contain_file('sshd_config').with_content(/^SyslogFacility DAEMON$/) }
    it { should contain_file('sshd_config').with_content(/^LogLevel INFO$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 60$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin no$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication no$/) }
    it { should contain_file('sshd_config').with_content(/^PrintMotd no$/) }
    it { should contain_file('sshd_config').with_content(/^UseDNS no$/) }
    it { should contain_file('sshd_config').with_content(/^Banner \/etc\/sshd_banner$/) }
    it { should contain_file('sshd_config').with_content(/^XAuthLocation \/opt\/ssh\/bin\/xauth$/) }
    it { should contain_file('sshd_config').with_content(/^Subsystem sftp \/opt\/ssh\/bin\/sftp$/) }
    it { should contain_file('sshd_config').with_content(/^PasswordAuthentication no$/) }
    it { should contain_file('sshd_config').with_content(/^KerberosAuthentication no$/) }
    it { should contain_file('sshd_config').with_content(/^AllowTcpForwarding no$/) }
    it { should contain_file('sshd_config').with_content(/^X11Forwarding no$/) }
    it { should contain_file('sshd_config').with_content(/^UsePAM no$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveInterval 242$/) }
    it { should contain_file('sshd_config').with_content(/^ServerKeyBits 1024$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveCountMax 0$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange yes$/) }
    it { should contain_file('sshd_config').with_content(/^AcceptEnv L.*$/) }
    it { should contain_file('sshd_config').with_content(/^AuthorizedKeysFile .ssh\/authorized_keys/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_dsa_key/) }
    it { should contain_file('sshd_config').with_content(/^StrictModes yes$/) }
    it { should contain_file('sshd_config').with_content(/^PermitUserEnvironment no/) }
    it { should contain_file('sshd_config').with_content(/^PermitEmptyPasswords no/) }
    it { should_not contain_file('sshd_config').with_content(/^MaxAuthTries/) }
    it { should_not contain_file('sshd_config').with_content(/^MaxStartups/) }
    it { should_not contain_file('sshd_config').with_content(/^MaxSessions/) }
    it { should contain_file('sshd_config').with_content(/^AuthorizedKeysCommand \/path\/to\/command$/) }
    it { should contain_file('sshd_config').with_content(/^AuthorizedKeysCommandUser asdf$/) }
    it { should contain_file('sshd_config').with_content(/^HostbasedAuthentication no$/) }
    it { should contain_file('sshd_config').with_content(/^PubkeyAuthentication no$/) }
    it { should contain_file('sshd_config').with_content(/^IgnoreUserKnownHosts no$/) }
    it { should contain_file('sshd_config').with_content(/^IgnoreRhosts yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChrootDirectory \/chrootdir$/) }
    it { should contain_file('sshd_config').with_content(/^ForceCommand \/force\/command --with-parameter 242$/) }
    it { should contain_file('sshd_config').with_content(/^Match User JohnDoe\n  AllowTcpForwarding yes\Z/) }
    it { should contain_file('sshd_config').with_content(/^\s*Ciphers aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc$/) }
    it { should contain_file('sshd_config').with_content(/^\s*MACs hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com$/) }
    it { should contain_file('sshd_config').with_content(/^\s*DenyUsers root lusers$/) }
    it { should contain_file('sshd_config').with_content(/^\s*DenyGroups nossh wheel$/) }
    it { should contain_file('sshd_config').with_content(/^\s*AllowUsers foo bar$/) }
    it { should contain_file('sshd_config').with_content(/^\s*AllowGroups ssh security$/) }
    it { should contain_file('sshd_config').with_content(/^ListenAddress 192.168.1.1\nListenAddress 2001:db8::dead:f00d$/) }
    it { should contain_file('sshd_config').with_content(/^TCPKeepAlive yes$/) }

    it {
      should contain_file('sshd_banner').with({
        'ensure'  => 'file',
        'path'    => '/etc/sshd_banner',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'content' => 'textinbanner',
        'require' => ['Package[openssh-server]', 'Package[openssh-clients]'],
      })
    }
  end

  describe 'sshd_config_chrootdirectory param' do
    ['/chrootdir/subdir','/baby/one/more/test',].each do |value|
      context "set to valid #{value} (as #{value.class})" do
        let(:params) { {'sshd_config_chrootdirectory' => value } }

        it { should contain_file('sshd_config').with_content(/^ChrootDirectory #{value}$/) }
      end
    end

    [true,'invalid','invalid/path/',3,2.42,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "set to invalid #{value} (as #{value.class})" do
        let(:params) { {'sshd_config_chrootdirectory' => value } }

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error, /is not an absolute path/)
        end
      end
    end

  end

  describe 'sshd_config_forcecommand param' do
    ['/bin/command','/bin/command -parameters','/bin/command --parameters','/bin/command /parameters'].each do |value|
      context "set to valid #{value} (as #{value.class})" do
        let(:params) { {'sshd_config_forcecommand' => value } }

        it { should contain_file('sshd_config').with_content(/^ForceCommand #{value}$/) }
      end
    end

    [true,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "set to invalid #{value} (as #{value.class})" do
        let(:params) { {'sshd_config_forcecommand' => value } }

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error, /is not a string/)
        end
      end
    end

  end

  describe 'sshd_config_match param' do
  # match and rules get alphabetically sorted by template, matches should be the last options in sshd_config (regex verify with= \Z)
    context 'set to valid hash containing nested arrays' do
      let(:params) do
        { :sshd_config_match      => {
            'User JohnDoe'        => [ 'AllowTcpForwarding yes', ],
            'Addresss 2.4.2.0'    => [ 'X11Forwarding yes', 'PasswordAuthentication no', ],
          },
        }
      end

      it { should contain_file('sshd_config').with_content(/^Match Addresss 2.4.2.0\n  PasswordAuthentication no\n  X11Forwarding yes\nMatch User JohnDoe\n  AllowTcpForwarding yes\Z/) }
    end

    [true,'string',3,2.42,['array']].each do |value|
      context "set to invalid #{value} (as #{value.class})" do
        let(:params) { {'sshd_config_match' => value } }
        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error, /is not a Hash/)
        end
      end
    end

  end

  describe 'sshd_listen_address param' do
    context 'when set to an array' do
      let(:params) { {'sshd_listen_address' => ['192.168.1.1','2001:db8::dead:f00d'] } }

      it { should contain_file('sshd_config').with_content(/^ListenAddress 192.168.1.1\nListenAddress 2001:db8::dead:f00d$/) }
    end

    context 'when set to a string' do
      let(:params) { {'sshd_listen_address' => ['192.168.1.1'] } }

      it { should contain_file('sshd_config').with_content(/^ListenAddress 192.168.1.1$/) }
    end

    context 'when not set' do
      it { should_not contain_file('sshd_config').with_content(/^\s*ListenAddress/) }
    end


    context 'when set to an invalid type (not string or array)' do
      let(:params) { {'sshd_listen_address' => true } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  describe 'sshd_loglevel param' do
    context 'when set to an invalid value' do
      let(:params) { {'sshd_config_loglevel' => 'BOGON'} }
      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error, /"BOGON" does not match/)
      end
    end
    ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE'].each do |supported_val|
      context "when set to #{supported_val}" do
        let(:params) { { 'sshd_config_loglevel' => supported_val} }
        it { should contain_file('sshd_config').with_content(/^LogLevel #{supported_val}$/) }
      end
    end
  end

  describe 'with sshd_kerberos_authentication' do
    ['yes','no'].each do |value|
      context "set to #{value}" do
        let(:params) { { 'sshd_kerberos_authentication' => value } }

        it { should contain_file('sshd_config').with_content(/^KerberosAuthentication #{value}$/) }
      end
    end

    context 'set to invalid value on valid osfamily' do
      let(:params) { { :sshd_kerberos_authentication => 'invalid' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::sshd_kerberos_authentication may be either \'yes\' or \'no\' and is set to <invalid>\./)
      end
    end
  end

  context 'when ssh_config_template has a nonstandard value' do
    context 'and that value is not valid' do
      let(:params) { {'ssh_config_template' => false} }
      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error, /is not a string/)
      end
    end
    context 'and that value is valid' do
      let(:params) { {'ssh_config_template' => 'ssh/sshd_config.erb'} }
      it 'should lay down the ssh_config file from the specified template' do
        should contain_file('ssh_config').with_content(/OpenBSD: sshd_config/)
      end
    end
  end

  context 'when sshd_config_template has a nonstandard value' do
    context 'and that value is not valid' do
      let(:params) { {'sshd_config_template' => false} }
      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error, /is not a string/)
      end
    end
    context 'and that value is valid' do
      let(:params) { {'sshd_config_template' => 'ssh/ssh_config.erb'} }
      it 'should lay down the sshd_config file from the specified template' do
        should contain_file('sshd_config').with_content(/OpenBSD: ssh_config/)
      end
    end
  end

  ['true',true].each do |value|
    context "with manage_root_ssh_config set to #{value} on valid osfamily" do
      let(:params) { { :manage_root_ssh_config => value } }

      it { should compile.with_all_deps }

      it { should contain_class('ssh')}

      it { should contain_class('common')}

      it {
        should contain_file('root_ssh_dir').with({
          'ensure'  => 'directory',
          'path'    => '/root/.ssh',
          'owner'   => 'root',
          'group'   => 'root',
          'mode'    => '0700',
          'require' => 'Common::Mkdir_p[/root/.ssh]',
        })
      }

      it {
        should contain_file('root_ssh_config').with({
          'ensure' => 'file',
          'path'   => '/root/.ssh/config',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0600',
        })
      }
    end
  end

  ['false',false].each do |value|
    context "with manage_root_ssh_config set to #{value} on valid osfamily" do
      let(:params) { { :manage_root_ssh_config => value } }

      it { should compile.with_all_deps }

      it { should contain_class('ssh')}

      it { should_not contain_class('common')}

      it { should_not contain_file('root_ssh_dir') }

      it { should_not contain_file('root_ssh_config') }
    end
  end

  [true,'invalid'].each do |ciphers|
    context "with ssh_config_ciphers set to invalid value #{ciphers}" do
      let(:params) { { :ssh_config_ciphers => ciphers } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  [true,'invalid'].each do |macs|
    context "with ssh_config_macs set to invalid value #{macs}" do
      let(:params) { { :ssh_config_macs => macs } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  context 'with ssh_config_hash_known_hosts set to invalid value on valid osfamily' do
    let(:params) { { :ssh_config_hash_known_hosts => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh::ssh_config_hash_known_hosts may be either \'yes\' or \'no\' and is set to <invalid>\./)
    end
  end

  [true,'invalid'].each do |ciphers|
    context "with sshd_config_ciphers set to invalid value #{ciphers}" do
      let(:params) { { :sshd_config_ciphers => ciphers } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  [true,'invalid'].each do |denyusers|
    context "with sshd_config_denyusers set to invalid value #{denyusers}" do
      let(:params) { { :sshd_config_denyusers => denyusers } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/is not an Array/)
      end
    end
  end

  [true,'invalid'].each do |denygroups|
    context "with sshd_config_denygroups set to invalid value #{denygroups}" do
      let(:params) { { :sshd_config_denygroups => denygroups } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/is not an Array/)
      end
    end
  end

  [true,'invalid'].each do |allowusers|
    context "with sshd_config_allowusers set to invalid value #{allowusers}" do
      let(:params) { { :sshd_config_allowusers => allowusers } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/is not an Array/)
      end
    end
  end

  [true,'invalid'].each do |allowgroups|
    context "with sshd_config_allowgroups set to invalid value #{allowgroups}" do
      let(:params) { { :sshd_config_allowgroups => allowgroups } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/is not an Array/)
      end
    end
  end

  [true,'invalid'].each do |macs|
    context "with sshd_config_macs set to invalid value #{macs}" do
      let(:params) { { :sshd_config_macs => macs } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  describe 'with sshd_config_permitemptypasswords' do
    ['yes','no'].each do |value|
      context "set to #{value}" do
        let(:params) { { 'sshd_config_permitemptypasswords' => value } }

        it { should contain_file('sshd_config').with_content(/^PermitEmptyPasswords #{value}$/) }
      end
    end

    context 'set to invalid value on valid osfamily' do
      let(:params) { { :sshd_config_permitemptypasswords => 'invalid' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::sshd_config_permitemptypasswords may be either \'yes\' or \'no\' and is set to <invalid>\./)
      end
    end
  end

  describe 'with sshd_config_permituserenvironment' do
    ['yes','no'].each do |value|
      context "set to #{value}" do
        let(:params) { { 'sshd_config_permituserenvironment' => value } }

        it { should contain_file('sshd_config').with_content(/^PermitUserEnvironment #{value}$/) }
      end
    end

    context 'set to invalid value on valid osfamily' do
      let(:params) { { :sshd_config_permituserenvironment => 'invalid' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::sshd_config_permituserenvironment may be either \'yes\' or \'no\' and is set to <invalid>\./)
      end
    end
  end

  describe 'sshd_config_port param' do
    context 'when set to an array' do
      let(:params) { {'sshd_config_port' => ['22222', '22223'] } }

      it { should contain_file('sshd_config').with_content(/^Port 22222\nPort 22223$/) }
    end

    context 'when set to a string' do
      let(:params) { {'sshd_config_port' => '22222' } }

      it { should contain_file('sshd_config').with_content(/^Port 22222$/) }
    end

    context 'when set to an integer' do
      let(:params) { {'sshd_config_port' => 22222 } }

      it { should contain_file('sshd_config').with_content(/^Port 22222$/) }
    end

    context 'when not set to a valid number' do
      let(:params) { {'sshd_config_port' => '22invalid' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::sshd_config_port must be a valid number and is set to <22invalid>\./)
      end
    end
  end

  context 'with manage_root_ssh_config set to invalid value on valid osfamily' do
    let(:params) { { :manage_root_ssh_config => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/Unknown type of boolean/)
    end
  end

  context 'with sshd_password_authentication set to invalid value on valid osfamily' do
    let(:params) { { :sshd_password_authentication => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh::sshd_password_authentication may be either \'yes\' or \'no\' and is set to <invalid>\./)
    end
  end

  context 'with sshd_allow_tcp_forwarding set to invalid value on valid osfamily' do
    let(:params) { { :sshd_allow_tcp_forwarding => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh::sshd_allow_tcp_forwarding may be either \'yes\' or \'no\' and is set to <invalid>\./)
    end
  end

  context 'with sshd_x11_forwarding set to invalid value on valid osfamily' do
    let(:params) { { :sshd_x11_forwarding => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh::sshd_x11_forwarding may be either \'yes\' or \'no\' and is set to <invalid>\./)
    end
  end

  context 'with sshd_use_pam set to invalid value on valid osfamily' do
    let(:params) { { :sshd_use_pam => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh::sshd_use_pam may be either \'yes\' or \'no\' and is set to <invalid>\./)
    end
  end

  context 'with sshd_config_serverkeybits set to invalid value on valid osfamily' do
    let(:params) { { :sshd_config_serverkeybits => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh::sshd_config_serverkeybits must be an integer and is set to <invalid>\./)
    end
  end

  context 'with sshd_client_alive_interval set to invalid value on valid osfamily' do
    let(:params) { { :sshd_client_alive_interval => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh::sshd_client_alive_interval must be an integer and is set to <invalid>\./)
    end
  end

  context 'with sshd_client_alive_count_max set to invalid value on valid osfamily' do
    let(:params) { { :sshd_client_alive_count_max => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh::sshd_client_alive_count_max must be an integer and is set to <invalid>\./)
    end
  end

  context 'with sshd_config_banner set to invalid value on valid osfamily' do
    let(:params) { { :sshd_config_banner => 'invalid/path' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/is not an absolute path/)
    end
  end

  context 'with sshd_config_authkey_location set to invalid value on valid osfamily' do
    let(:params) { { :sshd_config_authkey_location => false } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/is not a string/)
    end
  end

  context 'with sshd_config_hostkey set to invalid value on valid osfamily' do
    let(:params) { { :sshd_config_hostkey => false } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/is not an Array/)
    end
  end

  context 'with sshd_config_hostkey set to invalid path on valid osfamily' do
    let(:params) { { :sshd_config_hostkey => ['not_a_path'] } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/is not an absolute path./)
    end
  end


  context 'with sshd_config_strictmodes set to invalid value on valid osfamily' do
    let(:params) { { :sshd_config_strictmodes => 'invalid' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh::sshd_config_strictmodes may be either \'yes\' or \'no\' and is set to <invalid>\./)
    end
  end

  context 'with sshd_authorized_keys_command specified with an invalid path' do
    let(:params) { { :sshd_authorized_keys_command => 'invalid/path' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/"invalid\/path" is not an absolute path/)
    end
  end

  context 'with sshd_authorized_keys_command_user specified with an invalid type (non-string)' do
    let(:params) { { :sshd_authorized_keys_command_user => ['invalid','type'] } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/\["invalid", "type"\] is not a string/)
    end
  end

  context 'with sshd_banner_content set and with default value on sshd_config_banner on valid osfamily' do
    let(:params) { { :sshd_banner_content => 'textinbanner' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh::sshd_config_banner must be set to be able to use sshd_banner_content\./)
    end
  end


  context 'with ssh_config_sendenv_xmodifiers set to invalid type, array' do
    let(:params) { { :ssh_config_sendenv_xmodifiers => ['invalid','type'] } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/ssh::ssh_config_sendenv_xmodifiers type must be true or false\./)
    end
  end

  context 'with ssh_config_sendenv_xmodifiers set to stringified \'true\'' do
    let(:params) { { :ssh_config_sendenv_xmodifiers => 'true' } }

    it { should compile.with_all_deps }

    it { should contain_file('ssh_config').with_content(/^  SendEnv XMODIFIERS$/) }
  end

  context 'with manage_firewall set to true on valid osfamily' do
    let(:params) { { :manage_firewall => true } }

    it { should compile.with_all_deps }

    it { should contain_class('ssh')}

    it { should_not contain_class('common')}

    it {
      should contain_firewall('22 open port 22 for SSH').with({
        'action' => 'accept',
        'dport'  => '22',
        'proto'  => 'tcp',
      })
    }
  end

  context 'with keys defined on valid osfamily' do
    let(:params) { { :keys => {
      'root_for_userX' => {
        'ensure' => 'present',
        'user'   => 'root',
        'type'   => 'dsa',
        'key'    => 'AAAA==',
      },
      'apache_hup' => {
        'ensure'  => 'present',
        'user'    => 'apachehup',
        'type'    => 'dsa',
        'key'     => 'AAAA==',
        'options' => 'command="/sbin/service httpd restart"',
      },
      'root_for_userY' => {
        'ensure' => 'absent',
        'user'   => 'root',
      }
    } } }

    it { should compile.with_all_deps }

    it {
      should contain_ssh_authorized_key('root_for_userX').with({
        'ensure' => 'present',
        'user'   => 'root',
        'type'   => 'dsa',
        'key'    => 'AAAA==',
      })
    }

    it {
      should contain_ssh_authorized_key('apache_hup').with({
        'ensure'  => 'present',
        'user'    => 'apachehup',
        'type'    => 'dsa',
        'key'     => 'AAAA==',
        'options' => 'command="/sbin/service httpd restart"',
      })
    }

    it {
      should contain_ssh_authorized_key('root_for_userY').with({
        'ensure' => 'absent',
        'user'   => 'root',
      })
    }
  end

  context 'with keys specified as not of type hash' do
    let(:params) { { :keys => [ 'not', 'a', 'hash' ] } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error)
    end
  end

  describe 'with hiera_merge parameter specified' do
    context 'as a non-boolean or non-string' do
      let(:facts) { default_facts.merge( { :fqdn => 'hieramerge.example.com'} )}
      let(:params) { { :hiera_merge => ['not_a_boolean','or_a_string'] } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end

    context 'as an invalid string' do
      let(:params) { { :hiera_merge => 'invalid_string' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::hiera_merge may be either 'true' or 'false' and is set to <invalid_string>./)
      end
    end

    ['true',true].each do |value|
      context "as #{value} with hiera data getting collected" do
        let(:facts) { default_facts.merge( { :fqdn => 'hieramerge.example.com'} )}
        let(:params) { { :hiera_merge => value } }

        it { should compile.with_all_deps }

        it { should contain_class('ssh') }

        it { should contain_file('sshd_config').with_content(/^\s*DenyUsers denyuser_from_fqdn/) }
        it { should contain_file('sshd_config').with_content(/^\s*DenyGroups denygroup_from_fqdn/) }
        it { should contain_file('sshd_config').with_content(/^\s*AllowUsers allowuser_from_fqdn/) }
        it { should contain_file('sshd_config').with_content(/^\s*AllowGroups allowgroup_from_fqdn/) }

      end
    end

    context "as true with with hiera data getting merged through levels" do
      let(:facts) do
        default_facts.merge(
          {
            :fqdn              => 'hieramerge.example.com',
            :specific          => 'test_hiera_merge',
          }
        )
      end
      let(:params) { { :hiera_merge => true } }

      it { should compile.with_all_deps }

      it { should contain_class('ssh') }

      it { should contain_file('sshd_config').with_content(/^\s*DenyUsers denyuser_from_fqdn denyuser_from_fact/) }
      it { should contain_file('sshd_config').with_content(/^\s*DenyGroups denygroup_from_fqdn denygroup_from_fact/) }
      it { should contain_file('sshd_config').with_content(/^\s*AllowUsers allowuser_from_fqdn allowuser_from_fact/) }
      it { should contain_file('sshd_config').with_content(/^\s*AllowGroups allowgroup_from_fqdn allowgroup_from_fact/) }

    end

    context "as true with no hiera data provided" do
      let(:facts) do
        default_facts.merge(
          {
            :osfamily               => 'Suse',
            :operatingsystem        => 'SLES',
            :operatingsystemrelease => '11.4',
            :architecture           => 'x86_64',
          }
        )
      end
      let(:params) { { :hiera_merge => true } }

      it { should compile.with_all_deps }

      it { should contain_class('ssh') }

      it { should contain_file('sshd_config').without_content(/^\s*DenyUsers/) }
      it { should contain_file('sshd_config').without_content(/^\s*DenyGroups/) }
      it { should contain_file('sshd_config').without_content(/^\s*AllowUsers/) }
      it { should contain_file('sshd_config').without_content(/^\s*AllowGroups/) }

    end

    ['false',false].each do |value|
      context "as #{value}" do
        let(:params) { { :hiera_merge => value } }

        it { should compile.with_all_deps }

        it { should contain_class('ssh') }
      end
    end
  end

  describe 'with ssh_package_adminfile parameter specified' do
    context 'as a valid path' do
      let(:facts) { default_solaris_facts }
      let(:params) { { :ssh_package_adminfile => '/var/tmp/admin' } }

      ['SUNWsshcu','SUNWsshdr','SUNWsshdu','SUNWsshr','SUNWsshu'].each do |pkg|
        it {
          should contain_package(pkg).with({
            'ensure'    => 'installed',
            'source'    => '/var/spool/pkg',
            'adminfile' => '/var/tmp/admin',
          })
        }
      end
    end

    context 'as an invalid path' do
      let(:facts) { default_solaris_facts }
      let(:params) { { :ssh_package_adminfile => 'invalid/path' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/is not an absolute path/)
      end
    end
  end

  describe 'with sshd_config_xauth_location parameter specified' do
    context 'as a valid path' do
      let(:params) { { :sshd_config_xauth_location => '/opt/ssh/bin/xauth' } }

      it { should contain_file('sshd_config').with_content(/^XAuthLocation \/opt\/ssh\/bin\/xauth$/) }
    end

    context 'as an invalid path' do
      let(:params) { { :sshd_config_xauth_location => 'invalid/path' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/is not an absolute path/)
      end
    end

    context 'as an invalid type' do
      let(:params) { { :sshd_config_xauth_location => true } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  describe 'with ssh_package_source parameter specified' do
    let(:facts) { default_solaris_facts }
    context 'as a valid path' do
      let(:params) { { :ssh_package_source => '/mnt/packages' } }

      ['SUNWsshcu','SUNWsshdr','SUNWsshdu','SUNWsshr','SUNWsshu'].each do |pkg|
        it {
          should contain_package(pkg).with({
            'ensure'    => 'installed',
            'source'    => '/mnt/packages',
            'adminfile' => nil,
          })
        }
      end
    end

    context 'as an invalid path' do
      let(:params) { { :ssh_package_source => 'invalid/path' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/is not an absolute path/)
      end
    end

    context 'as an invalid type' do
      let(:params) { { :ssh_package_source => true } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  describe 'with parameter ssh_config_forward_x11_trusted' do
    ['yes','no'].each do |value|
      context "specified as #{value}" do
        let(:params) { { :ssh_config_forward_x11_trusted => value } }

        it { should contain_file('ssh_config').with_content(/^\s*ForwardX11Trusted #{value}$/) }
      end
    end

    context 'not specified' do
      let(:facts) { default_solaris_facts }
      it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11Trusted/) }
    end

    ['YES',true].each do |value|
      context "specified an invalid value #{value}" do
        let(:params) { { :ssh_config_forward_x11_trusted => value } }

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::ssh_config_forward_x11_trusted may be either 'yes' or 'no' and is set to <#{value}>\./)
        end
      end
    end
  end

  describe 'with parameter ssh_gssapidelegatecredentials' do
    ['yes','no'].each do |value|
      context "specified as #{value}" do
        let(:facts) { default_solaris_facts }
        let(:params) { { :ssh_gssapidelegatecredentials => value } }

        it { should contain_file('ssh_config').with_content(/^GSSAPIDelegateCredentials #{value}$/) }
      end
    end

    ['YES',true].each do |value|
      context "specified an invalid value #{value}" do
        let(:params) { { :ssh_gssapidelegatecredentials => value } }

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::ssh_gssapidelegatecredentials may be either 'yes' or 'no' and is set to <#{value}>\./)
        end
      end
    end
  end

  describe 'with parameter ssh_gssapiauthentication' do
    ['yes','no'].each do |value|
      context "specified as valid #{value} (as #{value.class})" do
        let(:params) { { :ssh_gssapiauthentication => value } }

        it { should contain_file('ssh_config').with_content(/^\s*GSSAPIAuthentication #{value}$/) }
      end
    end

    ['YES',true,2.42,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "specified as invalid value #{value} (as #{value.class})" do
        let(:params) { { :ssh_gssapiauthentication => value } }

        if value.is_a?(Array)
          value = value.join
        elsif value.is_a?(Hash)
          value = '{ha => sh}'
        end

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::ssh_gssapiauthentication may be either 'yes' or 'no' and is set to <#{Regexp.escape(value.to_s)}>\./)
        end
      end
    end
  end

  describe 'with parameter ssh_hostbasedauthentication' do
    ['yes','no'].each do |value|
      context "specified as valid #{value} (as #{value.class})" do
        let(:params) { { :ssh_hostbasedauthentication => value } }

        it { should contain_file('ssh_config').with_content(/^\s*HostbasedAuthentication #{value}$/) }
      end
    end

    ['YES',true,2.42,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "specified as invalid value #{value} (as #{value.class})" do
        let(:params) { { :ssh_hostbasedauthentication => value } }

        if value.is_a?(Array)
          value = value.join
        elsif value.is_a?(Hash)
          value = '{ha => sh}'
        end

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::ssh_hostbasedauthentication may be either 'yes' or 'no' and is set to <#{Regexp.escape(value.to_s)}>\./)
        end
      end
    end
  end

  describe 'with parameter ssh_strict_host_key_checking' do
    ['yes','no', 'ask'].each do |value|
      context "specified as valid #{value} (as #{value.class})" do
        let(:params) { { :ssh_strict_host_key_checking => value } }

        it { should contain_file('ssh_config').with_content(/^\s*StrictHostKeyChecking #{value}$/) }
      end
    end

    ['YES',true,2.42,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "specified as invalid value #{value} (as #{value.class})" do
        let(:params) { { :ssh_strict_host_key_checking => value } }

        if value.is_a?(Array)
          value = value.join
        elsif value.is_a?(Hash)
          value = '{ha => sh}'
        end

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::ssh_strict_host_key_checking may be 'yes', 'no' or 'ask' and is set to <#{Regexp.escape(value.to_s)}>\./)
        end
      end
    end
  end

  describe 'with parameter ssh_enable_ssh_keysign' do
    ['yes','no'].each do |value|
      context "specified as valid #{value} (as #{value.class})" do
        let(:params) { { :ssh_enable_ssh_keysign => value } }

        it { should contain_file('ssh_config').with_content(/^\s*EnableSSHKeysign #{value}$/) }
      end
    end

    ['YES',true,2.42,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "specified as invalid value #{value} (as #{value.class})" do
        let(:params) { { :ssh_enable_ssh_keysign => value } }

        if value.is_a?(Array)
          value = value.join
        elsif value.is_a?(Hash)
          value = '{ha => sh}'
        end

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::ssh_enable_ssh_keysign may be either 'yes' or 'no' and is set to <#{Regexp.escape(value.to_s)}>\./)
        end
      end
    end
  end

  describe 'with parameter sshd_gssapiauthentication' do
    ['yes','no'].each do |value|
      context "specified as valid #{value} (as #{value.class})" do
        let(:params) { { :sshd_gssapiauthentication => value } }

        it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication #{value}$/) }
      end
    end

    ['YES',true,2.42,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "specified as invalid value #{value} (as #{value.class})" do
        let(:params) { { :sshd_gssapiauthentication => value } }

        if value.is_a?(Array)
          value = value.join
        elsif value.is_a?(Hash)
          value = '{ha => sh}'
        end

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::sshd_gssapiauthentication may be either 'yes' or 'no' and is set to <#{Regexp.escape(value.to_s)}>\./)
        end
      end
    end
  end

  describe 'with parameter sshd_gssapikeyexchange' do
    ['yes','no'].each do |value|
      context "specified as #{value}" do
        let(:params) { { :sshd_gssapikeyexchange => value } }

        it { should contain_file('sshd_config').with_content(/^GSSAPIKeyExchange #{value}$/) }
      end
    end

    context 'not specified' do

      it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange/) }
    end

    ['YES',true].each do |value|
      context "specified an invalid value #{value}" do
        let(:params) { { :sshd_gssapikeyexchange => value } }

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::sshd_gssapikeyexchange may be either 'yes' or 'no' and is set to <#{value}>\./)
        end
      end
    end
  end

  describe 'with parameter sshd_pamauthenticationviakbdint' do
    ['yes','no'].each do |value|
      context "specified as #{value}" do
        let(:params) { { :sshd_pamauthenticationviakbdint => value } }

        it { should contain_file('sshd_config').with_content(/^PAMAuthenticationViaKBDInt #{value}$/) }
      end
    end

    context 'not specified' do

      it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt/) }
    end

    ['YES',true].each do |value|
      context "specified an invalid value #{value}" do
        let(:params) { { :sshd_pamauthenticationviakbdint => value } }

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::sshd_pamauthenticationviakbdint may be either 'yes' or 'no' and is set to <#{value}>\./)
        end
      end
    end
  end

  describe 'with parameter sshd_gssapicleanupcredentials' do
    ['yes','no'].each do |value|
      context "specified as #{value}" do
        let(:params) { { :sshd_gssapicleanupcredentials => value } }

        it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials #{value}$/) }
      end
    end

    context 'not specified' do
      let(:facts) { default_solaris_facts }

      it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPICleanupCredentials/) }
    end

    ['YES',true].each do |value|
      context "specified an invalid value #{value}" do
        let(:params) { { :sshd_gssapicleanupcredentials => value } }

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::sshd_gssapicleanupcredentials may be either 'yes' or 'no' and is set to <#{value}>\./)
        end
      end
    end
  end


  describe 'with parameter ssh_sendenv specified' do
    ['true',true].each do |value|
      context "as #{value}" do
        let(:params) { { :ssh_sendenv => value } }

        it { should contain_file('ssh_config').with_content(/^\s*SendEnv/) }
      end
    end

    ['false',false].each do |value|
      context "as #{value}" do
        let(:params) { { :ssh_sendenv => value } }

        it { should_not contain_file('ssh_config').with_content(/^\s*SendEnv/) }
      end
    end

    context 'as an invalid string' do
      let(:params) { { :ssh_sendenv => 'invalid' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::ssh_sendenv may be either 'true' or 'false' and is set to <invalid>\./)
      end
    end

    context 'as an invalid type' do
      let(:params) { { :ssh_sendenv => ['invalid','type'] } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::ssh_sendenv type must be true or false\./)
      end
    end
  end

  describe 'with paramter sshd_config_maxauthtries specified'  do
    context 'as a valid integer' do
     let(:params) { { :sshd_config_maxauthtries => 6}}
     it { should contain_file('sshd_config').with_content(/^MaxAuthTries 6$/)}
    end
    context 'as an invalid type' do
      let(:params) { { :sshd_config_maxauthtries => 'BOGUS'} }
      it 'should fail' do
        expect{
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::sshd_config_maxauthtries must be a valid number and is set to <BOGUS>\./)
      end
    end
 end

  describe 'with parameter sshd_config_maxstartups specified' do
    ['10','10:30:100'].each do |value|
      context "as a valid string - #{value}" do
        let(:params) { { :sshd_config_maxstartups => value } }

        it { should contain_file('sshd_config').with_content(/^MaxStartups #{value}$/) }
      end
    end

    ['10a',true,'10:30:1a'].each do |value|
      context "as an invalid string - #{value}" do
        let(:params) { { :sshd_config_maxstartups => value } }

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::sshd_config_maxstartups may be either an integer or three integers separated with colons, such as 10:30:100\. Detected value is <#{value}>\./)
        end
      end
    end

    context 'as an invalid type' do
      let(:params) { { :sshd_config_maxstartups => true } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  describe 'with parameter sshd_config_maxsessions specified' do
    context 'as a valid integer' do
      let(:params) { { :sshd_config_maxsessions => 10 } }

      it { should contain_file('sshd_config').with_content(/^MaxSessions 10$/) }
    end

    context 'as an invalid type' do
      let(:params) { { :sshd_config_maxsessions => 'BOGUS' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  describe 'with parameter sshd_acceptenv specified' do
    ['true',true].each do |value|
      context "as #{value}" do
        let(:params) { { :sshd_acceptenv => value } }

        it { should contain_file('sshd_config').with_content(/^\s*AcceptEnv/) }
      end
    end

    ['false',false].each do |value|
      context "as #{value}" do
        let(:params) { { :sshd_acceptenv => value } }

        it { should_not contain_file('sshd_config').with_content(/^\s*AcceptEnv/) }
      end
    end

    context 'as an invalid string' do
      let(:params) { { :sshd_acceptenv => 'invalid' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::sshd_acceptenv may be either 'true' or 'false' and is set to <invalid>\./)
      end
    end

    context 'as an invalid type' do
      let(:params) { { :sshd_acceptenv => ['invalid','type'] } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::sshd_acceptenv type must be true or false\./)
      end
    end
  end

  describe 'with parameter service_hasstatus' do
    ['true',true,'false',false].each do |value|
      context "specified as #{value}" do
        let(:params) { { :service_hasstatus => value } }

        it {
          should contain_service('sshd_service').with({
            'ensure'     => 'running',
            'name'       => 'sshd',
            'enable'     => 'true',
            'hasrestart' => 'true',
            'hasstatus'  => value,
            'subscribe'  => 'File[sshd_config]',
          })
        }
      end
    end

    context 'specified as an invalid string' do
      let(:params) { { :service_hasstatus => 'invalid' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::service_hasstatus must be 'true' or 'false' and is set to <invalid>\./)
      end
    end

    context 'specified as an invalid type' do
      let(:params) { { :service_hasstatus => ['invalid','type'] } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::service_hasstatus must be true or false\./)
      end
    end
  end

  describe 'with parameter ssh_config_global_known_hosts_file' do
    context 'specified as a valid path' do
      let(:params) { { :ssh_config_global_known_hosts_file => '/valid/path' } }

      it {
        should contain_file('ssh_known_hosts').with({
          'ensure' => 'file',
          'path'   => '/valid/path',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0644',
        })
      }

      it { should contain_file('ssh_config').with_content(/^\s*GlobalKnownHostsFile \/valid\/path$/) }
    end

    context 'specified as an invalid path' do
      let(:params) { { :ssh_config_global_known_hosts_file => 'invalid/path' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/\"invalid\/path\" is not an absolute path\./)
      end
    end

    context 'specified as an invalid type' do
      let(:params) { { :ssh_config_global_known_hosts_file => { 'invalid' => 'type'} } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/is not an absolute path/)
      end
    end
  end

  describe 'with parameter ssh_config_global_known_hosts_list' do
    context 'when set to an array of valid absolute paths' do
      let(:params) { {'ssh_config_global_known_hosts_list' => ['/valid/path1','/valid/path2'] } }

      it { should contain_file('ssh_config').with_content(/^\s*GlobalKnownHostsFile.*\/valid\/path1 \/valid\/path2$/) }
    end

    context 'specified as an invalid path' do
      let(:params) { { :ssh_config_global_known_hosts_list => ['/valid/path','invalid/path'] } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/\"invalid\/path\" is not an absolute path\./)
      end
    end

    ['YES',true,2.42,a = { 'ha' => 'sh' }].each do |value|
       context "specified as invalid value #{value} (as #{value.class})" do
         let(:params) { { :ssh_config_global_known_hosts_list => value } }

         if value.is_a?(Hash)
           value = '{ha => sh}'
         end

         it 'should fail' do
           expect {
             should contain_class('ssh')
           }.to raise_error(Puppet::Error, /is not an Array/)
         end
       end
     end
  end

  describe 'with parameter ssh_config_user_known_hosts_file' do
    context 'when set to an array of paths' do
      let(:params) { {'ssh_config_user_known_hosts_file' => ['valid/path1','/valid/path2'] } }

      it { should contain_file('ssh_config').with_content(/^\s*UserKnownHostsFile valid\/path1 \/valid\/path2$/) }
    end

    ['YES',true,2.42,a = { 'ha' => 'sh' }].each do |value|
       context "specified as invalid value #{value} (as #{value.class})" do
         let(:params) { { :ssh_config_user_known_hosts_file => value } }

         if value.is_a?(Hash)
           value = '{ha => sh}'
         end

         it 'should fail' do
           expect {
             should contain_class('ssh')
           }.to raise_error(Puppet::Error, /is not an Array/)
         end
       end
     end
  end

  describe 'with parameter ssh_config_global_known_hosts_owner' do
    context 'specified as a valid string' do
      let(:params) { { :ssh_config_global_known_hosts_owner => 'gh' } }

      it {
        should contain_file('ssh_known_hosts').with({
          'ensure' => 'file',
          'path'   => '/etc/ssh/ssh_known_hosts',
          'owner'  => 'gh',
          'group'  => 'root',
          'mode'   => '0644',
        })
      }
    end

    context 'specified as an invalid type [non-string]' do
      let(:params) { { :ssh_config_global_known_hosts_owner => ['invalid','type'] } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/\[\"invalid\", \"type\"\] is not a string\.  It looks to be a Array/)
      end
    end
  end

  describe 'with parameter ssh_config_global_known_hosts_group' do
    context 'specified as a valid string' do
      let(:params) { { :ssh_config_global_known_hosts_group => 'gh' } }

      it {
        should contain_file('ssh_known_hosts').with({
          'ensure' => 'file',
          'path'   => '/etc/ssh/ssh_known_hosts',
          'owner'  => 'root',
          'group'  => 'gh',
          'mode'   => '0644',
        })
      }
    end

    context 'specified as an invalid type [non-string]' do
      let(:params) { { :ssh_config_global_known_hosts_group => ['invalid','type'] } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/\[\"invalid\", \"type\"\] is not a string\.  It looks to be a Array/)
      end
    end
  end

  describe 'with parameter ssh_config_global_known_hosts_mode' do
    context 'specified as a valid mode' do
      let(:params) { { :ssh_config_global_known_hosts_mode => '0666' } }

      it {
        should contain_file('ssh_known_hosts').with({
          'ensure' => 'file',
          'path'   => '/etc/ssh/ssh_known_hosts',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0666',
        })
      }
    end

    ['666','0842','06666'].each do |value|
      context "specified as invalid mode - #{value}" do
        let(:params) { { :ssh_config_global_known_hosts_mode => value } }

        it 'should fail' do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::ssh_config_global_known_hosts_mode must be a valid 4 digit mode in octal notation\. Detected value is <#{value}>\./)
        end
      end
    end

    context 'specified as an invalid type [non-string]' do
      let(:params) { { :ssh_config_global_known_hosts_mode => ['invalid','type'] } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::ssh_config_global_known_hosts_mode must be a valid 4 digit mode in octal notation\. Detected value is <[\[]?invalid.*type[\]]?/)
      end
    end
  end

  describe 'with ssh_key_import parameter specified' do
    context 'as a non-boolean or non-string' do
    let(:params) { { :ssh_key_import => ['not_a_boolean','or_a_string'] } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end

    context 'as an invalid string' do
      let(:params) { { :ssh_key_import => 'invalid_string' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::ssh_key_import may be either 'true' or 'false' and is set to <invalid_string>\./)
      end
    end

    ['true',true].each do |value|
      context "as #{value}" do
        let(:params) { { :ssh_key_import => value } }

        it { should compile.with_all_deps }

        it { should contain_class('ssh') }

        it {
          should contain_file('ssh_known_hosts').with({
            'ensure'  => 'file',
            'path'    => '/etc/ssh/ssh_known_hosts',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
          })
        }
      end
    end

    ['false',false].each do |value|
      context "as #{value}" do
        let(:params) { { :ssh_key_import => value } }

        it { should compile.with_all_deps }

        it { should contain_class('ssh') }
      end
    end
  end

  describe 'with parameter sshd_hostbasedauthentication' do
    ['yes','no'].each do |value|
      context "specified as valid #{value} (as #{value.class})" do
        let(:params) { { :sshd_hostbasedauthentication => value } }

        it { should contain_file('sshd_config').with_content(/^HostbasedAuthentication #{value}$/) }
      end
    end

    ['YES',true,2.42,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "specified as invalid value #{value} (as #{value.class})" do
        let(:params) { { :sshd_hostbasedauthentication => value } }

        if value.is_a?(Array)
          value = value.join
        end

        it do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::sshd_hostbasedauthentication may be either 'yes' or 'no' and is set to/)
        end
      end
    end
  end

  describe 'with parameter sshd_pubkeyauthentication' do
    ['yes','no'].each do |value|
      context "specified as valid #{value} (as #{value.class})" do
        let(:params) { { :sshd_pubkeyauthentication => value } }

        it { should contain_file('sshd_config').with_content(/^PubkeyAuthentication #{value}$/) }
      end
    end

    ['YES',true,2.42,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "specified as invalid value #{value} (as #{value.class})" do
        let(:params) { { :sshd_pubkeyauthentication => value } }
        if value.is_a?(Array)
          value = value.join
        end

        it do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::sshd_pubkeyauthentication may be either 'yes' or 'no' and is set to/)
        end
      end
    end
  end

  describe 'with parameter sshd_ignoreuserknownhosts' do
    ['yes','no'].each do |value|
      context "specified as valid #{value} (as #{value.class})" do
        let(:params) { { :sshd_ignoreuserknownhosts => value } }

        it { should contain_file('sshd_config').with_content(/^IgnoreUserKnownHosts #{value}$/) }
      end
    end

    ['YES',true,2.42,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "specified as invalid value #{value} (as #{value.class})" do
        let(:params) { { :sshd_ignoreuserknownhosts => value } }
        if value.is_a?(Array)
          value = value.join
        end

        it do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::sshd_ignoreuserknownhosts may be either 'yes' or 'no' and is set to/)
        end
      end
    end
  end

  describe 'with parameter sshd_ignorerhosts' do
    ['yes','no'].each do |value|
      context "specified as valid #{value} (as #{value.class})" do
        let(:params) { { :sshd_ignorerhosts => value } }

        it { should contain_file('sshd_config').with_content(/^IgnoreRhosts #{value}$/) }
      end
    end

    ['YES',true,2.42,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "specified as invalid value #{value} (as #{value.class})" do
        let(:params) { { :sshd_ignorerhosts => value } }
        if value.is_a?(Array)
          value = value.join
        end

        it do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::sshd_ignorerhosts may be either 'yes' or 'no' and is set to/)
        end
      end
    end
  end

  describe 'with parameter manage_service' do
    ['YES','badvalue',2.42,['array'],a = { 'ha' => 'sh' }].each do |value|
      context "specified as invalid value #{value} (as #{value.class})" do
        let(:params) { { :manage_service => value } }
        it do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/(is not a boolean|Unknown type of boolean)/)
        end
      end
    end

    ['true', true].each do |value|
      context "specified as valid true value #{value} (as #{value.class})" do
        let(:params) { { :manage_service => value } }
        it { should contain_service('sshd_service') }
      end
    end

    ['false', false].each do |value|
      context "specified as valid false value #{value} (as #{value.class})" do
        let(:params) { { :manage_service => value } }
        it { should_not contain_service('sshd_service') }
      end
    end
  end

  describe 'sshd_config_tcp_keepalive param' do
    context 'when set to invalid' do
      let(:params) { { :sshd_config_tcp_keepalive => 'invalid' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::sshd_config_tcp_keepalive may be either \'yes\' or \'no\' and is set to <invalid>\./)
      end
    end
  end

  describe 'with parameter sshd_addressfamily' do
    ['any','inet','inet6'].each do |value|
      context "set to a valid entry of #{value}" do
        let(:params) { { :sshd_addressfamily => value } }
        it { should contain_file('sshd_config').with_content(/^AddressFamily #{value}$/) }
      end
    end

    ['foo','bar',123].each do |value|
      context "specified as invalid value #{value}" do
        let(:params) { { :sshd_addressfamily => value } }
        it do
          expect {
            should contain_class('ssh')
          }.to raise_error(Puppet::Error,/ssh::sshd_addressfamily can be undef, 'any', 'inet' or 'inet6' and is set to/)
        end
      end
    end
  end

  describe 'with parameter ssh_config_use_roaming' do
    ['yes','no','unset'].each do |value|
      context "set to valid value #{value}" do
        let(:params) { { :ssh_config_use_roaming => value } }
        if value == 'unset'
          it { should contain_file('ssh_config').without_content(/^\s*UseRoaming/) }
        else
          it { should contain_file('ssh_config').with_content(/^\s*UseRoaming #{value}$/) }
        end
      end
    end
  end

  describe 'variable type and content validations' do
    # set needed custom facts and variables
    let(:mandatory_params) do
      {
        #:param => 'value',
      }
    end

    validations = {
      'regex (yes|no|unset)' => {
        :name    => %w(ssh_config_use_roaming),
        :valid   => ['yes', 'no', 'unset'],
        :invalid => ['string', %w(array), { 'ha' => 'sh' }, 3, 2.42, true, false, nil],
        :message => 'may be either \'yes\', \'no\' or \'unset\'',
      },
    }

    validations.sort.each do |type, var|
      var[:name].each do |var_name|
        var[:params] = {} if var[:params].nil?
        var[:valid].each do |valid|
          context "when #{var_name} (#{type}) is set to valid #{valid} (as #{valid.class})" do
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
  end # describe 'variable type and content validations'
end
