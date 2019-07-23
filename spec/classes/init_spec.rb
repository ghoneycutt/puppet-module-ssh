require 'spec_helper'

describe 'ssh' do

  default_facts = {
    :fqdn                   => 'monkey.example.com',
    :hostname               => 'monkey',
    :ipaddress              => '127.0.0.1',
    :lsbmajdistrelease      => '6',
    :operatingsystemrelease => '6.7',
    :osfamily               => 'RedHat',
    :root_home              => '/root',
    :specific               => 'dummy',
    :ssh_version            => 'OpenSSH_6.6p1',
    :ssh_version_numeric    => '6.6',
    :sshrsakey              => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ==',
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
    'Debian-8' => {
      :architecture           => 'x86_64',
      :osfamily               => 'Debian',
      :operatingsystemrelease => '8',
      :ssh_version            => 'OpenSSH_6.7p1',
      :ssh_version_numeric    => '8.11',
      :ssh_packages           => ['openssh-server', 'openssh-client'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'ssh',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_debian8',
      :ssh_config_fixture     => 'ssh_config_debian8',
    },
    'Debian-9' => {
      :architecture           => 'x86_64',
      :osfamily               => 'Debian',
      :operatingsystemrelease => '9',
      :ssh_version            => 'OpenSSH_7.4p1',
      :ssh_version_numeric    => '7.4',
      :ssh_packages           => ['openssh-server', 'openssh-client'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'ssh',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_debian9',
      :ssh_config_fixture     => 'ssh_config_debian9',
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
    'RedHat-7.4' => {
      :architecture           => 'x86_64',
      :osfamily               => 'RedHat',
      :operatingsystemrelease => '7.4',
      :ssh_version            => 'OpenSSH_6.6p1',
      :ssh_version_numeric    => '6.6',
      :ssh_packages           => ['openssh-server', 'openssh-clients'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'sshd',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_rhel7',
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
    'Ubuntu-1804' => {
      :architecture           => 'x86_64',
      :osfamily               => 'Debian',
      :operatingsystemrelease => '18.04',
      :ssh_version            => 'OpenSSH_7.6p1',
      :ssh_version_numeric    => '7.6',
      :ssh_packages           => ['openssh-server', 'openssh-client'],
      :sshd_config_mode       => '0600',
      :sshd_service_name      => 'ssh',
      :sshd_service_hasstatus => true,
      :sshd_config_fixture    => 'sshd_config_ubuntu1804',
      :ssh_config_fixture     => 'ssh_config_ubuntu1804',
    },
  }

  osfamily_matrix.each do |os, facts|
    context "with default params on osfamily #{os}" do
      let(:facts) { default_facts.merge( facts )}

      it { should compile.with_all_deps }

      it { should contain_class('ssh')}

      it { should contain_class('ssh::package')}

      it { should_not contain_class('common')}

      it { should contain_ssh__sshd_config('sshd_config')}

      it {
        should contain_file('ssh_known_hosts').with({
          'ensure' => 'file',
          'path'   => '/etc/ssh/ssh_known_hosts',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0644',
        })
      }

      facts[:ssh_packages].each do |pkg|
        it {
          should contain_file('ssh_known_hosts').that_requires("Package[#{pkg}]")
        }
      end

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
        should contain_resources('sshkey').with({
          'purge' => 'true',
        })
      }

      it { should have_ssh__config_entry_resource_count(0) }

      context 'with exported sshkey resources' do
        subject { exported_resources}
        context 'With only IPv4 address' do
          let(:facts) { default_facts.merge( facts )}
          it { should contain_sshkey('monkey.example.com').with(
            'ensure' => 'present',
            'host_aliases' => ['monkey', '127.0.0.1']
          )}
        end
        context 'With dual stack IP' do
          let(:facts) { default_facts.merge({ :ipaddress6 => 'dead:beef::1/64' }) }
          it { should contain_sshkey('monkey.example.com').with(
            'ensure' => 'present',
            'host_aliases' => ['monkey', '127.0.0.1', 'dead:beef::1/64']
          )}
        end
        context 'With only IPv6 address' do
          let(:facts) { default_facts.merge({ :ipaddress6 => 'dead:beef::1/64', :ipaddress => nil }) }
          it { should contain_sshkey('monkey.example.com').with(
            'ensure' => 'present',
            'host_aliases' => ['monkey', 'dead:beef::1/64']
          )}
        end
      end

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
        :ssh_config_kexalgorithms          => [ 'curve25519-sha256@libssh.org',
            'ecdh-sha2-nistp256',
            'ecdh-sha2-nistp384',
            'ecdh-sha2-nistp521',
            'diffie-hellman-group-exchange-sha256',
            'diffie-hellman-group-exchange-sha1',
            'diffie-hellman-group14-sha1',
            'diffie-hellman-group1-sha1',
  ],
        :ssh_config_macs                    => [ 'hmac-md5-etm@openssh.com',
                                                 'hmac-sha1-etm@openssh.com',
        ],
        :ssh_config_proxy_command           => 'ssh -W %h:%p firewall.example.org',
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
    it { should contain_file('ssh_config').with_content(/^\s*KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1$/) }
    it { should contain_file('ssh_config').with_content(/^\s*MACs hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com$/) }
    it { should contain_file('ssh_config').with_content(/^\s*ProxyCommand ssh -W %h:%p firewall\.example\.org$/) }
    it { should contain_file('ssh_config').with_content(/^\s*GlobalKnownHostsFile \/etc\/ssh\/ssh_known_hosts2 \/etc\/ssh\/ssh_known_hosts3 \/etc\/ssh\/ssh_known_hosts4$/) }
    it { should contain_file('ssh_config').with_content(/^\s*UserKnownHostsFile \.ssh\/known_hosts1 \.ssh\/known_hosts2$/) }
    it { should contain_file('ssh_config').with_content(/^\s*HostbasedAuthentication yes$/) }
    it { should contain_file('ssh_config').with_content(/^\s*StrictHostKeyChecking ask$/) }
    it { should contain_file('ssh_config').with_content(/^\s*EnableSSHKeysign yes$/) }
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

  [true,'invalid'].each do |kexalgorithms|
    context "with ssh_config_kexalgorithms set to invalid value #{kexalgorithms}" do
      let(:params) { { :ssh_config_kexalgorithms => kexalgorithms } }

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

  [true, ['not','a','string']].each do |proxy_command|
    context "with ssh_config_proxy_command set to invalid value #{proxy_command}" do
      let(:params) { { :ssh_config_proxy_command => proxy_command } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  describe 'with ssh_config_hash_known_hosts param' do
    ['yes','no','unset'].each do |value|
      context "set to #{value}" do
        let (:params) { { :ssh_config_hash_known_hosts => value } }

        if value == 'unset'
          it { should contain_file('ssh_config').without_content(/^\s*HashKnownHosts/) }
        else
          it { should contain_file('ssh_config').with_content(/^\s*HashKnownHosts #{value}$/) }
        end
      end
    end

    context 'when set to an invalid value' do
      let (:params) { { :ssh_config_hash_known_hosts => 'invalid' } }

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error,/ssh::ssh_config_hash_known_hosts may be either \'yes\', \'no\' or \'unset\' and is set to <invalid>\./)
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

  context 'with config_entries defined on valid osfamily' do
    let(:params) do
      {
        :config_entries => {
          'root' => {
            'owner' => 'root',
            'group' => 'root',
            'path'  => '/root/.ssh/config',
            'host'  => 'test_host1',
          },
          'user' => {
            'owner' => 'user',
            'group' => 'group',
            'path'  => '/home/user/.ssh/config',
            'host'  => 'test_host2',
            'order' => '242',
            'lines' => [ 'ForwardX11 no', 'StrictHostKeyChecking no' ],
          },
        }
      }
    end

    it { should compile.with_all_deps }
    it { should have_ssh__config_entry_resource_count(2) }
    it do
      should contain_ssh__config_entry('root').with({
        'owner' => 'root',
        'group' => 'root',
        'path'  => '/root/.ssh/config',
        'host'  => 'test_host1',
      })
    end
    it do
      should contain_ssh__config_entry('user').with({
        'owner' => 'user',
        'group' => 'group',
        'path'  => '/home/user/.ssh/config',
        'host'  => 'test_host2',
        'order' => '242',
        'lines' => [ 'ForwardX11 no', 'StrictHostKeyChecking no' ],
      })
    end
  end

  describe 'with hiera providing data from multiple levels' do
    let(:facts) do
      default_facts.merge({
        :fqdn     => 'hieramerge.example.com',
        :specific => 'test_hiera_merge',
      })
    end

    context 'with defaults for all parameters' do
      it { should have_ssh__config_entry_resource_count(1) }
      it { should contain_ssh__config_entry('user_from_fqdn') }
    end

    context 'with hiera_merge set to valid <true>' do
      let(:params) { { :hiera_merge => true } }
      it { should have_ssh__config_entry_resource_count(2) }
      it { should contain_ssh__config_entry('user_from_fqdn') }
      it { should contain_ssh__config_entry('user_from_fact') }
    end
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
    end

    ['false',false].each do |value|
      context "as #{value}" do
        let(:params) { { :hiera_merge => value } }

        it { should compile.with_all_deps }

        it { should contain_class('ssh') }
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
        it { should contain_ssh__service('sshd_service')}
      end
    end

    ['false', false].each do |value|
      context "specified as valid false value #{value} (as #{value.class})" do
        let(:params) { { :manage_service => value } }
        it { should_not contain_ssh__service('sshd_service') }
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
    mandatory_params = {} if mandatory_params.nil?

    validations = {
      'hash' => {
        :name    => %w[config_entries],
        :valid   => [], # valid hashes are to complex to block test them here. types::mount should have its own spec tests anyway.
        :invalid => ['string', %w[array], 3, 2.42, true],
        :message => 'is not a Hash',
      },
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
            it { is_expected.to compile.and_raise_error(/#{var[:message]}/) }
          end
        end
      end # var[:name].each
    end # validations.sort.each
  end # describe 'variable type and content validations'
end
