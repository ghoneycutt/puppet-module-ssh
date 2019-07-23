require 'spec_helper'

describe 'ssh::service_instance' do
  let(:title) { 'additional_instance'}

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
      'Debian-10' => {
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

      it { should contain_ssh__service_instance('additional_instance')}

      it {
        should contain_file('/etc/systemd/system/additional_instance.service').with({
          'ensure' => 'file',
          'path'   => '/etc/systemd/system/additional_instance.service',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0644',
        })
      }

      service_fixture = File.read(fixtures('service'))
      it { should contain_file('/etc/systemd/system/additional_instance.service').with_content(service_fixture) }

    end
  end
end
