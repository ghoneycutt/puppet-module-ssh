require 'spec_helper'

describe 'ssh' do
  default_facts = {
    fqdn: 'monkey.example.com',
    hostname: 'monkey',
    ipaddress: '127.0.0.1',
    os: {
      family: 'RedHat',
      release: {
        major: '7',
      },
    },
    root_home: '/root',
    specific: 'dummy',
    ssh_version: 'OpenSSH_6.6p1',
    ssh_version_numeric: '6.6',
    sshrsakey: 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ==', # rubocop:disable Layout/LineLength
    ssh: {
      rsa: {
        key: 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1  AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ==', # rubocop:disable Layout/LineLength
      }
    }
  }

  #  default_solaris_facts = {
  #    fqdn: 'monkey.example.com',
  #    hostname: 'monkey',
  #    ipaddress: '127.0.0.1',
  #    kernelrelease: '5.10',
  #    osfamily: 'Solaris',
  #    root_home: '/root',
  #    specific: 'dummy',
  #    ssh_version: 'Sun_SSH_2.2',
  #    ssh_version_numeric: '2.2',
  #    sshrsakey: 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ==',   # rubocop:disable Layout/LineLength
  #    ssh: {
  #      rsa: {
  #        key: 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1  AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ==',   # rubocop:disable Layout/LineLength
  #      }
  #    }
  #  }

  let(:facts) { default_facts }

  osfamily_matrix = {
    #    'Debian-7' => {
    #      architecture: 'x86_64',
    #      osfamily: 'Debian',
    #      operatingsystemrelease: '7',
    #      ssh_version: 'OpenSSH_6.0p1',
    #      ssh_version_numeric: '6.0',
    #      ssh_packages: ['openssh-server', 'openssh-client'],
    #      ssh_config_fixture: 'ssh_config_debian',
    #    },
    #    'Debian-8' => {
    #      architecture: 'x86_64',
    #      osfamily: 'Debian',
    #      operatingsystemrelease: '8',
    #      ssh_version: 'OpenSSH_6.7p1',
    #      ssh_version_numeric: '8.11',
    #      ssh_packages: ['openssh-server', 'openssh-client'],
    #      ssh_config_fixture: 'ssh_config_debian8',
    #    },
    #    'Debian-9' => {
    #      architecture: 'x86_64',
    #      osfamily: 'Debian',
    #      operatingsystemrelease: '9',
    #      ssh_version: 'OpenSSH_7.4p1',
    #      ssh_version_numeric: '7.4',
    #      ssh_packages: ['openssh-server', 'openssh-client'],
    #      ssh_config_fixture: 'ssh_config_debian9',
    #    },
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
      ssh_packages: ['openssh-clients'],
      ssh_config_fixture: 'ssh_config_el5',
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
      ssh_packages: ['openssh-clients'],
      ssh_config_fixture: 'ssh_config_el6',
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
      ssh_packages: ['openssh-clients'],
      ssh_config_fixture: 'ssh_config_el7',
    },
    #    'Suse-10-x86_64' => {
    #      architecture: 'x86_64',
    #      osfamily: 'Suse',
    #      operatingsystem: 'SLES',
    #      operatingsystemrelease: '10.4',
    #      ssh_version: 'OpenSSH_5.1p1',
    #      ssh_version_numeric: '5.1',
    #      ssh_packages: ['openssh'],
    #      ssh_config_fixture: 'ssh_config_suse_old',
    #    },
    #    'Suse-10-i386' => {
    #      architecture: 'i386',
    #      osfamily: 'Suse',
    #      operatingsystem: 'SLES',
    #      operatingsystemrelease: '10.4',
    #      ssh_version: 'OpenSSH_5.1p1',
    #      ssh_version_numeric: '5.1',
    #      ssh_packages: ['openssh'],
    #      ssh_config_fixture: 'ssh_config_suse_old',
    #    },
    #    'Suse-11-x86_64' => {
    #      architecture: 'x86_64',
    #      osfamily: 'Suse',
    #      operatingsystem: 'SLES',
    #      operatingsystemrelease: '11.4',
    #      ssh_version: 'OpenSSH_6.6.1p1',
    #      ssh_version_numeric: '6.6',
    #      ssh_packages: ['openssh'],
    #      ssh_config_fixture: 'ssh_config_suse',
    #    },
    #    'Suse-11-i386' => {
    #      architecture: 'i386',
    #      osfamily: 'Suse',
    #      operatingsystem: 'SLES',
    #      operatingsystemrelease: '11.4',
    #      ssh_version: 'OpenSSH_6.6.1p1',
    #      ssh_version_numeric: '6.6',
    #      ssh_packages: ['openssh'],
    #      ssh_config_fixture: 'ssh_config_suse',
    #    },
    #    'Suse-12-x86_64' => {
    #      architecture: 'x86_64',
    #      osfamily: 'Suse',
    #      operatingsystem: 'SLES',
    #      operatingsystemrelease: '12.0',
    #      ssh_version: 'OpenSSH_6.6.1p1',
    #      ssh_version_numeric: '6.6',
    #      ssh_packages: ['openssh'],
    #      ssh_config_fixture: 'ssh_config_suse',
    #    },
    #    'Solaris-5.11' => {
    #      architecture: 'i86pc',
    #      osfamily: 'Solaris',
    #      kernelrelease: '5.11',
    #      ssh_version: 'Sun_SSH_2.2',
    #      ssh_version_numeric: '2.2',
    #      ssh_packages: ['network/ssh', 'network/ssh/ssh-key', 'service/network/ssh'],
    #      ssh_config_fixture: 'ssh_config_solaris',
    #    },
    #    'Solaris-5.10' => {
    #      architecture: 'i86pc',
    #      osfamily: 'Solaris',
    #      kernelrelease: '5.10',
    #      ssh_version: 'Sun_SSH_2.2',
    #      ssh_version_numeric: '2.2',
    #      ssh_packages: ['SUNWsshcu', 'SUNWsshdr', 'SUNWsshdu', 'SUNWsshr', 'SUNWsshu'],
    #      ssh_config_fixture: 'ssh_config_solaris',
    #    },
    #    'Solaris-5.9' => {
    #      architecture: 'i86pc',
    #      osfamily: 'Solaris',
    #      kernelrelease: '5.9',
    #      ssh_version: 'Sun_SSH_2.2',
    #      ssh_version_numeric: '2.2',
    #      ssh_packages: ['SUNWsshcu', 'SUNWsshdr', 'SUNWsshdu', 'SUNWsshr', 'SUNWsshu'],
    #      ssh_config_fixture: 'ssh_config_solaris',
    #    },
    #    'Ubuntu-1604' => {
    #      architecture: 'x86_64',
    #      osfamily: 'Debian',
    #      operatingsystemrelease: '16.04',
    #      ssh_version: 'OpenSSH_7.2p2',
    #      ssh_version_numeric: '7.2',
    #      ssh_packages: ['openssh-server', 'openssh-client'],
    #      ssh_config_fixture: 'ssh_config_ubuntu1604',
    #    },
    #    'Ubuntu-1804' => {
    #      architecture: 'x86_64',
    #      osfamily: 'Debian',
    #      operatingsystemrelease: '18.04',
    #      ssh_version: 'OpenSSH_7.6p1',
    #      ssh_version_numeric: '7.6',
    #      ssh_packages: ['openssh-server', 'openssh-client'],
    #      ssh_config_fixture: 'ssh_config_ubuntu1804',
    #    },
  }

  osfamily_matrix.each do |os, facts|
    context "with default params on osfamily #{os}" do
      let(:facts) { default_facts.merge(facts) }

      it { is_expected.to compile.with_all_deps }

      it { is_expected.to contain_class('ssh') }
      it { is_expected.to contain_class('ssh::server') }

      facts[:ssh_packages].each do |pkg|
        it {
          is_expected.to contain_package(pkg).with(
            {
              'ensure' => 'installed',
            },
          )
        }
      end

      it {
        is_expected.to contain_file('ssh_config').with(
          {
            'ensure'  => 'file',
            'path'    => '/etc/ssh/ssh_config',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
          },
        )
      }

      facts[:ssh_packages].each do |pkg|
        it {
          is_expected.to contain_file('ssh_config').that_requires("Package[#{pkg}]")
        }
      end

      ssh_config_fixture = File.read(fixtures("#{facts[:ssh_config_fixture]}_sorted"))
      it { is_expected.to contain_file('ssh_config').with_content(ssh_config_fixture) }

      it {
        is_expected.to contain_file('ssh_known_hosts').with(
          {
            'ensure' => 'file',
            'path'   => '/etc/ssh/ssh_known_hosts',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0644',
          },
        )
      }

      facts[:ssh_packages].each do |pkg|
        it {
          is_expected.to contain_file('ssh_known_hosts').that_requires("Package[#{pkg}]")
        }
      end

      it { is_expected.not_to contain_exec("mkdir_p-#{facts[:root_home]}/.ssh") }
      it { is_expected.not_to contain_file('root_ssh_dir') }
      it { is_expected.not_to contain_file('root_ssh_config') }
      it { is_expected.to have_ssh__config_entry_resource_count(0) }
      it { is_expected.to have_sshkey_resource_count(0) }

      it {
        is_expected.to contain_resources('sshkey').with(
          {
            'purge' => 'true',
          },
        )
      }

      it { is_expected.to have_ssh_authorized_key_resource_count(0) }
    end
  end

  # TODO: FIXME: access facts hash incorrectly?
  #
  #  describe 'with exported sshkey resources' do
  #    subject { exported_resources }
  #
  #    let(:params) { { key_export: true } }
  #
  #    context 'With only IPv4 address' do
  #      let(:facts) { default_facts.merge( facts ) }
  #      it {
  #        is_expected.to contain_sshkey('monkey.example.com').with(
  #          'ensure' => 'present',
  #          'host_aliases' => ['monkey', '127.0.0.1'],
  #          'type' => 'ssh-rsa',
  #          'key' => facts[:ssh['rsa']['key']],
  #        )
  #      }
  #    end
  #    context 'With dual stack IP' do
  #      let(:facts) { default_facts.merge({ ipaddress6: 'dead:beef::1/64' }) }
  #
  #      it {
  #        is_expected.to contain_sshkey('monkey.example.com').with(
  #          'ensure' => 'present',
  #          'host_aliases' => ['monkey', '127.0.0.1', 'dead:beef::1/64'],
  #          'type' => 'ssh-rsa',
  #          'key' => facts[:ssh[:rsa][:key]],
  #        )
  #      }
  #    end
  #
  #    context 'With only IPv6 address' do
  #      let(:facts) { default_facts.merge({ ipaddress6: 'dead:beef::1/64', ipaddress: nil }) }
  #      it {
  #        is_expected.to contain_sshkey('monkey.example.com').with(
  #          'ensure' => 'present',
  #          'host_aliases' => ['monkey', 'dead:beef::1/64'],
  #          'type' => 'ssh-rsa',
  #          'key' => facts[:ssh[:rsa][:key]],
  #        )
  #      }
  #    end
  #  end

  # TODO: FIXME: access facts hash incorrectly?
  #
  #  context 'with default params on invalid osfamily' do
  #    let(:facts) { default_facts.merge({ :os['family'] => 'C64' }) }
  #
  #    it 'should fail' do
  #      expect {
  #        is_expected.to contain_class('ssh')
  #      }.to raise_error(Puppet::Error, /ssh supports osfamilies RedHat, Suse, Debian and Solaris\. Detected os family is <C64>\./)
  #    end
  #  end

  context 'with config_entries defined' do
    let(:params) do
      {
        config_entries: {
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
            'order' => 242,
            'lines' => ['ForwardX11 no', 'StrictHostKeyChecking no'],
          },
        }
      }
    end

    it { is_expected.to compile.with_all_deps }
    it { is_expected.to have_ssh__config_entry_resource_count(2) }
    it do
      is_expected.to contain_ssh__config_entry('root').with(
        {
          'owner' => 'root',
          'group' => 'root',
          'path'  => '/root/.ssh/config',
          'host'  => 'test_host1',
        },
      )
    end
    it do
      is_expected.to contain_ssh__config_entry('user').with(
        {
          'owner' => 'user',
          'group' => 'group',
          'path'  => '/home/user/.ssh/config',
          'host'  => 'test_host2',
          'order' => 242,
          'lines' => ['ForwardX11 no', 'StrictHostKeyChecking no'],
        },
      )
    end
  end

  context 'with keys defined' do
    let(:params) do
      {
        keys: {
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
        }
      }
    end

    it { is_expected.to compile.with_all_deps }

    it {
      is_expected.to contain_ssh_authorized_key('root_for_userX').with(
        {
          'ensure' => 'present',
          'user'   => 'root',
          'type'   => 'dsa',
          'key'    => 'AAAA==',
        },
      )
    }

    it {
      is_expected.to contain_ssh_authorized_key('apache_hup').with(
        {
          'ensure'  => 'present',
          'user'    => 'apachehup',
          'type'    => 'dsa',
          'key'     => 'AAAA==',
          'options' => 'command="/sbin/service httpd restart"',
        },
      )
    }

    it {
      is_expected.to contain_ssh_authorized_key('root_for_userY').with(
        {
          'ensure' => 'absent',
          'user'   => 'root',
        },
      )
    }
  end

  describe 'with ssh_key_import parameter set to' do
    # TODO: FIXME: problem related to other commented out block. See 'with exported sshkey resources'
    #    context 'as true' do
    #      let(:params) { { ssh_key_import: true } }
    #
    #      it { is_expected.to have_sshkey_resource_count(1) }
    #    end

    context 'as false' do
      let(:params) { { ssh_key_import: false } }

      it { is_expected.to have_sshkey_resource_count(0) }
    end
  end
end
