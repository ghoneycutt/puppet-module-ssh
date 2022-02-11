require 'spec_helper'
describe 'ssh' do
  on_supported_os.sort.each do |os, os_facts|
    context "on #{os} with default values for parameters" do
      # OS specific SSH versions
      case "#{os_facts[:os]['name']}-#{os_facts[:os]['release']['major']}"
      when 'CentOS-5', 'OracleLinux-5', 'RedHat-5', 'Scientific-5'
        ssh_version = 'OpenSSH_4.3p2'
        ssh_version_numeric = '4.3'
      when 'CentOS-6', 'OracleLinux-6', 'RedHat-6', 'Scientific-6'
        ssh_version = 'OpenSSH_5.3p1'
        ssh_version_numeric = '5.3'
      when 'CentOS-7', 'OracleLinux-7', 'RedHat-7', 'Scientific-7'
        ssh_version = 'OpenSSH_6.6p1'
        ssh_version_numeric = '6.6'
      when 'SLED-10', 'SLES-10'
        ssh_version = 'OpenSSH_5.1p1'
        ssh_version_numeric = '5.1'
      when 'SLED-11', 'SLED-12', 'SLES-11', 'SLES-12'
        ssh_version = 'OpenSSH_6.6.1p1'
        ssh_version_numeric = '6.6'
      when 'SLED-15', 'SLES-15'
        ssh_version = 'OpenSSH_8.4p1'
        ssh_version_numeric = '8.4'
      when 'Solaris-9', 'Solaris-10', 'Solaris-11'
        ssh_version = 'Sun_SSH_2.2'
        ssh_version_numeric = '2.2'
      when 'Ubuntu-14.04'
        ssh_version = 'OpenSSH 6.6p1'
        ssh_version_numeric = '6.6'
      when 'Ubuntu-16.04'
        ssh_version = 'OpenSSH_7.2p2'
        ssh_version_numeric = '7.2'
      when 'Ubuntu-18.04'
        ssh_version = 'OpenSSH_7.6p1'
        ssh_version_numeric = '7.6'
      when 'Ubuntu-20.04'
        ssh_version = 'OpenSSH_8.2p1'
        ssh_version_numeric = '8.2'
      when 'Debian-7'
        ssh_version = 'OpenSSH_6.0p1'
        ssh_version_numeric = '6.0'
      when 'Debian-8'
        ssh_version = 'OpenSSH_6.7p1'
        ssh_version_numeric = '6.7'
      when 'Debian-9'
        ssh_version = 'OpenSSH_7.4p1'
        ssh_version_numeric = '7.4'
      when 'Debian-10'
        ssh_version = 'OpenSSH_7.9p1'
        ssh_version_numeric = '7.9'
      when 'Debian-11'
        ssh_version = 'OpenSSH_8.4p1'
        ssh_version_numeric = '8.4'
      else
        ssh_version = 'UnkownSSH_2.42'
        ssh_version_numeric = '2.42'
      end

      let(:facts) do
        os_facts.merge(
          {
            root_home: '/root',
            ssh_version: ssh_version,
            ssh_version_numeric: ssh_version_numeric,
          },
        )
      end

      # OS specific defaults
      case "#{os_facts[:os]['name']}-#{os_facts[:os]['release']['full']}"
      when %r{CentOS.*}, %r{OracleLinux.*}, %r{RedHat.*}, %r{Scientific.*}
        packages_default = ['openssh-clients']
      when %r{SLED.*}, %r{SLES.*}
        packages_default = ['openssh']
      when %r{Debian.*}, %r{Ubuntu.*}
        packages_default = ['openssh-client']
      when %r{Solaris-9.*}, %r{Solaris-10.*}
        packages_default    = ['SUNWsshcu', 'SUNWsshr', 'SUNWsshu']
        packages_ssh_source = '/var/spool/pkg'
      when %r{Solaris-11.*}
        packages_default    = ['network/ssh', 'network/ssh/ssh-key']
        packages_ssh_source = nil
      end

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_class('ssh') }

      packages_default.each do |package|
        it do
          is_expected.to contain_package(package).only_with(
            {
              'ensure'    => 'installed',
              'source'    => packages_ssh_source,
              'adminfile' => nil,
              'before'    => ['File[ssh_config]', 'File[ssh_known_hosts]'],
            },
          )
        end
      end

      content_fixture = File.read(fixtures("testing/#{os_facts[:os]['name']}-#{os_facts[:os]['release']['major']}_ssh_config"))

      it do
        is_expected.to contain_file('ssh_config').only_with(
          {
            'ensure'  => 'file',
            'path'    => '/etc/ssh/ssh_config',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'content' => content_fixture,
          },
        )
      end

      it { is_expected.not_to contain_exec("mkdir_p-#{os_facts[:root_home]}/.ssh") }
      it { is_expected.not_to contain_file('root_ssh_dir') }
      it { is_expected.not_to contain_file('root_ssh_config') }

      it { is_expected.to have_sshkey_resource_count(0) }

      it do
        is_expected.to contain_file('ssh_known_hosts').only_with(
          {
            'ensure'  => 'file',
            'path'    => '/etc/ssh/ssh_known_hosts',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
          },
        )
      end

      it { is_expected.to contain_resources('sshkey').with_purge('true') }
      it { is_expected.to have_ssh__config_entry_resource_count(0) }
      it { is_expected.to have_ssh_authorized_key_resource_count(0) }
      it { is_expected.to contain_class('ssh::server') }
    end

    context "on #{os} with config_entries set to valid hash" do
      let(:params) do
        {
          config_entries: {
            'root' => {
              'ensure' => 'absent',
              'owner'  => 'root',
              'group'  => 'root',
              'path'   => '/root/.ssh/config',
              'order'  => 3,
              'host'   => 'test_host1',
              'lines'  => ['Invalid value'],
            },
            'user' => {
              'ensure' => 'present',
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

      it { is_expected.to have_ssh__config_entry_resource_count(2) }
      it do
        is_expected.to contain_ssh__config_entry('root').only_with(
          {
            'ensure' => 'absent',
            'owner'  => 'root',
            'group'  => 'root',
            'path'   => '/root/.ssh/config',
            'order'  => 3,
            'host'   => 'test_host1',
            'lines'  => ['Invalid value'],
          },
        )
      end
      it do
        is_expected.to contain_ssh__config_entry('user').only_with(
          {
            'ensure' => 'present',
            'owner'  => 'user',
            'group'  => 'group',
            'path'   => '/home/user/.ssh/config',
            'host'   => 'test_host2',
            'order'  => 242,
            'lines'  => ['ForwardX11 no', 'StrictHostKeyChecking no'],
          },
        )
      end
    end

    context "on #{os} with config_group set to valid value test" do
      let(:params) { { config_group: 'test' } }

      it { is_expected.to contain_file('ssh_config').with_group('test') }
    end

    context "on #{os} with config_group set to valid value 0242" do
      let(:params) { { config_mode: '0242' } }

      it { is_expected.to contain_file('ssh_config').with_mode('0242') }
    end

    context "on #{os} with config_owner set to valid value test" do
      let(:params) { { config_owner: 'test' } }

      it { is_expected.to contain_file('ssh_config').with_owner('test') }
    end

    context "on #{os} with config_path set to valid value /unit/test" do
      let(:params) { { config_path: '/unit/test' } }

      it { is_expected.to contain_file('ssh_config').with_path('/unit/test') }
    end

    context "on #{os} with global_known_hosts_group set to valid value test" do
      let(:params) { { global_known_hosts_group: 'test' } }

      it { is_expected.to contain_file('ssh_known_hosts').with_group('test') }
    end

    context "on #{os} with global_known_hosts_group set to valid value 0242" do
      let(:params) { { global_known_hosts_mode: '0242' } }

      it { is_expected.to contain_file('ssh_known_hosts').with_mode('0242') }
    end

    context "on #{os} with global_known_hosts_owner set to valid value test" do
      let(:params) { { global_known_hosts_owner: 'test' } }

      it { is_expected.to contain_file('ssh_known_hosts').with_owner('test') }
    end

    context "on #{os} with global_known_hosts_path set to valid value /unit/test" do
      let(:params) { { global_known_hosts_path: '/unit/test' } }

      it { is_expected.to contain_file('ssh_known_hosts').with_path('/unit/test') }
    end

    context "on #{os} with host set to valid value unit.test.domain" do
      let(:params) { { host: 'unit.test.domain' } }

      it { is_expected.to contain_file('ssh_config').with_content(%r{Host unit.test.domain}) }
    end

    context "on #{os} with keys set to valid hash" do
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
          }
        }
      end

      it { is_expected.to have_ssh_authorized_key_resource_count(2) }

      it do
        is_expected.to contain_ssh_authorized_key('root_for_userX').only_with(
          {
            'ensure' => 'present',
            'user'   => 'root',
            'type'   => 'dsa',
            'key'    => 'AAAA==',
          },
        )
      end

      it do
        is_expected.to contain_ssh_authorized_key('apache_hup').only_with(
          {
            'ensure'  => 'present',
            'user'    => 'apachehup',
            'type'    => 'dsa',
            'key'     => 'AAAA==',
            'options' => 'command="/sbin/service httpd restart"',
          },
        )
      end
    end

    context "on #{os} with manage_root_ssh_config set to valid true" do
      let(:facts) { os_facts.merge({ root_home: '/root' }) }
      let(:params) { { manage_root_ssh_config: true } }

      it do
        is_expected.to contain_exec('mkdir_p-/root/.ssh').only_with(
          {
            'command' => 'mkdir -p /root/.ssh',
            'unless'  => 'test -d /root/.ssh',
            'path'    => '/bin:/usr/bin',
          },
        )
      end

      it do
        is_expected.to contain_file('root_ssh_dir').only_with(
          {
            'ensure'  => 'directory',
            'path'    => '/root/.ssh',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0700',
            'require' => 'Exec[mkdir_p-/root/.ssh]',
          },
        )
      end

      it do
        is_expected.to contain_file('root_ssh_config').only_with(
          {
            'ensure'  => 'file',
            'path'    => '/root/.ssh/config',
            'content' => "# This file is being maintained by Puppet.\n# DO NOT EDIT\n",
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0600',
          },
        )
      end
    end

    context "on #{os} with manage_server set to valid false" do
      let(:params) { { manage_server: false } }

      it { is_expected.not_to contain_class('ssh::server') }
    end

    context "on #{os} with package_adminfile set to valid /unit/test" do
      let(:facts) { os_facts  }
      let(:params) { { package_adminfile: '/unit/test' } }

      # OS specific defaults
      case "#{os_facts[:os]['name']}-#{os_facts[:os]['release']['full']}"
      when %r{CentOS.*}, %r{OracleLinux.*}, %r{RedHat.*}, %r{Scientific.*}
        packages_default = ['openssh-clients']
      when %r{SLED.*}, %r{SLES.*}
        packages_default = ['openssh']
      when %r{Debian.*}, %r{Ubuntu.*}
        packages_default = ['openssh-client']
      when %r{Solaris-9.*}, %r{Solaris-10.*}
        packages_default    = ['SUNWsshcu', 'SUNWsshr', 'SUNWsshu']
      when %r{Solaris-11.*}
        packages_default    = ['network/ssh', 'network/ssh/ssh-key']
      end

      packages_default.each do |package|
        it { is_expected.to contain_package(package).with_adminfile('/unit/test') }
      end
    end

    context "on #{os} with packages set to valid array [unit, test]" do
      let(:params) { { packages: ['unit', 'test'] } }

      it { is_expected.to have_package_resource_count(2) }
      it { is_expected.to contain_package('unit') }
      it { is_expected.to contain_package('test') }
    end

    context "on #{os} with package_source set to valid /unit/test" do
      let(:facts) { os_facts }
      let(:params) { { package_source: '/unit/test' } }

      # OS specific defaults
      case "#{os_facts[:os]['name']}-#{os_facts[:os]['release']['full']}"
      when %r{CentOS.*}, %r{OracleLinux.*}, %r{RedHat.*}, %r{Scientific.*}
        packages_default = ['openssh-clients']
      when %r{SLED.*}, %r{SLES.*}
        packages_default = ['openssh']
      when %r{Debian.*}, %r{Ubuntu.*}
        packages_default = ['openssh-client']
      when %r{Solaris-9.*}, %r{Solaris-10.*}
        packages_default    = ['SUNWsshcu', 'SUNWsshr', 'SUNWsshu']
      when %r{Solaris-11.*}
        packages_default    = ['network/ssh', 'network/ssh/ssh-key']
      end

      packages_default.each do |package|
        it { is_expected.to contain_package(package).with_source('/unit/test') }
      end
    end

    context "on #{os} with purge_keys set to valid false" do
      let(:params) { { purge_keys: false } }

      it { is_expected.to contain_resources('sshkey').with_purge('false') }
    end

    context "on #{os} with root_ssh_config_content set to valid #unit test (when manage_root_ssh_config is true)" do
      let(:facts) { os_facts.merge({ root_home: '/root' }) }
      let(:params) do
        {
          root_ssh_config_content: '#unit test',
          manage_root_ssh_config: true,
        }
      end

      it { is_expected.to contain_file('root_ssh_config').with_content('#unit test') }
    end
  end
end
