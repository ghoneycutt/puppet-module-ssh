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

      content_fixture = File.read(fixtures("#{os_facts[:os]['name']}-#{os_facts[:os]['release']['major']}_ssh_config"))

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
  end
end
