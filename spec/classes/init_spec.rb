require 'spec_helper'
describe 'ssh' do
  on_supported_os.sort.each do |os, os_facts|
    # OS specific module defaults
    case "#{os_facts[:os]['name']}-#{os_facts[:os]['release']['full']}"
    when %r{AlmaLinux.*}, %r{CentOS.*}, %r{OracleLinux.*}, %r{RedHat.*}, %r{Scientific.*}
      packages_client = ['openssh-clients']
      packages_server = ['openssh-server']
    when %r{SLED.*}, %r{SLES.*}
      packages_client = ['openssh']
      packages_server = []
    when %r{Debian.*}, %r{Ubuntu.*}
      packages_client = ['openssh-client']
      packages_server = ['openssh-server']
    when %r{Solaris-9.*}, %r{Solaris-10.*}
      packages_client = ['SUNWsshcu', 'SUNWsshr', 'SUNWsshu']
      packages_server = ['SUNWsshdr', 'SUNWsshdu']
      packages_ssh_source = '/var/spool/pkg'
    when %r{Solaris-11.*}
      packages_client = ['network/ssh', 'network/ssh/ssh-key']
      packages_server = ['service/network/ssh']
      packages_ssh_source = nil
    end

    describe "on #{os} with default values for parameters" do
      let(:facts) { os_facts.merge(root_home: '/root') }

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_class('ssh') }

      packages_client.each do |package|
        it do
          is_expected.to contain_package(package).only_with(
            {
              'ensure'    => 'installed',
              'source'    => packages_ssh_source,
              'adminfile' => nil,
              'before'    => 'File[ssh_config]',
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
        is_expected.to contain_file('global_known_hosts').only_with(
          {
            'ensure'  => 'file',
            'path'    => '/etc/ssh/ssh_known_hosts',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'require' => 'File[ssh_config]',
          },
        )
      end

      it { is_expected.to contain_resources('sshkey').with_purge('true') }
      it { is_expected.to have_ssh__config_entry_resource_count(0) }
      it { is_expected.to have_ssh_authorized_key_resource_count(0) }
      it { is_expected.to contain_class('ssh::server') }

      # tests needed to reach 100% resource coverage
      it { is_expected.to contain_file('sshd_config') }
      it { is_expected.to contain_service('sshd_service') }
      packages_server.each do |package|
        it { is_expected.to contain_package(package) }
      end
    end
  end

  # The following tests are OS independent, so we only test one
  redhat = {
    supported_os: [
      {
        'operatingsystem'        => 'RedHat',
        'operatingsystemrelease' => ['7'],
      },
    ],
  }

  on_supported_os(redhat).sort.each do |os, os_facts|
    let(:facts) { os_facts.merge({ root_home: '/root' }) }

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

      # tests needed to reach 100% resource coverage
      it { is_expected.to contain_file('sshd_config') }
      it { is_expected.to contain_concat__fragment('/home/user/.ssh/config Host test_host2') }
      it { is_expected.to contain_concat('/home/user/.ssh/config') }
      it { is_expected.to contain_concat__fragment('/root/.ssh/config Host test_host1') }
      it { is_expected.to contain_concat('/root/.ssh/config') }
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

      it { is_expected.to contain_file('global_known_hosts').with_group('test') }
    end

    context "on #{os} with global_known_hosts_group set to valid value 0242" do
      let(:params) { { global_known_hosts_mode: '0242' } }

      it { is_expected.to contain_file('global_known_hosts').with_mode('0242') }
    end

    context "on #{os} with global_known_hosts_owner set to valid value test" do
      let(:params) { { global_known_hosts_owner: 'test' } }

      it { is_expected.to contain_file('global_known_hosts').with_owner('test') }
    end

    context "on #{os} with global_known_hosts_path set to valid value /unit/test" do
      let(:params) { { global_known_hosts_path: '/unit/test' } }

      it { is_expected.to contain_file('global_known_hosts').with_path('/unit/test') }
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

    context "on #{os} with manage_global_known_hosts set to valid false" do
      let(:params) { { manage_global_known_hosts: false } }

      it { is_expected.not_to contain_file('global_known_hosts') }
    end

    context "on #{os} with manage_root_ssh_config set to valid true" do
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

    context "on #{os} with manage_sshkey set to valid false" do
      let(:params) { { manage_sshkey: false } }

      it { is_expected.not_to contain_resources('sshkey') }
    end

    context "on #{os} with packages set to valid array [array, of, strings]" do
      let(:params) { { packages: ['array', 'of', 'strings'] } }

      it { is_expected.to have_package_resource_count(4) } # test cases + openssh-server from ssh::server
      it { is_expected.to contain_package('array') }
      it { is_expected.to contain_package('of') }
      it { is_expected.to contain_package('strings') }
    end

    context "on #{os} with packages_adminfile set to valid /unit/test" do
      let(:params) { { packages_adminfile: '/unit/test' } }

      it { is_expected.to contain_package('openssh-clients').with_adminfile('/unit/test') }
    end

    context "on #{os} with packages_source set to valid /unit/test" do
      let(:params) { { packages_source: '/unit/test' } }

      it { is_expected.to contain_package('openssh-clients').with_source('/unit/test') }
    end

    context "on #{os} with purge_keys set to valid false" do
      let(:params) { { purge_keys: false } }

      it { is_expected.to contain_resources('sshkey').with_purge('false') }
    end

    context "on #{os} with root_ssh_config_content set to valid #unit test (when manage_root_ssh_config is true)" do
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
