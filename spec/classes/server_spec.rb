require 'spec_helper'
describe 'ssh::server' do
  on_supported_os.sort.each do |os, os_facts|
    context "on #{os} with default values for parameters" do
      let(:facts) { os_facts }

      fixture = fixtures("testing/#{os_facts[:os]['name']}-#{os_facts[:os]['release']['major']}_sshd_config")
      # OS specific defaults
      case "#{os_facts[:os]['name']}-#{os_facts[:os]['release']['full']}"
      when %r{AlmaLinux.9}, %r{Rocky.9}
        config_mode       = '0600'
        packages          = ['openssh-server']
        service_hasstatus = true
        service_name      = 'sshd'
        fixture           = fixtures("testing/#{os_facts[:os]['name']}-#{os_facts[:os]['release']['major']}_sshd_config")
        config_files      = '/etc/ssh/sshd_config.d/50-redhat.conf'
      when %r{AlmaLinux.*}, %r{CentOS.*}, %r{OracleLinux.*}, %r{RedHat.*}, %r{Rocky.*}, %r{Scientific.*}
        config_mode       = '0600'
        packages          = ['openssh-server']
        service_hasstatus = true
        service_name      = 'sshd'
        fixture           = fixtures("testing/#{os_facts[:os]['name']}-#{os_facts[:os]['release']['major']}_sshd_config")
      when %r{SLED.*}, %r{SLES.*}
        config_mode       = '0600'
        packages          = []
        service_name      = 'sshd'
        service_hasstatus = true
      when %r{Debian.*}, %r{Ubuntu.*}
        config_mode       = '0600'
        packages          = ['openssh-server']
        service_hasstatus = true
        service_name      = 'ssh'
      when %r{Solaris-9.*}
        config_mode       = '0644'
        packages          = 'SUNWsshdr', 'SUNWsshdu'
        packages_source   = '/var/spool/pkg'
        service_hasstatus = false
        service_name      = 'sshd'
      when %r{Solaris-10.*}
        config_mode       = '0644'
        packages          = 'SUNWsshdr', 'SUNWsshdu'
        packages_source   = '/var/spool/pkg'
        service_hasstatus = true
        service_name      = 'ssh'
      when %r{Solaris-11.*}
        config_mode       = '0644'
        packages          = ['service/network/ssh']
        service_hasstatus = true
        service_name      = 'ssh'
      end

      it { is_expected.to compile.with_all_deps }
      it { is_expected.to contain_class('ssh::server') }

      packages.each do |package|
        it do
          is_expected.to contain_package(package).only_with(
            {
              'ensure'    => 'installed',
              'source'    => packages_source,
              'adminfile' => nil,
              'before'    => 'File[sshd_config]',
            },
          )
        end
      end

      content_fixture = File.read(fixture)

      it do
        is_expected.to contain_file('sshd_config').only_with(
          {
            'ensure'  => 'file',
            'path'    => '/etc/ssh/sshd_config',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => config_mode,
            'content' => content_fixture,
          },
        )
      end

      it { is_expected.not_to contain_file('sshd_banner') }

      it do
        is_expected.to contain_service('sshd_service').only_with(
          {
            'ensure'     => 'running',
            'name'       => service_name,
            'enable'     => true,
            'hasrestart' => service_hasstatus,
            'hasstatus'  => true,
            'subscribe'  => 'File[sshd_config]',
          },
        )
      end

      if config_files
        content_config_files = File.read(fixtures("testing/#{os_facts[:os]['name']}-#{os_facts[:os]['release']['major']}_sshd_config.d"))
        it { is_expected.to have_ssh__config_file_server_resource_count(1) }
        it { is_expected.to contain_ssh__config_file_server(config_files) }
        it { is_expected.to contain_file(config_files).with_content(content_config_files) }
      else
        it { is_expected.to have_ssh__config_file_server_resource_count(0) }
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
    let(:facts) { os_facts }

    context "on #{os} with packages set to valid array [array, of, strings]" do
      let(:params) { { packages: ['array', 'of', 'strings'] } }

      it { is_expected.to have_package_resource_count(3) }
      it { is_expected.to contain_package('array') }
      it { is_expected.to contain_package('of') }
      it { is_expected.to contain_package('strings') }
    end

    context "on #{os} with packages_adminfile set to valid /unit/test" do
      let(:params) { { packages_adminfile: '/unit/test' } }

      it { is_expected.to contain_package('openssh-server').with_adminfile('/unit/test') }
    end

    context "on #{os} with packages_source set to valid /unit/test" do
      let(:params) { { packages_source: '/unit/test' } }

      it { is_expected.to contain_package('openssh-server').with_source('/unit/test') }
    end

    context "on #{os} with config_path set to valid value /test/ing" do
      let(:params) { { config_path: '/test/ing' } }

      it { is_expected.to contain_file('sshd_config').with_path('/test/ing') }
    end

    context "on #{os} with config_owner set to valid value unittest" do
      let(:params) { { config_owner: 'unittest' } }

      it { is_expected.to contain_file('sshd_config').with_owner('unittest') }
    end

    context "on #{os} with config_group set to valid value unittest" do
      let(:params) { { config_group: 'unittest' } }

      it { is_expected.to contain_file('sshd_config').with_group('unittest') }
    end

    context "on #{os} with config_mode set to valid value 0242" do
      let(:params) { { config_mode: '0242' } }

      it { is_expected.to contain_file('sshd_config').with_mode('0242') }
    end

    context "on #{os} with banner_path set to valid value /test/ing when banner_content is not unset" do
      let(:params) { { banner_path: '/test/ing', banner_content: 'dummy' } }

      it { is_expected.to contain_file('sshd_banner').with_path('/test/ing') }
    end

    context "on #{os} with banner_content set to valid value unittest" do
      let(:params) { { banner_content: 'unittest' } }

      it { is_expected.to contain_file('sshd_banner').with_content('unittest') }
    end

    context "on #{os} with banner_owner set to valid value unittest when banner_content is not unset" do
      let(:params) { { banner_owner: 'unittest', banner_content: 'dummy' } }

      it { is_expected.to contain_file('sshd_banner').with_owner('unittest') }
    end

    context "on #{os} with banner_group set to valid value unittest when banner_content is not unset" do
      let(:params) { { banner_group: 'unittest', banner_content: 'dummy' } }

      it { is_expected.to contain_file('sshd_banner').with_group('unittest') }
    end

    context "on #{os} with banner_mode set to valid value 0242 when banner_content is not unset" do
      let(:params) { { banner_mode: '0242', banner_content: 'dummy' } }

      it { is_expected.to contain_file('sshd_banner').with_mode('0242') }
    end

    context "on #{os} with manage_service set to valid value false" do
      let(:params) { { manage_service: false } }

      it { is_expected.not_to contain_service('sshd_service') }
    end

    context "on #{os} with service_ensure set to valid value stopped" do
      let(:params) { { service_ensure: 'stopped' } }

      it { is_expected.to contain_service('sshd_service').with_ensure('stopped') }
    end

    context "on #{os} with service_name set to valid value unittest" do
      let(:params) { { service_name: 'unittest' } }

      it { is_expected.to contain_service('sshd_service').with_name('unittest') }
    end

    context "on #{os} with service_enable set to valid value false" do
      let(:params) { { service_enable: false } }

      it { is_expected.to contain_service('sshd_service').with_enable('false') }
    end

    context "on #{os} with service_hasrestart set to valid value false" do
      let(:params) { { service_hasrestart: false } }

      it { is_expected.to contain_service('sshd_service').with_hasrestart('false') }
    end

    context "on #{os} with service_hasstatus set to valid value false" do
      let(:params) { { service_hasstatus: false } }

      it { is_expected.to contain_service('sshd_service').with_hasstatus('false') }
    end

    context "on #{os} with manage_config_files set to valid true" do
      let(:params) { { manage_config_files: true } }

      # config_files is not set
      it { is_expected.to have_ssh__config_file_server_resource_count(0) }
    end

    context "on #{os} with config_files set to a valid hash" do
      let(:params) do
        {
          config_files: {
            '/etc/ssh/sshd_config.d/50-redhat.conf' => {
              'lines'  => {
                'test' => 'test',
              },
            },
          }
        }
      end

      # manage_config_files is not true
      it { is_expected.to have_ssh__config_file_server_resource_count(0) }
      it { is_expected.not_to contain_ssh__config_file_server('/etc/ssh/sshd_config.d/50-redhat.conf') }
    end

    context "on #{os} with manage_config_files set to valid true when config_files set to a valid hash" do
      let(:params) do
        {
          manage_config_files: true,
          config_files: {
            '/etc/ssh/sshd_config.d/42-testing.conf' => {
              'ensure' => 'present',
              'owner'  => 'test',
              'group'  => 'test',
              'mode'   => '0242',
              'lines'  => {
                'GSSAPIAuthentication'     => 'yes',
                'GSSAPICleanupCredentials' => 'no',
              },
            },
            '/etc/ssh/sshd_config.d/50-redhat.conf' => {
              'lines' => {
                'X11Forwarding' => 'yes',
              },
            },
          }
        }
      end

      it { is_expected.to have_ssh__config_file_server_resource_count(2) }

      it do
        is_expected.to contain_ssh__config_file_server('/etc/ssh/sshd_config.d/42-testing.conf').only_with(
          {
            'ensure' => 'present',
            'path'   => '/etc/ssh/sshd_config.d/42-testing.conf',
            'owner'  => 'test',
            'group'  => 'test',
            'mode'   => '0242',
            'lines'  => {
              'GSSAPIAuthentication'     => 'yes',
              'GSSAPICleanupCredentials' => 'no',
            },
            'custom' => [],
          },
        )
      end

      it do
        is_expected.to contain_ssh__config_file_server('/etc/ssh/sshd_config.d/50-redhat.conf').only_with(
          {
            'ensure' => 'present',
            'path'   => '/etc/ssh/sshd_config.d/50-redhat.conf',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0600',
            'lines'  => {
              'X11Forwarding' => 'yes',
            },
            'custom' => [],
          },
        )
      end

      it { is_expected.to contain_file('/etc/ssh/sshd_config.d/42-testing.conf') } # only needed for 100% resource coverage
      it { is_expected.to contain_file('/etc/ssh/sshd_config.d/50-redhat.conf') }  # only needed for 100% resource coverage
    end
  end
end

at_exit { RSpec::Puppet::Coverage.report! }
