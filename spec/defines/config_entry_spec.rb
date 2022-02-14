require 'spec_helper'
describe 'ssh::config_entry' do
  let(:title) { 'test-title' }

  mandatory_params = {
    owner: 'test_owner',
    group: 'test_group',
    path:  '/test/path',
    host:  'test_host',
  }

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

    context "on #{os} with default values for parameters" do
      it 'fail' do
        expect { is_expected.to contain_class(:subject) }.to raise_error(Puppet::Error, %r{expects a value for parameter})
      end
    end

    context "on #{os} with mandatory parameters set to valid values" do
      let(:params) { mandatory_params }

      it { is_expected.to compile.with_all_deps }

      it do
        is_expected.to contain_concat('/test/path').with(
          {
            'ensure'         => 'present',
            'owner'          => 'test_owner',
            'group'          => 'test_group',
            'mode'           => '0644',
            'ensure_newline' => true,
          },
        )
      end

      it { is_expected.to have_concat__fragment_resource_count(1) }

      it do
        is_expected.to contain_concat__fragment('/test/path Host test_host').with(
          {
            'target'  => '/test/path',
            'content' => 'Host test_host',
            'order'   => '10',
            'tag'     => 'test_owner_ssh_config',
          },
        )
      end
    end

    context "on #{os} with owner set to valid value unittest when mandatory parameters are set" do
      let(:params) { mandatory_params.merge({ owner: 'unittest' }) }

      it { is_expected.to contain_concat('/test/path').with_owner('unittest') }
      it { is_expected.to contain_concat__fragment('/test/path Host test_host').with_tag('unittest_ssh_config') }
    end

    context "on #{os} with group set to valid value unittest when mandatory parameters are set" do
      let(:params) { mandatory_params.merge({ group: 'unittest' }) }

      it { is_expected.to contain_concat('/test/path').with_group('unittest') }
    end

    context "on #{os} with path set to valid value /unit/test when mandatory parameters are set" do
      let(:params) { mandatory_params.merge({ path: '/unit/test' }) }

      it { is_expected.to contain_concat('/unit/test') }
      it { is_expected.to contain_concat__fragment('/unit/test Host test_host') }
    end

    context "on #{os} with host set to valid value unittest when mandatory parameters are set" do
      let(:params) { mandatory_params.merge({ host: 'unittest' }) }

      it { is_expected.to contain_concat__fragment('/test/path Host unittest').with_content('Host unittest') }
    end

    context "on #{os} with order set to valid value 242 when mandatory parameters are set" do
      let(:params) { mandatory_params.merge({ order: 242 }) }

      it { is_expected.to contain_concat__fragment('/test/path Host test_host').with_order(242) }
    end

    # /!\ no functionality for $ensure implemented yet
    #  context 'with ensure set to valid string <absent>' do
    #    let(:params) { mandatory_params.merge({ ensure: 'absent' }) }
    #    it { is_expected.to contain_concat('/test/path').with_ensure('absent') }
    #  end

    context "on #{os} with lines set to valid value [ForwardX11 no, StrictHostKeyChecking no] when mandatory parameters are set" do
      let(:params) { mandatory_params.merge({ lines: ['ForwardX11 no', 'StrictHostKeyChecking no'] }) }

      it { is_expected.to contain_concat__fragment('/test/path Host test_host').with_content("Host test_host\n  ForwardX11 no\n  StrictHostKeyChecking no") }
    end
  end
end
