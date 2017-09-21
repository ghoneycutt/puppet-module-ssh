require 'spec_helper'
describe 'ssh::config_entry' do
  mandatory_params = {
    :owner => 'test_owner',
    :group => 'test_group',
    :path  => '/test/path',
    :host  => 'test_host',
  }

  let(:title) { 'example' }
  let(:params) { mandatory_params }

  context 'with no paramater is provided' do
    let(:params) { {} }
    it 'should fail' do
      expect do
        should contain_define(subject)
      end.to raise_error(Puppet::Error, /(Must pass|expects a value for parameter)/) # Puppet4/5
    end
  end

  context 'with mandatory params set' do
    let(:params) { mandatory_params }
    it { should compile.with_all_deps }

    it do
      should contain_concat('/test/path').with({
        'ensure'         => 'present',
        'owner'          => 'test_owner',
        'group'          => 'test_group',
        'mode'           => '0644',
        'ensure_newline' => true,
      })
    end

    it do
      should contain_concat__fragment('/test/path Host test_host').with({
        'target'  => '/test/path',
        'content' => 'Host test_host',
        'order'   => '10',
        'tag'     => 'test_owner_ssh_config',
      })
    end
  end

  context 'with owner set to valid string <other_owner>' do
    let(:params) { mandatory_params.merge({ :owner => 'other_owner' }) }
    it { should contain_concat('/test/path').with_owner('other_owner') }
    it { should contain_concat__fragment('/test/path Host test_host').with_tag('other_owner_ssh_config') }
  end

  context 'with group set to valid string <other_group>' do
    let(:params) { mandatory_params.merge({ :group => 'other_group' }) }
    it { should contain_concat('/test/path').with_group('other_group') }
  end

  context 'with path set to valid string </other/path>' do
    let(:params) { mandatory_params.merge({ :path => '/other/path' }) }
    it { should contain_concat('/other/path') }
    it { should contain_concat__fragment('/other/path Host test_host') }
  end

  context 'with host set to valid string <other_host>' do
    let(:params) { mandatory_params.merge({ :host => 'other_host' }) }
    it { should contain_concat__fragment('/test/path Host other_host').with_content('Host other_host') }
  end

  context 'with order set to valid string <242>' do
    let(:params) { mandatory_params.merge({ :order => '242' }) }
    it { should contain_concat__fragment('/test/path Host test_host').with_order('242') }
  end

# /!\ no functionality for $ensure implemented yet
#  context 'with ensure set to valid string <absent>' do
#    let(:params) { mandatory_params.merge({ :ensure => 'absent' }) }
#    it { should contain_concat('/test/path').with_ensure('absent') }
#  end

  context 'with lines set to valid array [ <ForwardX11 no>, <StrictHostKeyChecking no> ]' do
    let(:params) { mandatory_params.merge({ :lines => ['ForwardX11 no', 'StrictHostKeyChecking no'] }) }
    it { should contain_concat__fragment('/test/path Host test_host').with_content("Host test_host\nForwardX11 no\nStrictHostKeyChecking no") }
  end
end
