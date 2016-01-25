require 'spec_helper'

describe 'Facter::Util::Fact' do

  version_matrix = {
    'OpenSSH_5.1p1, OpenSSL 0.9.8a 11 Oct 2005' => { :ssh_version => 'OpenSSH_5.1p1', :ssh_version_numeric => '5.1' }, # SLES 10.4 i586
    'OpenSSH_5.1p1, OpenSSL 0.9.8j-fips 07 Jan 2009' => { :ssh_version => 'OpenSSH_5.1p1', :ssh_version_numeric => '5.1' }, # SLES 11.2 x86_64
    'OpenSSH_5.3p1, OpenSSL 1.0.1e-fips 11 Feb 2013' => { :ssh_version => 'OpenSSH_5.3p1', :ssh_version_numeric => '5.3' }, # CentOS 6.5 / RedHat 6.7 x86_64
    'OpenSSH_6.2p2, OpenSSL 0.9.8j-fips 07 Jan 2009' => { :ssh_version => 'OpenSSH_6.2p2', :ssh_version_numeric => '6.2' },
    'OpenSSH_6.6.1p1, OpenSSL 0.9.8j-fips 07 Jan 2009' => { :ssh_version => 'OpenSSH_6.6.1p1', :ssh_version_numeric => '6.6.1' }, # SLES 11.4 x86_64
    'Sun_SSH_1.1, SSH protocols 1.5/2.0, OpenSSL 0x0090700f' => { :ssh_version => 'Sun_SSH_1.1', :ssh_version_numeric => '1.1' }, # Solaris 9 SPARC
    'Sun_SSH_1.1.5, SSH protocols 1.5/2.0, OpenSSL 0x0090704f' => { :ssh_version => 'Sun_SSH_1.1.5', :ssh_version_numeric => '1.1.5' }, # Solaris 10 SPARC
    'broken string' => { :ssh_version => 'broken', :ssh_version_numeric => nil },
  }

  describe 'ssh_version' do
    version_matrix.sort.each do |ssh_version_string, result|
      context "with <#{ssh_version_string}>" do
        before do
          Facter.clear
          # Stub exec for older Facter Otherwise this spec will fail with
          # unexpected invocation: Facter::Util::Resolution.exec('uname -s')
          Facter::Util::Resolution.stubs(:exec)
          Facter::Util::Resolution.stubs(:exec).with('ssh -V 2>&1').returns("#{ssh_version_string}")
        end

        context "ssh_version should return <#{result[:ssh_version]}>" do
          it do
            expect(Facter.fact(:ssh_version).value).to eq(result[:ssh_version])
          end
        end

        context "ssh_version_numeric should return <#{result[:ssh_version_numeric]}>" do
          it do
            expect(Facter.fact(:ssh_version_numeric).value).to eq(result[:ssh_version_numeric])
          end
        end
      end
    end
  end
end
