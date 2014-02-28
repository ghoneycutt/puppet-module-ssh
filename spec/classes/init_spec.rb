require 'spec_helper'
describe 'ssh' do

  context 'with default params on osfamily RedHat' do
    let(:facts) do
      { :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end

    it { should compile.with_all_deps }

    it { should contain_class('ssh')}

    it { should_not contain_class('common')}

    ['openssh-server','openssh-clients'].each do |pkg|
      it {
        should contain_package(pkg).with({
          'ensure' => 'installed',
        })
      }
    end

    it {
      should contain_file('ssh_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => ['Package[openssh-server]', 'Package[openssh-clients]'],
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }
    it { should contain_file('ssh_config').with_content(/^\s*HashKnownHosts no$/) }
    it { should contain_file('ssh_config').with_content(/^\s*SendEnv L.*$/) }
    it { should contain_file('ssh_config').with_content(/^\s*ForwardX11Trusted yes$/) }

    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardAgent$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ServerAliveInterval$/) }

    it {
      should contain_file('sshd_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0600',
        'require' => ['Package[openssh-server]', 'Package[openssh-clients]'],
      })
    }

    it { should contain_file('sshd_config').with_content(/^Port 22$/) }
    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 120$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^PrintMotd yes$/) }
    it { should contain_file('sshd_config').with_content(/^UseDNS yes$/) }
    it { should contain_file('sshd_config').with_content(/^Banner none$/) }
    it { should contain_file('sshd_config').with_content(/^XAuthLocation \/usr\/bin\/xauth$/) }
    it { should contain_file('sshd_config').with_content(/^Subsystem sftp \/usr\/libexec\/openssh\/sftp-server$/) }
    it { should contain_file('sshd_config').with_content(/^PasswordAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^AllowTcpForwarding yes$/) }
    it { should contain_file('sshd_config').with_content(/^X11Forwarding yes$/) }
    it { should contain_file('sshd_config').with_content(/^UsePAM yes$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveInterval 0$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange no$/) }
    it { should contain_file('sshd_config').with_content(/^AcceptEnv L.*$/) }

    it {
      should contain_service('sshd_service').with({
        'ensure'     => 'running',
        'name'       => 'sshd',
        'enable'     => 'true',
        'hasrestart' => 'true',
        'hasstatus'  => 'true',
        'subscribe'  => 'File[sshd_config]',
      })
    }

    it {
      should contain_resources('sshkey').with({
        'purge' => 'true',
      })
    }
  end

  context 'with default params on osfamily Solaris kernelrelease 5.8' do
    let :facts do
      {
        :fqdn          => 'monkey.example.com',
        :osfamily      => 'Solaris',
        :kernelrelease => '5.8',
        :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end

    it 'should fail' do
      expect {
        should include_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh module supports Solaris kernel release 5.9, 5.10 and 5.11./)
    end
  end

  context 'with default params on osfamily Solaris kernelrelease 5.11' do
    let :facts do
      {
        :fqdn          => 'monkey.example.com',
        :osfamily      => 'Solaris',
        :kernelrelease => '5.11',
        :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end

    it { should include_class('ssh')}

    it { should_not include_class('common')}


    ['SUNWsshcu','SUNWsshdr','SUNWsshdu','SUNWsshr','SUNWsshu'].each do |pkg|
      it {
        should contain_package(pkg).with({
          'ensure'    => 'installed',
          'source'    => '/var/spool/pkg',
          'adminfile' => nil,
        })
      }
    end

    it {
      should contain_file('ssh_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => [ 'Package[SUNWsshcu]', 'Package[SUNWsshdr]', 'Package[SUNWsshdu]', 'Package[SUNWsshr]', 'Package[SUNWsshu]' ],
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*HashKnownHosts no$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11Trusted/) }

    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardAgent$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ServerAliveInterval$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*SendEnv L.*$/) }

    it {
      should contain_file('sshd_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => [ 'Package[SUNWsshcu]', 'Package[SUNWsshdr]', 'Package[SUNWsshdu]', 'Package[SUNWsshr]', 'Package[SUNWsshu]' ],
      })
    }

    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 120$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^PrintMotd yes$/) }
    it { should contain_file('sshd_config').with_content(/^Banner none$/) }
    it { should contain_file('sshd_config').with_content(/^XAuthLocation \/usr\/openwin\/bin\/xauth$/) }
    it { should contain_file('sshd_config').with_content(/^Subsystem sftp \/usr\/lib\/ssh\/sftp-server$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should contain_file('sshd_config').with_content(/^PAMAuthenticationViaKBDInt yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIKeyExchange yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*AcceptEnv L.*$/) }

    it {
      should contain_service('sshd_service').with({
        'ensure'     => 'running',
        'name'       => 'ssh',
        'enable'     => 'true',
        'hasrestart' => 'true',
        'hasstatus'  => 'true',
        'subscribe'  => 'File[sshd_config]',
      })
    }

    it {
      should contain_resources('sshkey').with({
        'purge' => 'true',
      })
    }
  end

  context 'with default params on osfamily Solaris kernelrelease 5.10' do
    let :facts do
      {
        :fqdn          => 'monkey.example.com',
        :osfamily      => 'Solaris',
        :kernelrelease => '5.10',
        :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end

    it { should include_class('ssh')}

    it { should_not include_class('common')}

    ['SUNWsshcu','SUNWsshdr','SUNWsshdu','SUNWsshr','SUNWsshu'].each do |pkg|
      it {
        should contain_package(pkg).with({
          'ensure'    => 'installed',
          'source'    => '/var/spool/pkg',
          'adminfile' => nil,
        })
      }
    end

    it {
      should contain_file('ssh_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => [ 'Package[SUNWsshcu]', 'Package[SUNWsshdr]', 'Package[SUNWsshdu]', 'Package[SUNWsshr]', 'Package[SUNWsshu]' ],
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*HashKnownHosts no$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11Trusted/) }

    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardAgent$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ServerAliveInterval$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*SendEnv L.*$/) }

    it {
      should contain_file('sshd_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => [ 'Package[SUNWsshcu]', 'Package[SUNWsshdr]', 'Package[SUNWsshdu]', 'Package[SUNWsshr]', 'Package[SUNWsshu]' ],
      })
    }

    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 120$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^PrintMotd yes$/) }
    it { should contain_file('sshd_config').with_content(/^Banner none$/) }
    it { should contain_file('sshd_config').with_content(/^XAuthLocation \/usr\/openwin\/bin\/xauth$/) }
    it { should contain_file('sshd_config').with_content(/^Subsystem sftp \/usr\/lib\/ssh\/sftp-server$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should contain_file('sshd_config').with_content(/^PAMAuthenticationViaKBDInt yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIKeyExchange yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*AcceptEnv L.*$/) }

    it {
      should contain_service('sshd_service').with({
        'ensure'     => 'running',
        'name'       => 'ssh',
        'enable'     => 'true',
        'hasrestart' => 'true',
        'hasstatus'  => 'true',
        'subscribe'  => 'File[sshd_config]',
      })
    }

    it {
      should contain_resources('sshkey').with({
        'purge' => 'true',
      })
    }
  end

  context 'with default params on osfamily Solaris kernelrelease 5.9' do
    let :facts do
      { :fqdn          => 'monkey.example.com',
        :osfamily      => 'Solaris',
        :kernelrelease => '5.9',
        :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end

    it { should include_class('ssh')}

    it { should_not include_class('common')}

    ['SUNWsshcu','SUNWsshdr','SUNWsshdu','SUNWsshr','SUNWsshu'].each do |pkg|
      it {
        should contain_package(pkg).with({
          'ensure'    => 'installed',
          'source'    => '/var/spool/pkg',
          'adminfile' => nil,
        })
      }
    end

    it {
      should contain_file('ssh_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => [ 'Package[SUNWsshcu]', 'Package[SUNWsshdr]', 'Package[SUNWsshdu]', 'Package[SUNWsshr]', 'Package[SUNWsshu]' ],
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*HashKnownHosts no$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11Trusted/) }

    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardAgent$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ServerAliveInterval$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*SendEnv L.*$/) }

    it {
      should contain_file('sshd_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => [ 'Package[SUNWsshcu]', 'Package[SUNWsshdr]', 'Package[SUNWsshdu]', 'Package[SUNWsshr]', 'Package[SUNWsshu]' ],
      })
    }

    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 120$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^PrintMotd yes$/) }
    it { should contain_file('sshd_config').with_content(/^Banner none$/) }
    it { should contain_file('sshd_config').with_content(/^XAuthLocation \/usr\/openwin\/bin\/xauth$/) }
    it { should contain_file('sshd_config').with_content(/^Subsystem sftp \/usr\/lib\/ssh\/sftp-server$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should contain_file('sshd_config').with_content(/^PAMAuthenticationViaKBDInt yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIKeyExchange yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*AcceptEnv L.*$/) }

    it {
      should contain_service('sshd_service').with({
        'ensure'     => 'running',
        'name'       => 'sshd',
        'enable'     => 'true',
        'hasrestart' => 'true',
        'hasstatus'  => 'false',
        'subscribe'  => 'File[sshd_config]',
      })
    }

    it {
      should contain_resources('sshkey').with({
        'purge' => 'true',
      })
    }
  end

  context 'with default params on osfamily Debian' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'Debian',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    it { should compile.with_all_deps }

    it { should contain_class('ssh')}

    it { should_not contain_class('common')}

    ['openssh-server','openssh-client'].each do |pkg|
      it {
        should contain_package(pkg).with({
          'ensure' => 'installed',
        })
      }
    end

    it {
      should contain_file('ssh_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => ['Package[openssh-server]', 'Package[openssh-client]'],
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }
    it { should contain_file('ssh_config').with_content(/^\s*HashKnownHosts no$/) }
    it { should contain_file('ssh_config').with_content(/^\s*SendEnv L.*$/) }
    it { should contain_file('ssh_config').with_content(/^\s*ForwardX11Trusted yes$/) }

    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardAgent$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ServerAliveInterval$/) }

    it {
      should contain_file('sshd_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0600',
        'require' => ['Package[openssh-server]', 'Package[openssh-client]'],
      })
    }

    it { should contain_file('sshd_config').with_content(/^Port 22$/) }
    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 120$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^PrintMotd yes$/) }
    it { should contain_file('sshd_config').with_content(/^UseDNS yes$/) }
    it { should contain_file('sshd_config').with_content(/^Banner none$/) }
    it { should contain_file('sshd_config').with_content(/^XAuthLocation \/usr\/bin\/xauth$/) }
    it { should contain_file('sshd_config').with_content(/^Subsystem sftp \/usr\/lib\/openssh\/sftp-server$/) }
    it { should contain_file('sshd_config').with_content(/^PasswordAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^AllowTcpForwarding yes$/) }
    it { should contain_file('sshd_config').with_content(/^X11Forwarding yes$/) }
    it { should contain_file('sshd_config').with_content(/^UsePAM yes$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveInterval 0$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange yes$/) }
    it { should contain_file('sshd_config').with_content(/^AcceptEnv L.*$/) }

    it {
      should contain_service('sshd_service').with({
        'ensure'     => 'running',
        'name'       => 'ssh',
        'enable'     => 'true',
        'hasrestart' => 'true',
        'hasstatus'  => 'true',
        'subscribe'  => 'File[sshd_config]',
      })
    }

    it {
      should contain_resources('sshkey').with({
        'purge' => 'true',
      })
    }
  end

  context 'with default params on osfamily Suse architecture x86_64' do
    let :facts do
      {
        :fqdn         => 'monkey.example.com',
        :osfamily     => 'Suse',
        :architecture => 'x86_64',
        :sshrsakey    => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end

    it { should compile.with_all_deps }

    it { should contain_class('ssh')}

    it { should_not contain_class('common')}

    it {
      should contain_package('openssh').with({
        'ensure' => 'installed',
      })
    }

    it {
      should contain_file('ssh_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => 'Package[openssh]',
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }
    it { should contain_file('ssh_config').with_content(/^\s*HashKnownHosts no$/) }
    it { should contain_file('ssh_config').with_content(/^\s*SendEnv L.*$/) }
    it { should contain_file('ssh_config').with_content(/^\s*ForwardX11Trusted yes$/) }

    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardAgent$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ServerAliveInterval$/) }

    it {
      should contain_file('sshd_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0600',
        'require' => 'Package[openssh]',
      })
    }

    it { should contain_file('sshd_config').with_content(/^Port 22$/) }
    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 120$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^PrintMotd yes$/) }
    it { should contain_file('sshd_config').with_content(/^UseDNS yes$/) }
    it { should contain_file('sshd_config').with_content(/^Banner none$/) }
    it { should contain_file('sshd_config').with_content(/^XAuthLocation \/usr\/bin\/xauth$/) }
    it { should contain_file('sshd_config').with_content(/^Subsystem sftp \/usr\/lib64\/ssh\/sftp-server$/) }
    it { should contain_file('sshd_config').with_content(/^PasswordAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^AllowTcpForwarding yes$/) }
    it { should contain_file('sshd_config').with_content(/^X11Forwarding yes$/) }
    it { should contain_file('sshd_config').with_content(/^UsePAM yes$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveInterval 0$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange yes$/) }
    it { should contain_file('sshd_config').with_content(/^AcceptEnv L.*$/) }

    it {
      should contain_service('sshd_service').with({
        'ensure'     => 'running',
        'name'       => 'sshd',
        'enable'     => 'true',
        'hasrestart' => 'true',
        'hasstatus'  => 'true',
        'subscribe'  => 'File[sshd_config]',
      })
    }

    it {
      should contain_resources('sshkey').with({
        'purge' => 'true',
      })
    }
  end

  context 'with default params on osfamily Suse architecture i386' do
    let :facts do
      {
        :fqdn         => 'monkey.example.com',
        :osfamily     => 'Suse',
        :architecture => 'i386',
        :sshrsakey    => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end

    it { should compile.with_all_deps }

    it { should contain_class('ssh')}

    it { should_not contain_class('common')}

    it {
      should contain_package('openssh').with({
        'ensure' => 'installed',
      })
    }

    it {
      should contain_file('ssh_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => 'Package[openssh]',
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }
    it { should contain_file('ssh_config').with_content(/^\s*HashKnownHosts no$/) }
    it { should contain_file('ssh_config').with_content(/^\s*SendEnv L.*$/) }
    it { should contain_file('ssh_config').with_content(/^\s*ForwardX11Trusted yes$/) }

    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardAgent$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ServerAliveInterval$/) }

    it {
      should contain_file('sshd_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0600',
        'require' => 'Package[openssh]',
      })
    }

    it { should contain_file('sshd_config').with_content(/^Port 22$/) }
    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 120$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^PrintMotd yes$/) }
    it { should contain_file('sshd_config').with_content(/^UseDNS yes$/) }
    it { should contain_file('sshd_config').with_content(/^Banner none$/) }
    it { should contain_file('sshd_config').with_content(/^XAuthLocation \/usr\/bin\/xauth$/) }
    it { should contain_file('sshd_config').with_content(/^Subsystem sftp \/usr\/lib\/ssh\/sftp-server$/) }
    it { should contain_file('sshd_config').with_content(/^PasswordAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^AllowTcpForwarding yes$/) }
    it { should contain_file('sshd_config').with_content(/^X11Forwarding yes$/) }
    it { should contain_file('sshd_config').with_content(/^UsePAM yes$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveInterval 0$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange yes$/) }
    it { should contain_file('sshd_config').with_content(/^AcceptEnv L.*$/) }

    it {
      should contain_service('sshd_service').with({
        'ensure'     => 'running',
        'name'       => 'sshd',
        'enable'     => 'true',
        'hasrestart' => 'true',
        'hasstatus'  => 'true',
        'subscribe'  => 'File[sshd_config]',
      })
    }

    it {
      should contain_resources('sshkey').with({
        'purge' => 'true',
      })
    }
  end

  context 'with default params on invalid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'C64',
        :root_home => '/root',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :manage_root_ssh_config => 'invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh supports osfamilies RedHat, Suse, Debian and Solaris. Detected osfamily is <C64>\./)
    end
  end

  context 'with optional params used in ssh_config set on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      {
        :ssh_config_hash_known_hosts      => 'yes',
        :ssh_config_forward_agent         => 'yes',
        :ssh_config_forward_x11           => 'yes',
        :ssh_config_server_alive_interval => '300',
        :ssh_config_sendenv_xmodifiers    => true,
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
        'require' => ['Package[openssh-server]', 'Package[openssh-clients]'],
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }
    it { should contain_file('ssh_config').with_content(/^   HashKnownHosts yes$/) }
    it { should contain_file('ssh_config').with_content(/^\s*SendEnv L.*$/) }
    it { should contain_file('ssh_config').with_content(/^  ForwardAgent yes$/) }
    it { should contain_file('ssh_config').with_content(/^  ForwardX11 yes$/) }
    it { should contain_file('ssh_config').with_content(/^  ServerAliveInterval 300$/) }
    it { should contain_file('ssh_config').with_content(/^  SendEnv XMODIFIERS$/) }
  end

  context 'with params used in sshd_config set on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      {
        :sshd_config_port                => '22222',
        :sshd_config_syslog_facility     => 'DAEMON',
        :sshd_config_login_grace_time    => '60',
        :permit_root_login               => 'no',
        :sshd_config_challenge_resp_auth => 'no',
        :sshd_config_print_motd          => 'no',
        :sshd_config_use_dns             => 'no',
        :sshd_config_banner              => '/etc/sshd_banner',
        :sshd_banner_content             => 'textinbanner',
        :sshd_config_xauth_location      => '/opt/ssh/bin/xauth',
        :sshd_config_subsystem_sftp      => '/opt/ssh/bin/sftp',
        :sshd_password_authentication    => 'no',
        :sshd_allow_tcp_forwarding       => 'no',
        :sshd_x11_forwarding             => 'no',
        :sshd_use_pam                    => 'no',
        :sshd_client_alive_interval      => '242',
      }
    end

    it { should compile.with_all_deps }

    it {
      should contain_file('sshd_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0600',
        'require' => ['Package[openssh-server]', 'Package[openssh-clients]'],
      })
    }

    it { should contain_file('sshd_config').with_content(/^Port 22222$/) }
    it { should contain_file('sshd_config').with_content(/^SyslogFacility DAEMON$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 60$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin no$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication no$/) }
    it { should contain_file('sshd_config').with_content(/^PrintMotd no$/) }
    it { should contain_file('sshd_config').with_content(/^UseDNS no$/) }
    it { should contain_file('sshd_config').with_content(/^Banner \/etc\/sshd_banner$/) }
    it { should contain_file('sshd_config').with_content(/^XAuthLocation \/opt\/ssh\/bin\/xauth$/) }
    it { should contain_file('sshd_config').with_content(/^Subsystem sftp \/opt\/ssh\/bin\/sftp$/) }
    it { should contain_file('sshd_config').with_content(/^PasswordAuthentication no$/) }
    it { should contain_file('sshd_config').with_content(/^AllowTcpForwarding no$/) }
    it { should contain_file('sshd_config').with_content(/^X11Forwarding no$/) }
    it { should contain_file('sshd_config').with_content(/^UsePAM no$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveInterval 242$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange yes$/) }
    it { should contain_file('sshd_config').with_content(/^AcceptEnv L.*$/) }

    it {
      should contain_file('sshd_banner').with({
        'ensure'  => 'file',
        'path'    => '/etc/sshd_banner',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'content' => 'textinbanner',
        'require' => ['Package[openssh-server]', 'Package[openssh-clients]'],
      })
    }
  end

  context 'with manage_root_ssh_config set to \'true\' on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :root_home => '/root',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :manage_root_ssh_config => 'true' }
    end

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

  context 'with ssh_config_hash_known_hosts set to invalid value on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :ssh_config_hash_known_hosts => 'invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::ssh_config_hash_known_hosts may be either \'yes\' or \'no\' and is set to <invalid>./)
    end
  end

  context 'with sshd_config_port not being a valid number' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :sshd_config_port => '22invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::sshd_config_port must be a valid number and is set to <22invalid>\./)
    end
  end

  context 'with manage_root_ssh_config set to invalid value on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :root_home => '/root',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :manage_root_ssh_config => 'invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::manage_root_ssh_config is <invalid> and must be \'true\' or \'false\'\./)
    end
  end

  context 'with sshd_password_authentication set to invalid value on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :sshd_password_authentication => 'invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::sshd_password_authentication may be either \'yes\' or \'no\' and is set to <invalid>\./)
    end
  end

  context 'with sshd_allow_tcp_forwarding set to invalid value on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :sshd_allow_tcp_forwarding => 'invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::sshd_allow_tcp_forwarding may be either \'yes\' or \'no\' and is set to <invalid>\./)
    end
  end

  context 'with sshd_x11_forwarding set to invalid value on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :sshd_x11_forwarding => 'invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::sshd_x11_forwarding may be either \'yes\' or \'no\' and is set to <invalid>\./)
    end
  end

  context 'with sshd_use_pam set to invalid value on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :sshd_use_pam => 'invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::sshd_use_pam may be either \'yes\' or \'no\' and is set to <invalid>\./)
    end
  end

  context 'with sshd_client_alive_interval set to invalid value on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :sshd_client_alive_interval => 'invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::sshd_client_alive_interval must be an integer and is set to <invalid>\./)
    end
  end

  context 'with sshd_config_banner set to invalid value on valid osfamily' do
    let(:params) { { :sshd_config_banner => 'invalid/path' } }
    let(:facts) do
      { :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/is not an absolute path/)
    end
  end

  context 'with sshd_banner_content set and with default value on sshd_config_banner on valid osfamily' do
    let(:params) { { :sshd_banner_content => 'textinbanner' } }
    let :facts do
      { :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::sshd_config_banner must be set to be able to use sshd_banner_content\./)
    end
  end


  context 'with ssh_config_sendenv_xmodifiers set to invalid type, array' do
    let(:params) { { :ssh_config_sendenv_xmodifiers => ['invalid','type'] } }
    let :facts do
      { :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::ssh_config_sendenv_xmodifiers type must be true or false\./)
    end
  end

  context 'with ssh_config_sendenv_xmodifiers set to stringified \'true\'' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      {
        :ssh_config_sendenv_xmodifiers => 'true',
      }
    end

    it { should compile.with_all_deps }

    it { should contain_file('ssh_config').with_content(/^  SendEnv XMODIFIERS$/) }
  end

  context 'with manage_firewall set to true on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :manage_firewall => true }
    end

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

  context 'with keys defined on valid osfamily' do
    let :facts do
      { :osfamily  => 'RedHat' }
    end
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
    let(:facts) { { :osfamily  => 'RedHat' } }

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error)
    end
  end

  describe 'with hiera_merge parameter specified' do
    context 'as a non-boolean or non-string' do
      let(:params) { { :hiera_merge => ['not_a_boolean','or_a_string'] } }
      let(:facts) do
        { :osfamily          => 'RedHat',
          :lsbmajdistrelease => '6',
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error) }
      end
    end

    context 'as an invalid string' do
      let(:params) { { :hiera_merge => 'invalid_string' } }
      let(:facts) do
        { :osfamily          => 'RedHat',
          :lsbmajdistrelease => '6',
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error,/^ssh::hiera_merge may be either 'true' or 'false' and is set to <invalid_string>./) }
      end
    end

    ['true',true].each do |value|
      context "as #{value}" do
        let(:params) { { :hiera_merge => value } }
        let(:facts) do
          { :osfamily          => 'RedHat',
            :lsbmajdistrelease => '6',
          }
        end

        it { should compile.with_all_deps }

        it { should contain_class('ssh') }
      end
    end

    ['false',false].each do |value|
      context "as #{value}" do
        let(:params) { { :hiera_merge => value } }
        let(:facts) do
          { :osfamily          => 'RedHat',
            :lsbmajdistrelease => '6',
          }
        end

        it { should compile.with_all_deps }

        it { should contain_class('ssh') }
      end
    end
  end

  describe 'with ssh_package_adminfile parameter specified' do
    context 'as a valid path' do
      let(:params) { { :ssh_package_adminfile => '/var/tmp/admin' } }
      let :facts do
        { :fqdn          => 'monkey.example.com',
          :osfamily      => 'Solaris',
          :kernelrelease => '5.11',
          :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      ['SUNWsshcu','SUNWsshdr','SUNWsshdu','SUNWsshr','SUNWsshu'].each do |pkg|
        it {
          should contain_package(pkg).with({
            'ensure'    => 'installed',
            'source'    => '/var/spool/pkg',
            'adminfile' => '/var/tmp/admin',
          })
        }
      end
    end

    context 'as an invalid path' do
      let(:params) { { :ssh_package_adminfile => 'invalid/path' } }
      let :facts do
        { :fqdn          => 'monkey.example.com',
          :osfamily      => 'Solaris',
          :kernelrelease => '5.11',
          :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error,/^is not an absolute path/) }
      end
    end
  end

  describe 'with sshd_config_xauth_location parameter specified' do
    context 'as a valid path' do
      let(:params) { { :sshd_config_xauth_location => '/opt/ssh/bin/xauth' } }
      let(:facts) do
        { :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it { should contain_file('sshd_config').with_content(/^XAuthLocation \/opt\/ssh\/bin\/xauth$/) }
    end

    context 'as an invalid path' do
      let(:params) { { :sshd_config_xauth_location => 'invalid/path' } }
      let(:facts) do
        { :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error,/^is not an absolute path/) }
      end
    end

    context 'as an invalid type' do
      let(:params) { { :sshd_config_xauth_location => true } }
      let(:facts) do
        { :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error) }
      end
    end
  end

  describe 'with ssh_package_source parameter specified' do
    context 'as a valid path' do
      let(:params) { { :ssh_package_source => '/mnt/packages' } }
      let(:facts) do
        { :fqdn          => 'monkey.example.com',
          :osfamily      => 'Solaris',
          :kernelrelease => '5.11',
          :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      ['SUNWsshcu','SUNWsshdr','SUNWsshdu','SUNWsshr','SUNWsshu'].each do |pkg|
        it {
          should contain_package(pkg).with({
            'ensure'    => 'installed',
            'source'    => '/mnt/packages',
            'adminfile' => nil,
          })
        }
      end
    end

    context 'as an invalid path' do
      let(:params) { { :ssh_package_source => 'invalid/path' } }
      let(:facts) do
        { :fqdn          => 'monkey.example.com',
          :osfamily      => 'Solaris',
          :kernelrelease => '5.11',
          :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error,/^is not an absolute path/) }
      end
    end

    context 'as an invalid type' do
      let(:params) { { :ssh_package_source => true } }
      let(:facts) do
        { :fqdn          => 'monkey.example.com',
          :osfamily      => 'Solaris',
          :kernelrelease => '5.11',
          :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error) }
      end
    end
  end

  describe 'with parameter ssh_config_forward_x11_trusted' do
    ['yes','no'].each do |value|
      context "specified as #{value}" do
        let(:params) { { :ssh_config_forward_x11_trusted => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it { should contain_file('ssh_config').with_content(/^\s*ForwardX11Trusted #{value}$/) }
      end
    end

    context 'not specified' do
      let(:facts) do
        { :fqdn          => 'monkey.example.com',
          :osfamily      => 'Solaris',
          :kernelrelease => '5.11',
          :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11Trusted/) }
    end

    ['YES',true].each do |value|
      context "specified an invalid value #{value}" do
        let(:params) { { :ssh_config_forward_x11_trusted => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it 'should fail' do
          expect { should raise_error(Puppet::Error,/^ssh::ssh_config_forward_x11_trusted may be either 'yes' or 'no' and is set to <#{value}>./) }
        end
      end
    end
  end

  describe 'with parameter sshd_gssapiauthentication' do
    ['yes','no'].each do |value|
      context "specified as #{value}" do
        let(:params) { { :sshd_gssapiauthentication => value } }
        let(:facts) do
          { :fqdn          => 'monkey.example.com',
            :osfamily      => 'Solaris',
            :kernelrelease => '5.11',
            :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication #{value}$/) }
      end
    end

    ['YES',true].each do |value|
      context "specified an invalid value #{value}" do
        let(:params) { { :sshd_gssapiauthentication => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it 'should fail' do
          expect { should raise_error(Puppet::Error,/^ssh::sshd_gssapiauthentication may be either 'yes' or 'no' and is set to <#{value}>./) }
        end
      end
    end
  end

  describe 'with parameter sshd_gssapikeyexchange' do
    ['yes','no'].each do |value|
      context "specified as #{value}" do
        let(:params) { { :sshd_gssapikeyexchange => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it { should contain_file('sshd_config').with_content(/^GSSAPIKeyExchange #{value}$/) }
      end
    end

    context 'not specified' do
      let(:facts) do
        { :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange/) }
    end

    ['YES',true].each do |value|
      context "specified an invalid value #{value}" do
        let(:params) { { :sshd_gssapikeyexchange => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it 'should fail' do
          expect { should raise_error(Puppet::Error,/^ssh::sshd_gssapikeyexchange may be either 'yes' or 'no' and is set to <#{value}>./) }
        end
      end
    end
  end

  describe 'with parameter sshd_pamauthenticationviakbdint' do
    ['yes','no'].each do |value|
      context "specified as #{value}" do
        let(:params) { { :sshd_pamauthenticationviakbdint => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it { should contain_file('sshd_config').with_content(/^PAMAuthenticationViaKBDInt #{value}$/) }
      end
    end

    context 'not specified' do
      let(:facts) do
        { :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt/) }
    end

    ['YES',true].each do |value|
      context "specified an invalid value #{value}" do
        let(:params) { { :sshd_pamauthenticationviakbdint => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it 'should fail' do
          expect { should raise_error(Puppet::Error,/^ssh::sshd_pamauthenticationviakbdint may be either 'yes' or 'no' and is set to <#{value}>./) }
        end
      end
    end
  end

  describe 'with parameter sshd_gssapicleanupcredentials' do
    ['yes','no'].each do |value|
      context "specified as #{value}" do
        let(:params) { { :sshd_gssapicleanupcredentials => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials #{value}$/) }
      end
    end

    context 'not specified' do
      let(:facts) do
        { :fqdn          => 'monkey.example.com',
          :osfamily      => 'Solaris',
          :kernelrelease => '5.11',
          :sshrsakey     => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPICleanupCredentials/) }
    end

    ['YES',true].each do |value|
      context "specified an invalid value #{value}" do
        let(:params) { { :sshd_gssapicleanupcredentials => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it 'should fail' do
          expect { should raise_error(Puppet::Error,/^ssh::sshd_gssapicleanupcredentials may be either 'yes' or 'no' and is set to <#{value}>./) }
        end
      end
    end
  end

  describe 'with parameter ssh_sendenv specified' do
    ['true',true].each do |value|
      context "as #{value}" do
        let(:params) { { :ssh_sendenv => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it { should contain_file('ssh_config').with_content(/^\s*SendEnv/) }
      end
    end

    ['false',false].each do |value|
      context "as #{value}" do
        let(:params) { { :ssh_sendenv => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it { should_not contain_file('ssh_config').with_content(/^\s*SendEnv/) }
      end
    end

    context 'as an invalid string' do
      let(:params) { { :ssh_sendenv => 'invalid' } }
      let(:facts) do
        { :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error,/^ssh::ssh_sendenv may be either 'true' or 'false' and is set to <invalid>./) }
      end
    end

    context 'as an invalid type' do
      let(:params) { { :ssh_sendenv => ['invalid','type'] } }
      let(:facts) do
        { :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error,/^ssh::ssh_sendenv type must be true or false./) }
      end
    end
  end

  describe 'with parameter sshd_acceptenv specified' do
    ['true',true].each do |value|
      context "as #{value}" do
        let(:params) { { :sshd_acceptenv => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it { should contain_file('sshd_config').with_content(/^\s*AcceptEnv/) }
      end
    end

    ['false',false].each do |value|
      context "as #{value}" do
        let(:params) { { :sshd_acceptenv => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it { should_not contain_file('sshd_config').with_content(/^\s*AcceptEnv/) }
      end
    end

    context 'as an invalid string' do
      let(:params) { { :sshd_acceptenv => 'invalid' } }
      let(:facts) do
        { :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error,/^ssh::sshd_acceptenv may be either 'true' or 'false' and is set to <invalid>./) }
      end
    end

    context 'as an invalid type' do
      let(:params) { { :sshd_acceptenv => ['invalid','type'] } }
      let(:facts) do
        { :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error,/^ssh::sshd_acceptenv type must be true or false./) }
      end
    end
  end

  describe 'with parameter service_hasstatus' do
    ['true',true,'false',false].each do |value|
      context "specified as #{value}" do
        let(:params) { { :service_hasstatus => value } }
        let(:facts) do
          { :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end

        it {
          should contain_service('sshd_service').with({
            'ensure'     => 'running',
            'name'       => 'sshd',
            'enable'     => 'true',
            'hasrestart' => 'true',
            'hasstatus'  => value,
            'subscribe'  => 'File[sshd_config]',
          })
        }
      end
    end

    context 'specified as an invalid string' do
      let(:params) { { :service_hasstatus => 'invalid' } }
      let(:facts) do
        { :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error,/^ssh::service_hasstatus must be 'true' or 'false' and is set to <invalid>./) }
      end
    end

    context 'specified as an invalid type' do
      let(:params) { { :service_hasstatus => ['invalid','type'] } }
      let(:facts) do
        { :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error,/^ssh::service_hasstatus must be true or false./) }
      end
    end
  end
end
