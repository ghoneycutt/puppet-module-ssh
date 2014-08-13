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
    it { should contain_file('ssh_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('ssh_config').without_content(/^\s*MACs/) }

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
    it { should contain_file('sshd_config').with_content(/^LogLevel INFO$/) }
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
    it { should contain_file('sshd_config').with_content(/^ServerKeyBits 1024$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveCountMax 3$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange no$/) }
    it { should_not contain_file('sshd_config').with_content(/^AuthorizedKeysFile/) }
    it { should_not contain_file('sshd_config').with_content(/^StrictModes/) }
    it { should contain_file('sshd_config').with_content(/^AcceptEnv L.*$/) }
    it { should contain_file('sshd_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('sshd_config').without_content(/^\s*MACs/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyGroups/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowGroups/) }

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
        should contain_class('ssh')
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

    it { should contain_class('ssh')}

    it { should_not contain_class('common')}


    ['network/ssh','network/ssh/ssh-key','service/network/ssh'].each do |pkg|
      it {
        should contain_package(pkg).with({
          'ensure'    => 'installed',
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
        'require' => [ 'Package[network/ssh]', 'Package[network/ssh/ssh-key]', 'Package[service/network/ssh]' ],
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
    it { should contain_file('ssh_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('ssh_config').without_content(/^\s*MACs/) }

    it {
      should contain_file('sshd_config').with({
        'ensure'  => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => [ 'Package[network/ssh]', 'Package[network/ssh/ssh-key]', 'Package[service/network/ssh]' ],
      })
    }

    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LogLevel INFO$/) }
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
    it { should_not contain_file('sshd_config').with_content(/^AuthorizedKeysFile/) }
    it { should_not contain_file('sshd_config').with_content(/^StrictModes/) }
    it { should contain_file('sshd_config').with_content(/^ServerKeyBits 768$/) }
    it { should contain_file('sshd_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('sshd_config').without_content(/^\s*MACs/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyGroups/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowGroups/) }

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

    it { should contain_class('ssh')}

    it { should_not contain_class('common')}

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
    it { should contain_file('ssh_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('ssh_config').without_content(/^\s*MACs/) }

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
    it { should contain_file('sshd_config').with_content(/^LogLevel INFO$/) }
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
    it { should_not contain_file('sshd_config').with_content(/^AuthorizedKeysFile/) }
    it { should_not contain_file('sshd_config').with_content(/^StrictModes/) }
    it { should contain_file('sshd_config').with_content(/^ServerKeyBits 768$/) }
    it { should contain_file('sshd_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('sshd_config').without_content(/^\s*MACs/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyGroups/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowGroups/) }

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

    it { should contain_class('ssh')}

    it { should_not contain_class('common')}

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
    it { should contain_file('ssh_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('ssh_config').without_content(/^\s*MACs/) }

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
    it { should contain_file('sshd_config').with_content(/^LogLevel INFO$/) }
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
    it { should_not contain_file('sshd_config').with_content(/^AuthorizedKeysFile/) }
    it { should_not contain_file('sshd_config').with_content(/^StrictModes/) }
    it { should contain_file('sshd_config').with_content(/^ServerKeyBits 768$/) }
    it { should contain_file('sshd_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('sshd_config').without_content(/^\s*MACs/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyGroups/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowGroups/) }

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
    it { should contain_file('ssh_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('ssh_config').without_content(/^\s*MACs/) }

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
    it { should contain_file('sshd_config').with_content(/^LogLevel INFO$/) }
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
    it { should contain_file('sshd_config').with_content(/^ServerKeyBits 1024$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveCountMax 3$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange yes$/) }
    it { should contain_file('sshd_config').with_content(/^AcceptEnv L.*$/) }
    it { should_not contain_file('sshd_config').with_content(/^AuthorizedKeysFile/) }
    it { should_not contain_file('sshd_config').with_content(/^StrictModes/) }
    it { should contain_file('ssh_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('ssh_config').without_content(/^\s*MACs/) }
    it { should contain_file('ssh_config').without_content(/^\s*DenyUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyGroups/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowGroups/) }

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
    it { should contain_file('ssh_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('ssh_config').without_content(/^\s*MACs/) }

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
    it { should contain_file('sshd_config').with_content(/^LogLevel INFO$/) }
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
    it { should contain_file('sshd_config').with_content(/^ServerKeyBits 1024$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveCountMax 3$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange yes$/) }
    it { should contain_file('sshd_config').with_content(/^AcceptEnv L.*$/) }
    it { should_not contain_file('sshd_config').with_content(/^AuthorizedKeysFile/) }
    it { should_not contain_file('sshd_config').with_content(/^StrictModes/) }
    it { should contain_file('sshd_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('sshd_config').without_content(/^\s*MACs/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyGroups/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowGroups/) }

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
    it { should contain_file('ssh_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('ssh_config').without_content(/^\s*MACs/) }

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
    it { should contain_file('sshd_config').with_content(/^LogLevel INFO$/) }
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
    it { should contain_file('sshd_config').with_content(/^ServerKeyBits 1024$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveCountMax 3$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange yes$/) }
    it { should contain_file('sshd_config').with_content(/^AcceptEnv L.*$/) }
    it { should_not contain_file('sshd_config').with_content(/^AuthorizedKeysFile/) }
    it { should_not contain_file('sshd_config').with_content(/^StrictModes/) }
    it { should contain_file('sshd_config').without_content(/^\s*Ciphers/) }
    it { should contain_file('sshd_config').without_content(/^\s*MACs/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*DenyGroups/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowUsers/) }
    it { should contain_file('sshd_config').without_content(/^\s*AllowGroups/) }

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
        :ssh_config_ciphers               => [ 'aes128-cbc',
                                                '3des-cbc',
                                                'blowfish-cbc',
                                                'cast128-cbc',
                                                'arcfour',
                                                'aes192-cbc',
                                                'aes256-cbc',
        ],
        :ssh_config_macs                  => [ 'hmac-md5-etm@openssh.com',
                                                'hmac-sha1-etm@openssh.com',
        ],
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
    it { should contain_file('ssh_config').with_content(/^\s*Ciphers aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc$/) }
    it { should contain_file('ssh_config').with_content(/^\s*MACs hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com$/) }
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
        :sshd_config_serverkeybits       => '1024',
        :sshd_client_alive_count_max     => '0',
        :sshd_config_authkey_location    => '.ssh/authorized_keys',
        :sshd_config_strictmodes         => 'yes',
        :sshd_config_ciphers             => [ 'aes128-cbc',
                                              '3des-cbc',
                                              'blowfish-cbc',
                                              'cast128-cbc',
                                              'arcfour',
                                              'aes192-cbc',
                                              'aes256-cbc',
        ],
        :sshd_config_macs                => [ 'hmac-md5-etm@openssh.com',
                                              'hmac-sha1-etm@openssh.com',
        ],
        :sshd_config_denyusers           => [ 'root',
                                              'lusers',
        ],
        :sshd_config_denygroups          => [ 'nossh',
                                              'wheel',
        ],
        :sshd_config_allowusers          => [ 'foo',
                                              'bar',
        ],
        :sshd_config_allowgroups         => [ 'ssh',
                                              'security',
        ],
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
    it { should contain_file('sshd_config').with_content(/^LogLevel INFO$/) }
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
    it { should contain_file('sshd_config').with_content(/^ServerKeyBits 1024$/) }
    it { should contain_file('sshd_config').with_content(/^ClientAliveCountMax 0$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPIAuthentication yes$/) }
    it { should contain_file('sshd_config').with_content(/^GSSAPICleanupCredentials yes$/) }
    it { should contain_file('sshd_config').with_content(/^HostKey \/etc\/ssh\/ssh_host_rsa_key$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*PAMAuthenticationViaKBDInt yes$/) }
    it { should_not contain_file('sshd_config').with_content(/^\s*GSSAPIKeyExchange yes$/) }
    it { should contain_file('sshd_config').with_content(/^AcceptEnv L.*$/) }
    it { should contain_file('sshd_config').with_content(/^AuthorizedKeysFile .ssh\/authorized_keys/) }
    it { should contain_file('sshd_config').with_content(/^StrictModes yes$/) }
    it { should contain_file('sshd_config').with_content(/^\s*Ciphers aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc$/) }
    it { should contain_file('sshd_config').with_content(/^\s*MACs hmac-md5-etm@openssh.com,hmac-sha1-etm@openssh.com$/) }
    it { should contain_file('sshd_config').with_content(/^\s*DenyUsers root lusers$/) }
    it { should contain_file('sshd_config').with_content(/^\s*DenyGroups nossh wheel$/) }
    it { should contain_file('sshd_config').with_content(/^\s*AllowUsers foo bar$/) }
    it { should contain_file('sshd_config').with_content(/^\s*AllowGroups ssh security$/) }

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

  describe 'ssh_config_appends parameter' do
    context 'when populated with an invalid value' do
      let (:facts) {{ :fqdn => 'monkey.example.com', :osfamily  => 'RedHat', :root_home => '/root', :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='}}
      let (:params) {{ 'ssh_config_appends' => 'BOGON'}}
      it 'should fail' do
        expect { subject }.to raise_error(Puppet::Error, /not an Array/)
      end
    end
    context 'when unpopulated' do
      let (:facts) {{ :fqdn => 'monkey.example.com', :osfamily  => 'RedHat', :root_home => '/root', :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='}}
      let (:params) {{ 'ssh_config_appends' => false}}
      it 'should not modify ssh_config.' do
        should contain_file('ssh_config').without_content(/#The following lines are managed by ssh::ssh_config_appends/)
      end
    end
    context 'when populated with a valid value' do
      let (:facts) {{ :fqdn => 'monkey.example.com', :osfamily  => 'RedHat', :root_home => '/root', :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='}}
      let (:params) {{ 'ssh_config_appends' => ['BOGON_ssh_one','BOGON_ssh_two']}}
      it 'should update ssh_config, appending each element as its own line.' do
        should contain_file('ssh_config').with_content(/#The following lines are managed by ssh::ssh_config_appends/).with_content(/^BOGON_ssh_one$/).with_content(/^BOGON_ssh_two$/)
      end
    end
  end

  describe 'sshd_config_appends parameter' do
    context 'when populated with an invalid value' do
      let (:facts) {{ :fqdn => 'monkey.example.com', :osfamily  => 'RedHat', :root_home => '/root', :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='}}
      let (:params) {{ 'sshd_config_appends' => 'BOGON'}}
      it 'should fail' do
        expect { subject }.to raise_error(Puppet::Error, /not an Array/)
      end
    end
    context 'when unpopulated' do
      let (:facts) {{ :fqdn => 'monkey.example.com', :osfamily  => 'RedHat', :root_home => '/root', :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='}}
      let (:params) {{ 'sshd_config_appends' => false}}
      it 'should not modify sshd_config.' do
        should contain_file('sshd_config').without_content(/#The following lines are managed by ssh::sshd_config_appends/)
      end
    end
    context 'when populated with a valid value' do
      let (:facts) {{ :fqdn => 'monkey.example.com', :osfamily  => 'RedHat', :root_home => '/root', :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='}}
      let (:params) {{ 'sshd_config_appends' => ['BOGON_sshd_one','BOGON_sshd_two']}}
      it 'should update sshd_config, appending each element as its own line.' do
        should contain_file('sshd_config').with_content(/#The following lines are managed by ssh::sshd_config_appends/).with_content(/^BOGON_sshd_one$/).with_content(/^BOGON_sshd_two$/)
      end
    end
  end

  describe 'sshd_loglevel param' do
    context 'when set to an invalid value' do
      let :facts do
        {
          :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :root_home => '/root',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end
      let (:params) {{'sshd_config_loglevel' => 'BOGON'}}
      it 'should fail' do
        expect { subject }.to raise_error(Puppet::Error, /"BOGON" does not match/)
      end
    end
    ['QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE'].each do |supported_val|
      context "when set to #{supported_val}" do
        let :facts do
          {
            :fqdn      => 'monkey.example.com',
            :osfamily  => 'RedHat',
            :root_home => '/root',
            :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
          }
        end
        let (:params) {{ 'sshd_config_loglevel' => supported_val}}
        it { should contain_file('sshd_config').with_content(/^LogLevel #{supported_val}$/) }
      end
    end
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

  [true,'invalid'].each do |ciphers|
    context "with ssh_config_ciphers set to invalid value #{ciphers}" do
      let(:params) { { :ssh_config_ciphers => ciphers } }

      let :facts do
        {
          :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  [true,'invalid'].each do |macs|
    context "with ssh_config_macs set to invalid value #{macs}" do
      let(:params) { { :ssh_config_macs => macs } }

      let :facts do
        {
          :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
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

  [true,'invalid'].each do |ciphers|
    context "with sshd_config_ciphers set to invalid value #{ciphers}" do
      let(:params) { { :sshd_config_ciphers => ciphers } }

      let :facts do
        {
          :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  [true,'invalid'].each do |denyusers|
    context "with sshd_config_denyusers set to invalid value #{denyusers}" do
      let(:params) { { :sshd_config_denyusers => denyusers } }

      let :facts do
        {
          :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  [true,'invalid'].each do |denygroups|
    context "with sshd_config_denygroups set to invalid value #{denygroups}" do
      let(:params) { { :sshd_config_denygroups => denygroups } }

      let :facts do
        {
          :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  [true,'invalid'].each do |allowusers|
    context "with sshd_config_allowusers set to invalid value #{allowusers}" do
      let(:params) { { :sshd_config_allowusers => allowusers } }

      let :facts do
        {
          :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  [true,'invalid'].each do |allowgroups|
    context "with sshd_config_allowgroups set to invalid value #{allowgroups}" do
      let(:params) { { :sshd_config_allowgroups => allowgroups } }

      let :facts do
        {
          :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  [true,'invalid'].each do |macs|
    context "with sshd_config_macs set to invalid value #{macs}" do
      let(:params) { { :sshd_config_macs => macs } }

      let :facts do
        {
          :fqdn      => 'monkey.example.com',
          :osfamily  => 'RedHat',
          :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
        }
      end

      it 'should fail' do
        expect {
          should contain_class('ssh')
        }.to raise_error(Puppet::Error)
      end
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

  context 'with sshd_config_serverkeybits set to invalid value on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :sshd_config_serverkeybits => 'invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::sshd_config_serverkeybits must be an integer and is set to <invalid>\./)
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

  context 'with sshd_client_alive_count_max set to invalid value on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :sshd_client_alive_count_max => 'invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::sshd_client_alive_count_max must be an integer and is set to <invalid>\./)
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

  context 'with sshd_config_authkey_location set to invalid value on valid osfamily' do
    let(:params) { { :sshd_config_authkey_location => false } }
    let(:facts) do
      { :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/is not a string/)
    end
  end

  context 'with sshd_config_strictmodes set to invalid value on valid osfamily' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :sshd_config_strictmodes => 'invalid' }
    end

    it 'should fail' do
      expect {
        should contain_class('ssh')
      }.to raise_error(Puppet::Error,/^ssh::sshd_config_strictmodes may be either \'yes\' or \'no\' and is set to <invalid>\./)
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
          :kernelrelease => '5.10',
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
          :kernelrelease => '5.10',
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
          :kernelrelease => '5.10',
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
          :kernelrelease => '5.10',
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
          :kernelrelease => '5.10',
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

  describe 'with ssh_key_import parameter specified' do
    context 'as a non-boolean or non-string' do
    let(:params) { { :ssh_key_import => ['not_a_boolean','or_a_string'] } }

      it 'should fail' do
        expect { should raise_error(Puppet::Error) }
      end
    end

    context 'as an invalid string' do
      let(:params) { { :ssh_key_import => 'invalid_string' } }
      let(:facts) do
        { :osfamily          => 'RedHat',
          :lsbmajdistrelease => '6',
        }
      end

      it 'should fail' do
        expect { should raise_error(Puppet::Error,/^ssh::ssh_key_import may be either 'true' or 'false' and is set to <invalid_string>./) }
      end
    end

    ['true',true].each do |value|
      context "as #{value}" do
        let(:params) { { :ssh_key_import => value } }
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
        let(:params) { { :ssh_key_import => value } }
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
end
