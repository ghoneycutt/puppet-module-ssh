require 'spec_helper'
describe 'ssh' do

  context 'with default params on osfamily RedHat' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    it { should include_class('ssh')}

    it { should_not include_class('common')}

    it {
      should contain_package('ssh_packages').with({
        'ensure' => 'installed',
        'name'   => ['openssh-server','openssh-clients'],
      })
    }

    it {
      should contain_file('ssh_config').with({
        'ensure' => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => 'Package[ssh_packages]',
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }

    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardAgent$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ForwardX11$/) }
    it { should_not contain_file('ssh_config').with_content(/^\s*ServerAliveInterval$/) }

    it {
      should contain_file('sshd_config').with({
        'ensure' => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0600',
        'require' => 'Package[ssh_packages]',
      })
    }

    it { should contain_file('sshd_config').with_content(/^Port 22$/) }
    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 120$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication no$/) }
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

  context 'with default params on osfamily Debian' do
    let :facts do
      {
        :fqdn            => 'monkey.example.com',
        :osfamily        => 'Debian',
        :sshrsakey       => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    it { should include_class('ssh')}

    it { should_not include_class('common')}

    it {
      should contain_package('ssh_packages').with({
        'ensure' => 'installed',
        'name'   => ['openssh-server','openssh-client'],
      })
    }

    it {
      should contain_file('ssh_config').with({
        'ensure' => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => 'Package[ssh_packages]',
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }

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
        'require' => 'Package[ssh_packages]',
      })
    }

    it { should contain_file('sshd_config').with_content(/^Port 22$/) }
    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 120$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication no$/) }
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
    it { should include_class('ssh')}

    it { should_not include_class('common')}

    it {
      should contain_package('ssh_packages').with({
        'ensure' => 'installed',
        'name'   => 'openssh',
      })
    }

    it {
      should contain_file('ssh_config').with({
        'ensure' => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => 'Package[ssh_packages]',
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }

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
        'require' => 'Package[ssh_packages]',
      })
    }

    it { should contain_file('sshd_config').with_content(/^Port 22$/) }
    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 120$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication no$/) }
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
    it { should include_class('ssh')}

    it { should_not include_class('common')}

    it {
      should contain_package('ssh_packages').with({
        'ensure' => 'installed',
        'name'   => 'openssh',
      })
    }

    it {
      should contain_file('ssh_config').with({
        'ensure' => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => 'Package[ssh_packages]',
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }

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
        'require' => 'Package[ssh_packages]',
      })
    }

    it { should contain_file('sshd_config').with_content(/^Port 22$/) }
    it { should contain_file('sshd_config').with_content(/^SyslogFacility AUTH$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 120$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin yes$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication no$/) }
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
        should include_class('ssh')
      }.to raise_error(Puppet::Error,/ssh supports osfamilies RedHat, Suse and Debian. Detected osfamily is <C64>./)
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
        :ssh_config_forward_agent         => 'yes',
        :ssh_config_forward_x11           => 'yes',
        :ssh_config_server_alive_interval => '300',
        :ssh_config_sendenv_xmodifiers    => true,
      }
    end

    it {
      should contain_file('ssh_config').with({
        'ensure' => 'file',
        'path'    => '/etc/ssh/ssh_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => 'Package[ssh_packages]',
      })
    }

    it { should contain_file('ssh_config').with_content(/^# This file is being maintained by Puppet.\n# DO NOT EDIT\n\n# \$OpenBSD: ssh_config,v 1.21 2005\/12\/06 22:38:27 reyk Exp \$/) }
    it { should contain_file('ssh_config').with_content(/^   Protocol 2$/) }
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
        :sshd_config_challenge_resp_auth => 'yes',
        :sshd_config_print_motd          => 'no',
        :sshd_config_use_dns             => 'no',
        :sshd_config_banner              => '/etc/sshd_banner',
        :sshd_config_xauth_location      => '/opt/ssh/bin/xauth',
        :sshd_config_subsystem_sftp      => '/opt/ssh/bin/sftp',
        :sshd_password_authentication    => 'no',
        :sshd_allow_tcp_forwarding       => 'no',
        :sshd_x11_forwarding             => 'no',
        :sshd_use_pam                    => 'no',
        :sshd_client_alive_interval      => '242',
      }
    end

    it {
      should contain_file('sshd_config').with({
        'ensure' => 'file',
        'path'    => '/etc/ssh/sshd_config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0600',
        'require' => 'Package[ssh_packages]',
      })
    }

    it { should contain_file('sshd_config').with_content(/^Port 22222$/) }
    it { should contain_file('sshd_config').with_content(/^SyslogFacility DAEMON$/) }
    it { should contain_file('sshd_config').with_content(/^LoginGraceTime 60$/) }
    it { should contain_file('sshd_config').with_content(/^PermitRootLogin no$/) }
    it { should contain_file('sshd_config').with_content(/^ChallengeResponseAuthentication yes$/) }
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

    it { should include_class('ssh')}

    it { should include_class('common')}

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
        'ensure'  => 'file',
        'path'    => '/root/.ssh/config',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0600',
      })
    }
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
        should include_class('ssh')
      }.to raise_error(Puppet::Error,/sshd_config_port must be a valid number and is set to <22invalid>./)
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
        should include_class('ssh')
      }.to raise_error(Puppet::Error,/manage_root_ssh_config is <invalid> and must be \'true\' or \'false\'./)
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
        should include_class('ssh')
      }.to raise_error(Puppet::Error,/sshd_password_authentication may be either \'yes\' or \'no\' and is set to <invalid>./)
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
        should include_class('ssh')
      }.to raise_error(Puppet::Error,/sshd_allow_tcp_forwarding may be either \'yes\' or \'no\' and is set to <invalid>./)
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
        should include_class('ssh')
      }.to raise_error(Puppet::Error,/sshd_x11_forwarding may be either \'yes\' or \'no\' and is set to <invalid>./)
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
        should include_class('ssh')
      }.to raise_error(Puppet::Error,/sshd_use_pam may be either \'yes\' or \'no\' and is set to <invalid>./)
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
        should include_class('ssh')
      }.to raise_error(Puppet::Error,/sshd_client_alive_interval must be an integer and is set to <invalid>./)
    end
  end

  context 'with ssh_config_sendenv_xmodifiers set to invalid type, array' do
    let :facts do
      {
        :fqdn      => 'monkey.example.com',
        :osfamily  => 'RedHat',
        :sshrsakey => 'AAAAB3NzaC1yc2EAAAABIwAAAQEArGElx46pD6NNnlxVaTbp0ZJMgBKCmbTCT3RaeCk0ZUJtQ8wkcwTtqIXmmiuFsynUT0DFSd8UIodnBOPqitimmooAVAiAi30TtJVzADfPScMiUnBJKZajIBkEMkwUcqsfh630jyBvLPE/kyQcxbEeGtbu1DG3monkeymanOBW1AKc5o+cJLXcInLnbowMG7NXzujT3BRYn/9s5vtT1V9cuZJs4XLRXQ50NluxJI7sVfRPVvQI9EMbTS4AFBXUej3yfgaLSV+nPZC/lmJ2gR4t/tKvMFF9m16f8IcZKK7o0rK7v81G/tREbOT5YhcKLK+0wBfR6RsmHzwy4EddZloyLQ=='
      }
    end
    let :params do
      { :ssh_config_sendenv_xmodifiers => ['invalid','type'] }
    end

    it 'should fail' do
      expect {
        should include_class('ssh')
      }.to raise_error(Puppet::Error,/ssh_config_sendenv_xmodifiers type must be true or false./)
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

    it { should include_class('ssh')}

    it { should_not include_class('common')}

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
      'root_for_userY' => {
        'ensure' => 'absent',
        'user'   => 'root',
      }
    } } }

    it {
      should contain_ssh_authorized_key('root_for_userX').with({
        'ensure' => 'present',
        'user'   => 'root',
        'type'   => 'dsa',
        'key'    => 'AAAA==',
      })
    }

    it {
      should contain_ssh_authorized_key('root_for_userY').with({
        'ensure' => 'absent',
        'user'   => 'root',
      })
    }
  end
end
