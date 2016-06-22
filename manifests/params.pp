# == Class: ssh::params
#
class ssh::params {

  case $::osfamily {
    'FreeBSD': {
      $default_packages                            = undef
      $default_service_name                        = 'sshd'
      $default_ssh_config_forward_x11_trusted      = 'yes'
      $default_ssh_config_global_known_hosts_group = 'wheel'
      $default_ssh_config_group                    = 'wheel'
      $default_ssh_config_hash_known_hosts         = 'no'
      $default_ssh_package_source                  = undef
      $default_ssh_package_adminfile               = undef
      $default_ssh_sendenv                         = true
      $default_sshd_banner_group                   = 'wheel'
      $default_sshd_config_group                   = 'wheel'
      $default_sshd_config_subsystem_sftp          = '/usr/libexec/sftp-server'
      $default_sshd_config_mode                    = '0644'
      $default_sshd_config_use_dns                 = 'yes'
      $default_sshd_config_xauth_location          = '/usr/local/bin/xauth'
      $default_sshd_use_pam                        = 'yes'
      $default_sshd_gssapikeyexchange              = undef
      $default_sshd_pamauthenticationviakbdint     = undef
      $default_sshd_gssapicleanupcredentials       = 'yes'
      $default_sshd_acceptenv                      = true
      $default_service_hasstatus                   = true
      $default_sshd_config_serverkeybits           = '1024'
      $default_sshd_config_hostkey                 = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily                  = 'any'
    }
    'RedHat': {
      $default_packages                            = ['openssh-server',
                                                       'openssh-clients']
      $default_service_name                        = 'sshd'
      $default_ssh_config_hash_known_hosts         = 'no'
      $default_ssh_config_forward_x11_trusted      = 'yes'
      $default_ssh_config_global_known_hosts_group = 'root'
      $default_ssh_config_group                    = 'root'
      $default_ssh_package_source                  = undef
      $default_ssh_package_adminfile               = undef
      $default_ssh_sendenv                         = true
      $default_sshd_banner_group                   = 'root'
      $default_sshd_config_group                   = 'root'
      $default_sshd_config_subsystem_sftp          = '/usr/libexec/openssh/sftp-server'
      $default_sshd_config_mode                    = '0600'
      $default_sshd_config_use_dns                 = 'yes'
      $default_sshd_config_xauth_location          = '/usr/bin/xauth'
      $default_sshd_use_pam                        = 'yes'
      $default_sshd_gssapikeyexchange              = undef
      $default_sshd_pamauthenticationviakbdint     = undef
      $default_sshd_gssapicleanupcredentials       = 'yes'
      $default_sshd_acceptenv                      = true
      $default_service_hasstatus                   = true
      $default_sshd_config_serverkeybits           = '1024'
      $default_sshd_config_hostkey                 = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily                  = 'any'
    }
    'Suse': {
      $default_packages                            = 'openssh'
      $default_service_name                        = 'sshd'
      $default_ssh_config_hash_known_hosts         = 'no'
      $default_ssh_package_source                  = undef
      $default_ssh_package_adminfile               = undef
      $default_ssh_sendenv                         = true
      $default_sshd_config_group                   = 'root'
      $default_ssh_config_forward_x11_trusted      = 'yes'
      $default_ssh_config_global_known_hosts_group = 'root'
      $default_ssh_config_group                    = 'root'
      $default_sshd_banner_group                   = 'root'
      $default_sshd_config_mode                    = '0600'
      $default_sshd_config_use_dns                 = 'yes'
      $default_sshd_config_xauth_location          = '/usr/bin/xauth'
      $default_sshd_use_pam                        = 'yes'
      $default_sshd_gssapikeyexchange              = undef
      $default_sshd_pamauthenticationviakbdint     = undef
      $default_sshd_gssapicleanupcredentials       = 'yes'
      $default_sshd_acceptenv                      = true
      $default_service_hasstatus                   = true
      $default_sshd_config_serverkeybits           = '1024'
      $default_sshd_config_hostkey                 = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily                  = 'any'
      case $::architecture {
        'x86_64': {
          if ($::operatingsystem == 'SLES') and ($::operatingsystemrelease =~ /^12\./) {
            $default_sshd_config_subsystem_sftp = '/usr/lib/ssh/sftp-server'
          } else {
            $default_sshd_config_subsystem_sftp = '/usr/lib64/ssh/sftp-server'
          }
        }
        'i386' : {
          $default_sshd_config_subsystem_sftp = '/usr/lib/ssh/sftp-server'
      }
        default: {
          fail("ssh supports architectures x86_64 and i386 for Suse. Detected architecture is <${::architecture}>.")
        }
      }
    }
    'Debian': {
      $default_packages                            = ['openssh-server',
                                                        'openssh-client']
      $default_service_name                        = 'ssh'
      $default_ssh_config_forward_x11_trusted      = 'yes'
      $default_ssh_config_global_known_hosts_group = 'root'
      $default_ssh_config_group                    = 'root'
      $default_ssh_config_hash_known_hosts         = 'no'
      $default_ssh_package_source                  = undef
      $default_ssh_package_adminfile               = undef
      $default_ssh_sendenv                         = true
      $default_sshd_banner_group                   = 'root'
      $default_sshd_config_group                   = 'root'
      $default_sshd_config_subsystem_sftp          = '/usr/lib/openssh/sftp-server'
      $default_sshd_config_mode                    = '0600'
      $default_sshd_config_use_dns                 = 'yes'
      $default_sshd_config_xauth_location          = '/usr/bin/xauth'
      $default_sshd_use_pam                        = 'yes'
      $default_sshd_gssapikeyexchange              = undef
      $default_sshd_pamauthenticationviakbdint     = undef
      $default_sshd_gssapicleanupcredentials       = 'yes'
      $default_sshd_acceptenv                      = true
      $default_service_hasstatus                   = true
      $default_sshd_config_serverkeybits           = '1024'
      $default_sshd_config_hostkey                 = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily                  = 'any'
    }
    'Solaris': {
      $default_ssh_config_hash_known_hosts         = undef
      $default_ssh_sendenv                         = false
      $default_ssh_config_forward_x11_trusted      = undef
      $default_ssh_config_global_known_hosts_group = 'root'
      $default_ssh_config_group                    = 'root'
      $default_sshd_banner_group                   = 'root'
      $default_sshd_config_group                   = 'root'
      $default_sshd_config_subsystem_sftp          = '/usr/lib/ssh/sftp-server'
      $default_sshd_config_mode                    = '0644'
      $default_sshd_config_use_dns                 = undef
      $default_sshd_config_xauth_location          = '/usr/openwin/bin/xauth'
      $default_sshd_use_pam                        = undef
      $default_sshd_gssapikeyexchange              = 'yes'
      $default_sshd_pamauthenticationviakbdint     = 'yes'
      $default_sshd_gssapicleanupcredentials       = undef
      $default_sshd_acceptenv                      = false
      $default_sshd_config_serverkeybits           = '768'
      $default_ssh_package_adminfile               = undef
      $default_sshd_config_hostkey                 = [ '/etc/ssh/ssh_host_rsa_key' ]
      $default_sshd_addressfamily                  = undef
      case $::kernelrelease {
        '5.11': {
          $default_packages                          = ['network/ssh',
                                                        'network/ssh/ssh-key',
                                                        'service/network/ssh']
          $default_service_name                      = 'ssh'
          $default_service_hasstatus                 = true
          $default_ssh_package_source                = undef
        }
        '5.10': {
          $default_packages                          = ['SUNWsshcu',
                                                        'SUNWsshdr',
                                                        'SUNWsshdu',
                                                        'SUNWsshr',
                                                        'SUNWsshu']
          $default_service_name                      = 'ssh'
          $default_service_hasstatus                 = true
          $default_ssh_package_source                = '/var/spool/pkg'
        }
        '5.9' : {
          $default_packages                          = ['SUNWsshcu',
                                                        'SUNWsshdr',
                                                        'SUNWsshdu',
                                                        'SUNWsshr',
                                                        'SUNWsshu']
          $default_service_name                      = 'sshd'
          $default_service_hasstatus                 = false
          $default_ssh_package_source                = '/var/spool/pkg'
        }
        default: {
          fail('ssh module supports Solaris kernel release 5.9, 5.10 and 5.11.')
        }
      }
    }
    default: {
      fail("ssh supports osfamilies RedHat, Suse, Debian, Solaris and FreeBSD. Detected osfamily is <${::osfamily}>.")
    }
  }
}
