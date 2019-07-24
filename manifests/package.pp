# Installs the ssh package(s)
class ssh::package(
  $packages                               = 'USE_DEFAULTS',
  $ssh_package_source                     = 'USE_DEFAULTS',
  $ssh_package_adminfile                  = 'USE_DEFAULTS',
) {

  case $::osfamily {
    'RedHat': {
      $default_packages                        = ['openssh-server', 'openssh-clients']
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
    }
    'Suse': {
      $default_packages                        = 'openssh'
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
    }
    'Debian': {
      # common for debian and ubuntu
      $default_packages                        = ['openssh-server', 'openssh-client']
      $default_ssh_package_source              = undef
      $default_ssh_package_adminfile           = undef
    }
    'Solaris': {
      $default_ssh_config_hash_known_hosts     = undef
      $default_ssh_sendenv                     = false
      $default_ssh_config_forward_x11_trusted  = undef
      case $::kernelrelease {
        '5.11': {
          $default_packages                      = ['network/ssh',
            'network/ssh/ssh-key',
            'service/network/ssh']
          $default_ssh_package_source            = undef
          $default_ssh_package_adminfile         = undef
        }
        '5.10': {
          $default_packages                      = ['SUNWsshcu',
            'SUNWsshdr',
            'SUNWsshdu',
            'SUNWsshr',
            'SUNWsshu']
          $default_ssh_package_source            = '/var/spool/pkg'
          $default_ssh_package_adminfile         = undef
        }
        '5.9' : {
          $default_packages                      = ['SUNWsshcu',
            'SUNWsshdr',
            'SUNWsshdu',
            'SUNWsshr',
            'SUNWsshu']
          $default_ssh_package_source            = '/var/spool/pkg'
          $default_ssh_package_adminfile         = undef
        }
        default: {
          fail('ssh module supports Solaris kernel release 5.9, 5.10 and 5.11.')
        }
      }
    }
    default: {
      fail("ssh supports osfamilies RedHat, Suse, Debian and Solaris. Detected osfamily is <${::osfamily}>.")
    }
  }

  if $packages == 'USE_DEFAULTS' {
    $packages_real = $default_packages
  } else {
    $packages_real = $packages
  }

  if $ssh_package_source == 'USE_DEFAULTS' {
    $ssh_package_source_real = $default_ssh_package_source
  } else {
    $ssh_package_source_real = $ssh_package_source
  }

  if $ssh_package_source_real != undef {
    validate_absolute_path($ssh_package_source_real)
  }

  if $ssh_package_adminfile == 'USE_DEFAULTS' {
    $ssh_package_adminfile_real = $default_ssh_package_adminfile
  } else {
    $ssh_package_adminfile_real = $ssh_package_adminfile
  }

  if $ssh_package_adminfile_real != undef {
    validate_absolute_path($ssh_package_adminfile_real)
  }

  package { $packages_real:
    ensure    => installed,
    source    => $ssh_package_source_real,
    adminfile => $ssh_package_adminfile_real,
  }


}