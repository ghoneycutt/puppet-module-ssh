define ssh::service(
  $service_ensure     = 'running',
  $service_name       = 'USE_DEFAULTS',
  $service_enable     = true,
  $service_hasrestart = true,
  $service_hasstatus  = 'USE_DEFAULTS',
  $service_subscribe  = [],
) {

  case $::osfamily {
    'RedHat': {
      $default_service_name                    = 'sshd'
      $default_service_hasstatus               = true
    }
    'Suse': {
      $default_service_name                    = 'sshd'
      $default_service_hasstatus               = true
    }
    'Debian': {
      # common for debian and ubuntu
      $default_service_name                    = 'ssh'
      $default_service_hasstatus               = true
    }
    'Solaris': {
      case $::kernelrelease {
        '5.11': {
          $default_service_name                  = 'ssh'
          $default_service_hasstatus             = true
        }
        '5.10': {
          $default_service_name                  = 'ssh'
          $default_service_hasstatus             = true
        }
        '5.9' : {
          $default_service_name                  = 'sshd'
          $default_service_hasstatus             = false
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

  if $service_name == 'USE_DEFAULTS' {
    $service_name_real = $default_service_name
  } else {
    $service_name_real = $service_name
  }

  if $service_hasstatus == 'USE_DEFAULTS' {
    $service_hasstatus_real = $default_service_hasstatus
  } else {
    case type3x($service_hasstatus) {
      'string': {
        validate_re($service_hasstatus, '^(true|false)$', "ssh::service_hasstatus must be 'true' or 'false' and is set to <${service_hasstatus}>.")
        $service_hasstatus_real = str2bool($service_hasstatus)
      }
      'boolean': {
        $service_hasstatus_real = $service_hasstatus
      }
      default: {
        fail('ssh::service_hasstatus must be true or false.')
      }
    }
  }

  if type3x($service_enable) == 'string' {
    $service_enable_real = str2bool($service_enable)
  } else {
    $service_enable_real = $service_enable
  }
  validate_bool($service_enable_real)

  if type3x($service_hasrestart) == 'string' {
    $service_hasrestart_real = str2bool($service_hasrestart)
  } else {
    $service_hasrestart_real = $service_hasrestart
  }
  validate_bool($service_hasrestart_real)


  service { $title :
    ensure     => $service_ensure,
    name       => $service_name_real,
    enable     => $service_enable_real,
    hasrestart => $service_hasrestart_real,
    hasstatus  => $service_hasstatus_real,
    subscribe  => $service_subscribe,
  }
}