# Additional instance of an ssh service
define ssh::service_instance(
  $ensure              = 'present',
  $service_name        = $title,
  $service_description = 'Additional SSH server',
  $service_env_file    = '/etc/sysconfig/sshd',
  # lint:ignore:empty_string_assignment
  $service_options     = '',
  # lint:endignore
) {
  case $::osfamily {
    'RedHat': {
      $service_type     = 'systemd'
      $service_file     = "/etc/systemd/system/${title}.service"
    }
    'Suse': {
      $service_type     = 'systemd'
      $service_file     = "/etc/systemd/system/${title}.service"
    }
    'Debian': {
      # common for debian and ubuntu
      case $::operatingsystemrelease {
        '16.04': {
          $service_type = 'systemd'
          $service_file = "/etc/systemd/system/${title}.service"
        }
        '18.04': {
          $service_type = 'systemd'
          $service_file = "/etc/systemd/system/${title}.service"
        }
        /^10.*/: {
          $service_type = 'systemd'
          $service_file = "/etc/systemd/system/${title}.service"
        }
        /^9.*/: {
          $service_type = 'systemd'
          $service_file = "/etc/systemd/system/${title}.service"
        }
        /^8.*/: {
          $service_type = 'systemd'
          $service_file = "/etc/systemd/system/${title}.service"
        }
        default: { fail ("Operating System : ${::operatingsystemrelease} not supported") }
      }
    }
    'Solaris': {
      fail('ssh::service_instance currently does not support Solaris')
    }
    default: {
      fail("ssh::service_instance supports osfamilies RedHat, Suse, Debian and Solaris. Detected osfamily is <${::osfamily}>.")
    }
  }
  validate_re($ensure, '^(present|absent)$', "ssh::service_instance::ensure may be either 'present' or 'absent' and is set to <${ensure}>.")

  if $ensure == 'present' {
    $file_ensure = 'file'
  } else {
    $file_ensure = 'absent'
  }
  case $service_type {
    'systemd': {
      file{$service_file:
        ensure  => $file_ensure,
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => template("ssh/service/${service_type}.erb"),
        notify  => [
          Exec["daemon-reload_${service_name}"],
          Service[$service_name],
          ],
      }
      -> exec { "daemon-reload_${service_name}":
        command     => '/bin/systemctl daemon-reload',
        refreshonly => true,
      }
    }
    default: {
      fail("ssh only supports systemd service types. Detected service type is <${service_type}>.")
    }
  }
}