# @summary Create config files to be used 
#
# Manage an entry in ~/.ssh/config for a particular user. Lines model the
# lines in each Host block.
#
# @param owner
#   User/Owner used for the generated ssh/config file.
#
# @param group
#   User group used for the generated ssh/config file.
#
# @param mode
#   File mode used for the generated ssh/config file.
#
# @param ensure
#   ensure attribute for entry.
#
# @param lines
#   Lines to be added tp ssh/config file.
#   These lines will be verified for valid directive names and values.
#
# @param custom
#   Lines to be added tp ssh/config file.
#   These lines will not be verified and can be used to add future and past directives.
#
define ssh::config_file_client (
  String[1]                $owner  = 'root',
  String[1]                $group  = 'root',
  Stdlib::Filemode         $mode   = '0644',
  Enum['present','absent'] $ensure = 'present',
  Ssh::Ssh_Config          $lines  = {},
  Array                    $custom = [],
) {
  include ssh
  if ! $ssh::include_dir {
    fail('ssh::config_file_client requires ssh::include be defined')
  }
  $path = "${ssh::include_dir}/${name}.conf"

  file { $path:
    ensure  => $ensure,
    owner   => $owner,
    group   => $group,
    mode    => $mode,
    content => epp('ssh/config_file.epp', { 'lines' => $lines, 'custom' => $custom }),
  }
}
