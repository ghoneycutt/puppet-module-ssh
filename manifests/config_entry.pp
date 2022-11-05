# @summary Create config entries in a users' ~/.ssh/config
#
# Manage an entry in ~/.ssh/config for a particular user. Lines model the
# lines in each Host block.
#
# @param ensure
#   ensure attribute for entry.
#
# @param group
#   User group used for the generated ssh/config file.
#
# @param host
#   Host this generated ssh/config file is used for.
#
# @param lines
#   Lines to be added tp ssh/config file.
#
# @param order
#   Order of entries in the ssh/config file used for concatenation.
#
# @param owner
#   User/Owner used for the generated ssh/config file.
#
# @param path
#   Absolute path used for the generated ssh/config file.
#
define ssh::config_entry (
  String[1] $owner,
  String[1] $group,
  Stdlib::Absolutepath $path,
  String[1] $host,
  Enum['present','absent'] $ensure = 'present',
  Integer[0] $order  = 10,
  Array[String] $lines  = [],
) {

  # All lines including the host line. This will be joined with "\n  " for
  # indentation.
  $entry = concat(["Host ${host}"], $lines)
  $content = join($entry, "\n  ")

  if ! defined(Concat[$path]) {
    concat { $path:
      ensure         => $ensure,
      owner          => $owner,
      group          => $group,
      mode           => '0644',
      ensure_newline => true,
    }
  }

  concat::fragment { "${path} Host ${host}":
    target  => $path,
    content => $content,
    order   => $order,
    tag     => "${owner}_ssh_config",
  }
}
