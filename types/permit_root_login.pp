# 'without-password' is a deprecated alias for 'prohibit-password'
type Ssh::Permit_root_login = Enum[
  'yes',
  'prohibit-password',
  'without-password',
  'forced-commands-only',
  'no',
]
