type Ssh::Syslog_facility = Enum[
  'DAEMON',
  'USER',
  'AUTH',
  'LOCAL0',
  'LOCAL1',
  'LOCAL2',
  'LOCAL3',
  'LOCAL4',
  'LOCAL5',
  'LOCAL6',
  'LOCAL7',
  'AUTHPRIV', # this is not documented, but it is what EL 7 uses
]
