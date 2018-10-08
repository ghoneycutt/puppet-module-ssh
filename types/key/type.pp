# From https://github.com/puppetlabs/puppetlabs-sshkeys_core/blob/master/lib/puppet/type/sshkey.rb v1.0.2
type Ssh::Key::Type = Enum[
  'ssh-dss',
  'ssh-ed25519',
  'ssh-rsa',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'ed25519',
  'rsa',
  'dsa',
]
