Facter.add('ssh_version') do
  setcode do
    if Facter::Util::Resolution.which('ssh')
      Facter::Util::Resolution.exec('ssh -V 2>&1').match(/^[A-Za-z0-9._]+/)[0]
    end
  end
end

Facter.add('ssh_version_numeric') do
  setcode do
    ssh_version = Facter.value(:ssh_version)
    if ssh_version
      ssh_version.match(/(\d+\.\d+\.\d+|\d+\.\d+)/)[0]
    end
  end
end
