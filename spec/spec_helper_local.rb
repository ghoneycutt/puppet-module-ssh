# frozen_string_literal: true

require 'json'

# Platforms listed in metadata.json without an operatingsystemrelease are known
# to work though no longer actively supported, so they are excluded from spec
# testing. Exception: Archlinux is versionless because it is a rolling release,
# not because it is unsupported, so it stays in the matrix.
UNVERSIONED_BUT_TESTED = ['Archlinux'].freeze

# Absolute path to a file under spec/fixtures. Previously provided by
# puppetlabs_spec_helper, which this module no longer uses.
def fixtures(path)
  File.expand_path(File.join('fixtures', path), __dir__)
end

def actively_supported_os
  metadata = JSON.parse(File.read(File.expand_path('../metadata.json', __dir__)))
  metadata['operatingsystem_support'].select do |os|
    os.key?('operatingsystemrelease') || UNVERSIONED_BUT_TESTED.include?(os['operatingsystem'])
  end
end
