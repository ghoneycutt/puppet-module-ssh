require 'beaker-rspec'
require 'beaker-puppet'
require 'beaker/module_install_helper'
require 'beaker/puppet_install_helper'

run_puppet_install_helper
install_module_dependencies
install_module

RSpec.configure do |c|
  # Readable test descriptions
  c.formatter = :documentation
end
