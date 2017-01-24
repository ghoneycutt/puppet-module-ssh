require 'rspec-puppet'
require 'rspec-puppet-utils'
require 'puppetlabs_spec_helper/module_spec_helper'

RSpec.configure do |c|
  # c.hiera_config = 'spec/hiera/hiera.yaml'
  c.after(:suite) do
    RSpec::Puppet::Coverage.report!
  end
end
