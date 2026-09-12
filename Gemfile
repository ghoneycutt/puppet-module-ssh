# frozen_string_literal: true

source ENV['GEM_SOURCE'] || 'https://rubygems.org'

group :development do
  gem 'faraday', '~> 1.0',             require: false
  gem 'github_changelog_generator',    require: false
  gem 'puppet-blacksmith',             require: false
  # 6.x depends on openfact; without the pin bundler resolves 5.x, which
  # pulls the Puppet Labs facter gem in alongside openfact
  gem 'rspec-puppet-facts', '~> 6.2',  require: false
  gem 'voxpupuli-rubocop', '~> 1.3.0', require: false
  gem 'voxpupuli-test', '~> 13.0',     require: false
end

group :system_tests do
  gem 'voxpupuli-acceptance', '~> 4.4', require: false
end

gem 'openvox', ENV.fetch('PUPPET_GEM_VERSION', '~> 8.0'), require: false
gem 'rake', require: false

# vim: syntax=ruby
