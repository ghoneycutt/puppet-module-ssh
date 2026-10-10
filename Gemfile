# frozen_string_literal: true

source ENV['GEM_SOURCE'] || 'https://rubygems.org'

group :development do
  gem 'github_changelog_generator',    require: false
  gem 'puppet-blacksmith',             require: false
  # 6.x depends on openfact; without the pin bundler resolves 5.x, which
  # pulls the Puppet Labs facter gem in alongside openfact
  gem 'rspec-puppet-facts', '~> 6.2',  require: false
  gem 'voxpupuli-rubocop', '~> 5.3', require: false
  gem 'voxpupuli-test', '~> 15.0',     require: false
end

group :system_tests do
  gem 'voxpupuli-acceptance', '~> 4.4', require: false
end

# jgrep (used by facterdb) calls JSON.create_id=, which the json gem removed
# in 3.0; constrain json until jgrep ships a fix
gem 'json', '< 3', require: false
gem 'openvox', ENV.fetch('OPENVOX_GEM_VERSION', ['>= 8.19', '< 10']), require: false
gem 'rake', require: false

# vim: syntax=ruby
