require 'puppetlabs_spec_helper/rake_tasks'
require 'puppet-lint/tasks/puppet-lint'
PuppetLint.configuration.send('disable_80chars')
PuppetLint.configuration.send('disable_140chars')
PuppetLint.configuration.send('disable_relative_classname_inclusion')
PuppetLint.configuration.relative = true
PuppetLint.configuration.ignore_paths = ['spec/**/*.pp', 'pkg/**/*.pp', 'vendor/**/*.pp']

desc 'Validate ruby files'
task :validate do
  Dir['spec/**/*.rb','lib/**/*.rb'].each do |ruby_file|
    sh "ruby -c #{ruby_file}" unless ruby_file =~ /spec\/fixtures/
  end
end

# Puppet Strings (Documentation generation from inline comments)
# See: https://github.com/puppetlabs/puppet-strings#rake-tasks
require 'puppet-strings/tasks'

desc 'Alias for strings:generate'
task :doc => ['strings:generate']

desc 'Generate REFERENCE.md'
task :reference do
  sh 'puppet strings generate --format markdown'
end
