require 'voxpupuli/acceptance/spec_helper_acceptance'

dir = File.expand_path(File.dirname(__FILE__))
Dir["#{dir}/acceptance/shared_examples/**/*.rb"].sort.each { |f| require f }
require 'spec_helper_acceptance_local' if File.file?(File.join(File.dirname(__FILE__), 'spec_helper_acceptance_local.rb'))

configure_beaker(modules: :metadata)

require 'spec_helper_acceptance_setup' if File.file?(File.join(File.dirname(__FILE__), 'spec_helper_acceptance_setup.rb'))
# 'spec_overrides' from sync.yml will appear below this line
