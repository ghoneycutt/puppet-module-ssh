# -*- mode: ruby -*-
# vi: set ft=ruby :
#
if not Vagrant.has_plugin?('vagrant-vbguest')
  abort <<-EOM

vagrant plugin vagrant-vbguest >= 0.16.0 is required.
https://github.com/dotless-de/vagrant-vbguest
To install the plugin, please run, 'vagrant plugin install vagrant-vbguest'.

  EOM
end

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"

  config.vm.provider :virtualbox do |vb|
    vb.customize ["modifyvm", :id, "--memory", "512"]
  end

  # TODO: remove comments around provision once we have a clean copy of
  # sshd_config and ssh_config from that platform and the platform has been
  # added to the module and those spec tests work.
  config.vm.define "el7-ssh", autostart: true do |c|
    c.vm.box = "centos/7"
    c.vm.hostname = 'el7-ssh.example.com'
    c.vm.provision :shell, :path => "tests/provision.sh", :args => "el"
    c.vm.provision :shell, :inline => "puppet apply /vagrant/examples/init.pp"
  end

  config.vm.define "el6-ssh", autostart: false do |c|
    c.vm.box = "centos/6"
    c.vm.hostname = 'el6-ssh.example.com'
    c.vm.provision :shell, :path => "tests/provision.sh", :args => "el"
    c.vm.provision :shell, :inline => "puppet apply /vagrant/examples/init.pp"
  end

  config.vm.define "debian8-ssh", autostart: false do |c|
    c.vm.box = "debian/jessie64"
    c.vm.hostname = 'debian8-ssh.example.com'
    c.vm.provision :shell, :path => "tests/provision.sh", :args => "debian"
#    c.vm.provision :shell, :inline => "puppet apply /vagrant/examples/init.pp"
  end

  config.vm.define "debian9-ssh", autostart: false do |c|
    c.vm.box = "debian/stretch64"
    c.vm.hostname = 'debian9-ssh.example.com'
    c.vm.provision :shell, :path => "tests/provision.sh", :args => "debian"
#    c.vm.provision :shell, :inline => "puppet apply /vagrant/examples/init.pp"
  end

  config.vm.define "ubuntu1604-ssh", autostart: false do |c|
    c.vm.box = "ubuntu/xenial64"
    c.vm.hostname = 'ubuntu1604-ssh.example.com'
    c.vm.provision :shell, :path => "tests/provision.sh", :args => "debian"
#    c.vm.provision :shell, :inline => "puppet apply /vagrant/examples/init.pp"
  end

  config.vm.define "ubuntu1804-ssh", autostart: false do |c|
    c.vm.box = "ubuntu/bionic64"
    c.vm.hostname = 'ubuntu1804-ssh.example.com'
    c.vm.provision :shell, :path => "tests/provision.sh", :args => "debian"
#    c.vm.provision :shell, :inline => "puppet apply /vagrant/examples/init.pp"
  end
end
