#!/bin/bash

if [ $# -ne 1 ]; then
  echo "Must pass one argument of either 'debian' or 'el'"
  exit 255
fi

case "$1" in
  'el')
    function rpm_install() {
      package=$(echo $1 | awk -F "/" '{print $NF}')
      wget --quiet $1
      yum install -y ./$package
      rm -f $package
    }

    release=$(awk -F \: '{print $5}' /etc/system-release-cpe)

    rpm --import http://download-ib01.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-${release}
    rpm --import http://yum.puppetlabs.com/RPM-GPG-KEY-puppet
    rpm --import http://vault.centos.org/RPM-GPG-KEY-CentOS-${release}

    yum install -y wget

    rpm_install http://yum.puppetlabs.com/puppet5/puppet5-release-el-${release}.noarch.rpm
    yum -y install puppet-agent
  ;;

  'debian')
    function deb_install() {
      package=$(echo $1 | awk -F "/" '{print $NF}')
      wget --quiet $1
      dpkg -i ./$package
      rm -f $package
    }

    export DEBIAN_FRONTEND=noninteractive

    if [ -f /etc/lsb-release ]; then
      # ubuntu
      . /etc/lsb-release
      CODENAME=$DISTRIB_CODENAME
    else
      # debian
      CODENAME=$(grep ^VERSION= /etc/os-release | awk -F \( '{print $2}' | awk -F \) '{print $1}')
      apt-get -y install apt-transport-https
      apt-get update
    fi

    # Debian 9 (stretch) complains about the dirmngr package missing.
    if [ "${CODENAME}" == 'stretch' ]; then
      apt-get -y install dirmngr
    fi

    apt-key adv --fetch-keys http://apt.puppetlabs.com/DEB-GPG-KEY-puppet
    apt-get -y install wget

    deb_install http://apt.puppetlabs.com/puppet5-release-${CODENAME}.deb
    apt-get update
    apt-get -y install puppet-agent
  ;;

  *)
    echo "argument is <${1}> and must be either 'debian' or 'el'."
    exit 1
  ;;
esac

# ensure puppet is in the path by symlinking to /usr/bin
ln -s /opt/puppetlabs/puppet/bin/puppet /usr/bin/puppet

# use local ssh module
puppet resource file /etc/puppetlabs/code/environments/production/modules/ssh ensure=link target=/vagrant

# setup module dependencies
puppet module install puppetlabs/stdlib --version 5.2.0

