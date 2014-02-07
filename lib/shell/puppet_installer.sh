#!/bin/bash
#
# Author:: Ashrith Mekala (<ashrith@cloudwick.com>)
# Description:: Script to install puppet server/client
#               * puppetdb for stored configs
#               * passenger for scaling puppet server
#               * postgresql (dependency for puppetdb)
#               * autosigning for puppet clients belonging to same domain
# Supported OS:: CentOS, Redhat, Ubuntu
# Version: 0.3
#
# Copyright 2013, Cloudwick, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

####
## Configuration Variables (change these, only if you know what you are doing)
####
puppet_modules_path="/etc/puppet/modules"
puppet_modules_download="https://github.com/cloudwicklabs/ankus-modules/archive/v2.2.tar.gz"
debug="false"

### !!! DONT CHANGE BEYOND THIS POINT. DOING SO MAY BREAK THE SCRIPT !!!

####
## Global Variables (script-use only)
####
# os specific variables
declare os
declare os_str
declare os_version
declare os_codename
declare os_arch
declare package_manager
declare puppet_server_package
declare puppet_client_package

# colors
clr_blue="\x1b[34m"
clr_green="\x1b[32m"
clr_yellow="\x1b[33m"
clr_red="\x1b[31m"
clr_cyan="\x1b[36m"
clr_end="\x1b[0m"

# log files
stdout_log="/tmp/puppet-install.stdout"
stderr_log="/tmp/puppet-install.stderr"

####
## Utility functions
####

function print_banner () {
  echo -e "\n* Logging enabled, check '${clr_cyan}${stdout_log}${clr_end}' for stdout and '${clr_cyan}${stderr_log}${clr_end}' for stderr output.\n"
}

function print_error () {
  printf "${clr_red}E${clr_end} -- $@\n"
}

function print_warning () {
  printf "${clr_yellow}W${clr_end} -- $@\n"
}

function print_info () {
  printf "${clr_green}I${clr_end} -- $@\n"
}

function execute () {
  local full_redirect="1>>$stdout_log 2>>$stderr_log"
  /bin/bash -c "$@ $full_redirect"
  ret=$?
  if [[ $debug = "true" ]]; then
    if [ $ret -ne 0 ]; then
      print_warning "Executed command \'$@\', returned non-zero code: $ret"
    else
      print_info "Executed command \'$@\', returned successfully."
    fi
  fi
  return $ret
}

function check_for_root () {
  if [ "$(id -u)" != "0" ]; then
   print_error "Please run with super user privileges."
   exit 1
  fi
}

function get_system_info () {
  print_info "Collecting system configuration..."
  
  os=`uname -s`
  if [[ "$os" = "SunOS" ]] ; then
    os="Solaris"
    os_arch=`uname -p`
  elif [[ "$os" = "Linux" ]] ; then
    if [[ -f /etc/lsb-release ]] ; then
      os_str=$( lsb_release -sd | tr '[:upper:]' '[:lower:]' | tr '"' ' ' | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } print $i; } }' )
      os_version=$( lsb_release -sd | tr '[:upper:]' '[:lower:]' | tr '"' ' ' | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } } }')
      if [[ $os_str =~ ubuntu ]]; then
        os="ubuntu"
        if grep -q precise /etc/lsb-release; then
          os_codename="precise"
        elif grep -q lucid /etc/lsb-release; then
          os_codename="lucid"
        else
          print_error "Sorry, only precise & lucid systems are supported by this script. Exiting."
          exit 1
        fi
      else
        print_error "OS: $os_str is not yet supported, contanct support@cloudwicklabs.com"
        exit 1        
      fi
    else
      os_str=$( cat `ls /etc/*release | grep "redhat\|SuSE"` | head -1 | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } print $i; } }' | tr '[:upper:]' '[:lower:]' )
      os_version=$( cat `ls /etc/*release | grep "redhat\|SuSE"` | head -1 | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } } }' | tr '[:upper:]' '[:lower:]')
      if [[ $os_str =~ centos ]]; then
        os="centos"
      elif [[ $os_str =~ redhat ]]; then
        os="redhat"
      else
        print_error "OS: $os_str is not yet supported, contanct support@cloudwicklabs.com"
        exit 1
      fi
    fi
    os=$( echo $os | sed -e "s/ *//g")
    os_arch=`uname -m`
    if [[ "xi686" == "x${os_arch}" || "xi386" == "x${os_arch}" ]]; then
      os_arch="i386"
    fi
    if [[ "xx86_64" == "x${os_arch}" || "xamd64" == "x${os_arch}" ]]; then
      os_arch="x86_64"
    fi
  elif [[ "$os" = "Darwin" ]]; then
    type -p sw_vers &>/dev/null
    [[ $? -eq 0 ]] && {
      os="macosx"
      os_version=`sw_vers | grep 'ProductVersion' | cut -f 2`
    } || {
      os="macosx"
    }
  fi

  if [[ $os =~ centos || $os =~ redhat ]]; then
    package_manager="yum"
  elif [[ $os =~ ubuntu ]]; then
    package_manager="apt-get"
  elif [[ $os =~ macosx ]]; then
    package_manager="brew"
  else
    print_error "Unsupported package manager. Please contact support@cloudwicklabs.com."
    exit 1
  fi
}

####
## Script specific functions
####

function check_preqs () {
  check_for_root
  print_info "Checking your system prerequisites..."

  for command in curl vim git wget; do
    type -P $command &> /dev/null || {
      print_warning "Command $command not found"
      print_info "Attempting to install $command..."
      execute "${package_manager} -y install $command" # brew does not have -y
      if [[ $? -ne 0 ]]; then
        print_warning "Could not install $command. This may cause issues."
      fi
    } 
  done
}

function add_epel_repo () {
  execute "ls -la /etc/yum.repos.d/*epel*"
  if [[ $? -ne 0 ]]; then
    print_info "Adding the EPEL repository to yum configuration..."
    if [[ $os_version -eq 5 ]]; then
      execute "curl -o epel.rpm -L http://download.fedoraproject.org/pub/epel/5/$os_arch/epel-release-5-4.noarch.rpm"
      execute "rpm -i epel.rpm"
      execute "rm -f epel.rpm"
    elif [[ $os_version -eq 6 ]]; then
      execute "curl -o epel.rpm -L http://download.fedoraproject.org/pub/epel/6/$os_arch/epel-release-6-8.noarch.rpm"
      execute "rpm -i epel.rpm"
      execute "rm -f epel.rpm"
    fi
  fi  
}

function add_puppetlabs_repo () {
  case "$os" in
    centos|redhat)
      add_epel_repo
      if [[ ! -f /etc/yum.repos.d/puppetlabs.repo ]]; then
        print_info "Adding puppetlabs repo to yum repositories list..."
        if [[ $os_version -eq 5 ]]; then
          execute "rpm -i http://yum.puppetlabs.com/el/5/products/$os_arch/puppetlabs-release-5-7.noarch.rpm"
        elif [[ $os_version -eq 6 ]]; then
          execute "rpm -i http://yum.puppetlabs.com/el/6/products/$os_arch/puppetlabs-release-6-7.noarch.rpm"
        fi        
        sed -i 's/gpgcheck=1/gpgcheck=0/g' /etc/yum.repos.d/puppetlabs.repo
      fi
      ;;
    ubuntu)
      if [[ ! -f /etc/apt/sources.list.d/puppetlabs.list ]]; then
        print_info "Adding puppetlabs repo to apt sources list"
        execute "curl -sO http://apt.puppetlabs.com/puppetlabs-release-${os_codename}.deb"
        execute "dpkg -i puppetlabs-release-${os_codename}.deb"
        execute "rm -f puppetlabs-release-${os_codename}.deb"
        print_info "Refreshing apt packages list..."
        execute "apt-get update"
      fi
      ;;
    *)
      print_error "$os is not yet supported, please contact support@cloudwicklabs.com."
      exit 1
      ;;
  esac
}

function stop_iptables () {
  case "$os" in
    centos|redhat)
      print_info "Stopping ip tables..."
      execute "service iptables stop"
      ;;
    ubuntu)
      print_info "Disabling ufw..."
      execute "ufw disable"
      ;;
    *)
      print_error "$os is not supported yet."
      exit 1
      ;;
  esac
}

function stop_selinux () {
  if [[ -f /etc/selinux/config ]]; then
    print_info "Disabling selinux..."
    execute "/usr/sbin/setenforce 0"
    execute "sed -i.old s/SELINUX=enforcing/SELINUX=disabled/ /etc/selinux/config"
  fi
}

# Retries a command a configurable number of times with backoff.
# The retry count is given by ATTEMPTS (default 5), the initial backoff
# timeout is given by TIMEOUT in seconds (default 1.)
# Successive backoff's double the timeout.
function with_backoff () {
  local max_attempts=${ATTEMPTS-5}
  local timeout=${TIMEOUT-1}
  local attempt=0
  local exitCode=0
  while [[ ${attempt} < ${max_attempts} ]]
  do
    #execute the command
    "$@"
    exitCode=$?

    if [[ ${exitCode} == 0 ]] ;then
      break
    fi
    print_warning "Failure! Retrying in $timeout.." 1>&2
    sleep ${timeout}
    attempt=$(( attempt + 1 ))
    timeout=$(( timeout * 2 ))
  done
  if [[ $exitCode != 0 ]]
  then
    print_error "Command for the last time! ($@)" 1>&2
  fi
  return ${exitCode}
}

function download_modules () {
  if [ ! -d ${puppet_modules_path} ]; then
    print_info "Puppet modules directory not found, creating"
    mkdir -p ${puppet_modules_path}
  fi
  cd /etc/puppet
  print_info "Downloading deployment modules ..."
  with_backoff wget --no-check-certificate --quiet -O modules.tar.gz ${puppet_modules_download}
  if [ $? -eq 0 ]; then
    print_info "Sucessfully downloaded puppet modules from git"
    print_info "Extracting modules ..."
    execute "tar xzf modules.tar.gz"
    if [ $? -eq 0 ]; then
      mv ankus-modules*/* ${puppet_modules_path}
      rm -f modules.tar.gz
      rm -rf ankus-modules*
    fi
  else
    print_error "Failed to download puppet modules from git, aborting!!!"
    exit 2
  fi
}

function install_puppet_apt_module () {
  print_info "Installing puppetlabs apt module ..."
  execute "puppet module install puppetlabs/apt"
  if [[ $? -eq 0 ]]; then
    print_info "Sucessfully installed puppetlabs apt module"
  else
    print_error "Failed to install puppetlabs apt module"
  fi
}

function create_log_dir () {
  local ankus_log_dir="/var/log/ankus"
  if [ ! -d ${ankus_log_dir} ]; then
    print_info "Creating ankus log directory structure"
    mkdir -p ${ankus_log_dir}
  fi
}

function check_if_postgres_is_installed () {
  print_info "Checking to see if postgres is installed..."
  case "$os" in
    centos|redhat)
      execute "rpm -q postgresql-server"
      return $?
      ;;
    ubuntu)
      execute "dpkg --list | grep postgresql"
      return $?
      ;;
    *)
      print_error "$os is not supported yet."
      exit 1
      ;;
  esac  
}

function install_postgres () {
  check_if_postgres_is_installed
  if [[ $? -eq 0 ]]; then
    print_info "Package postgres is already installed. Skipping installation step."
    return
  fi
  print_info "Installing postgres..."
  case "$os" in
    centos|redhat)
      execute "$package_manager install -y postgresql postgresql-server postgresql-devel"
      if [[ $? -ne 0 ]]; then
        print_error "Failed installing postgresql-server, stopping."
        exit 1
      fi
      print_info "Initalizing postgresql db..."
      execute "service postgresql initdb"
      ;;
    ubuntu)
      execute "$package_manager install -y postgresql libpq-dev"
      if [[ $? -ne 0 ]]; then
        print_error "Failed installing postgresql, stopping."
        exit 1
      fi      
      ;;
    *)
    print_error "$os is not yet supported"
    exit 1
  esac  
}

function configure_postgres () {
  local file_change="false"
  print_info "Configuring postgres..."
  case "$os" in
    centos|redhat)
      local psql_config="/var/lib/pgsql/data/pg_hba.conf"
      local psql_data_conf="/var/lib/pgsql/data/postgresql.conf"
      sed -e "s|local *all *postgres .*|local    all         postgres                   trust|g" \
          -e "s|local *all *all .*|local    all         all                   trust|g" \
          -e "s|host *all *all *127.0.0.1/32 .*|host    all         all        127.0.0.1/32           trust|g" \
          -e "s|host *all *all *::1/128 .*|host    all         all        ::1/128           trust|g" \
          -i $psql_config      
      execute "grep puppetdb $psql_config"
      if [[ $? -ne 0 ]]; then
        file_change="true"
        echo 'host puppetdb puppetdb 0.0.0.0/0 trust' >> $psql_config
      fi
      execute "grep \"listen_addresses = '0.0.0.0'\" $psql_data_conf"
      if [[ $? -ne 0 ]]; then
        file_change="true"
        echo "listen_addresses = '0.0.0.0'" >> $psql_data_conf
      fi      
      ;;
    ubuntu)
      local psql_config="/etc/postgresql/9.*/main/pg_hba.conf"
      local psql_data_conf="/etc/postgresql/9.*/main/postgresql.conf"
      sed -e "s|local *all *postgres .*|local    all         postgres                   trust|g" \
          -e "s|local *all *all .*|local    all         all                   trust|g" \
          -e "s|host *all *all *127.0.0.1/32 .*|host    all         all        127.0.0.1/32           trust|g" \
          -e "s|host *all *all *::1/128 .*|host    all         all        ::1/128           trust|g" \
          -i $psql_config
      execute "grep puppetdb $psql_config"
      if [[ $? -ne 0 ]]; then
        file_change="true"
        echo 'host  puppetdb  puppetdb  0.0.0.0/0   trust' >> $psql_config
      fi
      execute "grep \"listen_addresses = '0.0.0.0'\" $psql_data_conf"
      if [[ $? -ne 0 ]]; then
        file_change="true"
        echo "listen_addresses = '0.0.0.0'" >> $psql_data_conf
      fi      
      ;;
    *)
    print_error "$os is not yet supported"
    exit 1
  esac
  if [[ "$file_change" = "true" ]]; then
    print_info "Restarting postgresql to reload config"
    execute "service postgresql restart"
  fi
}

function start_postgres () {
  local service="postgresql"
  local service_count=$(ps -ef | grep -v grep | grep postmaster | wc -l)
  if [[ $service_count -gt 0 && "$force_restart" = "true" ]]; then
    print_info "Restarting service $service..."
    execute "service $service restart"
  elif [[ $service_count -gt 0 ]]; then
    print_info "Service $service is already running. Skipping start step."
  else
    print_info "Starting service $service..."
    execute "service $service start"
  fi
}

function configure_postgres_users () {
  sudo -u postgres psql template1 <<END 1>>$stdout_log 2>>$stderr_log
create user puppetdb with password '$postgresql_password';
create database puppetdb with owner puppetdb;
END
}

function check_if_puppet_server_is_installed () {
  print_info "Checking to see if puppet is installed..."
  case "$os" in
    centos|redhat)
      execute "rpm -q puppet-server"
      return $?
      ;;
    ubuntu)
      execute "dpkg --list | grep puppetmaster"
      return $?
      ;;
    *)
      print_error "$os is not supported yet."
      exit 1
      ;;
  esac
}

function install_puppet_server () {
  check_if_puppet_server_is_installed
  if [[ $? -eq 0 ]]; then
    print_info "Package puppet is already installed. Skipping installation step."
    return
  fi
  add_puppetlabs_repo
  print_info "Installing puppet server package..."
  case "$os" in
    centos|redhat)
      execute "$package_manager install -y puppet-server"
      if [[ $? -ne 0 ]]; then
        print_error "Failed installing puppet-server, stopping."
        exit 1
      fi
      ;;
    ubuntu)
      execute "$package_manager install -y puppetmaster"
      if [[ $? -ne 0 ]]; then
        print_error "Failed installing puppetmaster, stopping."
        exit 1
      fi      
      ;;
    *)
    print_error "$os is not yet supported"
    exit 1
  esac
}

function configure_puppet_server () {
  local eth0_ip_address=$(ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | grep 'Bcast' | awk '{print $1}')
  local puppet_server_fqdn=$(hostname --fqdn)

  cat > /etc/puppet/puppet.conf <<END
[main]
  logdir = /var/log/puppet
  rundir = /var/run/puppet
  ssldir = \$vardir/ssl
  server = $puppet_server_fqdn

[agent]
  classdir = \$vardir/classes.txt
  localconfig = \$vardir/localconfig

END
}

function configure_hiera () {
  cat > /etc/puppet/hiera.yaml <<\HIERADELIM
---
:hierarchy:
 - %{operatingsystem}
 - common
:backends:
 - yaml
:yaml:
 :datadir: '/etc/puppet/hieradata'
HIERADELIM
  if [[ ! -d /etc/puppet/hieradata ]]; then
    mkdir -p /etc/puppet/hieradata
  fi
}

function configure_enc () {
  local enc_dir="/etc/puppet/enc"
  if [[ ! -d $enc_dir ]]; then
    mkdir -p $enc_dir
  fi
  execute "grep 'node_terminus = exec' $enc_dir"
  if [[ $? -ne 0 ]]; then
      echo "  node_terminus = exec
  external_nodes = /etc/puppet/enc/ankus_puppet_enc" >> /etc/puppet/puppet.conf
  fi
}

function configure_autosign_certificates () {
  local puppet_server_fqdn=$(hostname --fqdn)
  local domain_name=$(echo $puppet_server_fqdn | cut -d "." -f 2-)
  echo "*.${domain_name}" > /etc/puppet/autosign.conf
}

function start_puppet_server () {
  print_info "Starting puppet master service..."
  execute "puppet resource service puppetmaster ensure=running"
}

function stop_puppet_server () {
  print_info "Stopping puppet master service..."
  execute "puppet resource service puppetmaster ensure=stopped" 
}

function check_if_puppet_client_is_installed () {
  print_info "Checking to see if puppet agent is installed..."
  case "$os" in
    centos|redhat)
      execute "rpm -q puppet"
      return $?
      ;;
    ubuntu)
      execute "dpkg --list | grep puppet"
      return $?
      ;;
    *)
      print_error "$os is not supported yet."
      exit 1
      ;;
  esac
}

function install_puppet_client () {
  check_if_puppet_client_is_installed
  if [[ $? -eq 0 ]]; then
    print_info "Package puppet is already installed. Skipping installation step."
    return
  fi
  add_puppetlabs_repo
  print_info "Installing puppet agent package..."
  execute "$package_manager install -y puppet"
  if [[ $? -ne 0 ]]; then
    print_error "Failed installing puppet, stopping."
    exit 1
  fi  
}

function configure_puppet_client () {
  print_info "Configuring puppet agent..."
  cat > /etc/puppet/puppet.conf <<END
[main]
  logdir = /var/log/puppet
  rundir = /var/run/puppet
  ssldir = \$vardir/classes.txt
[agent]
  classdir = \$vardir/classes.txt
  localconfig = \$vardir/localconfig
  server = $puppet_server_hostname
  pluginsync = true
END
}

function start_puppet_client () {
  print_info "Setting up cron job to start puppet agent"
  execute "puppet resource cron puppet-agent ensure=present user=root minute=30 command='/usr/bin/puppet agent --onetime --no-daemonize --splay'"
}

function check_if_passenger_is_installed () {
  print_info "Checking if passenger is already installed..."
  execute "gem list | grep passenger"
  return $?
}

function test_puppet_run () {
  print_info "Executing test puppet run"
  execute "puppet agent --test --noop"
  if [[ $? -eq 0 ]]; then
    print_info "Sucessfully executed puppet run"
  else
    print_warning "Failed executing test puppet run"
  fi
}

function install_dependencies_for_passenger () {
  print_info "Installing dependencies for passenger..."
  case "$os" in
    centos|redhat)
      execute "$package_manager -y install httpd httpd-devel ruby-devel rubygems mod_ssl.x86_64 curl-devel openssl-devel gcc-c++ zlib-devel make"
      if [[ -f /etc/httpd/conf.d/ssl.conf ]]; then
        execute "rm -f /etc/httpd/conf.d/ssl.conf"
      fi
      if [[ -f /etc/httpd/conf.d/welcome.conf ]]; then
        execute "rm -f /etc/httpd/conf.d/welcome.conf"
      fi
      execute "chkconfig httpd on"
      ;;
    ubuntu)
      execute "$package_manager -y install apache2 ruby1.8-dev rubygems libcurl4-openssl-dev libssl-dev zlib1g-dev apache2-prefork-dev libapr1-dev libaprutil1-dev"
      execute "a2enmod ssl"
      execute "a2enmod headers"
      execute "update-rc.d -f puppetmaster remove"
      ;;
    *)
      print_error "$os is not supported yet."
      exit 1
      ;;
  esac  
}

function install_passenger () {
  check_if_passenger_is_installed
  if [[ $? -eq 0 ]]; then
    print_info "Gem passenger is already installed. Skipping installation step."
    return
  fi
  install_dependencies_for_passenger
  execute "gem install --no-rdoc --no-ri rack"
  execute "gem install --no-rdoc --no-ri passenger --version=3.0.18"
  if [[ $? -ne 0 ]]; then
    print_error "Failed installing passenger gem, stopping."
    exit 1
  fi
  print_info "Setting up passenger as apache module, this might take a while..."
  case "$os" in
    centos|redhat)
      execute "/usr/bin/passenger-install-apache2-module -a"
      ;;
    ubuntu)
      execute "/usr/local/bin/passenger-install-apache2-module -a"
      ;;
  esac    
}

function configure_passenger () {
  print_info "Configuring passenger..."
  local puppet_server_fqdn=$(hostname --fqdn)
  local puppet_server_fqdn_lowercase=$(echo $puppet_server_fqdn | tr '[:upper:]' '[:lower:]')
  local puppet_conf="/etc/puppet/puppet.conf"
  local passenger_conf
  local ruby_path
  local ruby_exec
  case "$os" in
    centos|redhat)
      passenger_conf="/etc/httpd/conf.d/puppet.conf"
      ruby_path="/usr/lib/ruby"
      ruby_exec="/usr/bin/ruby"
      ;;
    ubuntu)
      passenger_conf="/etc/apache2/sites-available/puppetmasterd"
      ruby_path="/var/lib"
      ruby_exec="/usr/bin/ruby1.8"
      ;;
  esac
  execute "grep ssl_client_header $puppet_conf"
  if [[ $? -ne 0 ]]; then  
    cat >> $puppet_conf <<DELIM
[master]
  ssl_client_header = SSL_CLIENT_S_DN
  ssl_client_verify_header = SSL_CLIENT_VERIFY  
DELIM
  fi
  cat > $passenger_conf <<DELIM
# you probably want to tune these settings
PassengerHighPerformance on
PassengerMaxPoolSize 12
PassengerPoolIdleTime 1500
# PassengerMaxRequests 1000
PassengerStatThrottleRate 120
RackAutoDetect Off
RailsAutoDetect Off

Listen 8140

<VirtualHost *:8140>
        LoadModule passenger_module ${ruby_path}/gems/1.8/gems/passenger-3.0.18/ext/apache2/mod_passenger.so
        PassengerRoot ${ruby_path}/gems/1.8/gems/passenger-3.0.18
        PassengerRuby ${ruby_exec}
        LoadModule ssl_module modules/mod_ssl.so

        SSLEngine on
        SSLProtocol -ALL +SSLv3 +TLSv1
        SSLCipherSuite ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:-LOW:-SSLv2:-EXP

        SSLCertificateFile      /var/lib/puppet/ssl/certs/${puppet_server_fqdn_lowercase}.pem
        SSLCertificateKeyFile   /var/lib/puppet/ssl/private_keys/${puppet_server_fqdn_lowercase}.pem
        SSLCertificateChainFile /var/lib/puppet/ssl/ca/ca_crt.pem
        SSLCACertificateFile    /var/lib/puppet/ssl/ca/ca_crt.pem
        # If Apache complains about invalid signatures on the CRL, you can try disabling
        # CRL checking by commenting the next line, but this is not recommended.
        SSLCARevocationFile     /var/lib/puppet/ssl/ca/ca_crl.pem
        SSLVerifyClient optional
        SSLVerifyDepth  1
        SSLOptions +StdEnvVars

        # This header needs to be set if using a loadbalancer or proxy
        RequestHeader unset X-Forwarded-For

        RequestHeader set X-SSL-Subject %{SSL_CLIENT_S_DN}e
        RequestHeader set X-Client-DN %{SSL_CLIENT_S_DN}e
        RequestHeader set X-Client-Verify %{SSL_CLIENT_VERIFY}e

        DocumentRoot /usr/share/puppet/rack/puppetmasterd/public
        RackBaseURI /
        <Directory /usr/share/puppet/rack/puppetmasterd/>
                Options None
                AllowOverride None
                Order allow,deny
                allow from all
        </Directory>
</VirtualHost>
DELIM
  # tell rack how to spawn puppet master processes
  if [[ ! -d /usr/share/puppet/rack/puppetmasterd ]]; then
    execute "mkdir -p /usr/share/puppet/rack/puppetmasterd/{public,tmp}"
    if [[ ! -f /usr/share/puppet/rack/puppetmasterd/config.ru ]]; then
      execute "cd /usr/share/puppet/rack/puppetmasterd/ && curl -O https://raw.github.com/puppetlabs/puppet/master/ext/rack/config.ru"
      execute "chown puppet:puppet /usr/share/puppet/rack/puppetmasterd/config.ru"
    fi
  fi
  print_info "Restarting apache to reload config..."
  case "$os" in
    centos|redhat)
      execute "service httpd restart"
      ;;
    ubuntu)
      execute "a2ensite puppetmasterd"
      execute "service apache2 restart"
      ;;
  esac
}

function check_passenger_status () {
  execute "netstat -plunt | grep 8140"
  if [[ $? -eq 0 ]]; then
    print_info "Puppet server is running through passenger..."
  else
    print_error "Puppet server failed starting using passenger. Exiting"
    exit 1
  fi
}

function restart_apache () {
  print_info "Restarting apache to reload config..."
  case "$os" in
    centos|redhat)
      execute "service httpd restart"
      ;;
    ubuntu)
      execute "a2ensite puppetmasterd"
      execute "service apache2 restart"
      ;;
  esac
}

function check_if_puppetdb_is_installed () {
  print_info "Checking to see if puppetdb is installed..."
  case "$os" in
    centos|redhat)
      execute "rpm -q puppetdb"
      return $?
      ;;
    ubuntu)
      execute "dpkg --list | grep puppetdb"
      return $?
      ;;
    *)
      print_error "$os is not supported yet."
      exit 1
      ;;
  esac  
}

function install_puppetdb () {
  check_if_puppetdb_is_installed
  if [[ $? -eq 0 ]]; then
    print_info "Package puppetdb is already installed. Skipping installation step."
    return
  fi
  print_info "Installing puppetdb package"
  execute "$package_manager -y install puppetdb puppetdb-terminus"
  if [[ $? -ne 0 ]]; then
    print_error "Failed installing puppetdb, stopping."
    exit 1
  fi
}

function configure_puppetdb () {
  local puppetdb_default
  local puppet_server_fqdn=$(hostname --fqdn)
  case "$os" in
    centos|redhat)
      puppetdb_default="/etc/sysconfig/puppetdb"
      ;;
    ubuntu)
      puppetdb_default="/etc/default/puppetd"
      ;;
    *)
      print_error "$os is not supported yet."
      exit 1
      ;;
  esac
  cat > ${puppetdb_default} <<PUPPETDBDELIM
JAVA_BIN="/usr/bin/java"
JAVA_ARGS="${puppetdb_jvm_size} -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/var/log/puppetdb/puppetdb-oom.hprof "
USER="puppetdb"
INSTALL_DIR="/usr/share/puppetdb"
CONFIG="/etc/puppetdb/conf.d"
PUPPETDBDELIM

  cat > /etc/puppetdb/conf.d/database.ini <<PUPPETDBDELIM
[database]
classname = org.postgresql.Driver
subprotocol = postgresql
subname = //localhost:5432/puppetdb
username = puppetdb
password = ${postgresql_password}
# gc-interval = 60
log-slow-statements = 10
PUPPETDBDELIM

  # configure Jetty to listen on 8085 and ssl on 8086
  sed -i s/port\ \=\ 8080/port\ \=\ 8085/g  /etc/puppetdb/conf.d/jetty.ini
  sed -i s/ssl-port\ \=\ 8081/ssl-port\ \=\ 8086/g  /etc/puppetdb/conf.d/jetty.ini

  # install plugin to connect puppet master to puppetdb
  cat > /etc/puppet/puppetdb.conf <<DELIM
[main]
server = $puppet_server_fqdn
port = 8086
DELIM
  execute "grep 'storeconfigs = true' /etc/puppet/puppet.conf"
  if [[ $? -ne 0 ]]; then
    echo "  storeconfigs = true" >> /etc/puppet/puppet.conf
  fi
  execute "grep 'storeconfigs_backend = puppetdb' /etc/puppet/puppet.conf"
  if [[ $? -ne 0 ]]; then
    echo "  storeconfigs_backend = puppetdb" >> /etc/puppet/puppet.conf
  fi
  
  # make PuppetDB the authoritative source for the inventory service.
  cat > /etc/puppet/routes.yaml <<\DELIM
---
master:
 facts:
  terminus: puppetdb
  cache: yaml
DELIM

  # puppetdb ssl configuration script
  execute "puppetdb-ssl-setup"
}

function start_puppetdb () {
  local service="puppetdb"
  local service_count=$(ps -ef | grep -v grep | grep java | grep $service | wc -l)
  if [[ $service_count -gt 0 && "$force_restart" = "true" ]]; then
    print_info "Restarting service $service..."
    execute "service $service restart"
  elif [[ $service_count -gt 0 ]]; then
    print_info "Service $service is already running. Skipping start step."
  else
    print_info "Starting service $service..."
    execute "service $service start"
  fi
}

function pause_till_puppetdb_starts () {
  print_info "Waiting till puppetdb service starts up"
  timeout 60s bash -c '
while : ; do
 grep "Started SslSelectChannelConnector@" /var/log/puppetdb/puppetdb.log &>/dev/null && break
 sleep 1
done
'
  if [ $? -eq 124 ]; then
    print_error "Raised Timeout waiting for puppetdb to listen"
    exit 22
  else
    print_info "PuppetDB started successfully"
  fi
}

####
## Main
####

declare puppet_server_setup
declare puppet_client_setup
declare puppetdb_setup
declare passenger_setup
declare autosigning_enabled
declare puppetdb_jvm_size
declare postgresql_password
declare puppet_server_hostname
declare setup_puppet_cron_job
declare wait_for_puppetdb

function usage () {
  script=$0
  cat <<USAGE
Syntax
`basename ${script}` -s -c -d -p -a -j -J {-Xmx512m|-Xmx256m} -P {psql_password} -H {ps_hostname} -h

-s: puppet server setup
-c: puppet client setup
-d: setup puppetdb for stored configurations
-p: install and configure passenger which runs puppet master as a rack application inside apache
-a: set up auto signing for the same clients belonging to same domain
-j: set up cron job for running puppet agent every 30 minutes
-w: wait till puppetdb starts
-J: JVM Heap Size for puppetdb
-P: postgresql password for puppetdb|postgres user
-H: puppet server hostname (required for client setup)
-h: show help

Examples:
Install puppet server with all defaults:
`basename $script` -s
Install puppet server with puppetdb and passenger:
`basename $script` -s -p -d
Install puppet client:
`basename $script` -c -H {puppet_server_hostname}

USAGE
  exit 1
}

function check_variables () {
  print_info "Checking command line & user-defined variables for any errors..."

  if [[ "$puppet_client_setup" = "true" ]]; then
    if [[ -z $puppet_server_hostname ]]; then
      print_error "Option puppet client setup (-c) requires to pass puppet server hostname using (-H)"
      echo
      usage
      exit 1
    fi
  fi
  if [[ "$puppetdb_setup" = "true" ]]; then
    if [[ -z $puppetdb_jvm_size ]]; then
      print_warning "PuppetDB JVM size not set, default value of '-Xmx192m' will be used"
      puppetdb_jvm_size="-Xmx192m"
    fi
    if [[ -z $postgresql_password ]]; then
      print_warning "Postgresql password for puppetdb user not set, default value of 'Change3E' will be used"
      postgresql_password="Change3E"
    fi    
  fi
}

function main () {
  trap "kill 0" SIGINT SIGTERM EXIT

  # parse command line options
  while getopts J:P:H:scdpajwh opts
  do
    case $opts in
      s)
        puppet_server_setup="true"
        ;;
      c)
        puppet_client_setup="true"
        ;;
      d)
        puppetdb_setup="true"
        ;;
      p)
        passenger_setup="true"
        ;;
      a)
        autosigning_enabled="true"
        ;;
      j)
        setup_puppet_cron_job="true"
        ;;
      w)
        wait_for_puppetdb="true"
        ;;
      J)
        puppetdb_jvm_size=$OPTARG
        ;;
      P)
        postgresql_password=$OPTARG
        ;;
      H)
        puppet_server_hostname=$OPTARG
        ;;
      h)
        usage
        ;;        
      \?)
        usage
        ;;
    esac
  done

  print_banner
  check_variables
  local start_time="$(date +%s)"
  get_system_info
  check_preqs
  stop_iptables
  stop_selinux
  if [[ "$puppet_server_setup" = "true" ]]; then
    install_puppet_server
    configure_puppet_server
    if [[ "$autosigning_enabled" = "true" ]]; then
      configure_autosign_certificates
    fi
    start_puppet_server
    if [[ "$passenger_setup" = "true" ]]; then
      stop_puppet_server
      install_passenger
      configure_passenger
      check_passenger_status
    fi
    if [[ "$puppetdb_setup" = "true" ]]; then
        install_postgres
        configure_postgres
        start_postgres
        configure_postgres_users
        install_puppetdb
        configure_puppetdb
        start_puppetdb
        if [[ "$wait_for_puppetdb" = "true" ]]; then
          pause_till_puppetdb_starts
        fi
    fi
    test_puppet_run
    download_modules
    install_puppet_apt_module
    configure_hiera
    configure_enc
    if [[ "$passenger_setup" = "true" ]]; then
      restart_apache
    else
      execute "service puppetmaster restart"
    fi
  elif [[ "$puppet_client_setup" = "true" ]]; then
    install_puppet_client
    configure_puppet_client
    if [[ "$setup_puppet_cron_job" = "true" ]]; then
      start_puppet_client
    fi
  else
    print_error "Invalid script options, should wither pass -s or -c option"
    usage
    exit 1
  fi
  local end_time="$(date +%s)"
  print_info "Execution complete. Time took: $((end_time - start_time)) second(s)"
}

main $@