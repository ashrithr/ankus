#!/usr/bin/env bash

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

# ---
# Convenience wrapper to install ankus
# ---

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

OS=`uname -s`
REV=`uname -r`
MACH=`uname -m`

####
## Utility functions
####

function get_system_info () {
  os=`uname -s`
  if [[ "$os" = "SunOS" ]] ; then
    os="Solaris"
    os_arch=`uname -p`
  elif [[ "$os" = "Linux" ]] ; then
    if [[ -f /etc/redhat-release ]]; then
      os_str=$( cat `ls /etc/*release | grep "redhat\|SuSE"` | head -1 | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } print $i; } }' | tr '[:upper:]' '[:lower:]' )
      os_version=$( cat `ls /etc/*release | grep "redhat\|SuSE"` | head -1 | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } } }' | tr '[:upper:]' '[:lower:]')
      if [[ $os_str =~ centos ]]; then
        os="centos"
      elif [[ $os_str =~ red ]]; then
        os="redhat"
      else
        echo "OS: $os_str is not yet supported, contact support@cloudwicklabs.com"
        exit 1
      fi
    elif [[ -f /etc/lsb-release ]] ; then
      os_str=$( lsb_release -sd | tr '[:upper:]' '[:lower:]' | tr '"' ' ' | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } print $i; } }' )
      os_version=$( lsb_release -sd | tr '[:upper:]' '[:lower:]' | tr '"' ' ' | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } } }')
      if [[ $os_str =~ ubuntu ]]; then
        os="ubuntu"
        if grep -q precise /etc/lsb-release; then
          os_codename="precise"
        elif grep -q lucid /etc/lsb-release; then
          os_codename="lucid"
        else
          echo "Sorry, only precise & lucid systems are supported by this script. Exiting."
          exit 1
        fi
      else
        echo "OS: $os_str is not yet supported, contact support@cloudwicklabs.com"
        exit 1
      fi
    else
      echo "OS: $os_str is not yet supported, contact support@cloudwicklabs.com"
      exit 1
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
      os_arch=`arch`
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
    echo "Unsupported package manager. Please contact support@cloudwicklabs.com."
    exit 1
  fi

  echo "Detected OS: ${os}, Ver: ${os_version}, Arch: ${os_arch}"
}

function float_cond () {
  local cond=0
  if [[ $# -gt 0 ]]; then
    cond=$(echo "$*" | bc -q 2>/dev/null)
    if [[ -z "$cond" ]]; then cond=0; fi
    if [[ "$cond" != 0  &&  "$cond" != 1 ]]; then cond=0; fi
  fi
  local stat=$((cond == 0))
  return $stat
}

function mac_version_xcode () {
  local mac_version=`/usr/bin/sw_vers -productVersion | cut -d. -f1,2`
  echo "Requires XCODE"
  if echo "${mac_version}<10.7" | bc -q >/dev/null; then
    echo "Install XCODE from https://developer.apple.com/xcode/"
  else
    echo "Install the 'Command Line Tools for Xcode': http://connect.apple.com"
  fi
}

function install_preqs () {
  #Validate OS
  if [[ $os =~ centos || $os =~ redhat ]]; then
    sudo yum -y install git gcc ruby-devel libxml2 libxml2-devel libxslt \
                   libxslt-devel make curl
  elif [[ $os =~ ubuntu ]]; then
    sudo apt-get install -y build-essential libxml2-dev libxslt1-dev \
                       libreadline-dev zlib1g-dev git curl
  elif [[ $os =~ macosx ]]; then
    echo "[*] Checking if C compiler is installed or not"
    command -v cc >/dev/null && {
      echo "[*] Found C compiler at `command -v cc`";
    } || {
      echo "[*] Cannot Find C compiler";
      mac_version_xcode;
      exit;
    }
    command -v brew > /dev/null && {
      echo "[*] Found brew installed at `command -v brew`";
    } || {
      echo "[*] Installing HomeBrew";
      ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)";
    }
    command -v git >/dev/null && {
      echo "[*] Found git installed at `command -v git`";
    } || {
      echo "[*] Installing git";
      brew install git;
    }
    brew list | grep libxml2 &> /dev/null
    if [[ $? -eq 0 ]]; then
      echo "[*] Found libxml2, libxslt installed using brew"
    else
      echo "[*] Installing xml libraries (libxml2 & libxslt)"
      brew install libxml2 libxslt
      brew link libxml2 libxslt
    fi
  else
    echo "[Error]: ${OS} is not supported"
    exit 1
  fi
}

function install_rvm () {
  command -v rvm > /dev/null && {
    echo "[*] Found rvm installed at `command -v brew`";
  } || {
    echo "[*] Installing RVM (Ruby Version Manager)";
    curl -sSL https://get.rvm.io | bash -s stable;
    [ -f /etc/profile.d/rvm.sh ] && source /etc/profile.d/rvm.sh || source ~/.rvm/scripts/rvm;
    [ -f ~/.bashrc ] && echo 'source ~/.rvm/scripts/rvm' >> ~/.bashrc || echo 'source ~/.rvm/scripts/rvm' > ~/.bashrc;
  }
}

function install_ruby_193 () {
  echo "[*] Installing Ruby 1.9.3 using rvm"
  # RVM=~/.rvm/bin/rvm
  rvm list | grep 1.9.3 &> /dev/null
  if [[ $? -eq 0 ]]; then
    echo "[*] Already have ruby 1.9.3 installed using rvm"
  else
    source ~/.bashrc
    rvm requirements --verify-downloads 1
    rvm install 1.9.3
    rvm use 1.9.3
    rvm rubygems current
  fi
}

function install_ankus () {
  echo "[*] Installing Ankus to ${HOME}"
  cd ~ && git clone git://github.com/ashrithr/ankus.git
  gem install bundle --no-ri --no-rdoc
  cd ankus && bundle install
}

####
## Main
####

get_system_info
install_preqs
install_rvm
install_ruby_193
install_ankus

echo "[*] Installing Ankus completed"
echo 'The following line is added to start-up script "~/.bashrc"

"source ~/.rvm/scripts/rvm"

to make sure rvm loads correctly. Make sure to source that file before running ankus.
'

echo 'To run ankus:
source ~/.bashrc && rvm use 1.9.3 --default
~/ankus/bin/ankus
'
