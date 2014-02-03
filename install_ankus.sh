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

OS=`uname -s`
REV=`uname -r`
MACH=`uname -m`

GetVersionFromFile()
{
  VERSION=`cat $1 | tr "\n" ' ' | sed s/.*VERSION.*=\ // `
}

if [ "${OS}" == "SunOS" ] ; then
  OS=Solaris
  ARCH=`uname -p`
  OSSTR="${OS} ${REV}(${ARCH} `uname -v`)"
elif [ "${OS}" == "AIX" ] ; then
  OSSTR="${OS} `oslevel` (`oslevel -r`)"
elif [ "${OS}" == "Linux" ] ; then
  KERNEL=`uname -r`
  if [ -f /usr/bin/lsb_release ] ; then
    OS=$( lsb_release -sd | tr '[:upper:]' '[:lower:]' | tr '"' ' ' | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } print $i; } }' )
    VER=`lsb_release -sd | tr '[:upper:]' '[:lower:]' | tr '"' ' ' | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } } }'`
  else
    OS=$( cat `ls /etc/*release | grep "redhat\|SuSE"` | head -1 | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } print $i; } }' | tr '[:upper:]' '[:lower:]' )
    VER=`cat \`ls /etc/*release | grep "redhat\|SuSE"\` | head -1 | awk '{ for(i=1; i<=NF; i++) { if ( $i ~ /[0-9]+/ ) { cnt=split($i, arr, "."); if ( cnt > 1) { print arr[1] } else { print $i; } break; } } }' | tr '[:upper:]' '[:lower:]'`
  fi
  OS=`echo ${OS} | sed -e "s/ *//g"`
  ARCH=`uname -m`
  if [[ "xi686" == "x${ARCH}" || "xi386" == "x${ARCH}" ]]; then
    ARCH="i386"
  fi
  if [[ "xx86_64" == "x${ARCH}" || "xamd64" == "x${ARCH}" ]]; then
    ARCH="x86_64"
  fi
  OSSTR="${OS} ${VER} ${ARCH}"
elif [ "${OS}" == "Darwin" ]; then
  command -v sw_vers >/dev/null
  [ $? -eq 0 ] && {
    OS=`sw_vers | grep 'ProductName' | cut -f 2`;
    VER=`sw_vers | grep 'ProductVersion' | cut -f 2`;
    BUILD=`sw_vers | grep 'BuildVersion' | cut -f 2`;
    OSSTR="Darwin ${OS} ${VER} ${BUILD}";
  } || {
    OSSTR="MacOSX";
  }
fi

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
  MAC_VERSION=`/usr/bin/sw_vers -productVersion | cut -d. -f1,2`
  echo "Requires XCODE"
  if echo "${MAC_VERSION}<10.7" | bc -q >/dev/null
  then
    echo "Install XCODE from https://developer.apple.com/xcode/"
  else
    echo "Install the 'Command Line Tools for Xcode': http://connect.apple.com"
  fi
}

function install_preqs () {
  #Validate OS
  if [[ $OSSTR =~ centos || $OSSTR =~ redhat ]]; then
    echo "[*]  RedHat based system detected"
    INSTALL="yum"
    yum -y install git gcc ruby-devel libxml2 libxml2-devel libxslt \
                   libxslt-devel make curl
  elif [[ $OSSTR =~ ubuntu ]]; then
    echo "[*] Debian based system detected"
    INSTALL="apt-get"
    apt-get install -y build-essential libxml2-dev libxslt1-dev \
                       libreadline-dev zlib1g-dev git curl
  elif [[ $OSSTR =~ Darwin ]]; then
    echo "[*] Mac based system detected"
    echo "[*] Checking if C compiler is installed or not"
    command -v cc >/dev/null && {
      echo "[*] Found C compiler at `command -v cc`";
    } || {
      echo "[*] Cannot Find C compiler";
      mac_version_xcode;
      exit;
    }
    echo "[*] Installing HomeBrew"
    ruby -e "$(curl -fsSL https://raw.github.com/mxcl/homebrew/go)"
    command -v git >/dev/null || {
      echo "[*] Installing git"
      brew install git;
    }
    echo "[*] Installing xml libraries (libxml2 & libxslt)"
    brew install libxml2 libxslt
    brew link libxml2 libxslt
  else
    echo "[Error]: ${OS} is not supported"
    exit 1
  fi
}

function install_rvm () {
  echo "[*] Installing RVM (Ruby Version Manager)"
  curl -L get.rvm.io | bash -s stable
  [ -f /etc/profile.d/rvm.sh ] && source /etc/profile.d/rvm.sh || source ~/.rvm/scripts/rvm
  [ -f ~/.bashrc ] && echo 'source ~/.rvm/scripts/rvm' >> ~/.bashrc || echo 'source ~/.rvm/scripts/rvm' > ~/.bashrc
}

function install_ruby_193 () {
  echo "[*] Installing Ruby 1.9.3"
  # RVM=~/.rvm/bin/rvm
  source ~/.bashrc
  rvm requirements --verify-downloads 1
  rvm install 1.9.3
  rvm use 1.9.3
  rvm rubygems current
}

function install_ankus () {
  echo "[*] Installing Ankus to " ~
  cd ~ && git clone git://github.com/ashrithr/ankus.git
  gem install bundle --no-ri --no-rdoc
  cd ankus && bundle install
}

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