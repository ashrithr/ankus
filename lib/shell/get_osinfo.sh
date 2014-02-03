#!/bin/bash
#
# Author:: Ashrith Mekala (<ashrith@cloudwick.com>)
# Description:: Helper script to detect OS type
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

OS=''
VER=''
INSTALL=''
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

echo "${OS}, ${VER}, ${ARCH}"