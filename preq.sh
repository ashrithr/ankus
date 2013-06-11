#!/usr/bin/env bash

# ---
# Convenience wrapper to install ankuscli
# ---

#TODO handle ubuntu as well
apt-get install -y ruby1.8-dev ruby1.8 ri1.8 rdoc1.8 irb1.8 libreadline-ruby1.8 libruby1.8 libopenssl-ruby \
                   libxslt-dev libxml2-dev gcc make
yum -y install git ruby rubygems gcc ruby-devel libxml2 libxml2-devel libxslt libxslt-devel make
gem install bundle --no-ri --no-rdoc
cd ~ && git clone git://github.com/ashrithr/ankus-cli.git
cd ankus-cli && bundle install
