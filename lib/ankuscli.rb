require 'socket'
require 'fileutils'
require 'yaml'
require 'pp'
require 'tempfile'
require 'benchmark'
require 'thread'
begin
  require 'thor'
  require 'thor/group'
  require 'multi_json'
  require 'fog'
  require 'colored'
  require 'highline/import'
rescue LoadError
  puts 'Failed to load gems: fog, highline, thor, multi_json'
  puts <<-EOF
    Install the gems using:
    `gem install fog`
    `gem install thor`
    `gem install colored`
    `gem install multi_json`
    `gem install highline`
  EOF
  exit 1
end

module Ankuscli
  require 'ankuscli/version'
  require 'ankuscli/helper'
  require 'ankuscli/config_parser'
  require 'ankuscli/cli'
  require 'ankuscli/inventory'
  require 'ankuscli/utils'
  require 'ankuscli/cloud_init'
  require 'ankuscli/cloud_manage'
  require 'ankuscli/deploy'
end