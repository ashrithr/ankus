require 'socket'
require 'fileutils'
require 'yaml'
begin
  require 'thor'
  require 'thor/group'
  #require 'fog'
  require 'colored'
rescue LoadError
  puts 'Failed to load gems: fog, highline, thor'
  puts <<-EOF
    Install the gems using:
    `gem install fog`
    `gem install thor`
    `gem install colored`
  EOF
  exit 1
end

module Ankuscli
  require 'ankuscli/version'
  require 'ankuscli/config_parser'
  require 'ankuscli/cli'
  require 'ankuscli/inventory'
  require 'ankuscli/utils'
  require 'ankuscli/cloud_init'
  require 'ankuscli/cloud_manage'
  require 'ankuscli/deploy'
  require 'ankuscli/helper'
  require 'ankuscli/version'
end