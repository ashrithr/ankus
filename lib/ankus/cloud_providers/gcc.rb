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
module Ankus
  class Gcc
    # @param [String] gcc_project_name name of the project from which resources should be allocated
    # @param [String] gcc_client_email client authentication email use to validate
    # @param [String] gcc_key_path path where the use has downloaded key to
    # @param [Log4r] log => logger object to use for logging
    # @param [Boolean] mock => whether to enable mocking
    # @see To get following credentials go to `https://code.google.com/apis/console/` Navigate to
    #   'APIs & Auth' then to  'Credentials' and create a new service account by using 'Create new client ID'
    #   and select 'Service Account'. Once created a service account user can acquire the key and email address.
    def initialize(gcc_project_name, gcc_client_email, gcc_key_path, log, mock = false)
      @gcc_project_name = gcc_project_name
      @gcc_client_email = gcc_client_email
      @gcc_key_path = gcc_key_path
      @log = log
      @mock = mock
    end

    # Creates a openstack connection object with provided credentials
    def create_connection
      Fog::Compute.new({
                           :provider            => 'google',
                           :google_project      => @gcc_project_name,
                           :google_client_email => @gcc_client_email,
                           :google_key_location => @gcc_key_path
                       })
    rescue Excon::Errors::Unauthorized => ex
      @log.error 'Invalid Google Cloud Compute Credentials' + ex.message
      @log.error ex.backtrace
      exit 1
    rescue Excon::Errors::BadRequest => ex
      @log.error 'Malformed connection options' + JSON.parse(ex.response.body)['badRequest']['message']
      @log.error ex.backtrace
    end

    # Validates the connection object by running a simple request on the object
    # @param [Fog::Compute::OpenStack::Real] conn => fog openstack connection object
    # @return [boolean] true if connection succeeds to openstack using fog, false if cannot
    def valid_connection?(conn)
      conn.servers.length
      true
    rescue Excon::Errors::Forbidden, Excon::Errors::Unauthorized
      false
    end

    # Create a new server
    # @param conn => fog google connection object
    # @param [String] name => fqdn of the server being created
    # @param [String] zone_name => name of the zone in which server instance will be created
    # @param [String] type => instance size being created
    # @param [String] image_name => name of the image to boot
    # @return [Fog::Compute::Google::Server] server object
    #noinspection RubyStringKeysInHashInspection
    def create_server!(conn, name, zone_name, type, image_name)
      image = conn.images.find { |i| i.name == image_name }
      flavor = conn.flavors.find { |f| f.name == type }
      server = conn.servers.create(
          :name => name,
          :machine_type => flavor.id,
          :image_name => image.id,
          :zone_name => zone_name
      )
      # TODO: apply logic for mocking
      if @mock
        next
      end
      server
    end

    # Waits until all the servers get booted
    # @param [Array] servers => array of fog server objects (Fog::Compute::Google::Server)
    # (or)
    # [Fog::Compute::Google::Server] server => single server object
    # @return nil
    def wait_for_servers(servers)
      if servers.is_a?(Array)
        servers.each do |server|
          # check every 5 seconds to see if the server is in the active state for 1800 seconds if not exception
          # will be raised Fog::Errors::TimeoutError
          server.wait_for(1800, 5) do
            ready?
          end
        end
      else
        server.wait_for(1800, 5) do
          print '.'
          STDOUT.flush
          ready?
        end
        puts
      end
    end
  end
end