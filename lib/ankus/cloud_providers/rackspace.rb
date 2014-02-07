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
  class Rackspace
    # @param [String] api_key => rackspace api_key to use
    # @param [String] user_name => rackspace username to use
    # @param [Log4r] log => logger object to use for logging
    # @param [Boolean] mock => whether to enable mocking
    def initialize(api_key, user_name, log, mock = false)
      @rackspace_api_key = api_key
      @rackspace_username = user_name
      @centos_image_id = 'da1f0392-8c64-468f-a839-a9e56caebf07' #CentOS 6.3 @ dfw
      @ubuntu_image_id = 'e4dbdba7-b2a4-4ee5-8e8f-4595b6d694ce' #ubuntu 12.04 LTS @ dfw
      @log = log
      @mock = mock
    end

    # Creates a new rackspace connection object with provided credentials
    # @return [Fog::Compute] fog compute object
    def create_connection
      Fog::Compute.new({
                           :provider           => 'Rackspace',
                           :rackspace_username => @rackspace_username,
                           :rackspace_api_key  => @rackspace_api_key,
                           :version            => :v2
                       })
    rescue Excon::Errors::Unauthorized
      @log.error 'Invalid Rackspace Credentials'
      exit 1
    end

    # Validates the connection object
    # @param [Fog::Compute] conn => fog connection object to authenticate
    def valid_connection?(conn)
      conn.authenticate
      true
    rescue
      false
    end

    # Create a new server and inject provided ssh_key into instance
    # @param [Fog::Compute::RackspaceV2::Real] conn => fog rackspace connection object
    # @param [String] name => fqdn of the server being created
    # @param [String] ssh_key_path => path of the ssh public key that is used to ssh into the server
    # @param [String] type => instance size being created
    # @param [String] os_type => type of os to boot, supported values: CentOS|Ubuntu
    # @return [Fog::Compute::RackspaceV2::Server] server object
    def create_server!(conn, name, ssh_key_path, type, os_type)
      case os_type.downcase
        when 'centos'
          server = conn.servers.create(
              :name => name,
              :flavor_id => type,
              :image_id => @centos_image_id,
              :personality => [
                  {
                      :path => '/root/.ssh/authorized_keys',
                      :contents => Base64.encode64(File.read(File.expand_path(ssh_key_path)))
                  }
              ]
          )
          # reloading will assign random public and private ip addresses if mocking
          server.reload if @mock
          return server
        when 'ubuntu'
          server = conn.servers.create(
              :name => name,
              :flavor_id => type,
              :image_id => @ubuntu_image_id,
              :personality => [
                  {
                      :path => '/root/.ssh/authorized_keys',
                      :contents => Base64.encode64(File.read(File.expand_path(ssh_key_path)))
                  }
              ]
          )
          server.reload if @mock
          return server
        else
          @log.error 'OS not yet supported, contact support@cloudwick.com'
          exit 2
      end
    end

    # Create multiple servers
    # @param [Fog::Compute::RackspaceV2::Real] conn => rackspace connection object to use for creating server
    # @param [Integer] count => number of servers to create
    # @options [Hash] opts:
    #   @option [String] name_tag => fqdn to build upon, ex: if given slave.cw.com, this gets expanded to slave[1..count].cw.com
    #   @option [String] ssh_key_path => path of the ssh public key that is used to ssh into the server
    #   @option [String] type => instance size being created (2-512MB, 3-1GB, 4-2GB, 5-4GB, 6-8GB, 7-15GB, 8-30GB)
    #   @option [String] os_type => type of the os to boot into instance (CentOS|Ubuntu)
    # @return [Array] servers => array of servers object (Fog::Compute::RackspaceV2::Server)
    def create_servers!(conn, count, opts = {})
      options = {
          :name_tag     => 'slave.ankus.com',
          :ssh_key_path => '~/.ssh/id_rsa.pub',
          :type         => '4',
          :os_type      => 'CentOS',
      }.merge(opts)
      servers = []
      server_name, domain_name = options[:name_tag].split('.',2)
      count.times do |i|
        servers << create_server!(conn, "#{server_name}#{i}.#{domain_name}", options[:ssh_key_path], options[:type], options[:os_type])
      end
      servers
    end

    # Waits until all the servers got booted
    # @param [Array] servers => array of fog server objects (Fog::Compute::RackspaceV2::Server)
    # (or)
    # [Fog::Compute::RackspaceV2::Server] servers => single server object
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

    # Creates and attaches specified number of volumes to the instance provided
    # @param [Fog::Compute::RackspaceV2::Server] server => rackspace server object to which the instance should be attached to
    # @param [Integer] volumes => number of volumes to create
    # @param [Integer] size => size of each volume in GB
    # @return nil
    # @see there is a limitation on size of the volume being created, it should be between 100-1024GB
    def attach_volumes!(server, volumes, size)
      #create a new blockstorage connection obj
      block_storage = Fog::Rackspace::BlockStorage.new(
          {
              :rackspace_username => @rackspace_username,
              :rackspace_api_key  => @rackspace_api_key
          }
      )
      base = 'sdd'
      volumes.times do |i|
        base = base.next!
        #create a new volume
        vol = block_storage.volumes.new(:size => size, :display_name => "#{server.name}#{i}")
        vol.save
        #wait for the volume to get created
        vol.wait_for { ready? }
        #attach the volume to the instance provided
        server.attach_volume(vol, "/dev/#{base}")
        #wait until the attaching process is complete
        vol.wait_for { attached? }
      end
    end

    # Check's the status of the volume, raises exception if volume is still 'in-use'
    # @param [Fog::Rackspace::BlockStorage::Volume] bs => instance of blockstore class
    # @param [String] vol_id => id of the volume to verify the status
    def vol_status!(bs, vol_id)
      status = bs.get_volume(vol_id).body['volume']['status']
      unless status == 'available'
        # puts "vol status is not 'available' it is '#{status}' instead"
        @log.error "volume #{vol_id} is not available to delete"
        exit 2
      end
    end

    # Wait's until the volume get detached (or becomes available to delete), Timeout's at specified time
    # @param [Fog::Rackspace::BlockStorage::Volume] bs => instance of blockstore class
    # @param [String] vol_id => id of the volume to verify the status
    # @param [Integer] timeout => number of seconds in which to raise timeout
    def wait_for_vol(bs, vol_id, timeout = 120)
      Timeout::timeout(timeout) do
        begin
          vol_status! bs, vol_id
        rescue
          @log.debug 'sleeping for 5 seconds'
          sleep 5
          retry
        end
      end
    rescue Timeout::Error
      @log.error 'It took more than a min for a volume to become available'
    end

    # Delete a server based on it's fully qualified domain name (or) name given while booting instance
    # @param [Fog::Compute::RackspaceV2::Real] conn => connection object to rackspace
    # @param [String] fqdn => name of the server to delete
    # @param [Boolean] delete_volumes => whether to delete volumes attached to instance or not
    def delete_server_with_name(conn, fqdn, delete_volumes = false)
      conn.servers.all.each do |server|
        if server.name == fqdn
          @log.info "Deleting instance with fqdn: #{fqdn}\n"
          server.destroy
          if delete_volumes
            # create a new block storage connection obj
            block_storage = Fog::Rackspace::BlockStorage.new(
                {
                    :rackspace_username => @rackspace_username,
                    :rackspace_api_key  => @rackspace_api_key
                }
            )
            @log.info "Deleting volumes attached to instance: #{fqdn}\n"
            volumes_to_del = block_storage.list_volumes.body['volumes'].map do |v|
              v['id'] if v['display_name'] =~ /#{fqdn}/
            end
            if volumes_to_del.is_a?(Array) && volumes_to_del.length != 0
              volumes_to_del.each do |vol_id|
                @log.info "Waiting for volume to detach from instance: #{fqdn}\n"
                wait_for_vol(block_storage, vol_id)
                block_storage.delete_volume(vol_id)
              end
            else
              @log.info "No volumes found for the instance #{fqdn}\n"
            end
          end
        end
      end
    end
  end
end