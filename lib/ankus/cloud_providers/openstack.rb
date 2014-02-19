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
  class Openstack
    # @param [String] os_auth_url openstack auth url (ex: http://192.168.236.11:5000/v2.0/tokens)
    # @param [String] os_username openstack username (ex: admin)
    # @param [String] os_password openstack password (ex: secrete)
    # @param [String] os_tenant name of the tenant (ex: admin)
    # @param [Log4r] log => logger object to use for logging
    # @param [Boolean] mock => whether to enable mocking
    def initialize(os_auth_url, os_username, os_password, os_tenant, log, mock = false)
      @os_auth_url = os_auth_url
      @os_username = os_username
      @os_password = os_password
      @os_tenant = os_tenant
      @log = log
      @mock = mock
    end

    # Creates a openstack connection object with provided credentials
    def create_connection
      Fog::Compute.new({
                           :provider           => 'OpenStack',
                           :openstack_api_key  => @os_password,
                           :openstack_username => @os_username,
                           :openstack_auth_url => @os_auth_url,
                           :openstack_tenant   => @os_tenant,
                       })
    rescue Excon::Errors::Unauthorized => ex
      @log.error 'Invalid OpenStack Credentials' + ex.message
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

    # Creates required keypair and security group
    # @param conn [Fog::Compute::OpenStack::Real] conn => fog openstack connection object
    # @param key => openstack key pair to create and ingest into instances
    # @param groups => openstack security groups to create and inject basic rules
    def create_kp_sg!(conn, key, groups)
      unless @mock
        key_path = File.expand_path("~/.ssh/#{key}")
        # validate key, create if does not exist and write it to local file path
        if conn.key_pairs.get(key) # key pairs exists
          # but file does not exist
          if File.exist?(key_path) # file already exists, validate the fingerprint to be sure
            # check if ssh-keygen exists
            _, _, s = ShellUtils.system_quietly('which ssh-keygen')
            if s.exitstatus == 0
              out_key, _, _ = ShellUtils.system_quietly("ssh-keygen -y -f #{key_path}")
              remote_key = conn.key_pairs.get(key).public_key.match(/ssh-rsa ([^\s]+)/)[1]
              unless out_key.match(/ssh-rsa ([^\s]+)/)[1] == remote_key
                @log.error "key #{key_path} does not match remote key contents"
                abort
              end
            else
              @log.warn 'Cannot find ssh-keygen, its recommended to install ssh-keygen to check fingerprints of the keypair(s)'
            end
          else
            @log.error + "Key '#{key}' already exists but failed to find the key in " +
                "'#{key_path}', please change the 'os_key' name or delete the key in os to recreate the key"
            abort
          end
        else # key pair does not exist in os
          @log.debug "Cannot find the key pair specified, creating key_pair '#{key}'"
          if File.exist?(key_path) # but ssh file exists
            @log.error "Key '#{key}' already exists, please rename|delete '#{key_path}' to proceed"
            exit 1
          end
          key_pair = conn.key_pairs.create(:name => key)
          File.open(File.expand_path("~/.ssh/#{key}"), 'w') do |f|
            f.write(key_pair.private_key)
          end
          File.chmod(0600, File.expand_path("~/.ssh/#{key}"))
        end

        # validate group, create if does not exist and ingest some basic rules
        groups.each do |group|
          unless conn.security_groups.map {|x| x.name }.include?(group)
            @log.debug "Cannot find security group specified, creating security group #{group}"
            conn.security_groups.create(:name => group, :description => 'group managed by ankus')
          end
        end
        groups.each do |group|
          sec_group_id = conn.security_groups.find {|g| g.name == group}.id
          sec_group = conn.security_groups.get(sec_group_id)
          # check and authorize for ssh port
          open_ssh = sec_group.security_group_rules.detect do |ip_permission|
            ip_permission.ip_range.first && ip_permission.ip_range['cidr'] == '0.0.0.0/0' &&
                ip_permission.from_port == 22 &&
                ip_permission.to_port == 22 &&
                ip_permission.ip_protocol == 'tcp'
          end
          open_all_tcp = sec_group.security_group_rules.detect do |ip_permission|
            ip_permission.ip_range.first && ip_permission.ip_range['cidr'] == '0.0.0.0/0' &&
                ip_permission.from_port == 1 &&
                ip_permission.to_port == 65535 &&
                ip_permission.ip_protocol == 'tcp'
          end
          open_all_udp = sec_group.security_group_rules.detect do |ip_permission|
            ip_permission.ip_range.first && ip_permission.ip_range['cidr'] == '0.0.0.0/0' &&
                ip_permission.from_port == 1 &&
                ip_permission.to_port == 65535 &&
                ip_permission.ip_protocol == 'udp'
          end
          open_all_icmp = sec_group.security_group_rules.detect do |ip_permission|
            ip_permission.ip_range.first && ip_permission.ip_range['cidr'] == '0.0.0.0/0' &&
                ip_permission.from_port == -1 &&
                ip_permission.to_port == -1 &&
                ip_permission.ip_protocol == 'icmp'
          end
          open_icmp_echo_req = sec_group.security_group_rules.detect do |ip_permission|
            ip_permission.ip_range.first && ip_permission.ip_range['cidr'] == '0.0.0.0/0' &&
                ip_permission.from_port == 0 &&
                ip_permission.to_port == -1 &&
                ip_permission.ip_protocol == 'icmp'
          end
          open_icmp_echo_rep = sec_group.security_group_rules.detect do |ip_permission|
            ip_permission.ip_range.first && ip_permission.ip_range['cidr'] == '0.0.0.0/0' &&
                ip_permission.from_port == 8 &&
                ip_permission.to_port == -1 &&
                ip_permission.ip_protocol == 'icmp'
          end
          unless open_ssh
            conn.create_security_group_rule(sec_group_id, 'tcp', 22, 22, '0.0.0.0/0')
          end
          # TODO: authorize specific ports for hadoop, hbase
          unless open_all_tcp
            conn.create_security_group_rule(sec_group_id, 'tcp', 1, 65535, '0.0.0.0/0')
          end
          unless open_all_udp
            conn.create_security_group_rule(sec_group_id, 'udp', 1, 65535, '0.0.0.0/0')
          end
          unless open_all_icmp
            unless open_icmp_echo_req
              conn.create_security_group_rule(sec_group_id, 'icmp', 0, -1, '0.0.0.0/0')
            end
            unless open_icmp_echo_rep
              conn.create_security_group_rule(sec_group_id, 'icmp', 8, -1, '0.0.0.0/0')
            end
          end
        end
      end
    end

    # Validate if a specified flavor exists or not
    # @param [Fog::Compute::OpenStack::Real] conn => fog openstack connection object
    # @param [String] flavor_ref => flavor type to validate
    def validate_flavor(conn, flavor_ref)
      unless conn.flavors.find {|x| x.name == flavor_ref }
        @log.error "Cannot find flavor of type: #{flavor_ref}, available flavors: #{conn.flavors.map{|x| x.name}.join(', ')}"
        abort
      end
    end

    # Validate if a specified image id exists or not
    # @param [Fog::Compute::OpenStack::Real] conn => fog openstack connection object
    # @param [String] image_name => name of the image to validate
    def validate_image(conn, image_name)
      unless conn.images.find {|x| x.name == image_name }
        @log.error "Cannot find image with name: #{image_name}, available images: #{conn.images.map{|x| x.name}.join(', ')}"
        abort
      end
    end

    # Associate a floating ip to the instance
    # @param [Fog::Compute::OpenStack::Real] conn => fog openstack connection object
    # @param [Fog::Compute::OpenStack::Server] server => server object to attach the ip to
    # @param [String] pool_name => name of the pool from which to assign the ip from
    def associate_address!(conn, server, pool_name = nil)
      pool_name ||= conn.addresses.get_address_pools.first['name']
      ip = conn.addresses.create(:pool => pool_name)
      ip.server = server
      server.reload
    end

    # Waits until all the servers get booted
    # @param [Array] servers => array of fog server objects (Fog::Compute::OpenStack::Server)
    # (or)
    # [Fog::Compute::OpenStack::Server] server => single server object
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
    # @param [Fog::Compute::OpenStack::Server] server => openstack server object to which the instance should be attached to
    # @param [Integer] volumes_count => number of volumes to create
    # @param [Integer] size => size of each volume in GB
    # @return nil
    def attach_volumes!(server, volumes_count, size)
      #create a new block storage connection obj
      volume_service = Fog::Volume::OpenStack.new(
          :openstack_api_key  => @os_password,
          :openstack_username => @os_username,
          :openstack_auth_url => @os_auth_url,
          :openstack_tenant   => @os_tenant,
      )
      base = 'sdd'
      volumes_count.times do |i|
        base = base.next!
        #create a new volume
        vol = volume_service.volumes.create(
            :size => size,
            :display_name => "#{server.name}-#{i}",
            :description => "Volume attached to #{server.name} - managed by ankus"
        )
        vol.reload
        vol.wait_for { status == 'available' }
        server.attach_volume(vol.id, "/dev/#{base}")
        vol.wait_for { status == 'in-use' }
      end
    end

    # Check's the status of the volume, raises exception if volume is still 'in-use'
    # @param [Fog::Volume::OpenStack] vs => fog openstack volume object
    # @param [String] vol_id => id of the volume to verify the status
    def vol_status(vs, vol_id)
      vol = vs.volumes.get(vol_id)
      unless vol.status == 'available'
        # puts "vol status is not 'available' it is '#{status}' instead"
        @log.error 'vol is not avaiable to delete'
        exit 2
      end
    end

    # Wait's until the volume get detached (or becomes available to delete), Timeout's at specified time
    # @param [Fog::Volume::OpenStack] vs => fog openstack volume object
    # @param [String] vol_id => id of the volume to verify the status
    # @param [Integer] timeout => number of seconds in which to raise timeout
    def wait_for_vol(vs, vol_id, timeout = 120)
      Timeout::timeout(timeout) do
        begin
          vol_status vs, vol_id
        rescue
          @log.debug 'sleeping for 5 seconds'
          sleep 5
          retry
        end
      end
    rescue Timeout::Error
      @log.error "It took more than #{timeout} seconds for a volume to become available"
    end

    # Delete a server based on it's fully qualified domain name (or) name given while booting instance
    # @param [Fog::Compute::OpenStack::Real] conn => fog connection object to openstack
    # @param [String] server_name => name of the server to delete
    # @param [Boolean] delete_volumes => whether to delete volumes attached to instance or not
    def delete_server!(conn, server_name, delete_volumes = false)
      server = conn.servers.find{ |i| i.name == server_name }
      if server
        @log.info "Deleting instance with name: #{server_name}"
        # check and delete any floating ip addresses associated with instance
        server.all_addresses.each do |address|
          if address['ip']
            begin
              @log.info "Disassociating floating ip address associated with instance: #{server.name}"
              conn.disassociate_address(server.id, address['ip'])
              @log.info "Releasing floating ip address: #{address['ip']}"
              conn.release_address(conn.addresses.find {|a| a.ip == address['ip']}.id)
            rescue Exception => ex
              @log.debug "Error encountered releasing floating ip, reason: #{ex}"
              # continue
            end
          end
        end
        server.destroy
        if delete_volumes
          volume_service = Fog::Volume::OpenStack.new(
              :openstack_api_key  => @os_password,
              :openstack_username => @os_username,
              :openstack_auth_url => @os_auth_url,
              :openstack_tenant   => @os_tenant,
          )
          vols_to_del = volume_service.volumes.find{|v| v.display_name =~ /#{server_name}/}
          if vols_to_del
            vols_to_del.each do |vol|
              @log.info "Waiting for volume to detach from instance: #{server_name}"
              wait_for_vol(volume_service, vol.id)
              vol.destroy
            end
          else
            @log.info "No volumes attached for the instance #{server_name}"
          end
        end
      end
    end

    # Create a new server and inject provided ssh_key into instance
    # @param [Fog::Compute::OpenStack::Real] conn => fog openstack connection object
    # @param [String] name => fqdn of the server being created
    # @param [String] key_name => name of the key pair to use
    # @param [String] type => instance size being created
    # @param [String] image => id of the image to boot
    # @param [String] sec_groups => list of security groups to use for an instance
    # @return [Fog::Compute::OpenStack::Server] server object
    #noinspection RubyStringKeysInHashInspection
    def create_server!(conn, name, key_name, type, image, sec_groups)
      unless @mock
        unless conn.images.find { |i| i.id == image }
          @log.error "Cannot find image with id #{image}, available images: "
          conn.images.table([:id, :name])
          abort
        end
        unless conn.flavors.find { |f| f.id == type.to_s }
          @log.error "Cannot find flavor with id #{type}, available flavors: "
          conn.flavors.table([:id, :name])
          abort
        end
      end
      server = conn.servers.create(
          :name => name,
          :flavor_ref => type,
          :image_ref => image,
          :key_name => key_name,
          :security_groups => sec_groups
      )
      # TODO -- mocking is not working, reload is not assigning ip addresses. Custom assigning is not
      # TODO -- getting persisted to the server object hence getting the public ip address is working
      # TODO -- and getting the internal ip address is not working. FIX THIS for mocking to work!!!
      if @mock
        server.reload
        server.addresses= {
          'public'=>[
            {
              'OS-EXT-IPS-MAC:mac_addr' => (1..6).map{'%0.2X'%rand(256)}.join(':'),
              'version' => 4,
              'addr' => 4.times.map{ Fog::Mock.random_numbers(3) }.join('.'),
              'OS-EXT-IPS:type' => 'fixed'
            },
            {
              'OS-EXT-IPS-MAC:mac_addr' => (1..6).map{'%0.2X'%rand(256)}.join(':'),
              'version' => 4,
              'addr' => 4.times.map{ Fog::Mock.random_numbers(3) }.join('.'),
              'OS-EXT-IPS:type' => 'floating'
            }
          ]
        }
      end
      server
    end

    # [Experimental] Download openstack compatible image using url provided
    def download_image!(image_url)
      # lazy load libraries
      require 'zlib'
      require 'securerandom'
      require 'rubygems/package'

      file_with_ext = File.basename(image_url)
      extract_path = "/tmp/ankus-downloads-#{SecureRandom.hex}"
      file_name = case file_with_ext
                    when /\.tar\.gz$/
                      File.basename(file_with_ext, '.tar.gz')
                    when /\.tar$/
                      File.basename(file_with_ext, '.tar')
                    else
                      File.basename(file_with_ext, '.*')
                  end
      out = File.open("/tmp/#{file_name}-#{SecureRandom.hex}", 'wb')

      FileUtils.mkdir_p extract_path

      # Efficient image write
      @log.info "Downloading #{file_with_ext} file..."
      streamer = lambda do |chunk, _, _|
        out.write chunk
      end
      Excon.get image_url, :response_block => streamer
      out.close
      @log.info "Image downloaded to #{out.path}"

      @log.info "Extracting image contents to #{extract_path}..."
      packaged_files = []
      Gem::Package::TarReader.new(Zlib::GzipReader.open(out.path)).each do |entry|
        FileUtils.mkdir_p "#{extract_path}/#{File.dirname(entry.full_name)}"
        packaged_files << entry.full_name
        File.open "#{extract_path}/#{entry.full_name}", 'w' do |f|
          f.write entry.read
        end
      end
    end

    # [Experimental] Uploads the image from local file system to openstack glance
    #noinspection RubyStringKeysInHashInspection
    def upload_image(extract_path, packaged_files)
      image_service = Fog::Image.new({
         :provider => 'OpenStack',
         :openstack_api_key  => @os_password,
         :openstack_username => @os_username,
         :openstack_auth_url => @os_auth_url,
         :openstack_tenant   => @os_tenant,
      })

      aki = "#{extract_path}/#{packaged_files.find{|x| x =~ /vmlinuz$/}}"
      ami = "#{extract_path}/#{packaged_files.find{|x| x =~ /\.img$/}}"
      ari = "#{extract_path}/#{packaged_files.find{|x| x =~ /initrd$/}}"

      @log.info 'Uploding AKI ...'
      aki = image_service.images.create :name => "#{File.basename(aki, '-vmlinuz')}-aki",
                                        :size => File.size(aki),
                                        :disk_format => 'aki',
                                        :container_format => 'aki',
                                        :location => aki
      @log.info 'Uploading ARI ...'
      ari = image_service.images.create :name => "#{File.basename(ari, '-initrd')}-ari",
                                        :size => File.size(ari),
                                        :disk_format => 'ari',
                                        :container_format => 'ari',
                                        :location => ari
      @log.info 'Uploading AMI ...'
      image_service.images.create :name => "#{File.basename(ari, '-initrd')}",
                                  :size => File.size(ami),
                                  :disk_format => 'ami',
                                  :container_format => 'ami',
                                  :location => ami,
                                  :properties => {
                                      'kernel_id'  => aki.id,
                                      'ramdisk_id' => ari.id
                                  }
    end
  end
end