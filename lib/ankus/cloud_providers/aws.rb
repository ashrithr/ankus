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
  # Class to manage Amazon Web Service API calls
  class Aws
    # Create a new Ankus aws object
    # @param [String] access_id => aws access_id
    # @param [String] secret_key => aws secret_key
    # @param [String] region => aws region to connect to
    # @return [Ankus::Aws] aws connection object
    def initialize(access_id, secret_key, region, log, mock = false)
      @aws_access_id  = access_id
      @aws_secret_key = secret_key
      @region         = region
      @centos_amis    = {
        'us-east-1'       => 'ami-a96b01c0',  # Virginia
        'us-west-1'       => 'ami-51351b14',  # Northern California
        'us-west-2'       => 'ami-bd58c98d',  # Oregon
        'eu-west-1'       => 'ami-050b1b71',  # Ireland
        'ap-southeast-1'  => 'ami-23682671',  # Singapore
        'ap-southeast-2'  => 'ami-ffcd5ec5',  # Sydney
        'ap-northeast-1'  => 'ami-3fe8603e',  # Tokyo
        'sa-east-1'       => 'ami-e2cd68ff',  # Sao Paulo
      }
      # centos ami's modified with extended root partition of 250G
      @centos_amis_mod = {
        'us-east-1'       => 'ami-d8a2deb1',
        'us-west-1'       => 'ami-727a5237',
        'us-west-2'       => 'ami-f5a83bc5'
      }
      @ubuntu_amis    = {
        'us-east-1'       => 'ami-9b85eef2',  # Virginia
        'us-west-1'       => 'ami-9b2d03de',  # Northern California
        'us-west-2'       => 'ami-77be2f47',  # Oregon
        'eu-west-1'       => 'ami-f5736381',  # Ireland
        'ap-southeast-1'  => 'ami-085b155a',  # Singapore
        'ap-southeast-2'  => 'ami-37c0530d',  # Sydney
        'ap-northeast-1'  => 'ami-57109956',  # Tokyo
        'sa-east-1'       => 'ami-a4fb5eb9',  # Sao Paulo
      }
      @log            = log
      @mock           = mock  # if enabled will enable Fog.mock!
    end

    # Creates a new aws connection object with the provided aws access and
    # secret key
    # @return [Fog::Compute::AWS::Real] fog aws connection object
    def create_connection
      Fog::Compute.new(
        :provider               => 'AWS',
        :aws_access_key_id      => @aws_access_id,
        :aws_secret_access_key  => @aws_secret_key,
        :region                 => @region
      )
    end

    # Validates the connection object by running a simple request on the object
    # @param [Fog::Compute::AWS::Real] conn => fog aws connection object
    # @return [boolean] true if connection succeeds to aws using fog
    def valid_connection?(conn)
      conn.servers.length
      true
    rescue Excon::Errors::Forbidden, Excon::Errors::Unauthorized, Fog::Compute::AWS::Error
      false
    end

    # Creates required keypair and security group
    # @param conn [Fog::Compute::AWS::Real] conn => fog aws connection object
    # @param key => aws key pair to create and ingest into instances
    # @param groups => aws security groups to create and create basic rules
    def create_kp_sg!(conn, key, groups)
      unless @mock
        key_path = File.expand_path("~/.ssh/#{key}")
        # validate key, create if does not exist and write it to out
        if conn.key_pairs.get(key) # key pairs exists
          # file already exists, validate the fingerprint to be sure
          if File.exist?(key_path)
            # check if openssl exists
            _, _, s = Util::ShellUtils.system_quietly('which openssl')
            if s.exitstatus == 0
              out_fp, _, _ =
                Util::ShellUtils.system_quietly(
                  "openssl pkcs8 -in #{key_path} -nocrypt " \
                  '-topk8 -outform DER | openssl sha1 -c'
                )
              remote_fp = conn.key_pairs.get(key).fingerprint
              unless out_fp.chomp == remote_fp
                @log.error "Key '#{key}' already exists on local system and" \
                  " it's fingerprint does not match with remote key_pair's" \
                  " fingerprint. Either delete the key in aws and rename the" \
                  " local file ['#{key_path}'] (or) update the 'aws_key'" \
                  " property in the config file to another name."
                abort
              end
            else
              @log.warn 'Cannot find openssl, its recommended to install ' \
                'openssl to check fingerprints of the keypair(s)'
            end
          else
            @log.error "Key '#{key}' already exists in aws but failed to find"\
            " the key in local path '#{key_path}', please update the 'aws_key'"\
            " property (or) delete the key in aws to recreate the key"
            abort
          end
        else # key pair does not exist in aws
          @log.debug "Cannot find the key pair specified, creating the"\
            " key_pair #{key}" if @debug
          if File.exist?(key_path) # but ssh file exists
            @log.error "Key '#{key}' already exists, please rename|delete"\
              " '#{key_path}' to proceed"
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
          unless conn.security_groups.get(group)
            conn.security_groups.create(
              :name => group,
              :description => 'group managed by ankus'
            )
          end
        end
        groups.each do |group|
          sec_group = conn.security_groups.get(group)
          # check and authorize for ssh port
          authorized = sec_group.ip_permissions.detect do |ip_permission|
            ip_permission['ipRanges'].first &&
              ip_permission['ipRanges'].first['cidrIp'] == '0.0.0.0/0' &&
              ip_permission['fromPort'] == 22 &&
              ip_permission['ipProtocol'] == 'tcp' &&
              ip_permission['toPort'] == 22
          end
          open_all_tcp = sec_group.ip_permissions.detect do |ip_permission|
            ip_permission['ipRanges'].first &&
              ip_permission['ipRanges'].first['cidrIp'] == '0.0.0.0/0' &&
              ip_permission['fromPort'] == 0 &&
              ip_permission['ipProtocol'] == 'tcp' &&
              ip_permission['toPort'] == 65_535
          end
          open_all_udp = sec_group.ip_permissions.detect do |ip_permission|
            ip_permission['ipRanges'].first &&
              ip_permission['ipRanges'].first['cidrIp'] == '0.0.0.0/0' &&
              ip_permission['fromPort'] == 0 &&
              ip_permission['ipProtocol'] == 'udp' &&
              ip_permission['toPort'] == 65_535
          end
          open_all_icmp = sec_group.ip_permissions.detect do |ip_permission|
            ip_permission['ipRanges'].first &&
              ip_permission['ipRanges'].first['cidrIp'] == '0.0.0.0/0' &&
              ip_permission['fromPort'] == -1 &&
              ip_permission['ipProtocol'] == 'icmp' &&
              ip_permission['toPort'] == -1
          end
          open_icmp_echo_req = sec_group.ip_permissions.detect do |ip_permission|
            ip_permission['ipRanges'].first &&
              ip_permission['ipRanges'].first['cidrIp'] == '0.0.0.0/0' &&
              ip_permission['fromPort'] == 0 &&
              ip_permission['ipProtocol'] == 'icmp' &&
              ip_permission['toPort'] == -1
          end
          open_icmp_echo_rep = sec_group.ip_permissions.detect do |ip_permission|
            ip_permission['ipRanges'].first &&
              ip_permission['ipRanges'].first['cidrIp'] == '0.0.0.0/0' &&
              ip_permission['fromPort'] == 8 &&
              ip_permission['ipProtocol'] == 'icmp' &&
              ip_permission['toPort'] == -1
          end
          sec_group.authorize_port_range(22..22) unless authorized
          # TODO: authorize specific ports for hadoop, hbase
          sec_group.authorize_port_range(0..65_535) unless open_all_tcp
          unless open_all_udp
            sec_group.authorize_port_range(0..65_535, :ip_protocol => 'udp')
          end
          unless open_all_icmp
            unless open_icmp_echo_req
              sec_group.authorize_port_range(0..-1, :ip_protocol => 'icmp')
            end
            unless open_icmp_echo_rep
              sec_group.authorize_port_range(8..-1, :ip_protocol => 'icmp')
            end
          end
        end
      end
    end

    # Create a single server in aws cloud
    # @param [Fog::Compute::AWS::Real] conn => fog aws connection object
    # @param [String] instance_tag => type of the instance being created, used
    #   for the creating tags
    # @param [Hash] opts:
    #   @option [String] os_type => type of servers to create (CentOS|Ubuntu)
    #   @option [String] key => security key to ingest into system
    #   @option [Array] groups => array of security groups to use
    #   @option [String] flavor_id => size of instance to create
    #   @option [Integer] num_of_vols => ebs volumes to create and attach
    #   @option [Integer] vol_size => size of the each ebs volumes in GB
    #   @option [Integer] root_vol_size => size of the root ebs volume
    # @return [Fog::Compute::AWS::Server] server object
    def create_server!(conn, instance_tag, opts = {})
      options = {
          :key => 'ankus',
          :groups => %w(ankus),
          :flavor_id => 'm1.medium',
          :os_type => 'CentOS',
          :num_of_vols => 0,
          :vol_size => 50,
          :root_vol_size => 250,
          :vol_type => 'ebs',
          :iops => 0
      }.merge(opts)

      unless valid_connection?(conn)
        @log.error 'Unable to authenticate with AWS, check your credentials'
        exit 2
      end

      case options[:os_type].downcase
      when 'centos'
        ami = @centos_amis_mod.has_key?(@region) ? @centos_amis_mod[@region] : @centos_amis[@region]
        root_ebs_size = @centos_amis_mod.has_key?(@region) ? 0 : options[:root_vol_size]
        server = create_server(
          conn,
          options[:key],
          instance_tag,
          options[:groups],
          options[:flavor_id],
          ami,
          :num_of_vols => options[:num_of_vols],
          :vol_size => options[:vol_size],
          :root_ebs_size => root_ebs_size,
          :vol_type => options[:vol_type],
          :iops => options[:iops]
        )
        return server
      when 'ubuntu'
        server = create_server(
          conn,
          options[:key],
          instance_tag,
          options[:groups],
          options[:flavor_id],
          @ubuntu_amis[@region],
          :num_of_vols => options[:num_of_vols],
          :vol_size => options[:vol_size],
          :root_ebs_size => options[:root_vol_size],
          :vol_type => options[:vol_type],
          :iops => options[:iops]
        )
        return server
      else
        @log.error 'Provided OS not supported by Ankus yet!'
        exit 2
      end
    end

    # Creates servers in aws cloud
    # @param [String] conn => fog aws connection object
    # @param [Integer] count => number of servers to create, other than
    #   controller
    # @param [Hash] options
    #   @option [String] os_type => type of servers to create (CentOS|Ubuntu)
    #   @option [String] key => security key to ingest into system
    #   @option [Array]  groups => array of security groups to use
    #   @option [String] flavor_id => size of instance to create
    #   @option [String] instance_tag => array of instance tags to ingest
    # @return [Array] list of server objects (Fog::Compute::AWS::Server)
    def create_servers!(conn, count, options = {})
      server_objects = []
      tag = options[:instance_tag] || 'slave'
      count.times do |i|
        server_objects << create_server!(conn, "#{tag}#{i}", options)
      end
      server_objects
    end

    # Creates and attaches, volumes to instances
    # @param [Ankus::Aws.new] conn => fog aws connection object
    # @param [Fog::Compute::AWS::Server] server => fog server object to which
    #   volumes should be attached to
    # @param [Integer] volumes => number of volumes to create
    # @param [Integer] size => size in GB for each volume
    # @return nil
    def attach_volumes!(conn, server, volumes, size)
      base = 'sde' #sdf-p
      volumes.times do |i|
        base = base.next!
        @log.info "Attaching volume: #{base} (size: #{size}) to serer:" \
                  " #{server.dns_name}"
        volume = conn.volumes.create(
          :size => size,
          :availability_zone => server.availability_zone,
          :device => "/dev/#{base}"
        )
        volume.reload
        volume.wait_for { ready? }
        conn.tags.create(
          :resource_id => volume.id,
          :key => 'Name',
          :value => 'ankus'
        )
        conn.tags.create(
          :resource_id => volume.id,
          :key => 'Internal',
          :value => "data-#{i + 1}"
        )
        volume.server = server
        # volume.delete_on_termination = true
      end
      # sleep 5
    end


    # Waits until all the servers got created (:state => :running)
    # @param [Array] servers => array of fog server objects
    #   (Fog::Compute::AWS::Server)
    # (or)
    # [Fog::Compute::AWS::Server] servers => single server object
    # @return nil
    def wait_for_servers(servers)
      if servers.is_a?(Array)
        servers.each do |server|
          server.wait_for { ready? }
        end
      else
        servers.wait_for { ready? }
        puts
      end
    end

    # Waits for the complete boot the instance by monitoring instances
    #   console_output
    # @param [Array] servers => array of fog server objects to wait for
    #   (or) [Fog::Compute::AWS::Server] servers => single server object to
    #   wait for
    # @param [String] os_type => type of os being booted into the instance(s)
    def complete_wait(servers, os_type)
      Timeout::timeout(600) do # Timeout after 10 minutes
        if @mock # if mock is enabled sleep for some time and return back
          # sleep 5
          return
        end
        if servers.is_a?(Array)
          servers.each do |server|
            if os_type.downcase == 'centos'
              server.wait_for do
                console_output.body['output'] =~ /CentOS release 6\.3 \(Final\)/
              end
            elsif os_type.downcase == 'ubuntu'
              # server.wait_for { console_output.body['output'] =~ /^cloud-init boot finished/ }
              server.wait_for do
                console_output.body['output'] =~ /^cloud-init start running/
              end
            else
              true
            end
          end
        else
          if os_type.downcase == 'centos'
            server.wait_for do
              console_output.body['output'] =~ /CentOS release 6\.3 \(Final\)/
            end
          elsif os_type.downcase == 'ubuntu'
            # server.wait_for { console_output.body['output'] =~ /^cloud-init boot finished/ }
            server.wait_for do
              console_output.body['output'] =~ /^cloud-init start running/
            end
          else
            true
          end
        end
      end
    rescue Timeout::Error
      # Destroy the servers as we cannot manage them any more
      if servers.is_a?(Array)
        servers.each { |server| server.destroy }
      else
        servers.destroy
      end
      fail 'It took more than 10 minutes for the servers to complete boot,' \
           ' this generally does not happen.'
    end

    # Terminates an instance on aws with provided instance id
    # @param [Fog::Compute::AWS::Real] conn => fog aws connection object
    # @param [String] instance_id => id of the instance to delete
    def delete_server_with_id(conn, instance_id)
      response = conn.servers.get(instance_id)
      unless response
        @log.error "InstanceId Not found :#{instance_id}"
        exit 1
      end
      if response.state == 'terminated'
        @log.warn 'Instance is already in terminated state'
      else
        response.destroy
        @log.info "Terminated Instance: #{instance_id}"
      end
    end

    # Terminates a instance on aws, also can detach and delete volumes attached
    # to instances
    # @param [Fog::Compute::AWS::Real] conn => fog aws connection object
    # @param [String] dns_name => dns name of ec2 instance to terminate
    # @param [Boolean] delete_volumes => specify whether to delete volumes
    #   attached to instances ot not
    def delete_server_with_dns_name(conn, dns_name, delete_volumes = false)
      block_mappings = []
      server = conn.servers.all('dns-name' => dns_name).first
      if server
        @log.info "Terminating instance with dns_name: #{dns_name}"
        server.destroy if server.state == 'running'
        block_mappings << server.block_device_mapping
        if delete_volumes
          @log.info "Deleting volumes attached to instance: #{dns_name}"
          unless block_mappings.length == 0
            block_mappings.each do |bm|
              bm.each do |vol_info|
                vol = conn.volumes.get(vol_info['volumeId'])
                @log.info "Waiting for volume to detach from instance:" \
                          " #{dns_name}"
                vol.wait_for { vol.state == 'available' }
                vol.destroy if vol_info['deleteOnTermination'] != 'true'
              end
            end
          end
        end
      else
        @log.error "No server found with dns_name: #{dns_name}"
        exit 1
      end
    end

    private

    # Create a single server, create tags for the server and returns server_id
    # @param [Fog::Compute::AWS::Real] conn => fog aws connection object
    # @param [String] key_name => aws key to ingest into system
    # @param [String] tag => type of the system being created, used for
    #   creating tags
    # @param [Array] groups => security groups to use
    # @param [String] flavor_id => type of instance to create
    #   (t1.micro m1.small m1.medium m1.large m1.xlarge m3.xlarge m3.2xlarge
    #    m2.xlarge m2.2xlarge m2.4xlarge c1.medium c1.xlarge hs1.8xlarge)
    # @param [Hash] ebs_options => options for ebs volumes to create and
    #   attach to instances
    #   @option [Integer] :num_of_vols => number of volumes for the instance
    #   @option [Integer] :vol_size => volumes size in GB per volume
    #   @option [Integer] :root_ebs_size => size of the root volume
    # @return [Fog::Compute::AWS::Server] fog server object
    def create_server(
      conn,
      key_name,
      tag,
      groups,
      flavor_id,
      ami_id,
      ebs_options = {}
    )
      num_of_volumes = ebs_options[:num_of_vols] || 0
      size_of_volumes = ebs_options[:vol_size] || 50
      root_volume_size = ebs_options[:root_ebs_size] || 100
      vol_type = ebs_options[:vol_type] || 'ebs'
      iops = ebs_options[:iops] || 0
      image = conn.images.get(ami_id)
      region = @region
      root_ebs_name = if @mock
                        '/dev/sda'
                      else
                        image.block_device_mapping.first['deviceName']
                      end
      if @mock
        # assign a random public_dns_name and private_dns_name
        server = conn.servers.create
        server.dns_name = "ec2-54-#{rand(100)}-#{rand(10)}-#{rand(255)}." \
          "#{region}.compute.amazonaws.com"
        server.private_dns_name = "ip-54-#{rand(100)}-#{rand(10)}-" +
          "#{rand(255)}.#{region}.compute.internal"
      else
        server = conn.servers.new(
          :image_id             => ami_id,
          :flavor_id            => flavor_id,
          :key_name             => key_name,
          :groups               => groups,
          :block_device_mapping => map_ebs_devices(
                                      num_of_volumes,
                                      size_of_volumes,
                                      root_volume_size,
                                      root_ebs_name,
                                      vol_type,
                                      iops
                                   )
        )
        server.save
        server.reload
      end
      conn.tags.create(
        :resource_id  => server.id,
        :key          => 'Name',
        :value        => "ankus-#{tag}"
      )
      conn.tags.create(
        :resource_id  => server.id,
        :key          => 'Type',
        :value        => tag
      )
      server
    end

    # create a map of block devices from inputs provided
    # @param [Integer] num_of_vols => number of volumes to build the hash for
    # @param [Integer] size_per_vol => size of each volume in GB
    # @param [Integer] root_ebs_size => size of the root device
    #   (should be able to run `resize2fs /dev/sda` to re-claim re-sized space)
    # @param [String] root_ebs_name => device name of the root
    #   (default: /dev/sda)
    # @param [String] vol_type => type of the volume being create standard or
    #   io1 (iops provisioned)
    # @param [String] iops => input output operations per second for io1 type
    #   devices (should be between 1-4000)
    # @return [Hash] block_device_mapping => Array of block to device mappings
    def map_ebs_devices(
      num_of_vols,
      size_per_vol,
      root_ebs_size,
      root_ebs_name = '/dev/sda',
      vol_type = 'ebs',
      iops = 0
    )
      block_device_mapping = []
      # change the root ebs size only if root_ebs_size > 0 i.e, user should not
      # pass 0 to resize root
      unless root_ebs_size == 0
        block_device_mapping << {
          :DeviceName => root_ebs_name,
          'Ebs.VolumeSize' => root_ebs_size,
          'Ebs.DeleteOnTermination' => false
        }
      end
      if num_of_vols > 0
        base = 'sdh' # sd[i-z]
        num_of_vols.times do
          base = base.next
          if vol_type == 'io1'
            mapping = {
              :DeviceName               => base,
              'Ebs.VolumeSize'          => size_per_vol,
              'Ebs.VolumeType'          => 'io1',
              'Ebs.Iops'                => iops,
              'Ebs.DeleteOnTermination' => false
            }
          else
            mapping = {
              :DeviceName               => base,
              'Ebs.VolumeSize'          => size_per_vol,
              'Ebs.DeleteOnTermination' => false
            }
          end
          block_device_mapping << mapping
        end
      end
      block_device_mapping
    end

    # creates a map of block devices for instance stores supported by the
    # instance type
    # @param [String] instance_type to use
    # @return [Hash] array of block device mappings
    def map_instance_storage_devices(instance_type)
      block_device_mapping = []
      base = 'sdh'
      Ankus::AWS_INSTANCE_TYPES[instance_type][:instance_storage][:count].each do |dev|
        block_device_mapping << {
          :DeviceName => "/dev/#{base.next!}",
          :VirtualName => "ephemeral#{dev}"
        }
      end
      block_device_mapping
    end
  end
end
