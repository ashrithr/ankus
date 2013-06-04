=begin
  Cloud initializer class to create cloud instances in aws, rackspace
  TODO accommodate for google cloud compute
=end
module Ankuscli
  class Aws
    # Create a new Ankuscli aws object
    # @param [String] access_id => aws access_id
    # @param [String] secret_key => aws secret_key
    # @param [String] region => aws region to connect to
    # @return [AnkusCli::Aws] aws connection object
    def initialize(access_id, secret_key, region = 'us-west-1')
      @aws_access_id  = access_id
      @aws_secret_key = secret_key
      @region         = region
      @centos_amis    = {
          'us-east-1'       => 'ami-a96b01c0',  #Virginia
          'us-west-1'       => 'ami-51351b14',  #Northern California
          'us-west-2'       => 'ami-bd58c98d',  #Oregon
          'eu-west-1'       => 'ami-050b1b71',  #Ireland
          'ap-southeast-1'  => 'ami-23682671',  #Singapore
          'ap-southeast-2'  => 'ami-ffcd5ec5',  #Sydney
          'ap-northeast-1'  => 'ami-3fe8603e',  #Tokyo
          'sa-east-1'       => 'ami-e2cd68ff',  #Sao Paulo
      }
      @ubuntu_amis    = {
          'us-east-1'       => 'ami-9b85eef2',  #Virginia
          'us-west-1'       => 'ami-9b2d03de',  #Northern California
          'us-west-2'       => 'ami-77be2f47',  #Oregon
          'eu-west-1'       => 'ami-f5736381',  #Ireland
          'ap-southeast-1'  => 'ami-085b155a',  #Singapore
          'ap-southeast-2'  => 'ami-37c0530d',  #Sydney
          'ap-northeast-1'  => 'ami-57109956',  #Tokyo
          'sa-east-1'       => 'ami-a4fb5eb9',  #Sao Paulo
      }
    end

    # Creates a new aws connection object with the provided aws access and secret key
    # @return [Fog::Compute::AWS::Real] fog aws connection object
    def create_connection
      Fog::Compute.new({
                           :provider               => 'AWS',
                           :aws_access_key_id      => @aws_access_id,
                           :aws_secret_access_key  => @aws_secret_key,
                           :region                 => @region
                       })
    end

    # Validates the connection object by running a simple request on the object
    # @param [Fog::Compute::AWS::Real] conn => fog aws connection object
    # @return [boolean] true if connection succeeds to aws using fog, false if cannot
    def valid_connection?(conn)
      conn.servers.length
      true
    rescue Excon::Errors::Forbidden, Excon::Errors::Unauthorized
      false
    end

    #Create a single server in aws cloud
    # @param [Fog::Compute::AWS::Real] conn => fog aws connection object
    # @param [String] instance_type => type of the instance being created, used for the creating tags
    # @param [Hash] opts:
    #   @option [String] os_type    => type of servers to create (CentOS|Ubuntu)
    #   @option [String] key        => security key to ingest into system
    #   @option [Array] groups      => array of security groups to use
    #   @option [String] flavor_id  => size of instance to create
    # @return [Fog::Compute::AWS::Server] server object
    def create_server!(conn, instance_type, opts = {})
      options = {
          :key => 'ankuscli',
          :groups => %w(default),
          :flavor_id => 'm1.medium',
          :os_type => 'CentOS',
      }.merge(opts)

      unless valid_connection?(conn)
        puts '[Error]: Unable to connect to AWS, check your credentials'
        exit 2
      end

      #validate key, create if does not exist and write it to local system
      unless conn.key_pairs.get(options[:key])
        puts "[Debug]: Cannot find the key pair specified, creating the key_pair #{options[:key]}"
        key_pair = conn.key_pairs.create(:name => options[:key])
        File.open(File.expand_path("~/.ssh/#{options[:key]}"), 'w') do |f|
          f.write(key_pair.private_key)
        end
        File.chmod(0600, File.expand_path("~/.ssh/#{options[:key]}"))
      end

      #validate group, create if does not exist and ingest some basic rules
      options[:groups].each do |group|
        unless conn.security_groups.get(group)
          conn.security_groups.create(:name => group, :description => 'group managed by ankuscli')
        end
      end
      options[:groups].each do |group|
        sec_group = conn.security_groups.get(group)
        #check and authorize for ssh port
        authorized = sec_group.ip_permissions.detect do |ip_permission|
          ip_permission['ipRanges'].first && ip_permission['ipRanges'].first['cidrIp'] == '0.0.0.0/0' &&
              ip_permission['fromPort'] == 22 &&
              ip_permission['ipProtocol'] == 'tcp' &&
              ip_permission['toPort'] == 22
        end
        unless authorized
          sec_group.authorize_port_range(22..22)
        end
        #TODO: authorize hadoop, hbase ports
      end

      case options[:os_type].downcase
        when 'centos'
          server = create_server(conn, options[:key], instance_type, options[:groups], options[:flavor_id], @centos_amis[@region])
          return server
        when 'ubuntu'
          server = create_server(conn, options[:key], instance_type, options[:groups], options[:flavor_id], @ubuntu_amis[@region])
          return server
        else
          puts '[Error]: Provided OS not supported with ankuscli'
          exit 2
      end
    end

    # Creates servers in aws cloud
    # @param [String] conn => fog aws connection object
    # @param [Integer] count => number of servers to create, other than controller
    # @param [Hash] options
    #   @option [String] os_type => type of servers to create (CentOS|Ubuntu)
    #   @option [String] key => security key to ingest into system
    #   @option [Array]  groups => array of security groups to use
    #   @option [String] flavor_id => size of instance to create
    #   @option [String] instance_tag => array of instance tags to ingest into instance
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
    # @param [AnkusCli::Aws.new] conn => fog aws connection object
    # @param [Fog::Compute::AWS::Server] server => fog server object to which volumes should be attached to
    # @param [Integer] volumes => number of volumes to create
    # @param [Integer] size => size in GB for each volume
    # @return nil
    def attach_volumes!(conn, server, volumes, size)
      base = 'sdh' #sdi-z
      volumes.times do |i|
        base = base.next!
        volume = conn.volumes.create(:size => size, :availability_zone => server.availability_zone, :device => "/dev/#{base}")
        volume.wait_for { ready? }
        conn.tags.create(
            :resource_id => volume.id,
            :key => 'Name',
            :value => 'ankuscli',
        )
        conn.tags.create(
            :resource_id => volume.id,
            :key => 'Internal',
            :value => "data-#{i + 1}",
        )
        volume.server = server
      end
    end


    # Waits until all the servers got created
    # @param [Array] servers => array of fog server objects (Fog::Compute::AWS::Server)
    # (or)
    # [Fog::Compute::AWS::Server] servers => single server object
    # @return nil
    def wait_for_servers(servers)
      if servers.is_a?(Array)
        puts 'Waiting until all the servers gets created ...'
        servers.each do |server|
          server.wait_for { ready? }
        end
      else
        printf 'Waiting for server to get created'
        servers.wait_for { print'.' ; ready? }
        puts
      end
    end

    private

    # Create a single server, create tags for the server and returns server_id
    # @param [Fog::Compute::AWS::Real] conn => fog aws connection object
    # @param [String] key_name => aws key to ingest into system
    # @param [String] type => type of the system being created, used for creating tags
    # @param [Array] groups => security groups to use
    # @param [String] flavor_id => type of instance to create (t1.micro m1.small m1.medium m1.large m1.xlarge m3.xlarge m3.2xlarge m2.xlarge m2.2xlarge m2.4xlarge c1.medium c1.xlarge hs1.8xlarge)
    # @return [Fog::Compute::AWS::Server] fog server object
    def create_server(conn, key_name, type, groups, flavor_id, ami_id)
      server = conn.servers.create(
          :image_id   => ami_id,
          :flavor_id  => flavor_id,
          :key_name   => key_name,
          :groups     => groups
      )
      server.reload
      conn.tags.create(
          :resource_id  => server.id,
          :key          => 'Name',
          :value        => 'ankuscli'
      )
      conn.tags.create(
          :resource_id  => server.id,
          :key          => 'Type',
          :value        => type
      )
      server
    end

  end

  class RackSpace
    def initialize(api_key, user_name)
      @rackspace_api_key = api_key
      @rackspace_username = user_name
      @centos_image_id = 'da1f0392-8c64-468f-a839-a9e56caebf07' #CentOS 6.3 @ dfw
      @ubuntu_image_id = 'e4dbdba7-b2a4-4ee5-8e8f-4595b6d694ce' #ubuntu 12.04 LTS @ dfw
    end

    # Creates a new rackspace connection object with provided credentials
    def create_connection
      Fog::Compute.new({
                           :provider           => 'Rackspace',
                           :rackspace_username => @rackspace_username,
                           :rackspace_api_key  => @rackspace_api_key,
                           :version            => :v2
                       })
    rescue Excon::Errors::Unauthorized
      puts 'Invalid Rackspace Credentials'
      exit 1
    end

    # Validates the connection object
    # @param [Fog::Compute] conn => fog connection object to authenticate
    def validate_connection?(conn)
      conn.authenticate
      true
    rescue
      false
    end

    # Create a new server and inject provided ssh_key into instance
    # @param [Fog::Compute::RackspaceV2::Real] conn => fog rackspace connection object
    # @param [String] name => fqdn of the server being created
    # @param [String] ssh_key_path => path of the ssh public key that is used to ssh into the server
    # @param [String] type => instance size being created (2-512MB, 3-1GB, 4-2GB, 5-4GB, 6-8GB, 7-15GB, 8-30GB)
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
          return server
        else
          puts '[Error]: OS not supported'
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
        puts 'Waiting until all the servers gets created ...'
        servers.each do |server|
          server.wait_for { ready? }
        end
      else
        printf 'Waiting for server to get created'
        servers.wait_for { print'.' ; ready? }
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
  end
end