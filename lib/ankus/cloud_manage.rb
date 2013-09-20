=begin
  Class to manage cloud instances
  currently supported cloud platforms are aws and rackspace
=end

module Ankus
  require 'erb'

  class Cloud
    include Ankus
    # Create a new Cloud class object
    # @param [String] provider => Cloud service provider; aws|rackspace
    # @param [Hash] parsed_config => Configuration that has been already parsed from cloud_configuration file
    # @param [Hash] cloud_credentials => Credentials configurations
    #     if aws: cloud_credentials => { aws_access_id: '', aws_secret_key: '', aws_machine_type: 'm1.large', 
    #                                    aws_region: 'us-west-1', aws_key: 'ankus' }
    #     if rackspace: cloud_credentials => { rackspace_username: '', rackspace_api_key: '', 
    #                                          rackspace_instance_type: '', rackspace_ssh_key: '~/.ssh/id_rsa.pub' }
    # @param [Integer] thread_pool_size => number of threads to use to perform instance creation, volume attachements
    # @param [Boolean] debug => if enabled will print more info to stdout
    # @param [Boolean] mock => if enabled will mock fog, instead of creating actual instances
    def initialize(provider, parsed_config, cloud_credentials, thread_pool_size = 10, debug = false, mock = false)
      @provider         = provider || parsed_config[:cloud_platform]
      @cloud_os         = parsed_config[:cloud_os_type] || 'CentOS'
      @parsed_hash      = parsed_config
      @credentials      = cloud_credentials || parsed_config[:cloud_credentials]
      @debug            = debug
      @thread_pool_size = thread_pool_size
      @mock             = mock
      @nodes            = Hash.new{ |h,k| h[k] = Hash.new(&h.default_proc) }
      raise unless @credentials.is_a?(Hash)
    end

    # Create a connection object to aws
    # @return [Ankus::Aws]
    def create_aws_connection
      Ankus::Aws.new @credentials[:aws_access_id], @credentials[:aws_secret_key], @credentials[:aws_region], @mock
    end

    # Create a connection object to rackspace
    # @return [Ankus::Rackspace]
    def create_rackspace_connection
      Ankus::Rackspace.new @credentials[:rackspace_api_key], @credentials[:rackspace_username], @mock
    end

    # Create instance definitions
    def create_cloud_instances
      num_of_slaves   = @parsed_hash[:slave_nodes_count]
      num_of_zks      = @parsed_hash[:zookeeper_quorum_count]
      volume_count    = @parsed_hash[:volumes] != 'disabled' ? @parsed_hash[:volumes][:count] : 0
      volume_size     = @parsed_hash[:volumes] != 'disabled' ? @parsed_hash[:volumes][:size] : 0
      default_config= { :os_type => @cloud_os, :volumes => 0, :volume_size => 250 }
      slaves_config = { :os_type => @cloud_os, :volumes => volume_count, :volume_size => volume_size }

      nodes_to_create_masters = {}
      nodes_to_create_slaves = {}
      nodes_to_create_masters[:controller] = %w(controller)
      if @parsed_hash[:hadoop_deploy] != 'disabled'
        if @parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
          nodes_to_create_masters[:namenode1] = %w(namenode1)
          nodes_to_create_masters[:namenode2] = %w(namenode2)
          if @parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
            nodes_to_create_masters[:jobtracker] = %w(jobtracker)
          end
        else
          nodes_to_create_masters[:namenode] = %w(namenode)
        end
        if @parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
          nodes_to_create_masters[:jobtracker] = %w(jobtracker secondarynamenode)
        elsif @parsed_hash[:hadoop_deploy][:mapreduce] and @parsed_hash[:hadoop_deploy][:hadoop_ha] == 'disabled'
          nodes_to_create_masters[:secondarynamenode] = %w(secondarynamenode)
        end
        if @parsed_hash[:hbase_deploy] != 'disabled'
          @parsed_hash[:hbase_deploy][:hbase_master_count].times do |hm|
            nodes_to_create_masters["hbasemaster#{hm+1}".to_sym] = ["hbasemaster#{hm+1}"]
          end
        end
        num_of_slaves.times do |i|
          nodes_to_create_slaves["slaves#{i+1}".to_sym] = ["slaves#{i+1}"]
        end
      end
      if @parsed_hash[:cassandra_deploy] != 'disabled'
        unless @parsed_hash[:cassandra_deploy][:colocate] # if ! colocate then create separate cassandra instances          
          @parsed_hash[:cassandra_deploy][:number_of_instances].times do |cn|
            nodes_to_create_slaves["cassandra#{cn+1}".to_sym] = ["cassandra#{cn+1}"]
          end
          @parsed_hash[:cassandra_deploy][:number_of_seeds].times do |cs|
            nodes_to_create_slaves["cassandra#{cs+1}".to_sym] << "cassandraseed#{cs+1}"
          end          
        else # colocate cassandra instances on hadoop slaves
          num_of_slaves.times { |i| nodes_to_create_slaves["slaves#{i+1}".to_sym] << "cassandra#{i+1}" }
          @parsed_hash[:cassandra_deploy][:number_of_seeds].times do |cs|
            nodes_to_create_slaves["slaves#{cs+1}".to_sym] << "cassandraseed#{cs+1}"
          end                    
        end
      end
      if @parsed_hash[:kafka_deploy] != 'disabled'
        unless @parsed_hash[:kafka_deploy][:colocate]
          @parsed_hash[:kafka_deploy][:number_of_brokers].times do |kn|
            nodes_to_create_slaves["kafka#{kn+1}".to_sym] = ["kafka#{kn+1}"]
          end
        else #colocate daemons in either hadoop or cassandra based on deploy scenario
          if @parsed_hash[:hadoop_deploy] != 'disabled'
            @parsed_hash[:kafka_deploy][:number_of_brokers].times do |kn| 
              nodes_to_create_slaves["slaves#{kn+1}".to_sym] << "kafka#{kn+1}"
            end
          else
            @parsed_hash[:kafka_deploy][:number_of_brokers].times do |kn| 
              nodes_to_create_slaves["cassandra#{kn+1}".to_sym] << "kafka#{kn+1}"
            end            
          end
        end
      end
      if @parsed_hash[:storm_deploy] != 'disabled'
        nodes_to_create_masters[:stormnimbus] = %w(stormnimbus)
        unless @parsed_hash[:storm_deploy][:colocate]
          @parsed_hash[:storm_deploy][:number_of_supervisors].times do |sn|
            nodes_to_create_slaves["stormworker#{sn+1}".to_sym] = ["stormworker#{sn+1}"]
          end
        else #colocate daemons in either hadoop or cassandra based on deploy scenario
          if @parsed_hash[:hadoop_deploy] != 'disabled'
            @parsed_hash[:storm_deploy][:number_of_supervisors].times do |sn| 
              nodes_to_create_slaves["slaves#{sn+1}".to_sym] << "stormworker#{sn+1}"
            end
          else
            @parsed_hash[:storm_deploy][:number_of_supervisors].times do |sn|
              nodes_to_create_slaves["cassandra#{sn+1}".to_sym] << "stormworker#{sn+1}"
            end            
          end
        end
      end
      #zookeepers
      if @parsed_hash[:hadoop_deploy] != 'disabled' && @parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
        num_of_zks.times do |i|
          nodes_to_create_masters["zookeeper#{i+1}".to_sym] = %w(zookeeper)
        end
      elsif @parsed_hash[:hbase_deploy] != 'disabled' or 
        @parsed_hash[:kafka_deploy] != 'disabled' or 
        @parsed_hash[:storm_deploy] != 'disabled'
        unless nodes_to_create_masters.keys.find { |e| /zookeeper/ =~ e }
          num_of_zks.times do |i|
            nodes_to_create_masters["zookeeper#{i+1}".to_sym] = %w(zookeeper)
          end
        end
      end 

      # Create node wrapper objects
      if @provider == 'aws'
        nodes_to_create_masters.each do |name, tags|
          @nodes[name] = create_node_obj(default_config, tags)
        end 
        nodes_to_create_slaves.each do |name, tags|
          @nodes[name] = create_node_obj(slaves_config, tags)
        end        
      elsif @provider == 'rackspace'
        domain_name = "#{@parsed_hash[:cloud_credentials][:rackspace_cluster_identifier]}.ankus.com"
        # add domain name to roles to form fqdn
        nodes_to_create_masters_fqdn = {}
        nodes_to_create_slaves_fqdn = {}
        nodes_to_create_masters.each {|k,v| nodes_to_create_masters_fqdn["#{k}.#{domain_name}"] = v }
        nodes_to_create_slaves.each {|k,v| nodes_to_create_slaves_fqdn["#{k}.#{domain_name}"] = v }
        nodes_to_create_masters_fqdn.each do |name, tags|
          @nodes[name] = create_node_obj(default_config, tags)
        end
        nodes_to_create_slaves_fqdn.each do |name, tags|
          @nodes[name] = create_node_obj(default_config, tags)
        end        
      end
      @nodes
    end

    # Creates cloud instances on both AWS or Rackspace using the paesed config file
    # @return [Hash] nodes => contains created node info each node is of the form
    # { :node_tag =>
    #   {
    #    :fqdn                  =>  "fully_qualified_domain_name (or) public ip",
    #    :private_ip            =>  "internal_dns_name (or) private ip",
    #    :config                =>  {:os_type=>"CentOS", :volumes=>0, :volume_size=>250},
    #    :puppet_install_status =>  null,
    #    :puppet_run_status     =>  null,
    #    :last_run              =>  null,
    #    :tags                  =>  ["list of tags for this node"]
    #   }
    # }
    def create_cloud_instances!
      create_cloud_instances
      case @provider
      when 'aws'
        @nodes = create_aws_instances(@nodes, @credentials, @thread_pool_size)
      when 'rackspace'
        @nodes = create_rackspace_instances(@nodes, @credentials, @thread_pool_size)
      end
      @nodes
    end

    # Create instances if the node has no fqdn is assigned
    # @param [Hash] nodes => merged nodes info
    def safe_create_instances!(nodes)
      nodes = nodes.select { |k, v| k if v[:fqdn].empty? }
      case @provider
      when 'aws'
        nodes = create_aws_instances(nodes, @credentials, @thread_pool_size)
      when 'rackspace'
        nodes = create_rackspace_instances(nodes, @credentials, @thread_pool_size)
      end
      nodes
    end

    # Create a single instance and return instance mappings
    # @param [Array] tags => name of the server(s), if aws used as tag | if rackspace used as fqdn
    # @return [Hash] nodes:
    #   for aws cloud, nodes: { 'tag' => [public_dns_name, private_dns_name], 
    #                           'tag' => [public_dns_name, private_dns_name] }
    #   for rackspace, nodes: { 'tag(fqdn)' => [public_ip_address, private_ip_address] }
    def create_instances_on_count(tags)
      node_created = {}
      nodes_to_create = {}
      volume_count, volume_size = calculate_disks
      tags.each do |tag|
        nodes_to_create[tag] = { :os_type => @cloud_os, :volumes => volume_count, :volume_size => volume_size }
      end
      if @provider == 'aws'
        node_created = create_on_aws nodes_to_create, @credentials, @thread_pool_size
      elsif @provider == 'rackspace'
        node_created = create_on_rackspace nodes_to_create, @credentials, @thread_pool_size
      end
      node_created
    end

    # Delete cloud instances created by ankus
    # @param [Hash] nodes_hash => hash containing info about instances (as returned by Cloud#create_instances)
    # @param [Boolean] delete_volumes => specifies whether to delete volumes attached to instances as well
    def delete_instances(nodes_hash, delete_volumes = false)
      threads_pool    = Ankus::ThreadPool.new(@thread_pool_size)
      if @parsed_hash[:cloud_platform] == 'aws'
        aws   = create_aws_connection
        conn  = aws.create_connection
        nodes_hash.each do |_, nodes_dns_map|
          threads_pool.schedule do
            server_dns_name = nodes_dns_map.first
            aws.delete_server_with_dns_name(conn, server_dns_name, delete_volumes)
          end
        end
        threads_pool.shutdown
      elsif @parsed_hash[:cloud_platform] == 'rackspace'
        rackspace = create_rackspace_connection
        conn      = rackspace.create_connection
        nodes_hash.each do |fqdn, _|
          threads_pool.schedule do
            rackspace.delete_server_with_name(conn, fqdn)
          end
        end
        threads_pool.shutdown
      end
    end

    def find_internal_ip(nodes, tag)
      if @provider == 'aws'
        find_pip_for_tag(nodes, tag)
      elsif @provider == 'rackspace'
        find_key_for_tag(nodes, tag)
      end
    end

    # Modifies the original parsed_config hash to look more like the local install mode
    # @param [Hash] parsed_hash => original parsed hash generated from configuration file
    # @param [Hash] nodes_hash => nodes hash generated by Cloud#create_on_aws|Cloud#create_on_rackspace
    # @return if rackspace [Hash, Hash] parsed_hash, parsed_internal_ips => which can be used same as local install_mode
    #         if aws [Hash, Hash] parsed_hash, parsed_internal_ips => which can be used same as local install_mode
    def modify_cloud_config(parsed_hash, nodes)
      parsed_hash_internal_ips = Marshal.load(Marshal.dump(parsed_hash))
     
      parsed_hash[:ssh_key]      =  if @provider == 'aws'
                                      File.expand_path('~/.ssh') + '/' + @credentials[:aws_key]
                                    elsif @provider == 'rackspace'
                                      File.split(File.expand_path(@credentials[:rackspace_ssh_key])).first + '/' +
                                      File.basename(File.expand_path(@credentials[:rackspace_ssh_key]), '.pub')
                                    end
      parsed_hash[:storage_dirs] =  if parsed_hash[:volumes] != 'disabled'
                                      Array.new(parsed_hash[:volumes][:count] + 1){ |i| "/data/#{i}" }
                                    else
                                      ['/data/0']
                                    end
      parsed_hash[:controller] = find_fqdn_for_tag(nodes, 'controller').first
      if parsed_hash[:hadoop_deploy] != 'disabled'
        parsed_hash[:hadoop_deploy][:hadoop_namenode] = find_fqdn_for_tag(nodes, 'namenode')
        if parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
          parsed_hash[:hadoop_deploy][:mapreduce][:master] = find_fqdn_for_tag(nodes, 'jobtracker').first
        end
        if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'disabled'
          parsed_hash[:hadoop_deploy][:hadoop_secondarynamenode] = find_fqdn_for_tag(nodes, 'secondarynamenode').first
        end
        parsed_hash[:slave_nodes] = find_fqdn_for_tag(nodes, 'slaves')
        if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
          parsed_hash[:hadoop_deploy][:journal_quorum] = find_fqdn_for_tag(nodes, 'zookeeper')
        end
        if parsed_hash[:hbase_deploy] != 'disabled'
          parsed_hash[:hbase_deploy][:hbase_master] = find_fqdn_for_tag(nodes, 'hbasemaster')
        end
      end

      if parsed_hash[:cassandra_deploy] != 'disabled'
        parsed_hash[:cassandra_deploy][:cassandra_nodes] =  find_fqdn_for_tag(nodes, 'cassandra')
        parsed_hash[:cassandra_deploy][:cassandra_seeds] =  find_fqdn_for_tag(nodes, 'cassandraseed')
      end

      if parsed_hash[:kafka_deploy] != 'disabled'
        parsed_hash[:kafka_deploy][:kafka_brokers] = find_fqdn_for_tag(nodes, 'kafka')
      end

      if parsed_hash[:storm_deploy] != 'disabled'
        parsed_hash[:storm_deploy][:storm_supervisors] =  find_fqdn_for_tag(nodes, 'stormworker')
        parsed_hash[:storm_deploy][:storm_master] = find_fqdn_for_tag(nodes, 'stormnimbus').first
      end
      #zookeepers
      if parsed_hash[:hadoop_deploy] != 'disabled' and parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
        parsed_hash[:zookeeper_quorum] = find_fqdn_for_tag(nodes, 'zookeeper')
      end
      if parsed_hash[:hbase_depoy] != 'disabled' or 
        parsed_hash[:kafka_deploy] != 'disabled' or 
        parsed_hash[:storm_deploy] != 'disabled'
        unless parsed_hash.has_key? :zookeeper_quorum
          parsed_hash[:zookeeper_quorum] = find_fqdn_for_tag(nodes, 'zookeeper')
        end
      end

      # If AWS, hash with internal ips should contain private_ip
      # If RackSpace, hash with internal ips should contain fqdn

      parsed_hash_internal_ips[:ssh_key]  = 
          if @provider == 'aws'
            File.expand_path('~/.ssh') + '/' + @credentials[:aws_key]
          elsif @provider == 'rackspace'
            File.split(File.expand_path(@credentials[:rackspace_ssh_key])).first + '/' +
            File.basename(File.expand_path(@credentials[:rackspace_ssh_key]), '.pub')
          end 
      parsed_hash_internal_ips[:controller] = find_internal_ip(nodes, 'controller').first
      if parsed_hash[:hadoop_deploy] != 'disabled'
        parsed_hash_internal_ips[:hadoop_deploy][:hadoop_namenode] = find_internal_ip(nodes, 'namenode')
        if parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
          parsed_hash_internal_ips[:hadoop_deploy][:mapreduce][:master] = find_internal_ip(nodes, 'jobtracker').first
        end    
        if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'disabled'
          parsed_hash_internal_ips[:hadoop_deploy][:hadoop_secondarynamenode] = find_internal_ip(nodes, 'secondarynamenode').first
        end
        parsed_hash_internal_ips[:slave_nodes] = find_internal_ip(nodes, 'slaves')
        if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
          parsed_hash_internal_ips[:hadoop_deploy][:journal_quorum] = find_internal_ip(nodes, 'zookeeper')
        end
        if parsed_hash[:hbase_deploy] != 'disabled'      
          parsed_hash_internal_ips[:hbase_deploy][:hbase_master] = find_internal_ip(nodes, 'hbasemaster')
        end
      end
      if parsed_hash[:cassandra_deploy] != 'disabled'
        parsed_hash_internal_ips[:cassandra_deploy][:cassandra_nodes] =  find_internal_ip(nodes, 'cassandra')
        parsed_hash_internal_ips[:cassandra_deploy][:cassandra_seeds] =  find_internal_ip(nodes, 'cassandraseed')
      end
      if parsed_hash[:kafka_deploy] != 'disabled'
        parsed_hash_internal_ips[:kafka_deploy][:kafka_brokers] = find_internal_ip(nodes, 'kafka')
      end
      if parsed_hash[:storm_deploy] != 'disabled'
        parsed_hash_internal_ips[:storm_deploy][:storm_supervisors] =  find_internal_ip(nodes, 'stormworker')
        parsed_hash_internal_ips[:storm_deploy][:storm_master] = find_internal_ip(nodes, 'stormnimbus').first
      end
      if parsed_hash[:hadoop_deploy] != 'disabled' and parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
        parsed_hash_internal_ips[:zookeeper_quorum] = find_internal_ip(nodes, 'zookeeper')
      end
      if parsed_hash[:hbase_depoy] != 'disabled' or 
        parsed_hash[:kafka_deploy] != 'disabled' or 
        parsed_hash[:storm_deploy] != 'disabled'
        unless parsed_hash_internal_ips.has_key? :zookeeper_quorum
          parsed_hash_internal_ips[:zookeeper_quorum] = find_internal_ip(nodes, 'zookeeper') 
        end
      end

      return parsed_hash, parsed_hash_internal_ips
    end

    # Create servers on aws using Ankus::Aws
    # @param [Hash] nodes => hash of nodes to create with their info as shown below
    # @param [Hash] credentials: {  aws_access_id: '', aws_secret_key: '', aws_machine_type: 'm1.large', 
    #                               aws_region: 'us-west-1', aws_key: 'ankus'}
    # @param [Integer] thread_pool_size => size of the thread pool
    # @return [Hash] modified ver of nodes
    def create_aws_instances(nodes, credentials, thread_pool_size)
      #defaults
      threads_pool    = Ankus::ThreadPool.new(thread_pool_size)
      key             = credentials[:aws_key] || 'ankus'
      groups          = credentials[:aws_sec_groups] || %w(ankus)
      flavor_id       = credentials[:aws_machine_type] || 'm1.large'
      aws             = create_aws_connection
      conn            = aws.create_connection
      ssh_key         = File.expand_path('~/.ssh') + "/#{key}"
      ssh_user        = @parsed_hash[:ssh_user]
      server_objects  = {} # hash to store server object to tag mapping { tag => server_obj }

      if aws.valid_connection?(conn)
        puts "\r[Debug]: successfully authenticated with aws" if @debug
      else
        puts "\r[Error]".red + ' failed connecting to aws'
        exit 1
      end

      begin
        SpinningCursor.start do
          banner "\rCreating servers with roles: " + "#{nodes.keys.join(',')}".blue
          type :dots
          message "\rCreating servers with roles: " + "#{nodes.keys.join(',')}".blue + ' [DONE]'.cyan
        end
        iops =  if @parsed_hash[:volumes] != 'disabled' and @parsed_hash[:volumes][:type] == 'io1'
                  @parsed_hash[:volumes][:iops]
                else
                  0
                end
        vol_type =  if @parsed_hash[:volumes] != 'disabled'
                      @parsed_hash[:volumes][:type]
                    else
                      'ebs'
                    end
        nodes.each do |tag, info|
          server_objects[tag] = aws.create_server!(
            conn,
            tag,
            :key => key,
            :groups => groups,
            :flavor_id => flavor_id,
            :os_type => info[:config][:os_type],
            :num_of_vols => info[:config][:volumes],
            :vol_size => info[:config][:volume_size],
            :vol_type => vol_type,
            :iops => iops
          )
        end
        SpinningCursor.stop
      rescue SpinningCursor::CursorNotRunning
        # silently ignore this for mocking
      end

      # wait for servers to get created (:state => running)
      SpinningCursor.start do
        banner "\rWaiting for servers to get created "
        type :dots
        action do
          aws.wait_for_servers(server_objects.values)
        end
        message "\rWaiting for servers to get created " + '[DONE]'.cyan
      end
      # wait for the boot to complete
      if ! @mock
        SpinningCursor.start do
          banner "\rWaiting for cloud instances to complete their boot (which includes mounting the volumes) "
          type :dots
          action do
            #TODO: this method is taking forever, find another way to make sure volumes are properly mounted
            aws.complete_wait(server_objects.values, @cloud_os)
          end
          message "\rWaiting for cloud instances to complete their boot " + '[DONE]'.cyan
        end
      end
      # build the return string
      nodes.each do |tag, node_info|
        # fill in nodes hash with public and private dns
        node_info[:fqdn] = server_objects[tag].dns_name
        node_info[:private_ip] = server_objects[tag].private_dns_name
      end
      if ! @mock
        puts "\rPartitioning|Formatting attached volumes".blue
        # partition and format attached disks using thread pool
        nodes.each do |tag, info|
          threads_pool.schedule do
            if info[:config][:volumes] > 0
              printf "\r[Debug]: Formatting attached volumes on instance #{server_objects[tag].dns_name}\n" if @debug
              #build partition script
              partition_script = gen_partition_script(info[:config][:volumes], true)
              tempfile = Tempfile.new('partition')
              tempfile.write(partition_script)
              tempfile.close
              # wait for the server to be ssh'able
              Ankus::SshUtils.wait_for_ssh(server_objects[tag].dns_name, ssh_user, ssh_key)
              # upload and execute the partition script on the remote machine
              SshUtils.upload!(
                  tempfile.path,
                  '/tmp',
                  server_objects[tag].dns_name,
                  ssh_user,
                  ssh_key,
                  22,
                  @debug
              )
              output = Ankus::SshUtils.execute_ssh!(
                  "chmod +x /tmp/#{File.basename(tempfile.path)} && sudo sh -c '/tmp/#{File.basename(tempfile.path)}" + 
                    " | tee /var/log/bootstrap_volumes.log'",
                  server_objects[tag].dns_name,
                  ssh_user,
                  ssh_key,
                  22,
                  false # we don't want output of formatting volumes to be printed in real time to stdout!!
              )
              tempfile.unlink # delete the tempfile
              if @debug
                puts "\r[Debug]: Stdout on #{server_objects[tag].dns_name}"
                puts "\r#{output[server_objects[tag].dns_name][0]}"
                puts "\r[Debug]: Stderr on #{server_objects[tag].dns_name}"
                puts "\r#{output[server_objects[tag].dns_name][1]}"
                puts "\r[Debug]: Exit code from #{server_objects[tag].dns_name}: " + 
                      "#{output[server_objects[tag].dns_name][2]}"
              end
            else
              # if not waiting for mounting volumes, wait for instances to become sshable
              Ankus::SshUtils.wait_for_ssh(server_objects[tag].dns_name, ssh_user, ssh_key)
            end
          end
        end
        threads_pool.shutdown

        puts "\r[Debug]: Finished creating and attaching volumes" if @debug
      else
        # pretend doing some work while mocking
        puts "\rPartitioning/Formatting attached volumes".blue
        nodes.each do |tag, info|
          threads_pool.schedule do
            if info[:config][:volumes] > 0
              printf "\r[Debug]: Preping attached volumes on instance #{server_objects[tag].dns_name}\n"
              sleep 5
            else
              printf "\r[Debug]: Waiting for instance to become ssh'able #{server_objects[tag].dns_name} " + 
                     "with ssh_user: #{ssh_user} and ssh_key: #{ssh_key}\n"
            end
          end
        end
        threads_pool.shutdown
      end
      nodes
    end    

    # Create servers on rackspace using Ankus::RackSpace
    # @param [Hash] nodess => hash of nodes to create with their info
    # @param [Hash] #cloud_credentials: { rackspace_username: , rackspace_api_key: , rackspace_instance_type: ,
    #                                     rackspace_ssh_key: '~/.ssh/id_rsa.pub' }
    # @param [Integer] thread_pool_size => size of the thread pool
    # @return [Hash] modified variant of nodes with fqdn and private_ip
    def create_rackspace_instances(nodes, credentials, thread_pool_size)
      threads_pool        = Ankus::ThreadPool.new(thread_pool_size)
      machine_type        = credentials[:rackspace_instance_type] || 4
      public_ssh_key_path = credentials[:rackspace_ssh_key] || '~/.ssh/id_rsa.pub'
      ssh_key_path        = File.split(public_ssh_key_path).first + '/' + File.basename(public_ssh_key_path, '.pub')
      ssh_user            = @parsed_hash[:ssh_user]
      rackspace           = create_rackspace_connection
      conn                = rackspace.create_connection
      server_objects      = {} # hash to store server object to tag mapping { tag => server_obj }

      puts "\r[Debug]: Using ssh_key #{ssh_key_path}" if @debug
      puts "\rCreating servers with roles: " + "#{nodes.keys.join(',')} ...".blue
      nodes.each do |tag, info|
        server_objects[tag] = rackspace.create_server!(conn, 
                                  tag, 
                                  public_ssh_key_path, 
                                  machine_type, 
                                  info[:config][:os_type]
                              )
      end
      puts "\rCreating servers with roles: " + "#{nodes.keys.join(',')} ".blue + '[DONE]'.cyan

      # wait for servers to get created (:state => ACTIVE)
      begin
        SpinningCursor.start do
          banner "\rWaiting for servers to get created "
          type :dots
          action do
            rackspace.wait_for_servers(server_objects.values)
          end
          message "\rWaiting for servers to get created " + '[DONE]'.cyan
        end
      rescue SpinningCursor::CursorNotRunning
        # silently ignore this
      end

      # build the return string
      nodes.each do |tag, node_info|
        # fill in nodes fqdn and private_ip
        node_info[:fqdn] = server_objects[tag].public_ip_address
        node_info[:private_ip] = server_objects[tag].private_ip_address
      end

      # Attach Volumes
      if ! @mock
        puts "\rPartitioning|Formatting attached volumes".blue
        # parition and format attached disks using thread pool
        nodes.each do |tag, info|
          threads_pool.schedule do
            if info[:config][:volumes] > 0
              printf "\r[Debug]: Preping attached volumes on instnace #{server_objects[tag]}\n" if @debug
              # attach specified volumes to server
              rackspace.attach_volumes!(server_objects[tag], info[:config][:volumes], info[:config][:volume_size])
              # build partition script
              partition_script = gen_partition_script(info[:config][:volumes])
              tempfile = Tempfile.new('partition')
              tempfile.write(partition_script)
              tempfile.close
              # wait for the server to be ssh'able
              Ankus::SshUtils.wait_for_ssh(server_objects[tag].public_ip_address, 
                                            ssh_user, 
                                            File.expand_path(ssh_key_path)
                                          )
              # upload and execute the partition script on the remote machine
              SshUtils.upload!(
                  tempfile.path,
                  '/tmp',
                  server_objects[tag].public_ip_address,
                  ssh_user,
                  File.expand_path(ssh_key_path),
                  22,
                  @debug
              )
              output = Ankus::SshUtils.execute_ssh!(
                  "chmod +x /tmp/#{File.basename(tempfile.path)} && sudo sh -c '/tmp/#{File.basename(tempfile.path)}" +
                    " | tee /var/log/bootstrap_volumes.log'",
                  server_objects[tag].public_ip_address,
                  ssh_user,
                  File.expand_path(ssh_key_path),
                  22,
                  false)
              tempfile.unlink # delete the tempfile
              if @debug
                puts "\r[Debug]: Stdout on #{server_objects[tag].public_ip_address}"
                puts "\r#{output[server_objects[tag].public_ip_address][0]}"
                puts "\r[Debug]: Stdout on #{server_objects[tag].public_ip_address}"
                puts "\r#{output[server_objects[tag].public_ip_address][1]}"
                puts "\r[Debug]: Exit code from #{server_objects[tag].public_ip_address}: " + 
                    " #{output[server_objects[tag].public_ip_address][2]}"
              end
            else
              # if not mounting volumes wait for instances to become available
              Ankus::SshUtils.wait_for_ssh(server_objects[tag].public_ip_address, 
                                            ssh_user, 
                                            File.expand_path(ssh_key_path)
                                          )
            end
          end
        end
        threads_pool.shutdown
        puts "\r[Debug]: Finished creating and attaching volumes" if @debug
      else
        #MOCKING
        # pretend doing some work while mocking
        puts "\rPartitioning|Formatting attached volumes".blue
        nodes.each do |tag, info|
          threads_pool.schedule do
            if info[:config][:volumes] > 0
              printf "\r[Debug]: Preping attached volumes on instance #{server_objects[tag].public_ip_address}\n"
              sleep 5
            else
              printf "\r[Debug]: Waiting for instance to become ssh'able #{server_objects[tag].public_ip_address} " +
                     "with ssh_user: #{ssh_user} and ssh_key: #{File.expand_path(ssh_key_path)}\n"
            end
          end
        end
        threads_pool.shutdown
      end
      nodes
    end    

    # Builds and returns a shell script for partitioning and resizing root volume(s)
    # @param [Integer] number_of_volumes => number of volumes to partition & mount, this number is used to grep the
    #                                       value from /proc/partitions
    # @param [Boolean] resize_root_vol => whether to resize th root partition or not
    # @return [ERB] build out shell script
    def gen_partition_script(number_of_volumes, resize_root_vol = false)
      resize_root = resize_root_vol ? 0 : 1
      template    = <<-END.gsub(/^ {6}/, '')
      #!/bin/bash
      RESIZE_ROOT=<%= resize_root %>
      if [ $RESIZE_ROOT -eq 0 ]; then
      echo "Resizing the root partition"
      resize2fs /dev/`cat /proc/partitions | awk '/xvd*/ {print $4}' | head -n1`
      fi
      NUM_OF_VOLS=<%= number_of_volumes %>
      if [ $NUM_OF_VOLS -ne 0 ]; then
      DEVICES=`cat /proc/partitions | awk '/xvd*/ {print $4}' | tail -n<%= number_of_volumes %>`
      echo "Formatting and mounting initiated"
      count=1
      for dev in $DEVICES; do
      echo "Formatting and mounting $dev"
      fdisk -u /dev/$dev << EOF
      n
      p
      1


      w
      EOF
      mkfs.ext4 /dev/${dev}1
      data_dir=$((count++))
      mkdir -p /data/${data_dir}
      mount /dev/${dev}1 /data/${data_dir}
      done
      fi
      END
      ERB.new(template).result(binding)
    end

    # Builds /etc/hosts file @ file path specified
    # @param [Hash] nodes => { 'tag(fqdn)' => {:fqdn => '', :private_ip => '', ...}, ... }
    # @return [String] contents of hosts file
    def build_hosts(nodes)
      hosts_string = ''
      if @cloud_os.downcase == 'centos'
        hosts_string << "127.0.0.1\tlocalhost localhost.localdomain localhost4 localhost4.localdomain4" << "\n"
        hosts_string << "::1\tlocalhost localhost.localdomain localhost6 localhost6.localdomain6" << "\n"
      elsif @cloud_os.downcase == 'ubuntu'
        hosts_string << "127.0.0.1\tlocalhost" << "\n"
        hosts_string << "::1\tip6-localhost\tip6-loopback" << "\n"
        hosts_string << "fe00::0\tip6-localnet\nff00::0\tip6-mcastprefix\nff02::1\tip6-allnodes\nff02::2\tip6-allrouters" << "\n"
      end
      nodes.each do |fqdn, node_info|
        hosts_string << "#{node_info[:fqdn]}\t#{fqdn}\t#{fqdn.split('.').first}" << "\n"
      end
      hosts_string
    end

    # Creates a wrapper around the node object
    # @param [Hash] config => {:ostype => 'centos', :volumes => 0, :volume_size => 250}
    # @param [Hash] tags => ['node_tag']
    # @return [Hash]
    def create_node_obj(config, tags)
      {
        :fqdn => '',
        :private_ip => '',
        :config => config,
        :puppet_install_status => false,
        :puppet_run_status => false,
        :last_run => '',
        :tags => tags
      }
    end

    # Calculates number of disks to insert into vms and their size based on users specified total storage in
    # configuration
    # @return [Fixnum, Fixnum] number of volumes to create and size of each volume
    def calculate_disks
      slave_nodes_disk_size = @parsed_hash[:slave_nodes_storage_capacity] || 0
      if @provider == 'aws'
        volume_count =  if slave_nodes_disk_size.nil? or slave_nodes_disk_size.to_i == 0
                          # assume user do not want any extra volumes
                          0
                        else
                          # user wants extra volumes
                          4
                        end
        volume_size =   if slave_nodes_disk_size.nil? or slave_nodes_disk_size.to_i == 0
                          0
                        else
                          slave_nodes_disk_size / volume_count
                        end
        return volume_count, volume_size
      elsif @provider == 'rackspace'
        volume_count =  if slave_nodes_disk_size.nil? or slave_nodes_disk_size.to_i == 0
                          0
                        elsif slave_nodes_disk_size.to_i > 400
                          4
                        else
                          slave_nodes_disk_size.to_i / 100
                        end
        volume_size =   if slave_nodes_disk_size.nil? or slave_nodes_disk_size.to_i == 0
                          0
                        elsif slave_nodes_disk_size.to_i > 400
                          slave_nodes_disk_size / volume_count
                        else
                          100
                        end
        return volume_count, volume_size
      end
    end
  end
end
