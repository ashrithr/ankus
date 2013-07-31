=begin
  Class to manage cloud instances
  currently supported cloud platforms are aws and rackspace
=end

module Ankuscli
  require 'erb'

  class Cloud
    # Create a new Cloud class object
    # @param [String] provider => Cloud service provider; aws|rackspace
    # @param [Hash] parsed_config => Configuration that has been already parsed from cloud_configuration file
    # @param [Hash] cloud_credentials => Credentials configurations
    #     if aws: cloud_credentials => { aws_access_id: '', aws_secret_key: '', aws_machine_type: 'm1.large', aws_region: 'us-west-1', aws_key: 'ankuscli' }
    #     if rackspace: cloud_credentials => { rackspace_username: '', rackspace_api_key: '', rackspace_instance_type: '', rackspace_ssh_key: '~/.ssh/id_rsa.pub' }
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
      raise unless @credentials.is_a?(Hash)
    end

    # Create a connection object to aws
    # @return [Ankuscli::Aws]
    def create_aws_connection
      Ankuscli::Aws.new @credentials[:aws_access_id], @credentials[:aws_secret_key], @credentials[:aws_region], @mock
    end

    # Create a connection object to rackspace
    # @return [Ankuscli::Rackspace]
    def create_rackspace_connection
      Ankuscli::Rackspace.new @credentials[:rackspace_api_key], @credentials[:rackspace_username], @mock
    end

    # Parse cloud_configuration; create instances and return instance mappings
    # @return [Hash]
    #   for aws cloud, nodes: { 'tag' => [public_dns_name, private_dns_name], 'tag' => [public_dns_name, private_dns_name], ... }
    #   for rackspace, nodes: { 'tag(fqdn)' => [public_ip_address, private_ip_address], ... }
    def create_instances
      num_of_slaves   = @parsed_hash[:slave_nodes_count]
      num_of_zks      = @parsed_hash[:zookeeper_quorum_count]
      nodes_created   = {}
      nodes_to_create = {}
      volume_count, volume_size = calculate_disks

      #create nodes to create
      nodes_to_create['controller'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 250 }
      if @parsed_hash[:hadoop_deploy] != 'disabled'
        if @parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
          nodes_to_create['namenode1']  = { :os_type => @cloud_os, :volumes => 0, :volume_size => 250 }
          nodes_to_create['namenode2']  = { :os_type => @cloud_os, :volumes => 0, :volume_size => 250 }
          nodes_to_create['jobtracker'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 250 } if @parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
          num_of_zks.times do |i|
            nodes_to_create["zookeeper#{i+1}"] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 250 }
          end
        else
          nodes_to_create['namenode'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 250 }
        end
        if @parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
          nodes_to_create['jobtracker'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 250 } #JT and SNN
        elsif @parsed_hash[:hadoop_deploy][:mapreduce] and @parsed_hash[:hadoop_deploy][:hadoop_ha] == 'disabled'
          nodes_to_create['snn'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 250 } #SNN
        end
        if @parsed_hash[:hbase_deploy] != 'disabled'
          @parsed_hash[:hbase_deploy][:hbase_master_count].times do |hm|
            nodes_to_create["hbasemaster#{hm+1}"] =  { :os_type => @cloud_os, :volumes => 0, :volume_size => 250 }
          end
          unless nodes_to_create.keys.find { |e| /zookeeper/ =~ e }
            num_of_zks.times do |i|
              nodes_to_create["zookeeper#{i+1}"] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 250 }
            end
          end
        end
        num_of_slaves.times do |i|
          nodes_to_create["slaves#{i+1}"] = { :os_type => @cloud_os, :volumes => volume_count, :volume_size => volume_size }
        end
      end
      if @parsed_hash[:cassandra_deploy] != 'disabled'
        unless @parsed_hash[:cassandra_deploy][:hadoop_colocation]
          # if hadoop colocation is not enabled then create separate cassandra instances
          @parsed_hash[:cassandra_deploy][:number_of_instances].times do |cn|
            nodes_to_create["cassandra#{cn+1}"] = { :os_type => @cloud_os, :volumes => volume_count, :volume_size => volume_size }
          end
        end
      end

      pp nodes_to_create if @mock

      if @provider == 'aws'
        nodes_created = create_on_aws(nodes_to_create, @credentials, @thread_pool_size)
      elsif @provider == 'rackspace'
        domain_name = "#{@parsed_hash[:cloud_credentials][:rackspace_cluster_identifier]}.ankus.com"
        # add domain name to roles to form fqdn
        nodes_to_create_fqdn = {}
        nodes_to_create.each {|k,v| nodes_to_create_fqdn["#{k}.#{domain_name}"] = v }
        nodes_created = create_on_rackspace(nodes_to_create_fqdn, @credentials, @thread_pool_size)
      end
      # returns parse nodes hash
      nodes_created
    end

    # Create a single instance and return instance mappings
    # @param [Array] tags => name of the server(s), if aws used as tag | if rackspace used as fqdn
    # @return [Hash] nodes:
    #   for aws cloud, nodes: { 'tag' => [public_dns_name, private_dns_name], 'tag' => [public_dns_name, private_dns_name] }
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

    # Delete cloud instances created by ankuscli
    # @param [Hash] nodes_hash => hash containing info about instances (as returned by Cloud#create_instances)
    # @param [Boolean] delete_volumes => specifies whether to delete volumes attached to instances as well
    def delete_instances(nodes_hash, delete_volumes = false)
      if @parsed_hash[:cloud_platform] == 'aws'
        aws   = create_aws_connection
        conn  = aws.create_connection
        nodes_hash.each do |_, nodes_dns_map|
          server_dns_name = nodes_dns_map.first
          aws.delete_server_with_dns_name(conn, server_dns_name, delete_volumes)
        end
      elsif @parsed_hash[:cloud_platform] == 'rackspace'
        rackspace = create_rackspace_connection
        conn      = rackspace.create_connection
        nodes_hash.each do |fqdn, _|
          rackspace.delete_server_with_name(conn, fqdn)
        end
      end
    end

    # Modifies the original parsed_config hash to look more like the local install mode
    # @param [Hash] parsed_hash => original parsed hash generated from configuration file
    # @param [Hash] nodes_hash => nodes hash generated by Cloud#create_on_aws|Cloud#create_on_rackspace
    # @return if rackspace [Hash, Hash] parsed_hash, parsed_internal_ips => which can be used same as local install_mode
    #         if aws [Hash, Hash] parsed_hash, parsed_internal_ips => which can be used same as local install_mode
    def modify_config_hash(parsed_hash, nodes_hash)
      parsed_hash_internal_ips = Marshal.load(Marshal.dump(parsed_hash))
      #things to add back to parsed_hash:
      # ssh_key:
      # controller:
      # hadoop_namenode: []
      # hadoop_secondarynamenode: if hadoop_ha == 'disabled'
      # zookeeper_quorum: []
      # journal_quorum: []
      # mapreduce['master']:
      # slave_nodes: []
      # hbase_master: [] if hbase_install == enabled
      parsed_hash[:ssh_key] =  if @provider == 'aws'
                                  File.expand_path('~/.ssh') + '/' + @credentials[:aws_key]
                                elsif @provider == 'rackspace'
                                  File.split(File.expand_path(@credentials[:rackspace_ssh_key])).first + '/' +
                                  File.basename(File.expand_path(@credentials[:rackspace_ssh_key]), '.pub')
                                end
      parsed_hash[:controller] = nodes_hash.map { |k,v| v.first if k =~ /controller/ }.compact.first
      if parsed_hash[:hadoop_deploy] != 'disabled'
        parsed_hash[:hadoop_deploy][:hadoop_namenode]    = nodes_hash.map { |k,v| v.first if k =~ /namenode/ }.compact
        parsed_hash[:hadoop_deploy][:mapreduce][:master] = nodes_hash.map { |k,v| v.first if k =~ /jobtracker/ }.compact.first if parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
        if parsed_hash[:hadoop_deploy][:mapreduce] == 'disabled' and parsed_hash[:hadoop_deploy][:hadoop_ha] == 'disabled'
          parsed_hash[:hadoop_deploy][:hadoop_secondarynamenode] = nodes_hash.map { |k,v| v.first if k =~ /snn/ }.compact.first
        elsif parsed_hash[:hadoop_deploy][:mapreduce] and parsed_hash[:hadoop_deploy][:hadoop_ha] == 'disabled'
          parsed_hash[:hadoop_deploy][:hadoop_secondarynamenode] = nodes_hash.map { |k,v| v.first if k =~ /jobtracker/ }.compact.first
        end
        parsed_hash[:slave_nodes]                     = nodes_hash.map { |k,v| v.first if k =~ /slaves/ }.compact
        parsed_hash[:zookeeper_quorum]                = nodes_hash.map { |k,v| v.first if k =~ /zookeeper/ }.compact if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled' or parsed_hash[:hbase_deploy] != 'disabled'
        parsed_hash[:hadoop_deploy][:journal_quorum]  = nodes_hash.map { |k,v| v.first if k =~ /zookeeper/ }.compact if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
        parsed_hash[:hbase_deploy][:hbase_master]     = nodes_hash.map { |k,v| v.first if k =~ /hbasemaster/ }.compact if parsed_hash[:hbase_deploy] != 'disabled'
      end
      if parsed_hash[:cassandra_deploy] != 'disabled' and ! parsed_hash[:cassandra_deploy][:hadoop_colocation]
        parsed_hash[:cassandra_deploy][:cassandra_nodes] = nodes_hash.map { |k,v| v.first if k =~ /cassandra/ }.compact
      elsif parsed_hash[:cassandra_deploy] != 'disabled' and parsed_hash[:cassandra_deploy][:hadoop_colocation]
        parsed_hash[:cassandra_deploy][:cassandra_nodes] = nodes_hash.map { |k,v| v.first if k =~ /slaves/ }.compact
      end

      # hash with internal ips
      if @provider == 'aws' # internal_ips
        parsed_hash_internal_ips[:ssh_key]    = File.expand_path('~/.ssh') + '/' + @parsed_hash[:cloud_credentials][:aws_key]
        parsed_hash_internal_ips[:controller] = nodes_hash.map { |k,v| v.last if k =~ /controller/ }.compact.first
        if parsed_hash[:hadoop_deploy] != 'disabled'
          parsed_hash_internal_ips[:hadoop_deploy][:hadoop_namenode] = nodes_hash.map { |k,v| v.last if k =~ /namenode/ }.compact
          parsed_hash_internal_ips[:hadoop_deploy][:mapreduce][:master] = nodes_hash.map { |k,v| v.last if k =~ /jobtracker/ }.compact.first if parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
          if parsed_hash[:hadoop_deploy][:mapreduce] == 'disabled' and parsed_hash[:hadoop_deploy][:hadoop_ha] == 'disabled'
            parsed_hash_internal_ips[:hadoop_deploy][:hadoop_secondarynamenode] = nodes_hash.map { |k,v| v.last if k =~ /snn/ }.compact.first
          elsif parsed_hash[:hadoop_deploy][:mapreduce] and parsed_hash[:hadoop_deploy][:hadoop_ha] == 'disabled'
            parsed_hash_internal_ips[:hadoop_deploy][:hadoop_secondarynamenode] = nodes_hash.map { |k,v| v.last if k =~ /jobtracker/ }.compact.first
          end
          parsed_hash_internal_ips[:slave_nodes]                    = nodes_hash.map { |k,v| v.last if k =~ /slaves/ }.compact
          parsed_hash_internal_ips[:zookeeper_quorum]               = nodes_hash.map { |k,v| v.last if k =~ /zookeeper/ }.compact if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled' or parsed_hash[:hbase_deploy] != 'disabled'
          parsed_hash_internal_ips[:hadoop_deploy][:journal_quorum] = nodes_hash.map { |k,v| v.last if k =~ /zookeeper/ }.compact if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
          parsed_hash_internal_ips[:hbase_deploy][:hbase_master]    = nodes_hash.map { |k,v| v.last if k =~ /hbasemaster/ }.compact if parsed_hash[:hbase_deploy] != 'disabled'
        end
        if parsed_hash[:cassandra_deploy] != 'disabled' and ! parsed_hash[:cassandra_deploy][:hadoop_colocation]
          parsed_hash_internal_ips[:cassandra_deploy][:cassandra_nodes] = nodes_hash.map { |k,v| v.last if k =~ /cassandra/ }.compact
        elsif parsed_hash[:cassandra_deploy] != 'disabled' and parsed_hash[:cassandra_deploy][:hadoop_colocation]
          parsed_hash_internal_ips[:cassandra_deploy][:cassandra_nodes] = nodes_hash.map { |k,v| v.last if k =~ /slaves/ }.compact
        end
      elsif @provider == 'rackspace' # fqdn
        parsed_hash_internal_ips[:ssh_key] = File.split(File.expand_path(@credentials[:rackspace_ssh_key])).first + '/' +
                                                        File.basename(File.expand_path(@credentials[:rackspace_ssh_key]), '.pub')
        parsed_hash_internal_ips[:controller] = nodes_hash.map { |k,_| k if k =~ /controller/ }.compact.first
        if parsed_hash[:hadoop_deploy] != 'disabled'
          parsed_hash_internal_ips[:hadoop_deploy][:hadoop_namenode]    = nodes_hash.map { |k,_| k if k =~ /namenode/ }.compact
          parsed_hash_internal_ips[:hadoop_deploy][:mapreduce][:master] = nodes_hash.map { |k,_| k if k =~ /jobtracker/ }.compact.first if parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
          if parsed_hash[:hadoop_deploy][:mapreduce] == 'disabled' and parsed_hash[:hadoop_deploy][:hadoop_ha] == 'disabled'
            parsed_hash_internal_ips[:hadoop_deploy][:hadoop_secondarynamenode] = nodes_hash.map { |k,_| k if k =~ /snn/ }.compact.first
          elsif parsed_hash[:hadoop_deploy][:mapreduce] and parsed_hash[:hadoop_deploy][:hadoop_ha] == 'disabled'
            parsed_hash_internal_ips[:hadoop_deploy][:hadoop_secondarynamenode] = nodes_hash.map { |k,_| k if k =~ /jobtracker/ }.compact.first
          end
          parsed_hash_internal_ips[:slave_nodes]                    = nodes_hash.map { |k,_| k if k =~ /slaves/ }.compact
          parsed_hash_internal_ips[:zookeeper_quorum]               = nodes_hash.map { |k,_| k if k =~ /zookeeper/ }.compact if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled' or parsed_hash[:hbase_install] != 'disabled'
          parsed_hash_internal_ips[:hadoop_deploy][:journal_quorum] = nodes_hash.map { |k,_| k if k =~ /zookeeper/ }.compact if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
          parsed_hash_internal_ips[:hbase_deploy][:hbase_master]    = nodes_hash.map { |k,_| k if k =~ /hbasemaster/ }.compact if parsed_hash[:hbase_deploy] != 'disabled'
        end
        if parsed_hash[:cassandra_deploy] != 'disabled' and ! parsed_hash[:cassandra_deploy][:hadoop_colocation]
          parsed_hash_internal_ips[:cassandra_deploy][:cassandra_nodes] = nodes_hash.map { |k,_| k if k =~ /cassandra/ }.compact
        elsif parsed_hash[:cassandra_deploy] != 'disabled' and parsed_hash[:cassandra_deploy][:hadoop_colocation]
          parsed_hash_internal_ips[:cassandra_deploy][:cassandra_nodes] = nodes_hash.map { |k,_| k if k =~ /slaves/ }.compact
        end
      end
      return parsed_hash, parsed_hash_internal_ips
    end

    # Create servers on aws using Ankuscli::Aws
    # @param [Hash] nodes_to_create => hash of nodes to create with their info as shown below
    #      { 'node_tag' => { :os_type => cloud_os_type, :volumes => 2, :volume_size => 50 }, ... }
    # @param [Hash] credentials: {  aws_access_id: '', aws_secret_key: '', aws_machine_type: 'm1.large', aws_region: 'us-west-1', aws_key: 'ankuscli'}
    # @param [Integer] thread_pool_size => size of the thread pool
    # @return [Hash] results => { 'instance_tag' => [public_dns_name, private_dns_name], ... }
    def create_on_aws(nodes_to_create, credentials, thread_pool_size)
      #defaults
      threads_pool    = Ankuscli::ThreadPool.new(thread_pool_size)
      key             = credentials[:aws_key] || 'ankuscli'
      groups          = credentials[:aws_sec_groups] || %w(ankuscli)
      flavor_id       = credentials[:aws_machine_type] || 'm1.large'
      aws             = create_aws_connection
      conn            = aws.create_connection
      ssh_key         = File.expand_path('~/.ssh') + "/#{key}"
      ssh_user        = @parsed_hash[:ssh_user]
      results         = {}
      server_objects  = {} # hash to store server object to tag mapping { tag => server_obj }, used for attaching volumes

      if aws.valid_connection?(conn)
        puts "\r[Debug]: successfully authenticated with aws" if @debug
      else
        puts "\r[Error]".red + ' failed connecting to aws'
        exit 1
      end

      begin
        SpinningCursor.start do
          banner "\rCreating servers with roles: " + "#{nodes_to_create.keys.join(',')}".blue
          type :dots
          message "\rCreating servers with roles: " + "#{nodes_to_create.keys.join(',')}".blue + ' [DONE]'.cyan
        end
        nodes_to_create.each do |tag, info|
          server_objects[tag] = aws.create_server!(
            conn,
            tag,
            :key => key,
            :groups => groups,
            :flavor_id => flavor_id,
            :os_type => info[:os_type],
            :num_of_vols => info[:volumes],
            :vol_size => info[:volume_size]
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
            aws.complete_wait(server_objects.values, @cloud_os) #TODO: this method is taking forever, find another way to make sure volumes are properly mounted
          end
          message "\rWaiting for cloud instances to complete their boot " + '[DONE]'.cyan
        end
      end
      # build the return string
      nodes_to_create.each do |tag, _|
        # fill in return hash
        results[tag] = [ server_objects[tag].dns_name, server_objects[tag].private_dns_name ]
      end
      if ! @mock
        puts "\rPartitioning|Formatting attached volumes".blue
        # partition and format attached disks using thread pool
        nodes_to_create.each do |tag, info|
          threads_pool.schedule do
            if info[:volumes] > 0
              puts "\r[Debug]: Formatting attached volumes on instance #{server_objects[tag].dns_name}" if @debug
              #build partition script
              partition_script = gen_partition_script(info[:volumes], true)
              tempfile = Tempfile.new('partition')
              tempfile.write(partition_script)
              tempfile.close
              # wait for the server to be ssh'able
              Ankuscli::SshUtils.wait_for_ssh(server_objects[tag].dns_name, ssh_user, ssh_key)
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
              output = Ankuscli::SshUtils.execute_ssh!(
                  "chmod +x /tmp/#{File.basename(tempfile.path)} && sudo sh -c '/tmp/#{File.basename(tempfile.path)} | tee /var/log/bootstrap_volumes.log'",
                  server_objects[tag].dns_name,
                  ssh_user,
                  ssh_key,
                  22,
                  @debug)
              tempfile.unlink # delete the tempfile
              if @debug
                puts "\r[Debug]: Stdout on #{server_objects[tag].dns_name}"
                puts "\r#{output[server_objects[tag].dns_name][0]}"
                puts "\r[Debug]: Stderr on #{server_objects[tag].dns_name}"
                puts "\r#{output[server_objects[tag].dns_name][1]}"
                puts "\r[Debug]: Exit code from #{server_objects[tag].dns_name}: #{output[server_objects[tag].dns_name][2]}"
              end
            else
              # if not waiting for mounting volumes, wait for instances to become sshable
              Ankuscli::SshUtils.wait_for_ssh(server_objects[tag].dns_name, ssh_user, ssh_key)
            end
          end
        end
        threads_pool.shutdown

        puts "\r[Debug]: Finished creating and attaching volumes" if @debug
      else
        # pretend doing some work while mocking
        puts "\rPartitioning/Formatting attached volumes".blue
        nodes_to_create.each do |tag, info|
          threads_pool.schedule do
            if info[:volumes] > 0
              puts "\r[Debug]: Preping attached volumes on instance #{server_objects[tag].dns_name}"
              sleep 5
            else
              puts "\r[Debug]: Waiting for instance to become ssh'able #{server_objects[tag].dns_name} with ssh_user: #{ssh_user} and ssh_key: #{ssh_key}"
            end
          end
        end
        threads_pool.shutdown
      end
      results
    end

    # Create servers on rackspace using Ankuscli::RackSpace
    # @param [Hash] nodes_to_create => hash of nodes to create with their info as shown below
    #      { 'node_tag' => { :os_type => cloud_os_type, :volumes => 2, :volume_size => 100 }, ... }
    # @param [Hash] #cloud_credentials: { rackspace_username: , rackspace_api_key: , rackspace_instance_type: ,rackspace_ssh_key: '~/.ssh/id_rsa.pub' }
    # @param [Integer] thread_pool_size => size of the thread pool
    # @return [Hash] results => { 'instance_tag(fqdn)' => [public_ip_address, private_ip_address], ... }
    def create_on_rackspace(nodes_to_create, credentials, thread_pool_size)
      threads_pool        = Ankuscli::ThreadPool.new(thread_pool_size)
      api_key             = credentials[:rackspace_api_key]
      username            = credentials[:rackspace_username]
      machine_type        = credentials[:rackspace_instance_type] || 4
      public_ssh_key_path = credentials[:rackspace_ssh_key] || '~/.ssh/id_rsa.pub'
      ssh_key_path        = File.split(public_ssh_key_path).first + '/' + File.basename(public_ssh_key_path, '.pub')
      ssh_user            = @parsed_hash[:ssh_user]
      rackspace           = create_rackspace_connection
      conn                = rackspace.create_connection
      results             = {}
      server_objects      = {} # hash to store server object to tag mapping { tag => server_obj }, used for attaching volumes

      puts "\r[Debug]: Using ssh_key #{ssh_key_path}" if @debug
      puts "\rCreating servers with roles: " + "#{nodes_to_create.keys.join(',')} ...".blue
      nodes_to_create.each do |tag, info|
        server_objects[tag] = rackspace.create_server!(conn, tag, public_ssh_key_path, machine_type, info[:os_type])
      end
      puts "\rCreating servers with roles: " + "#{nodes_to_create.keys.join(',')} ".blue + '[DONE]'.cyan

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
      nodes_to_create.each do |tag, info|
        # fill in return hash
        results[tag] = [ server_objects[tag].public_ip_address, server_objects[tag].private_ip_address ]
      end
      # Attach Volumes
      if ! @mock
        puts "\rPartitioning|Formatting attached volumes".blue
        # parition and format attached disks using thread pool
        nodes_to_create.each do |tag, info|
          threads_pool.schedule do
            if info[:volumes] > 0
              puts "\r[Debug]: Preping attached volumes on instnace #{server_objects[tag]}" if @debug
              # attach specified volumes to server
              rackspace.attach_volumes!(server_objects[tag], info[:volumes], info[:volume_size])
              # build partition script
              partition_script = gen_partition_script(info[:volumes])
              tempfile = Tempfile.new('partition')
              tempfile.write(partition_script)
              tempfile.close
              # wait for the server to be ssh'able
              Ankuscli::SshUtils.wait_for_ssh(server_objects[tag].public_ip_address, ssh_user, File.expand_path(ssh_key_path))
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
              output = Ankuscli::SshUtils.execute_ssh!(
                  "chmod +x /tmp/#{File.basename(tempfile.path)} && sudo sh -c '/tmp/#{File.basename(tempfile.path)} | tee /var/log/bootstrap_volumes.log'",
                  server_objects[tag].public_ip_address,
                  ssh_user,
                  File.expand_path(ssh_key_path),
                  22,
                  @debug)
              tempfile.unlink # delete the tempfile
              if @debug
                puts "\r[Debug]: Stdout on #{server_objects[tag].public_ip_address}"
                puts "\r#{output[server_objects[tag].public_ip_address][0]}"
                puts "\r[Debug]: Stdout on #{server_objects[tag].public_ip_address}"
                puts "\r#{output[server_objects[tag].public_ip_address][1]}"
                puts "\r[Debug]: Exit code from #{server_objects[tag].public_ip_address}: #{output[server_objects[tag].public_ip_address][2]}"
              end
            else
              # if not mounting volumes wait for instances to become available
              Ankuscli::SshUtils.wait_for_ssh(server_objects[tag].public_ip_address, ssh_user, File.expand_path(ssh_key_path))
            end
          end
        end
        threads_pool.shutdown
        puts "\r[Debug]: Finished creating and attaching volumes" if @debug
      else
        #MOCKING
        # pretend doing some work while mocking
        puts "\rPartitioning|Formatting attached volumes".blue
        nodes_to_create.each do |_, info|
          threads_pool.schedule do
            sleep 5 if info[:volumes] > 0 and @debug
          end
        end
        threads_pool.shutdown
      end
      results
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
    # @param [Hash] nodes_ips_map => { 'tag(fqdn)' => [public_ip_address, private_ip_address], ... }
    # @return [String] contents of hosts file
    def build_hosts(nodes_ips_map)
      hosts_string = ''
      if @cloud_os.downcase == 'centos'
        hosts_string << "127.0.0.1\tlocalhost localhost.localdomain localhost4 localhost4.localdomain4" << "\n"
        hosts_string << "::1\tlocalhost localhost.localdomain localhost6 localhost6.localdomain6" << "\n"
      elsif @cloud_os.downcase == 'ubuntu'
        hosts_string << "127.0.0.1\tlocalhost" << "\n"
        hosts_string << "::1\tip6-localhost\tip6-loopback" << "\n"
        hosts_string << "fe00::0\tip6-localnet\nff00::0\tip6-mcastprefix\nff02::1\tip6-allnodes\nff02::2\tip6-allrouters" << "\n"
      end
      nodes_ips_map.each do |fqdn, ip_map|
        hosts_string << "#{ip_map.first}\t#{fqdn}\t#{fqdn.split('.').first}" << "\n"
      end
      hosts_string
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