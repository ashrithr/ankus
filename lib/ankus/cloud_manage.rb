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

=begin
  Cloud abstraction layer for aws, rackspace, openstack and google cloud compute
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
    # @param [Integer] thread_pool_size => number of threads to use to perform instance creation, volume attachments
    # @param [Log4r] log => logger object to use
    # @param [Boolean] debug => if enabled will print more info to stdout
    # @param [Boolean] mock => if enabled will mock fog, instead of creating actual instances
    def initialize(provider, parsed_config, cloud_credentials, log, thread_pool_size = 10, debug = false, mock = false)
      @provider         = provider || parsed_config[:cloud_platform]
      @cloud_os         = parsed_config[:cloud_os_type] || 'CentOS'
      @parsed_hash      = parsed_config
      @credentials      = cloud_credentials || parsed_config[:cloud_credentials]
      @debug            = debug
      @thread_pool_size = thread_pool_size
      @log              = log
      @mock             = mock
      @nodes            = Hash.new{ |h,k| h[k] = Hash.new(&h.default_proc) }
      raise unless @credentials.is_a?(Hash)
    end

    # Create a connection object to aws
    # @return [Ankus::Aws]
    def create_aws_connection
      Ankus::Aws.new @credentials[:aws_access_id], @credentials[:aws_secret_key], @credentials[:aws_region], @log, @mock
    end

    # Create a connection object to rackspace
    # @return [Ankus::Rackspace]
    def create_rackspace_connection
      Ankus::Rackspace.new @credentials[:rackspace_api_key], @credentials[:rackspace_username], @log, @mock
    end

    # Create a connection object to openstack
    # @return [Ankus::Openstack]
    def create_openstack_connection
      Ankus::Openstack.new @credentials[:os_auth_url], @credentials[:os_username], @credentials[:os_password], @credentials[:os_tenant], @log, @mock
    end

    # Create instance definitions
    def create_cloud_instances
      num_of_slaves   = @parsed_hash[:worker_nodes_count]
      num_of_zks      = @parsed_hash[:zookeeper_deploy][:quorum_count] if @parsed_hash[:zookeeper_deploy] != 'disabled'
      default_config  = { :os_type => @cloud_os, :volumes => 0, :volume_size => 250, :volume_mount_prefix => '/data' }
      if @parsed_hash[:cloud_platform] == 'aws'
        default_config[:volume_type] = 'ebs'
        default_config[:iops] = 0
      elsif @parsed_hash[:cloud_platform] == 'rackspace'
        default_config[:volume_type] = 'blockstore'
      end

      nodes_to_create_masters = {}
      nodes_to_create_hadoop_master = {}
      nodes_to_create_hadoop_worker = {}
      nodes_to_create_cassandra = {}
      nodes_to_create_slaves = {}
      hadoop_master_nodes_config = {}
      hadoop_worker_nodes_config = {}
      cassandra_nodes_config = {}
      nodes_to_create_masters[:controller] = %w(controller)
      if @parsed_hash[:hadoop_deploy] != 'disabled'
        if @parsed_hash[:hadoop_deploy][:ha] == 'enabled'
          nodes_to_create_hadoop_master[:namenode1] = %w(namenode1)
          nodes_to_create_hadoop_master[:namenode2] = %w(namenode2)
          if @parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
            nodes_to_create_hadoop_master[:jobtracker] = %w(jobtracker)
          end
        else
          nodes_to_create_hadoop_master[:namenode] = %w(namenode)
        end
        if @parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
          nodes_to_create_hadoop_master[:jobtracker] = %w(jobtracker secondarynamenode)
        elsif @parsed_hash[:hadoop_deploy][:mapreduce] and @parsed_hash[:hadoop_deploy][:ha] == 'disabled'
          nodes_to_create_hadoop_master[:secondarynamenode] = %w(secondarynamenode)
        end
        if @parsed_hash[:hbase_deploy] != 'disabled'
          @parsed_hash[:hbase_deploy][:master_count].times do |hm|
            nodes_to_create_masters["hbasemaster#{hm+1}".to_sym] = ["hbasemaster#{hm+1}"]
          end
        end
        num_of_slaves.times do |i|
          nodes_to_create_hadoop_worker["slaves#{i+1}".to_sym] = ["slaves#{i+1}"]
        end
        master_volumes = @parsed_hash[:hadoop_deploy][:master_volumes]
        if master_volumes
          hadoop_master_nodes_config = {
              :os_type => @cloud_os,
              :volumes => master_volumes[:count],
              :volume_size => master_volumes[:size],
              :volume_type => master_volumes[:type],
              :volume_mount_prefix => '/data/hadoop/'
          }
          if master_volumes[:type] == 'io1' && master_volumes[:iops]
            hadoop_master_nodes_config[:iops] = master_volumes[:iops]
          end
        end
        worker_volumes = @parsed_hash[:hadoop_deploy][:worker_volumes]
        if worker_volumes
          hadoop_worker_nodes_config = {
              :os_type => @cloud_os,
              :volumes => worker_volumes[:count],
              :volume_size => worker_volumes[:size],
              :volume_type => worker_volumes[:type],
              :volume_mount_prefix => '/data/hadoop'
          }
          if worker_volumes[:type] == 'io1' && worker_volumes[:iops]
            hadoop_worker_nodes_config[:iops] = worker_volumes[:iops]
          end
        end
      end
      if @parsed_hash[:cassandra_deploy] != 'disabled'
        if @parsed_hash[:cassandra_deploy][:collocate] # collocate cassandra instances on hadoop slaves
          num_of_slaves.times { |i| nodes_to_create_slaves["slaves#{i+1}".to_sym] << "cassandra#{i+1}" }
          @parsed_hash[:cassandra_deploy][:number_of_seeds].times do |cs|
            nodes_to_create_hadoop_worker["slaves#{cs+1}".to_sym] << "cassandraseed#{cs+1}"
          end
        else # if ! collocate then create separate cassandra instances
          @parsed_hash[:cassandra_deploy][:number_of_instances].times do |cn|
            nodes_to_create_cassandra["cassandra#{cn+1}".to_sym] = ["cassandra#{cn+1}"]
          end
          @parsed_hash[:cassandra_deploy][:number_of_seeds].times do |cs|
            nodes_to_create_cassandra["cassandra#{cs+1}".to_sym] << "cassandraseed#{cs+1}"
          end
        end
        cassandra_volumes = @parsed_hash[:cassandra_deploy][:volumes]
        if cassandra_volumes
          cassandra_nodes_config = {
              :os_type => @cloud_os,
              :volumes => cassandra_volumes[:count],
              :volume_size => cassandra_volumes[:size],
              :volume_type => cassandra_volumes[:type],
              :volume_mount_prefix => '/data/cassandra'
          }
          if cassandra_volumes[:type] == 'io1' && cassandra_volumes[:iops]
            cassandra_nodes_config[:iops] = cassandra_volumes[:iops]
          end
        end
      end
      if @parsed_hash[:solr_deploy] != 'disabled'
        if @parsed_hash[:solr_deploy][:hdfs_integration] == 'disabled'
          @parsed_hash[:solr_deploy][:number_of_instances].times do |ss|
            nodes_to_create_slaves["solr#{ss+1}".to_sym] = ["solr#{ss+1}"]
          end
        else
          @parsed_hash[:worker_nodes_count].times do |sn|
            nodes_to_create_slaves["slaves#{sn+1}".to_sym] << "solr#{sn+1}"
          end
        end
      end
      if @parsed_hash[:kafka_deploy] != 'disabled'
        if @parsed_hash[:kafka_deploy][:collocate] # collocate daemons in either hadoop or cassandra based on deploy scenario
          if @parsed_hash[:hadoop_deploy] != 'disabled'
            @parsed_hash[:kafka_deploy][:number_of_brokers].times do |kn|
              nodes_to_create_slaves["slaves#{kn+1}".to_sym] << "kafka#{kn+1}"
            end
          else
            @parsed_hash[:kafka_deploy][:number_of_brokers].times do |kn|
              nodes_to_create_slaves["cassandra#{kn+1}".to_sym] << "kafka#{kn+1}"
            end
          end
        else
          @parsed_hash[:kafka_deploy][:number_of_brokers].times do |kn|
            nodes_to_create_slaves["kafka#{kn+1}".to_sym] = ["kafka#{kn+1}"]
          end
        end
      end
      if @parsed_hash[:storm_deploy] != 'disabled'
        nodes_to_create_masters[:stormnimbus] = %w(stormnimbus)
        if @parsed_hash[:storm_deploy][:collocate] # collocate daemons in either hadoop or cassandra based on deploy scenario
          if @parsed_hash[:hadoop_deploy] != 'disabled'
            @parsed_hash[:storm_deploy][:number_of_supervisors].times do |sn|
              nodes_to_create_slaves["slaves#{sn+1}".to_sym] << "stormworker#{sn+1}"
            end
          else
            @parsed_hash[:storm_deploy][:number_of_supervisors].times do |sn|
              nodes_to_create_slaves["cassandra#{sn+1}".to_sym] << "stormworker#{sn+1}"
            end
          end
        else
          @parsed_hash[:storm_deploy][:number_of_supervisors].times do |sn|
            nodes_to_create_slaves["stormworker#{sn+1}".to_sym] = ["stormworker#{sn+1}"]
          end
        end
      end
      # zookeepers
      if @parsed_hash[:hadoop_deploy] != 'disabled' && @parsed_hash[:hadoop_deploy][:ha] == 'enabled'
        num_of_zks.times do |i|
          nodes_to_create_masters["zookeeper#{i+1}".to_sym] = %w(zookeeper)
        end
      elsif @parsed_hash[:hbase_deploy] != 'disabled' or 
        @parsed_hash[:kafka_deploy] != 'disabled' or 
        @parsed_hash[:storm_deploy] != 'disabled' or
        @parsed_hash[:solr_deploy] != 'disabled'
        unless nodes_to_create_masters.keys.find { |e| /zookeeper/ =~ e }
          num_of_zks.times do |i|
            nodes_to_create_masters["zookeeper#{i+1}".to_sym] = %w(zookeeper)
          end
        end
      end 

      # If provider is rackspace add domain to roles to form fqdn's
      if @provider == 'rackspace' or @provider == 'openstack'
        # n.dup.each { |k, v| n["#{k}.cw.com"] = v && n.delete(k)}
        domain_name = "#{@parsed_hash[:cloud_credentials][:cluster_identifier]}.ankus.com"
        nodes_to_create_hadoop_master && nodes_to_create_hadoop_master.dup.each { |name, tags|
          nodes_to_create_hadoop_master["#{name}.#{domain_name}"] = tags && nodes_to_create_hadoop_master.delete(name)
        }
        nodes_to_create_hadoop_worker && nodes_to_create_hadoop_worker.dup.each { |name, tags|
          nodes_to_create_hadoop_worker["#{name}.#{domain_name}"] = tags && nodes_to_create_hadoop_worker.delete(name)
        }
        nodes_to_create_cassandra && nodes_to_create_cassandra.dup.each { |name, tags|
          nodes_to_create_cassandra["#{name}.#{domain_name}"] = tags && nodes_to_create_cassandra.delete(name)
        }
        nodes_to_create_masters && nodes_to_create_masters.dup.each { |name, tags|
          nodes_to_create_masters["#{name}.#{domain_name}"] = tags && nodes_to_create_masters.delete(name)
        }
        nodes_to_create_slaves && nodes_to_create_slaves.dup.each { |name, tags|
          nodes_to_create_slaves["#{name}.#{domain_name}"] = tags && nodes_to_create_slaves.delete(name)
        }
      end
      # Create node wrapper objects
      nodes_to_create_hadoop_master && nodes_to_create_hadoop_master.each do |name, tags|
        @nodes[name] = hadoop_master_nodes_config.empty? ? create_node_obj(default_config, tags) : create_node_obj(hadoop_master_nodes_config, tags)
      end
      nodes_to_create_hadoop_worker && nodes_to_create_hadoop_worker.each do |name, tags|
        @nodes[name] = hadoop_worker_nodes_config.empty? ? create_node_obj(default_config, tags) : create_node_obj(hadoop_worker_nodes_config, tags)
      end
      nodes_to_create_cassandra && nodes_to_create_cassandra.each do |name, tags|
        @nodes[name] = cassandra_nodes_config.empty? ? create_node_obj(default_config, tags) : create_node_obj(cassandra_nodes_config, tags)
      end
      nodes_to_create_masters.each do |name, tags|
        @nodes[name] = create_node_obj(default_config, tags)
      end
      nodes_to_create_slaves.each do |name, tags|
        @nodes[name] = create_node_obj(default_config, tags)
      end
      # Return node definitions
      @nodes
    end

    # Creates cloud instances using specified cloud provider and the parsed config file
    # Used for initial creation of instances
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
      begin
        case @provider
        when 'aws'
          @nodes = create_aws_instances(@nodes, @credentials, @thread_pool_size)
        when 'rackspace'
          @nodes = create_rackspace_instances(@nodes, @credentials, @thread_pool_size)
        when 'openstack'
          @nodes = create_openstack_instances(@nodes, @credentials, @thread_pool_size)
        else
          # Not implemented yet
        end
      rescue RuntimeError => ex
        @log.error "Something went wrong provisioning instances on cloud, reason: #{ex}"
        @log.error 'Rolling back instance(s)'
        delete_instances(@nodes, true)
        exit 1
      end
      @nodes
    end

    # Create instances if the node has no fqdn is assigned
    # Used for adding instances to the existing cluster (reload ankus based on config)
    # @param [Hash] nodes => merged nodes info
    def safe_create_instances!(nodes)
      nodes = nodes.select { |k, v| k if v[:fqdn].empty? }
      begin
        case @provider
        when 'aws'
          nodes = create_aws_instances(nodes, @credentials, @thread_pool_size)
        when 'rackspace'
          nodes = create_rackspace_instances(nodes, @credentials, @thread_pool_size)
        when 'openstack'
          nodes = create_openstack_instances(nodes, @credentials, @thread_pool_size)
        else
          # Not yet implemented
        end
      rescue RuntimeError => ex
        @log.error "Something went wrong provisioning vms on cloud, reason: #{ex}"
        @log.error 'Rolling back instance(s)'
        delete_instances(nodes, true)
        exit 1
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
        node_created = create_aws_instances(nodes_to_create, @credentials, @thread_pool_size)
      elsif @provider == 'rackspace'
        node_created = create_rackspace_instances(nodes_to_create, @credentials, @thread_pool_size)
      elsif @provider == 'openstack'
        node_created = create_openstack_instances(nodes_to_create, @credentials, @thread_pool_size)
      end
      node_created
    end

    # Delete cloud instances created by ankus
    # @param [Hash] nodes_hash => hash containing info about instances (as returned by Cloud#create_instances)
    # @param [Boolean] delete_volumes => specifies whether to delete volumes attached to instances as well
    def delete_instances(nodes_hash, delete_volumes = false)
      threads_pool = Ankus::ThreadPool.new(@thread_pool_size)
      if @parsed_hash[:cloud_platform] == 'aws'
        aws  = create_aws_connection
        conn = aws.create_connection
        nodes_hash.each do |_, node_info|
          threads_pool.schedule do
            server_dns_name = node_info[:fqdn]
            aws.delete_server_with_dns_name(conn, server_dns_name, delete_volumes)
          end
        end
        threads_pool.shutdown
      elsif @parsed_hash[:cloud_platform] == 'rackspace'
        rackspace = create_rackspace_connection
        conn      = rackspace.create_connection
        nodes_hash.each do |fqdn, _|
          threads_pool.schedule do
            rackspace.delete_server_with_name(conn, fqdn, delete_volumes)
          end
        end
        threads_pool.shutdown
      elsif @parsed_hash[:cloud_platform] == 'openstack'
        openstack = create_openstack_connection
        conn = openstack.create_connection
        nodes_hash.each do |fqdn, _|
          threads_pool.schedule do
            openstack.delete_server!(conn, fqdn, delete_volumes)
          end
        end
        threads_pool.shutdown
      end
    end

    # Finds the internal ip of a node with its tag name
    def find_internal_ip(nodes, tag)
      if @provider == 'aws'
        find_pip_for_tag(nodes, tag)
      elsif @provider == 'rackspace' or @provider == 'openstack'
        find_key_for_tag(nodes, tag)
      end
    end

    # Modifies the original parsed_config hash to look more like the local install mode
    # @param [Hash] parsed_hash => original parsed hash generated from configuration file
    # @param [Hash] nodes => nodes hash generated by Cloud#create_on_aws|Cloud#create_on_rackspace
    # @return if rackspace [Hash, Hash] parsed_hash, parsed_internal_ips => which can be used same as local install_mode
    #         if aws [Hash, Hash] parsed_hash, parsed_internal_ips => which can be used same as local install_mode
    def modify_cloud_config(parsed_hash, nodes)
      parsed_hash_internal_ips = Marshal.load(Marshal.dump(parsed_hash))
     
      parsed_hash[:ssh_key]      =  if @provider == 'aws'
                                      File.expand_path('~/.ssh') + '/' + @credentials[:aws_key]
                                    elsif @provider == 'openstack'
                                      File.expand_path('~/.ssh') + '/' + @credentials[:os_ssh_key]
                                    elsif @provider == 'rackspace'
                                      File.split(File.expand_path(@credentials[:rackspace_ssh_key])).first + '/' +
                                      File.basename(File.expand_path(@credentials[:rackspace_ssh_key]), '.pub')
                                    end
      parsed_hash[:controller] = find_fqdn_for_tag(nodes, 'controller').first
      if parsed_hash[:hadoop_deploy] != 'disabled'
        parsed_hash[:hadoop_deploy][:namenode] = find_fqdn_for_tag(nodes, 'namenode')
        if parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
          parsed_hash[:hadoop_deploy][:mapreduce][:master] = find_fqdn_for_tag(nodes, 'jobtracker').first
        end
        if parsed_hash[:hadoop_deploy][:ha] == 'disabled'
          parsed_hash[:hadoop_deploy][:secondarynamenode] = find_fqdn_for_tag(nodes, 'secondarynamenode').first
        end
        parsed_hash[:worker_nodes] = find_fqdn_for_tag(nodes, 'slaves')
        if parsed_hash[:hadoop_deploy][:ha] == 'enabled'
          parsed_hash[:hadoop_deploy][:journal_quorum] = find_fqdn_for_tag(nodes, 'zookeeper')
        end
        if parsed_hash[:hbase_deploy] != 'disabled'
          parsed_hash[:hbase_deploy][:master] = find_fqdn_for_tag(nodes, 'hbasemaster')
        end
        # volumes to mount points
        worker_volumes = parsed_hash[:hadoop_deploy][:worker_volumes]
        parsed_hash[:hadoop_deploy][:data_dirs] = if worker_volumes
                                                    Array.new(worker_volumes[:count]){ |i| "/data/hadoop/#{i+1}" }
                                                  else
                                                    ['/data/hadoop']
                                                  end
        master_volumes = parsed_hash[:hadoop_deploy][:master_volumes]
        parsed_hash[:hadoop_deploy][:master_dirs] = if master_volumes
                                                      Array.new(master_volumes[:count]){ |i| "/data/hadoop/#{i+1}" }
                                                    else
                                                      ['/data/hadoop']
                                                    end
      end

      if parsed_hash[:cassandra_deploy] != 'disabled'
        parsed_hash[:cassandra_deploy][:nodes] =  find_fqdn_for_tag(nodes, 'cassandra')
        parsed_hash[:cassandra_deploy][:seeds] =  find_fqdn_for_tag(nodes, 'cassandraseed')
        cassandra_volumes = parsed_hash[:cassandra_deploy][:volumes]
        cassandra_mounts  = if cassandra_volumes
                              Array.new(cassandra_volumes[:count]){|i| "/data/cassandra/#{i+1}" }
                            end
        parsed_hash[:cassandra_deploy][:data_dirs] = if cassandra_mounts
                                                       if cassandra_mounts.size > 1
                                                         cassandra_mounts[0..cassandra_mounts.size-2].map { |dir| dir = dir + '/data' }
                                                       else
                                                         cassandra_mounts.first + '/data'
                                                       end
                                                     else
                                                       ['/var/lib/cassandra/data']
                                                     end
        parsed_hash[:cassandra_deploy][:commitlog_dirs] = if cassandra_mounts
                                                            if cassandra_mounts.size > 1
                                                              cassandra_mounts.last + '/commitlog'
                                                            else
                                                              cassandra_mounts.first + '/commitlog'
                                                            end
                                                          else
                                                            '/var/lib/cassandra/commitlog'
                                                          end
        parsed_hash[:cassandra_deploy][:saved_caches_dirs] = if cassandra_mounts
                                                               if cassandra_mounts.size > 1
                                                                 cassandra_mounts.last + '/saved_caches'
                                                               else
                                                                 cassandra_mounts.first + '/saved_caches'
                                                               end
                                                             else
                                                               '/var/lib/cassandra/saved_caches'
                                                             end
      end

      if parsed_hash[:solr_deploy] != 'disabled'
        if parsed_hash[:solr_deploy][:hdfs_integration] == 'disabled'
          parsed_hash[:solr_deploy][:nodes] = find_fqdn_for_tag(nodes, 'solr')
        else
          parsed_hash[:solr_deploy][:nodes] = find_fqdn_for_tag(nodes, 'slaves')
        end
      end

      if parsed_hash[:kafka_deploy] != 'disabled'
        parsed_hash[:kafka_deploy][:brokers] = find_fqdn_for_tag(nodes, 'kafka')
      end

      if parsed_hash[:storm_deploy] != 'disabled'
        parsed_hash[:storm_deploy][:supervisors] =  find_fqdn_for_tag(nodes, 'stormworker')
        parsed_hash[:storm_deploy][:master] = find_fqdn_for_tag(nodes, 'stormnimbus').first
      end
      #zookeepers
      if parsed_hash[:hadoop_deploy] != 'disabled' and parsed_hash[:hadoop_deploy][:ha] == 'enabled'
        parsed_hash[:zookeeper_deploy][:quorum] = find_fqdn_for_tag(nodes, 'zookeeper')
      end
      if parsed_hash[:hbase_deploy] != 'disabled' or
        parsed_hash[:kafka_deploy] != 'disabled' or 
        parsed_hash[:storm_deploy] != 'disabled'
        unless parsed_hash.has_key? :zookeeper_deploy
          parsed_hash[:zookeeper_deploy][:quorum] = find_fqdn_for_tag(nodes, 'zookeeper')
        end
      end

      # If AWS, hash with internal ips should contain private_ip
      # If RackSpace, hash with internal ips should contain fqdn

      parsed_hash_internal_ips[:ssh_key]  = 
          if @provider == 'aws'
            File.expand_path('~/.ssh') + '/' + @credentials[:aws_key]
          elsif @provider == 'openstack'
            File.expand_path('~/.ssh') + '/' + @credentials[:os_ssh_key]
          elsif @provider == 'rackspace'
            File.split(File.expand_path(@credentials[:rackspace_ssh_key])).first + '/' +
            File.basename(File.expand_path(@credentials[:rackspace_ssh_key]), '.pub')
          end
      parsed_hash_internal_ips[:controller] = find_internal_ip(nodes, 'controller').first
      if parsed_hash[:hadoop_deploy] != 'disabled'
        parsed_hash_internal_ips[:hadoop_deploy][:namenode] = find_internal_ip(nodes, 'namenode')
        if parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
          parsed_hash_internal_ips[:hadoop_deploy][:mapreduce][:master] = find_internal_ip(nodes, 'jobtracker').first
        end    
        if parsed_hash[:hadoop_deploy][:ha] == 'disabled'
          parsed_hash_internal_ips[:hadoop_deploy][:secondarynamenode] = find_internal_ip(nodes, 'secondarynamenode').first
        end
        parsed_hash_internal_ips[:worker_nodes] = find_internal_ip(nodes, 'slaves')
        if parsed_hash[:hadoop_deploy][:ha] == 'enabled'
          parsed_hash_internal_ips[:hadoop_deploy][:journal_quorum] = find_internal_ip(nodes, 'zookeeper')
        end
        if parsed_hash[:hbase_deploy] != 'disabled'      
          parsed_hash_internal_ips[:hbase_deploy][:master] = find_internal_ip(nodes, 'hbasemaster')
        end
        parsed_hash_internal_ips[:hadoop_deploy][:data_dirs] = parsed_hash[:hadoop_deploy][:data_dirs]
        parsed_hash_internal_ips[:hadoop_deploy][:master_dirs] = parsed_hash[:hadoop_deploy][:master_dirs]
      end
      if parsed_hash[:cassandra_deploy] != 'disabled'
        parsed_hash_internal_ips[:cassandra_deploy][:nodes] =  find_internal_ip(nodes, 'cassandra')
        parsed_hash_internal_ips[:cassandra_deploy][:seeds] =  find_internal_ip(nodes, 'cassandraseed')
        # cassandra storage directories
        parsed_hash_internal_ips[:cassandra_deploy][:data_dirs] = parsed_hash[:cassandra_deploy][:data_dirs]
        parsed_hash_internal_ips[:cassandra_deploy][:commitlog_dirs] = parsed_hash[:cassandra_deploy][:commitlog_dirs]
        parsed_hash_internal_ips[:cassandra_deploy][:saved_caches_dirs] = parsed_hash[:cassandra_deploy][:saved_caches_dirs]
      end
      if parsed_hash[:solr_deploy] != 'disabled'
        if parsed_hash[:solr_deploy][:hdfs_integration] == 'disabled'
          parsed_hash_internal_ips[:solr_deploy][:nodes] = find_internal_ip(nodes, 'solr')
        else
          parsed_hash_internal_ips[:solr_deploy][:nodes] = find_internal_ip(nodes, 'slaves')
        end
      end
      if parsed_hash[:kafka_deploy] != 'disabled'
        parsed_hash_internal_ips[:kafka_deploy][:brokers] = find_internal_ip(nodes, 'kafka')
      end
      if parsed_hash[:storm_deploy] != 'disabled'
        parsed_hash_internal_ips[:storm_deploy][:supervisors] =  find_internal_ip(nodes, 'stormworker')
        parsed_hash_internal_ips[:storm_deploy][:master] = find_internal_ip(nodes, 'stormnimbus').first
      end
      if parsed_hash[:hadoop_deploy] != 'disabled' and parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
        parsed_hash_internal_ips[:zookeeper_deploy][:quorum] = find_internal_ip(nodes, 'zookeeper')
      end
      if parsed_hash[:hbase_deploy] != 'disabled' or
        parsed_hash[:kafka_deploy] != 'disabled' or 
        parsed_hash[:storm_deploy] != 'disabled'
        unless parsed_hash_internal_ips.has_key? :zookeeper_deploy
          parsed_hash_internal_ips[:zookeeper_deploy][:quorum] = find_internal_ip(nodes, 'zookeeper')
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
        @log.debug 'Successfully authenticated with aws' if @debug
      else
        @log.error 'Failed connecting to aws'
        abort
      end

      # Create key pairs and security groups
      aws.create_kp_sg!(conn, key, groups)

      @log.info 'Creating servers with roles: ' + "#{nodes.keys.join(',')}".blue + ' ...'
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
          :vol_type => info[:config][:volume_type],
          :iops => info[:config][:iops]
        )
      end

      # wait for servers to get created (:state => running)
      @log.info 'Waiting for cloud instances to get initialized ...'
      aws.wait_for_servers(server_objects.values)
      # wait for the boot to complete
      unless @mock
        @log.info 'Waiting for cloud instances to complete their boot process ...'
        aws.complete_wait(server_objects.values, @cloud_os)
      end
      # build the return string
      nodes.each do |tag, node_info|
        # fill in nodes hash with public and private dns
        node_info[:fqdn] = server_objects[tag].dns_name
        node_info[:private_ip] = server_objects[tag].private_dns_name
      end
      if @mock
        # pretend doing some work while mocking
        nodes.each do |tag, info|
          threads_pool.schedule do
            if info[:config][:volumes] > 0
              @log.debug "Preparing attached volumes on instance #{server_objects[tag].dns_name}" if @debug
              sleep 5
            else
              @log.debug "Waiting for instance to become ssh'able #{server_objects[tag].dns_name} " +
                             "with ssh_user: #{ssh_user} and ssh_key: #{ssh_key}" if @debug
            end
          end
        end
        threads_pool.shutdown
      else
        # partition and format attached disks using thread pool
        nodes.each do |tag, info|
          threads_pool.schedule do
            if info[:config][:volumes] > 0
              @log.debug "Formatting attached volumes on instance #{server_objects[tag].dns_name}" if @debug
              #build partition script
              partition_script = gen_partition_script(info[:config][:volumes], info[:config][:volume_mount_prefix], true)
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
                  @log,
                  22,
                  @debug
              )
              output = Ankus::SshUtils.execute_ssh!(
                  "chmod +x /tmp/#{File.basename(tempfile.path)} && sudo sh -c '/tmp/#{File.basename(tempfile.path)}" +
                      " | tee /var/log/bootstrap_volumes.log'",
                  server_objects[tag].dns_name,
                  ssh_user,
                  ssh_key,
                  @log,
                  22,
                  false # we don't want output of formatting volumes to be printed in real time to stdout!!
              )
              tempfile.unlink # delete the tempfile
              if @debug
                @log.debug "Stdout on #{server_objects[tag].dns_name}"
                puts "\r#{output[server_objects[tag].dns_name][0]}"
                @log.debug "Stderr on #{server_objects[tag].dns_name}"
                puts "\r#{output[server_objects[tag].dns_name][1]}"
                @log.debug "Exit code from #{server_objects[tag].dns_name}: #{output[server_objects[tag].dns_name][2]}"
              end
            else
              # if not waiting for mounting volumes, wait for instances to become sshable
              @log.debug "Waiting for instance '#{server_objects[tag].dns_name}' to become ssh'albe using " +
                             "username: '#{ssh_user}' and key: '#{ssh_key}'" if @debug
              Ankus::SshUtils.wait_for_ssh(server_objects[tag].dns_name, ssh_user, ssh_key)
            end
          end
        end
        threads_pool.shutdown
        @log.debug 'Finished creating and attaching volumes' if @debug
      end
      nodes
    end

    # Create servers on rackspace using Ankus::RackSpace
    # @param [Hash] nodes => hash of nodes to create with their info
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

      @log.debug "Using ssh_key #{ssh_key_path}" if @debug
      @log.info 'Creating servers with fqdn: ' + "#{nodes.keys.join(',')}".blue + ' ...'
      @log.info 'Completed instantiating servers'
      nodes.each do |tag, info|
        server_objects[tag] = rackspace.create_server!(conn, 
                                  tag, 
                                  public_ssh_key_path, 
                                  machine_type, 
                                  info[:config][:os_type]
                              )
      end

      # wait for servers to get created (:state => ACTIVE)
      @log.info 'Waiting for cloud instances to get created ...'
      rackspace.wait_for_servers(server_objects.values)

      # build the return string
      nodes.each do |tag, node_info|
        # fill in nodes fqdn and private_ip
        node_info[:fqdn] = server_objects[tag].public_ip_address
        node_info[:private_ip] = server_objects[tag].private_ip_address
      end

      # Attach Volumes
      if @mock
        # MOCKING
        # pretend doing some work while mocking
        @log.info 'Partitioning|Formatting attached volumes'
        nodes.each do |tag, info|
          threads_pool.schedule do
            if info[:config][:volumes] > 0
              @log.debug "Preparing attached volumes on instance #{server_objects[tag].public_ip_address}"
              sleep 5
            else
              @log.debug "Waiting for instance to become ssh'able #{server_objects[tag].public_ip_address} " +
                             "with ssh_user: #{ssh_user} and ssh_key: #{File.expand_path(ssh_key_path)}" if @debug
            end
          end
        end
        threads_pool.shutdown
      else
        # partition and format attached disks using thread pool
        nodes.each do |tag, info|
          threads_pool.schedule do
            if info[:config][:volumes] > 0
              @log.debug "Preparing attached volumes on instance #{server_objects[tag]}" if @debug
              # attach specified volumes to server
              rackspace.attach_volumes!(server_objects[tag], info[:config][:volumes], info[:config][:volume_size])
              # build partition script
              partition_script = gen_partition_script(info[:config][:volumes], info[:config][:volume_mount_prefix])
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
                  @log,
                  22,
                  @debug
              )
              output = Ankus::SshUtils.execute_ssh!(
                  "chmod +x /tmp/#{File.basename(tempfile.path)} && sudo sh -c '/tmp/#{File.basename(tempfile.path)}" +
                      " | tee /var/log/bootstrap_volumes.log'",
                  server_objects[tag].public_ip_address,
                  ssh_user,
                  File.expand_path(ssh_key_path),
                  @log,
                  22,
                  false)
              tempfile.unlink # delete the tempfile
              if @debug
                @log.debug "Stdout on #{server_objects[tag].public_ip_address}"
                puts "\r#{output[server_objects[tag].public_ip_address][0]}"
                @log.debug "Stdout on #{server_objects[tag].public_ip_address}"
                puts "\r#{output[server_objects[tag].public_ip_address][1]}"
                @log.debug "Exit code from #{server_objects[tag].public_ip_address}:  #{output[server_objects[tag].public_ip_address][2]}"
              end
            else
              # if not mounting volumes; wait for instances to become available
              @log.debug "Waiting for instance #{server_objects[tag].public_ip_address} to become ssh'albe..." if @debug
              Ankus::SshUtils.wait_for_ssh(server_objects[tag].public_ip_address,
                                           ssh_user,
                                           File.expand_path(ssh_key_path)
              )
            end
          end
        end
        threads_pool.shutdown
        @log.debug 'Finished creating and attaching volumes' if @debug
      end
      nodes
    end

    # Create servers on openstack using Ankus::OpenStack
    # @param [Hash] nodes => hash of nodes to create with their info as shown below
    # @param [Hash] credentials hash from config
    # @param [Integer] thread_pool_size => size of the thread pool
    # @return [Hash] modified ver of nodes
    def create_openstack_instances(nodes, credentials, thread_pool_size)
      #defaults
      threads_pool    = Ankus::ThreadPool.new(thread_pool_size)
      key             = credentials[:os_ssh_key] || 'ankus'
      groups          = credentials[:os_sec_groups] || %w(ankus)
      flavor_id       = credentials[:os_flavor]
      image_id        = credentials[:os_image_ref]
      os              = create_openstack_connection
      conn            = os.create_connection
      ssh_key         = File.expand_path('~/.ssh') + "/#{key}"
      ssh_user        = @parsed_hash[:ssh_user]
      server_objects  = {} # hash to store server object to tag mapping { tag => server_obj }

      if os.valid_connection?(conn)
        @log.debug 'Successfully authenticated with openstack' if @debug
      else
        @log.error 'Failed connecting to aws'
        abort
      end

      # Create key pairs and security groups
      os.create_kp_sg!(conn, key, groups)

      @log.info 'Creating servers with roles: ' + "#{nodes.keys.join(',')}".blue + ' ...'
      begin
        nodes.each do |tag, _|
          server_objects[tag] = os.create_server!(
            conn,
            tag,
            key,
            flavor_id,
            image_id,
            groups
          )
        end
      rescue Excon::Errors::BadRequest
        raise "Failed creating instances, reason: #{$!.message} (#{$!.class})"
      end

      # wait for servers to get created (:state => running)
      @log.info 'Waiting for cloud instances to get created ...'
      os.wait_for_servers(server_objects.values)

      # attach floating ip's to instances
      @log.info 'Attaching floating ip(s) to instances'
      nodes.each do |tag, _|
        os.associate_address!(conn, server_objects[tag])
      end

      # build the return string
      nodes.each do |tag, node_info|
        # fill in nodes hash with public and private dns
        node_info[:fqdn] = server_objects[tag].public_ip_address
        node_info[:private_ip] = server_objects[tag].private_ip_address
      end
      if @mock
        # pretend doing some work while mocking
        nodes.each do |tag, info|
          threads_pool.schedule do
            if info[:config][:volumes] > 0
              @log.debug "Preparing attached volumes on instance #{server_objects[tag].public_ip_address}" if @debug
              sleep 5
            else
              @log.debug "Waiting for instance to become ssh'able #{server_objects[tag].public_ip_address} " +
                             "with ssh_user: #{ssh_user} and ssh_key: #{ssh_key}" if @debug
            end
          end
        end
        threads_pool.shutdown
      else
        # partition and format attached disks using thread pool
        nodes.each do |tag, info|
          threads_pool.schedule do
            if info[:config][:volumes] > 0
              @log.debug "Formatting attached volumes on instance #{server_objects[tag].public_ip_address}" if @debug
              os.attach_volumes!(server_objects[tag], info[:config][:volumes], info[:config][:volume_size])
              #build partition script
              partition_script = gen_partition_script(info[:config][:volumes], info[:config][:volume_mount_prefix], true)
              tempfile = Tempfile.new('partition')
              tempfile.write(partition_script)
              tempfile.close
              # wait for the server to be ssh'able
              Ankus::SshUtils.wait_for_ssh(server_objects[tag].public_ip_address, ssh_user, ssh_key)
              # upload and execute the partition script on the remote machine
              SshUtils.upload!(
                  tempfile.path,
                  '/tmp',
                  server_objects[tag].public_ip_address,
                  ssh_user,
                  ssh_key,
                  @log,
                  22,
                  @debug
              )
              output = Ankus::SshUtils.execute_ssh!(
                  "chmod +x /tmp/#{File.basename(tempfile.path)} && sudo sh -c '/tmp/#{File.basename(tempfile.path)}" +
                      " | tee /var/log/bootstrap_volumes.log'",
                  server_objects[tag].public_ip_address,
                  ssh_user,
                  ssh_key,
                  @log,
                  22,
                  false # we don't want output of formatting volumes to be printed in real time to stdout!!
              )
              tempfile.unlink # delete the tempfile
              if @debug
                @log.debug "Stdout on #{server_objects[tag].public_ip_address}"
                puts "\r#{output[server_objects[tag].public_ip_address][0]}"
                @log.debug "Stderr on #{server_objects[tag].public_ip_address}"
                puts "\r#{output[server_objects[tag].public_ip_address][1]}"
                @log.debug "Exit code from #{server_objects[tag].public_ip_address}: #{output[server_objects[tag].public_ip_address][2]}"
              end
            else
              # if not waiting for mounting volumes, wait for instances to become sshable
              @log.debug "Waiting for instance '#{server_objects[tag].public_ip_address}' to become ssh'albe using " +
                             "username: '#{ssh_user}' and key: '#{ssh_key}'" if @debug
              Ankus::SshUtils.wait_for_ssh(server_objects[tag].public_ip_address, ssh_user, ssh_key)
            end
          end
        end
        threads_pool.shutdown
        @log.debug 'Finished creating and attaching volumes' if @debug
      end
      nodes
    end

    # Builds and returns a shell script for partitioning and resizing root volume(s)
    # @param [Integer] number_of_volumes => number of volumes to partition & mount, this number is used to grep the
    #                                       value from /proc/partitions
    # @param [String] mount_point_prefix => string prefix to use for mount paths
    # @param [Boolean] resize_root_vol => whether to resize th root partition or not
    # @return [ERB] build out shell script
    def gen_partition_script(number_of_volumes, mount_point_prefix, resize_root_vol = false)
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
      mkdir -p <%= mount_point_prefix %>/${data_dir}
      mount /dev/${dev}1 <%= mount_point_prefix %>${data_dir}
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
      if @provider == 'rackspace'
        nodes.each do |fqdn, node_info|
          hosts_string << "#{node_info[:fqdn]}\t#{fqdn}\t#{fqdn.split('.').first}" << "\n"
        end
      elsif @provider == 'openstack'
        nodes.each do |fqdn, node_info|
          hosts_string << "#{node_info[:private_ip]}\t#{fqdn}\t#{fqdn.split('.').first}" << "\n"
        end
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