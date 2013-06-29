module Ankuscli
  # Command line interface for ankuscli
  class CLI < Thor

    include Ankuscli

    #Constants
    DEFAULT_CONFIG = File.expand_path(File.dirname(__FILE__) + '/../../conf/ankus_conf.yaml')
    NODES_FILE = File.expand_path(File.dirname(__FILE__) + '/../../data/nodes.yaml')
    NODES_FILE_CLOUD = File.expand_path(File.dirname(__FILE__) + '/../../data/nodes_cloud.yaml')
    CLOUD_INSTANCES = File.expand_path(File.dirname(__FILE__) + '/../../data/cloud_instances.yaml')

    class_option :config, :type => :string, :desc => 'optionally pass path to config file', :default => DEFAULT_CONFIG

    class_option :debug, :type => :boolean, :desc => 'print more to the console', :default => false

    class_option :thread_pool_size, :type => :numeric, :desc => 'size of the thread pool', :default => 10

    class_option :mock, :type => :boolean, :desc => 'mock the creating of instances in cloud (debug mode)', :default => false

    desc 'parse', 'parse the config file for errors'
    def parse
      parse_config
    end

    desc 'version', 'show the version'
    def version
      puts "Ankus CLI Deployment Tool - Version: #{Ankuscli::VERSION}"
    end

    desc 'deploy', 'deploy components specified in config'
    def deploy
      initiate_deployment
    end

    desc 'add_node', 'add a node to existing cluster'
    method_option :type, :desc => 'type of node being added, hadoop will install datanode, tasktracker and regionserver if hbase is enabled'
    def add_node
      puts 'Not yet implemented'.yellow
    end

    desc 'refresh', 'reload the config files and update the configurations across the cluster'
    def refresh
      puts 'Not yet implemented'.yellow
    end

    private

    # Parses the configuraion file
    def parse_config
      puts 'Parsing config file ...'
      @parsed_hash = ConfigParser.new(options[:config], options[:debug]).parse_config
      puts 'Parsing config file ... ' + '[OK]'.green.bold
    end

    # Initializes the deployment process either on local or cloud
    def initiate_deployment
      #get the size of the terminal
      size = `stty size 2>/dev/null`
      cols =  if $? == 0
                size.split.map { |x| x.to_i }.reverse.first
              else
                80
              end
      puts 'MOCKING'.center(cols, '-') if options[:mock]
      puts 'Starting deployment'
      if @parsed_hash.nil? or @parsed_hash.empty?
        parse_config
      end
      hosts_file = @parsed_hash['cloud_platform'] == 'rackspace' ? Tempfile.new('hosts') : nil
      hosts_file_path = @parsed_hash['cloud_platform'] == 'rackspace' ? hosts_file.path : nil
      if @parsed_hash['install_mode'] == 'cloud'
        #Kick off cloud instances and add them back to configuration hash
        Fog.mock! if options[:mock]
        cloud = Cloud.new(
                  @parsed_hash['cloud_platform'],
                  @parsed_hash,
                  @parsed_hash['cloud_credentials'],
                  options[:thread_pool_size],
                  options[:debug],
                  options[:mock]
                )
        nodes_fqdn_map = cloud.create_instances
        YamlUtils.write_yaml(nodes_fqdn_map, CLOUD_INSTANCES)
        if options[:mock] and options[:debug]
          puts 'NODES HASH'.red
          pp nodes_fqdn_map
          puts
        end
        # @parsed_hash_with_internal_ips is a rebuild'ed hash which is similar to @parsed_hash only difference is
        # that it contains private_ips which are resolved internally by cloud instances, which is required for building
        # hiera data and enc data
        @parsed_hash, @parsed_hash_with_internal_ips = cloud.modify_config_hash(@parsed_hash, nodes_fqdn_map)
        if options[:mock] and options[:debug]
          puts 'PARSED HASH'.red
          pp @parsed_hash
          puts
          puts 'PARSED HASH WITH INTERNAL IPS'.red
          pp @parsed_hash_with_internal_ips
        end
        Fog.unmock! if options[:mock]

        # if cloud_provider is rackspace create /etc/hosts
        if @parsed_hash['cloud_platform'] == 'rackspace'
          hosts_file.write(cloud.build_hosts(nodes_fqdn_map))
          hosts_file.close
          if options[:mock] and options[:debug]
            puts 'HOSTS FILE'.red
            puts cloud.build_hosts(nodes_fqdn_map)
          end
        end
      end
      # generate puppet nodes file from configuration
      if @parsed_hash['install_mode'] == 'cloud'
        Inventory::Generator.new(NODES_FILE_CLOUD, options[:config], @parsed_hash_with_internal_ips).generate #for enc generate
        Inventory::Generator.new(NODES_FILE, options[:config], @parsed_hash).generate # for puppet install/runs
      else
        Inventory::Generator.new(NODES_FILE, options[:config], @parsed_hash).generate
      end

      ## install puppet & generate hiera data, enc data
      puppet = Deploy::Puppet.new(
                YamlUtils.parse_yaml(NODES_FILE)['puppet_server'],  #puppet server
                YamlUtils.parse_yaml(NODES_FILE)['puppet_clients'], #nodes to install puppet client on
                @parsed_hash['root_ssh_key'],                       #ssh_key to use
                @parsed_hash,                                       #parsed config hash
                options[:thread_pool_size],                         #number of processes to use
                'root',                                             #ssh_user to use
                hosts_file_path,                                    #hostfile path if cloud_provider is rackspace
                options[:debug],
                options[:mock]
              )
      begin
        # Install puppet on all nodes
        puppet.install_puppet
        # Generate Hiera data
        @parsed_hash['install_mode'] == 'cloud' ? puppet.generate_hiera(@parsed_hash_with_internal_ips) : puppet.generate_hiera(@parsed_hash)
        # Generate ENC data
        @parsed_hash['install_mode'] == 'cloud' ? puppet.generate_enc(@parsed_hash_with_internal_ips, NODES_FILE_CLOUD) : puppet.generate_enc(@parsed_hash, NODES_FILE)
      rescue SocketError
        puts '[Error]:'.red + " Problem doing ssh into servers: #{$!}"
      ensure
        hosts_file.unlink if @parsed_hash['cloud_platform'] == 'rackspace'
      end
      # kick off puppet run based on deployment configuration
      puppet.run_puppet
      print_cluster_info(@parsed_hash)
    end

    # Prints the cluster information
    # @param [Hash] parsed_hash => contains cluster info
    def print_cluster_info(parsed_hash)
      (cluster_info ||= '') << 'Ankuscli Cluster info:' << "\n"
      cluster_info << " # Hadoop High Availability Configuration: #{parsed_hash['hadoop_ha']} \n"
      cluster_info << " # MapReduce Framework: #{parsed_hash['mapreduce']['type']} \n"
      cluster_info << " # HBase Cluster: #{parsed_hash['hbase_install']} \n"
      cluster_info << " # Security: #{parsed_hash['security']} \n"
      cluster_info << " # Monitoring(with ganglia): #{parsed_hash['monitoring']} \n"
      cluster_info << " # Altering(with nagios): #{parsed_hash['alerting']} \n"

      cluster_info << "\n"
      cluster_info << "Nodes in the cluster: \n"
      cluster_info << " * Controller: #{parsed_hash['controller']}\n"
      if parsed_hash['hadoop_ha'] == 'enabled'
        cluster_info << " * Namenode(s): \n"
        cluster_info << "\t - Active Namenode: #{parsed_hash['hadoop_namenode'].first} \n"
        cluster_info << "\t - Standby Namenode: #{parsed_hash['hadoop_namenode'].last} \n"
        cluster_info << " * Journal Quorum: \n"
        parsed_hash['journal_quorum'].each do |jn|
          cluster_info << "\t - #{jn}\n"
        end
      else
        cluster_info << " * Namenode: #{parsed_hash['hadoop_namenode'].first}\n"
        cluster_info << " * Secondary Namenode: #{parsed_hash['hadoop_secondarynamenode']}\n"
      end
      if parsed_hash['hbase_install'] == 'enabled'
        cluster_info << " * Hbase Master: #{parsed_hash['hbase_master'].join(',')} \n"
      end
      cluster_info << " * MapReduce Master: #{parsed_hash['mapreduce']['master']} \n"
      if parsed_hash['hadoop_ha'] == 'enabled' and parsed_hash['hbase_install'] == 'enabled'
        cluster_info << " * Zookeeper Quorum: \n"
        parsed_hash['zookeeper_quorum'].each do |zk|
          cluster_info << "\t - #{zk} \n"
        end
      end
      cluster_info << "\n"
      cluster_info << "Login Information:\n"
      cluster_info << " * ssh into nodes using: #{parsed_hash['root_ssh_key']}"

      puts "\r#{cluster_info}".squeeze(' ')
    end

  end
end