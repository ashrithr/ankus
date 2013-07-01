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

    desc 'info', 'show the cluster information deployed using ankuscli'
    def info
      if @parsed_hash.nil? or @parsed_hash.empty?
        parse_config
      end
      deployment_info(@parsed_hash)
    end

    desc 'ssh', 'ssh into instance'
    method_option :role, :required => true, :desc => 'role of the instance to ssh into'
    def ssh
      if @parsed_hash.nil? or @parsed_hash.empty?
        parse_config
      end
      ssh_into_instance options[:role], @parsed_hash
    end

    desc 'destroy', 'destroy the cluster (only valid for cloud deployments)'
    def destroy
      if agree('Are you sure want to destroy the cluster ?  ')
        if @parsed_hash.nil? or @parsed_hash.empty?
          parse_config
        end
        raise 'Only applicable for cloud deployments' if @parsed_hash['install_mode'] == 'local'
        destroy_cluster(@parsed_hash)
      end
    end

    private

    # Parses the configuraion file
    def parse_config
      @parsed_hash = ConfigParser.new(options[:config], options[:debug]).parse_config
    end

    # Creates a cloud class object which is the interface to ankuscli cloud interactions
    def create_cloud_obj(parsed_hash)
      Cloud.new(
          parsed_hash['cloud_platform'],
          parsed_hash,
          parsed_hash['cloud_credentials'],
          options[:thread_pool_size],
          options[:debug],
          options[:mock]
      )
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
        puts 'Parsing config file ...'
        parse_config
        puts 'Parsing config file ... ' + '[OK]'.green.bold
      end
      hosts_file = @parsed_hash['cloud_platform'] == 'rackspace' ? Tempfile.new('hosts') : nil
      hosts_file_path = @parsed_hash['cloud_platform'] == 'rackspace' ? hosts_file.path : nil
      if @parsed_hash['install_mode'] == 'cloud'
        #Kick off cloud instances and add them back to configuration hash
        Fog.mock! if options[:mock]
        cloud = create_cloud_obj(@parsed_hash)
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
      deployment_info @parsed_hash
    end

    # Prints the cluster information
    # @param [Hash] parsed_hash => contains cluster info
    def deployment_info(parsed_hash)
      (cluster_info ||= '') << 'Ankuscli Cluster info:' << "\n"
      cluster_info << " # Hadoop High Availability Configuration: #{parsed_hash['hadoop_ha']} \n"
      cluster_info << " # MapReduce Framework: #{parsed_hash['mapreduce']['type']} \n"
      cluster_info << " # HBase Cluster: #{parsed_hash['hbase_install']} \n"
      cluster_info << " # Security: #{parsed_hash['security']} \n"
      cluster_info << " # Monitoring(with ganglia): #{parsed_hash['monitoring']} \n"
      cluster_info << " # Altering(with nagios): #{parsed_hash['alerting']} \n"
      cluster_info << " # Log Aggregation(with Logstash): #{parsed_hash['log_aggregation']} \n"

      cluster_info << "\n"
      cluster_info << "Nodes in the cluster: \n"

      if parsed_hash['install_mode'] == 'cloud'
        #cloud deployment mode
        cloud_instances = YamlUtils.parse_yaml(CLOUD_INSTANCES)

        controller = cloud_instances.select { |k, _| k.include? 'controller'}.values.first
        cluster_info << " * Controller: #{controller.first} \n"
        if parsed_hash['hadoop_ha'] == 'enabled'
          cluster_info << " * Namenode(s): \n"
          nns = cloud_instances.select {|k, _| k.include? 'namenode'}
          nns.each do |k, v|
            cluster_info << "\t #{k}: #{v.first} \n"
          end
          cluster_info << " * Journal Quorum & ZooKeeper Quoram: \n"
          zks = cloud_instances.select { |k, _| k.include? 'zookeeper' }
          zks.each do |k, v|
            cluster_info << "\t #{k}: #{v.first} \n"
          end
        else
          namenode = cloud_instances.select { |k, _| k.include? 'namenode'}.values.first
          snn = cloud_instances.select { |k, _| k.include? 'jobtracker'}.values.first
          cluster_info << " * Namenode: #{namenode.first}\n"
          cluster_info << " * Secondary Namenode: #{snn.first}\n"
        end
        jt = cloud_instances.select { |k, _| k.include? 'jobtracker'}.values.first
        cluster_info << " * MapReduce Master: #{jt.first} \n"
      else
        #local deployment mode
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
      end
      cluster_info << "\n"
      cluster_info << "Login Information:\n"
      cluster_info << " * ssh into nodes using: ankuscli ssh <role> \n" << "\t Ex: ankuscli ssh controller\n"
      if parsed_hash['install_mode'] == 'cloud'
        if parsed_hash['cloud_platform'] == 'aws'
          cluster_info << " (or) using `ssh -i ~/.ssh/#{parsed_hash['cloud_credentials']['aws_key']} username@host`\n"
        elsif parsed_hash['cloud_platform'] == 'rackspace'
          cluster_info << " (or) using `ssh -i #{parsed_hash['cloud_credentials']['rackspace_ssh_key']} username@host`\n"
        end
      else
        cluster_info << " (or) using `ssh -i #{parsed_hash['root_ssh_key']} username@host`\n"
      end
      puts "\r#{cluster_info}".squeeze(' ')
    end

    # destroy the instances in the cloud
    def destroy_cluster(parsed_hash)
      cloud = create_cloud_obj(parsed_hash)
      cloud.delete_instances(YamlUtils.parse_yaml(CLOUD_INSTANCES))
    end

    def ssh_into_instance(role, parsed_hash)
      if parsed_hash['install_mode'] == 'cloud'
        #check tags and show available tags into machine
        cloud_instances = YamlUtils.parse_yaml(CLOUD_INSTANCES)
        if cloud_instances.keys.find { |e| /#{role}/ =~ e  }
          host = cloud_instances.select { |k, _| k.include? role}.values.first.first
          username = if parsed_hash['cloud_os_type'].downcase == 'centos'
                       'root'
                     elsif parsed_hash['cloud_os_type'].downcase == 'ubuntu'
                       'ubuntu'
                     end
          private_key = if parsed_hash['cloud_platform'] == 'aws'
                          "~/.ssh/#{parsed_hash['cloud_credentials']['aws_key']}"
                        else
                          parsed_hash['cloud_credentials']['rackspace_ssh_key']
                        end
          SshUtils.ssh_into_instance(host, username, private_key, 22)
        else
          puts "No such role found #{role}"
        end
      else
        puts 'Does not work with local install mode'.yellow
        puts "Use `ankuscli info` to look at instances info and ssh using \'#{parsed_hash['root_ssh_key']}\'"
      end
    end
  end
end