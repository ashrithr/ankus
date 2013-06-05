module Ankuscli
  # Command line interface for ankuscli
  class CLI < Thor

    include Ankuscli

    #Constants
    DEFAULT_CONFIG = File.expand_path(File.dirname(__FILE__) + '/../../conf/ankus_conf.yaml')
    NODES_FILE = File.expand_path(File.dirname(__FILE__) + '/../../data/nodes.yaml')
    NODES_FILE_CLOUD = File.expand_path(File.dirname(__FILE__) + '/../../data/nodes_cloud.yaml')

    class_option :config, :type => :string, :desc => 'optionally pass path to config file', :default => DEFAULT_CONFIG

    class_option :debug, :type => :boolean, :desc => 'print more to the console', :default => false

    class_option :thread_pool_size, :type => :numeric, :desc => 'size of the thread pool', :default => 10

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

    end

    desc 'refresh', 'reload the config files and update the configurations across the cluster'
    def refresh
      #TODO
    end

    private

    # Parses the configuraion file
    def parse_config
      puts 'parsing config file ...'
      @parsed_hash = ConfigParser.new(options[:config], options[:debug]).parse_config
      puts 'parsing config file ... ' + '[OK]'.green.bold
    end

    # Initializes the deployment process either on local or cloud
    def initiate_deployment
      puts 'starting deployment'
      if @parsed_hash.nil? or @parsed_hash.empty?
        parse_config
      end
      if @parsed_hash['install_mode'] == 'cloud'
        #Kick off cloud instances and add them back to configuration hash
        cloud = Cloud.new(
                  @parsed_hash['cloud_platform'],
                  @parsed_hash,
                  @parsed_hash['cloud_credentials'],
                  options[:thread_pool_size],
                  options[:debug]
                )
        nodes_fqdn_map = cloud.create_instances
        @parsed_hash, @parsed_hash_with_internal_ips = cloud.modify_config_hash(@parsed_hash, nodes_fqdn_map)
        # @parsed_hash_with_internal_ips is a rebuild'ed hash which is similar to @parsed_hash only difference is
        # that it contains private_ips which are resolved internally by cloud instances
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
                options[:thread_pool_size],                                                 #number of processes to use
                'root',                                             #ssh_user to use
                options[:debug]
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
      end
      # kick off puppet run based on deployment configuration
      puppet.run_puppet
    end

  end
end