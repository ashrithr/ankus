module Ankus
  # Command line interface for ankus
  class CLI < Thor
    require 'ankus/helper'

    include Ankus

    class_option :config,
                 :type => :string,
                 :desc => 'optionally pass path to config file',
                 :default => DEFAULT_CONFIG

    class_option :debug,
                 :type => :boolean,
                 :desc => 'print more to the console',
                 :default => false

    class_option :thread_pool_size,
                 :type => :numeric,
                 :desc => 'size of the thread pool',
                 :default => 10

    class_option :mock,
                 :type => :boolean,
                 :desc => 'mock the creating of instances in cloud (debug mode)',
                 :default => false

    desc 'parse', 'Parse the config file for errors'
    def parse
      puts "Parsing config file '#{options[:config]}' ... "
      parse_config
      puts 'Parsing config file ... ' + '[OK]'.green.bold
    end

    desc 'version', 'Show the version'
    def version
      puts "Ankus Deployment Tool - Version: #{Ankus::VERSION}"
    end

    desc 'deploy', 'Deploy components specified in config'
    method_option :add_nodes,
                  :desc => 'flag to specify whether to add nodes to the existing cluster',
                  :default => false
    method_option :reload,
                  :desc => 'reloads deployment with respect to any changes to config',
                  :type => :boolean,
                  :default => false
    method_option :run_only,
                  :type => :boolean,
                  :default => false,
                  :desc => 'orchestrates only puppet runs accross cluster'
    def deploy
      unless options[:reload] or options[:run_only]
        if File.exists? NODES_FILE
          if YamlUtils.parse_yaml(NODES_FILE).is_a? Hash
            puts "\r[Error]: Deployment info exists! ".red
            puts "\rIf to update|change the deployment try using " + "deploy --reload".blue
            exit 1
          end
        end
      end
      initiate_deployment options
    end

    desc 'refresh', 'Reload the config files and update the configurations across the cluster'
    def refresh
      reload_deployment
    end

    desc 'info', 'Show the cluster information deployed using ankus'
    method_option :extended,
                  :desc => 'show more information like slaves in the cluster',
                  :type => :boolean,
                  :default => false
    def info
      if @config.nil? or @config.empty?
        parse_config
      end
      deployment_info(@config)
    end

    desc 'ssh', 'SSH into instance'
    method_option :role, :required => true, :desc => 'role of the instance to ssh into'
    def ssh
      if @config.nil? or @config.empty?
        parse_config
      end
      ssh_into_instance options[:role], @config
    end

    desc 'destroy', 'Destroy the cluster (only valid for cloud deployments)'
    method_option :delete_volumes,
                  :type => :boolean,
                  :default => false,
                  :desc => 'deletes volumes attached to instances as well (danger zone)'
    def destroy
      if @config.nil? or @config.empty?
        parse_config
      end
      raise 'Only applicable for cloud deployments' if @config['install_mode'] == 'local'
      destroy_cluster(@config, options)
    end

    private

    def parse_config
      @config = ConfigParser.new(options[:config], options[:debug]).parse_config
      HadoopConfigParser.new(HADOOP_CONF, options[:debug])
      HBaseConfigParser.new(HBASE_CONF, options[:debug])
    end

    def create_cloud_obj(config)
      Cloud.new(
          config[:cloud_platform],
          config,
          config[:cloud_credentials],
          options[:thread_pool_size],
          options[:debug],
          options[:mock]
      )
    end

    def initiate_deployment(options)
      size = `stty size 2>/dev/null`
      cols =  if $? == 0
                size.split.map { |x| x.to_i }.reverse.first
              else
                80
              end
      if options[:mock]
        puts '*' * cols
        puts 'MOCKING'.center(cols, ' ')
        puts '*' * cols
      end
      options[:run_only] ? puts('Orchestrating puppet runs') : puts('Starting deployment')
      if @config.nil? or @config.empty?
        puts 'Parsing config file ...'
        parse_config
        puts 'Parsing config file ... ' + '[OK]'.green.bold
      end

      unless options[:run_only]
        # if cloud provider is rackspace generate|store hosts file
        hosts_file = @config[:cloud_platform] == 'rackspace' ? Tempfile.new('hosts') : nil
        hosts_file_path = @config[:cloud_platform] == 'rackspace' ? hosts_file.path : nil

        # If deployment mode is cloud | local
        #   1. Create cloud instances based on configuration (cloud mode)
        #   2. Add hosts info to bookkeeping files
        #   3. Generate puppet nodes file (used for puppet installs | runs)
        #   4. Install puppet
        #   5. Generate Hiera and ENC data
        #   6. Kick off puppet on all instances (Orchestrate the puppet runs based on roles)
        if @config[:install_mode] == 'cloud'
          Fog.mock! if options[:mock]

          #
          # =>  Create cloud instance, used to create and manage cloud vm's
          #
          cloud = create_cloud_obj(@config)
          
          if options[:reload]
            #
            # => Check the existing config for change in nodes config and create new node if required
            #
            old_nodes_config = YamlUtils.parse_yaml(NODES_FILE)
            unless old_nodes_config.is_a? Hash
              abort 'No cluster found to update'.red
            end
            new_nodes_config = cloud.create_cloud_instances # just create instance definitions
            diff = new_nodes_config.keys - old_nodes_config.keys
            if diff.empty?
              puts '[Info]: No new nodes have to be created based on the new configuration'
              exit 0
            else
              puts '[Info]: New nodes have to be created based on the new configuration provided'
              puts '[Info]: Creating new instances ' +  "#{diff.join(',')}".blue
              # create new instances and add them back to old nodes
              nodes = old_nodes_config.merge!(cloud.safe_create_instances!(new_nodes_config.merge(old_nodes_config)))
            end
          else
            #
            # => Creates cloud instances and returns nodes hash
            #
            nodes = cloud.create_cloud_instances!
          end
          YamlUtils.write_yaml(nodes, NODES_FILE)
          if options[:mock] and options[:debug]
            puts '[Debug]: ' + 'Nodes Hash'.blue
            pp YamlUtils.parse_yaml(NODES_FILE)
            puts
          end
          #
          # =>  Create config based hash(es)
          #
          # @c and @cip are rebuild'ed hash(es) which are similar to @config only difference is that they
          # make config look more like local deployment, @ph contains hash with public ip(s) and @phip contains hash
          # with private dns (ip's)
          @config, @config_with_internal_ips = cloud.modify_cloud_config(@config, nodes)
          if options[:mock] and options[:debug]
            puts '[Debug]: ' + 'Parsed Hash'.blue
            pp @config
            puts
            puts '[Debug]: ' + 'Parsed hash with internal ip(s)'.blue
            pp @config_with_internal_ips
            puts
          end
          Fog.unmock! if options[:mock]

          # if cloud_provider is rackspace build /etc/hosts
          if @config[:cloud_platform] == 'rackspace'
            hosts_map = cloud.build_hosts(nodes)
            hosts_file.write(hosts_map)
            hosts_file.close
            if options[:mock] and options[:debug]
              puts '[Debug]: ' + 'Hosts file'.blue
              pp hosts_map
            end
          end
        end # @config[:install_mode] == 'cloud'
        #
        # => Generate puppet nodes hash from configuration for local mode only
        #
        if @config[:install_mode] == 'local'
          # Create puppet nodes from configuration
          Inventory::Generator.new(@config).generate! NODES_FILE
        end
      else
        #
        # => Run only mode, read config
        #
        if @config[:install_mode] == 'cloud'
          cloud = create_cloud_obj(@config)
          @config, @config_with_internal_ips = cloud.modify_cloud_config(@config, YamlUtils.parse_yaml(NODES_FILE))
        end
      end # unless options[:run_only]

      
      @nodes = YamlUtils.parse_yaml(NODES_FILE)

      #
      # => Crete puppet object used for installing, orchestrating puppet runs and also generating hiera and enc data.
      #
      puppet = Deploy::Puppet.new(
                @nodes,                       # puppet nodes hash
                @config[:ssh_key],            # ssh_key to use
                @config,                      # parsed config hash
                options[:thread_pool_size],   # number of threads to use
                @config[:ssh_user],           # ssh_user
                options[:debug],              # enabled debud mode
                options[:mock],               # enable mocking
                hosts_file_path               # hostfile path if cloud_provider is rackspace
              )
      unless options[:run_only]
        begin
          #
          # => install puppet on master ans client(s)
          #
          puppet.install

          #
          # => generate hiera data
          #
          @config[:install_mode] == 'cloud' ?
              puppet.generate_hiera(@config_with_internal_ips) :
              puppet.generate_hiera(@config)

          #
          # => generate enc data
          #
          @config[:install_mode] == 'cloud' ?
              puppet.generate_enc(@config_with_internal_ips, NODES_FILE) :
              puppet.generate_enc(@config, NODES_FILE)
        rescue SocketError
          puts '[Error]:'.red + " Problem doing ssh into servers: #{$!}"
        ensure
          # make sure to remove the temp hosts file generated if cloud provider is rackspace
          hosts_file.unlink if @config[:cloud_platform] == 'rackspace'
        end

        #
        # => puppet run on all nodes
        #
        puppet.run

        #
        # => display deployment info
        #
        deployment_info @config unless options[:reload]
      else
        #
        # => Run only mode
        #
        puppet.run
      end
    end

    # Refresh the cluster using updated configuration files
    def reload_deployment
      # 1. Reload Configurations
      # 2. Re-Generate Hiera data
      # 4. Re-Generate ENC data
      # 3. Re-Run puppet on all nodes
      @nodes = YamlUtils.parse_yaml(NODES_FILE)
      unless @nodes.is_a? Hash
        abort 'No cluster found to refresh'.red
      end
      parse_config if @config.nil? or @config.empty?
      puts 'Reloading Configurations ...'
      if @config[:install_mode] == 'cloud'
        cloud = create_cloud_obj(@config)
        @config, @config_with_internal_ips = cloud.modify_cloud_config(@config, @nodes)
      end
      puppet = Deploy::Puppet.new(
          @nodes,
          @config[:ssh_key],
          @config,
          options[:thread_pool_size],
          @config[:ssh_user],
          options[:debug],
          options[:mock]
      )
      @config[:install_mode] == 'cloud' ?
          puppet.generate_hiera(@config_with_internal_ips) :
          puppet.generate_hiera(@config)
      @config[:install_mode] == 'cloud' ?
          puppet.generate_enc(@config_with_internal_ips, NODES_FILE) :
          puppet.generate_enc(@config, NODES_FILE)
      puts 'Initializing Refresh across cluster'.blue
      #
      # Force run puppet on all nodes and update 'last_run' on @nodes
      #
      puppet.run!
      puts 'Completed Refreshing Cluster'.blue
    end

    # Prints the cluster information
    # @param [Hash] config => contains cluster info
    def deployment_info(config)
      # check for files in DATA_DIR if does not exists, we can assume user hasn't deployed a cluster yet
      unless YamlUtils.parse_yaml(NODES_FILE).is_a? Hash
        puts 'No cluster details found'.red
        puts <<-EOS.undent
          Deploy a cluster by running `ankus deploy`
        EOS
        abort
      end
      hiera_data = YamlUtils.parse_yaml(HIERA_DATA_FILE)
      cloud = create_cloud_obj(config) if config[:install_mode] == 'cloud'
      hbase_deploy = if config[:hbase_deploy] == 'disabled'
                      'disabled'
                     else
                      'enabled'
                     end
      mapreduce   = if config[:hadoop_deploy] != 'disabled' and config[:hadoop_deploy][:mapreduce] != 'disabled'
                      config[:hadoop_deploy][:mapreduce][:type]
                    else
                      'disabled'
                    end
      cassandra_deploy  =  config[:cassandra_deploy] != 'disabled' ? 'enabled' : 'disabled'
      storm_deploy      =  config[:storm_deploy] != 'disabled' ? 'enabled' : 'disabled'
      kafka_deploy      =  config[:kafka_deploy] != 'disabled' ? 'enabled' : 'disabled'
      solr_deploy       =  config[:solr_deploy] != 'disabled' ? 'enabled' : 'disabled'

      (cluster_info ||= '') << 'Ankus Cluster Info'.yellow_on_cyan.bold.underline << "\n"
      if config[:hadoop_deploy] != 'disabled'
        cluster_info << "\r" << ' #'.green << " Hadoop High Availability Configuration:" + 
                                              " #{config[:hadoop_deploy][:hadoop_ha]} \n"
        cluster_info << "\r" << ' #'.green << " MapReduce Framework: #{mapreduce} \n"
      else
        cluster_info << "\r" << ' #'.green << " Hadoop Deploy: disabled \n"
      end
      cluster_info << "\r" << ' #'.green << " HBase Deploy: #{hbase_deploy} \n"
      cluster_info << "\r" << ' #'.green << " Cassandra Deploy: #{cassandra_deploy} \n"
      cluster_info << "\r" << ' #'.green << " Storm Deploy: #{storm_deploy} \n"
      cluster_info << "\r" << ' #'.green << " Kafka Deploy: #{kafka_deploy} \n"
      cluster_info << "\r" << ' #'.green << " Solr Deploy: #{solr_deploy} \n"
      cluster_info << "\r" << ' #'.green << " Security: #{config[:security]} \n"
      cluster_info << "\r" << ' #'.green << " Monitoring(with ganglia): #{config[:monitoring]} \n"
      cluster_info << "\r" << ' #'.green << " Altering(with nagios): #{config[:alerting]} \n"
      cluster_info << "\r" << ' #'.green << " Log Aggregation(with Logstash): #{config[:log_aggregation]} \n"

      (urls ||= '') << 'Access URL(s)'.bold.underline << "\n"

      cluster_info << "\n"
      cluster_info << "\r" << 'Nodes in the cluster'.bold.underline << "\n"

      if config[:install_mode] == 'cloud'
        #cloud deployment mode
        cloud_instances = YamlUtils.parse_yaml(NODES_FILE)

        # controller, nagios, ganglia and logstash
        controller = find_fqdn_for_tag(cloud_instances, 'controller').first
        cluster_info << "\r" << ' *'.cyan << " Controller: #{controller} \n"
        urls << "\r" << ' %'.black << " Ganglia: http://#{controller}/ganglia \n" if config[:monitoring] == 'enabled'
        if config[:cloud_os_type].downcase == 'centos'
          urls << "\r" << ' %'.black << " Nagios: http://#{controller}/nagios \n" if config[:alerting] == 'enabled'
        elsif config[:cloud_os_type].downcase == 'ubuntu'
          urls << "\r" << ' %'.black << " Nagios: http://#{controller}/nagios3 \n" if config[:alerting] == 'enabled'
        end
        urls << "\r" << ' %'.black << " LogStash: http://#{controller}:5601 \n" if config[:log_aggregation] == 'enabled'

        if config[:hadoop_deploy] != 'disabled'
          if config[:hadoop_deploy][:hadoop_ha] == 'enabled'
            cluster_info << "\r" << ' *'.cyan << " Namenode(s): \n"
            nns = find_fqdn_for_tag(cloud_instances, 'namenode')
            nns.each do |k, v|
              cluster_info << "\r" << "\t #{k.capitalize}: #{v.first} \n"
              urls << "\r" << ' %'.black << " #{k.capitalize}: http://#{v.first}:50070 \n"
            end
          else
            namenode = cloud.find_fqdn_for_tag(cloud_instances, 'namenode').first
            snn = find_fqdn_for_tag(cloud_instances, 'secondarynamenode').first
            cluster_info << "\r" << ' *'.cyan << " Namenode: #{namenode}\n"
            cluster_info << "\r" << ' *'.cyan << " Secondary Namenode: #{snn}\n"
            urls << "\r" << ' %'.black << " Namenode: http://#{namenode}:50070 \n"
          end
          if config[:hadoop_deploy][:mapreduce] != 'disabled'
            jt = find_fqdn_for_tag(cloud_instances, 'jobtracker').first
            if mapreduce == 'mr1'
              cluster_info << "\r" << ' *'.cyan << " MapReduce Master: #{jt} \n"
              urls << "\r" << ' %'.black << " MapReduce Master: http://#{jt}:50030 \n"
            else
              cluster_info << "\r" << ' *'.cyan << " Resource Manager: #{jt} \n"
              urls << "\r" << ' %'.black << " Resource Manager: http://#{jt}:8088 \n"
              urls << "\r" << ' %'.black << " Job History Server: http://#{jt}:19888 \n"
            end              
            #hadoop_ecosystem
            if config[:hadoop_deploy][:hadoop_ecosystem] and config[:hadoop_deploy][:hadoop_ecosystem].include?('oozie')
              urls << "\r" << ' %'.black << " Oozie Console: http://#{jt}:11000/oozie \n"
            end
          end
          if config[:hadoop_deploy][:hadoop_ha] == 'enabled' or config[:hbase_deploy] != 'disabled'
            if config[:hadoop_deploy][:hadoop_ha] == 'enabled'
              cluster_info << "\r" << ' *'.cyan << " Journal Quorum & ZooKeeper Quoram: \n"
            else
              cluster_info << "\r" << ' *'.cyan << " ZooKeeper Quoram: \n"
            end
            zks = find_fqdn_for_tag(cloud_instances, 'zookeeper')
            zks.each do |k, v|
              cluster_info << "\r" << "\t #{k.capitalize}: #{v.first} \n"
            end
          end
        end
        if config[:hbase_deploy] != 'disabled'
          hms = find_fqdn_for_tag(cloud_instances, 'hbasemaster')
          hms.each do |k, v|
            cluster_info << "\r" << ' *'.cyan << " #{k.capitalize}: #{v.first} \n"
          end
          urls << "\r" << ' %'.black << " HBaseMaster: " + 
                          "http://#{Hash[hms.select {|k,v| k.include? 'hbasemaster1'}].values.flatten.first}:60010 \n"
        end
        if storm_deploy != 'disabled'
          stn = find_fqdn_for_tag(cloud_instances, 'stormnimbus').first
          cluster_info << "\r" << ' *'.cyan << " Storm Master: #{stn} \n"
          urls << "\r" << ' %'.black << " Storm UI: http://#{stn}:8080 \n"
        end
        if config[:solr_deploy] != 'disabled'
          solr_nodes = find_fqdn_for_tag(cloud_instances, 'solr')
          urls << "\r" << ' %'.black << " Solr Admin: http://#{solr_nodes.sample}:8983/solr \n"
        end        
        if options[:extended]
          if config[:hadoop_deploy] != 'disabled' or config[:hbase_deploy] != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Slaves: \n"
            find_fqdn_for_tag(cloud_instances, 'slaves').each_with_index do |k, i|
              cluster_info << "\r" << "\t" << '- '.cyan << "slave#{i+1}: #{k}" << "\n"
            end
          end
          if cassandra_deploy != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Cassandra Nodes: \n"
            find_fqdn_for_tag(cloud_instances, 'cassandra').each_with_index do |k, i|
              cluster_info << "\r" << "\t" << '- '.cyan << "cassandra#{i+1}: #{k}" << "\n"
            end
          end
          if storm_deploy != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Storm Supervisor Nodes: \n"
            find_fqdn_for_tag(cloud_instances, 'stormworker').each_with_index do |k, i|
              cluster_info << "\r" << "\t" << "- ".cyan << "stormworker#{i+1}: #{k}" << "\n"
            end
          end
          if kafka_deploy != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Kafka Nodes: \n"
            find_fqdn_for_tag(cloud_instances, 'kafka').each_with_index do |k, i|
              cluster_info << "\r" << "\t" << "- ".cyan << "kafka#{i+1}: #{k}" << "\n"
            end            
          end
          if solr_deploy != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Solr Nodes: \n"
            find_fqdn_for_tag(cloud_instances, 'solr').each_with_index do |k, i|
              cluster_info << "\r" << "\t" << "- ".cyan << "solr#{i+1}: #{k}" << "\n"
            end
          end
        end
      else
        #local deployment mode
        cluster_info << "\r" << ' *'.cyan << " Controller: #{config[:controller]}\n"
        if config[:monitoring] == 'enabled'
          urls << "\r" << ' %'.black << " Ganglia: http://#{config[:controller]}/ganglia \n"
        end
        if config[:alerting] == 'enabled'
          if hiera_data['nagios_server_ostype'].downcase == 'centos'
            urls << "\r" << ' %'.black << " Nagios: http://#{config[:controller]}/nagios \n"
          elsif hiera_data['nagios_server_ostype'].downcase == 'ubuntu'
            urls << "\r" << ' %'.black << " Nagios: http://#{config[:controller]}/nagios3 \n"
          end
        end
        if config[:log_aggregation] == 'enabled'
          urls << "\r" << ' %'.black << " LogStash: http://#{config[:controller]}:5601 \n"
        end

        if config[:hadoop_deploy] != 'disabled'
          if config[:hadoop_deploy][:hadoop_ha] == 'enabled'
            cluster_info << "\r" << ' *'.cyan << " Namenode(s): \n"
            cluster_info << "\r" << "\t - Active Namenode: #{config[:hadoop_deploy][:hadoop_namenode].first} \n"
            cluster_info << "\r" << "\t - Standby Namenode: #{config[:hadoop_deploy][:hadoop_namenode].last} \n"
            urls << "\r" << ' %'.black << " Active Namenode: " + 
                                          "http://#{config[:hadoop_deploy][:hadoop_namenode].first}:50070 \n"
            urls << "\r" << ' %'.black << " Standby Namenode:" + 
                                          " http://#{config[:hadoop_deploy][:hadoop_namenode].last}:50070 \n"
            cluster_info << "\r" << ' *'.cyan << " Journal Quorum: \n"
            config[:hadoop_deploy][:journal_quorum].each do |jn|
              cluster_info << "\r" << "\t - #{jn}\n"
            end
          else
            cluster_info << "\r" << ' *'.cyan << " Namenode: #{config[:hadoop_deploy][:hadoop_namenode].first}\n"
            cluster_info << "\r" << ' *'.cyan << " Secondary Namenode:" + 
                                                 " #{config[:hadoop_deploy][:hadoop_secondarynamenode]}\n"
            urls << "\r" << ' %'.black << " Namenode: http://#{config[:hadoop_deploy][:hadoop_namenode].first}:50070 \n"
          end
          if config[:hadoop_deploy][:hadoop_ha] == 'enabled' and config[:hbase_deploy] != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Zookeeper Quorum: \n"
            config[:zookeeper_quorum].each do |zk|
              cluster_info << "\r"<< "\t - #{zk} \n"
            end
          end
          if config[:hadoop_deploy][:mapreduce] != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " MapReduce Master: #{config[:hadoop_deploy][:mapreduce][:master]} \n"
          end
        end
        if config[:hbase_deploy] != 'disabled'
          cluster_info << "\r" << ' *'.cyan << " Hbase Master: #{config[:hbase_deploy][:hbase_master].join(',')} \n"
          urls << "\r" << ' %'.black << " Hbase Master: http://#{config[:hbase_deploy][:hbase_master].first}:60010 \n"
        end
        if config[:storm_deploy] != 'disabled'
          cluster_info << "\r" << ' *'.cyan << " Storm Master: #{config[:storm_deploy][:storm_master]} \n"
          urls << "\r" << ' %'.black << " Hbase Master: http://#{config[:storm_deploy][:storm_master]}:8080 \n"
        end
        if config[:solr_deploy] != 'disabled'
          urls << "\r" << ' %'.black << "Solr Admin: http://#{config[:solr_deploy][:solr_nodes].sample}:8983/solr \n"
        end
        if options[:extended]
          if config[:hadoop_deploy] != 'disabled' or config[:hbase_deploy] != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Slaves: \n"
            config[:slave_nodes].each do |slave|
              cluster_info << "\r" << "\t" << '- '.cyan << slave << "\n"
            end
          end
          if config[:cassandra_deploy] != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Cassandra Node(s): \n"
            config[:cassandra_deploy][:cassandra_nodes].each do |cn|
              cluster_info << "\r" << "\t" << '- '.cyan << cn << "\n"
            end
            cluster_info << "\r" << ' *'.cyan << " Cassandra Seed Node(s): \n"
            config[:cassandra_deploy][:cassandra_seeds].each do |cn|
              cluster_info << "\r" << "\t" << '- '.cyan << cn << "\n"
            end            
          end
          if config[:storm_deploy] != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Storm Supervisors: \n"
            config[:storm_deploy][:storm_supervisors].each do |cn|
              cluster_info << "\r" << "\t" << '- '.cyan << cn << "\n"
            end
            urls << "\r" << ' %'.black << " Storm Master: http://#{config[:storm_deploy][:storm_master]}:8080" 
          end
          if config[:kafka_deploy] != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Kafka Brokers: \n"
            config[:kafka_deploy][:kafka_brokers].each do |cn|
              cluster_info << "\r" << "\t" << '- '.cyan << cn << "\n"
            end            
            # cluster_info << "\r" << ' *'.cyan << " Kafka Node(s): \n"
            # config[:kafka_deploy][:kafka_nodes].each do |cn|
            #   cluster_info << "\r" << "\t" << '- '.cyan << cn << "\n"
            # end            
          end
          if config[:solr_deploy] != 'disabled'
            config[:solr_deploy][:solr_nodes].each do |sn|
              cluster_info << "\r" << "\t" << '- '.cyan << sn << "\n"
            end
          end          
        end
      end
      cluster_info << "\n"
      (login_info ||= '') << "\r" << 'Login Information'.underline << "\n"
      login_info << "\r" << ' *'.cyan << " ssh into nodes using: ankus ssh --role <role> \n" <<
                                         "\r\t Ex: ankus ssh --role controller\n"
      if config[:install_mode] == 'cloud'
        if config[:cloud_platform] == 'aws'
          username = config[:cloud_os_type].downcase == 'centos' ? 'root' : 'ubuntu'
          login_info << "\r" << " (or) using `ssh -i ~/.ssh/#{config[:cloud_credentials][:aws_key]}" + 
                                " #{username}@[host]`\n"
        elsif config[:cloud_platform] == 'rackspace'
          login_info << "\r" << " (or) using `ssh -i #{config[:cloud_credentials][:rackspace_ssh_key]} root@[host]`\n"
        end
      else
        username = config[:ssh_user]
        login_info << "\r" << " (or) using `ssh -i #{config[:ssh_key]} #{username}@[host]`\n"
      end
      puts
      puts "\r#{cluster_info.squeeze(' ')}"
      puts "\r#{urls.squeeze(' ')}"         if options[:extended]
      puts                                  if options[:extended]
      puts "\r#{login_info.squeeze(' ')}"
      puts
    end

    # destroy the instances in the cloud
    def destroy_cluster(config, options)
      unless YamlUtils.parse_yaml(NODES_FILE).is_a? Hash
        abort 'No cluster found to delete'.red
      end
      if agree('Are you sure want to destroy the cluster ?  ')
        cloud = create_cloud_obj(config)
        cloud.delete_instances(YamlUtils.parse_yaml(NODES_FILE), options[:delete_volumes])
        FileUtils.rm_rf DATA_DIR
      end
    end

    # Invoke ssh process on the instance specified with role
    # @param [String] role => role of the instance to perform ssh
    # @param [Hash] config => configration hash
    def ssh_into_instance(role, config)
      if config[:install_mode] == 'cloud'
        # check tags and show available tags into machine
        cloud_instances = YamlUtils.parse_yaml(NODES_FILE)
        host = find_fqdn_for_tag(cloud_instances, role) && find_fqdn_for_tag(cloud_instances, role).first
        if host
          username = config[:ssh_user]
          private_key = if config[:cloud_platform] == 'aws'
                          "~/.ssh/#{config[:cloud_credentials][:aws_key]}"
                        elsif config[:cloud_platform] == 'rackspace'
                          # rackspace instances need private file to login
                          config[:cloud_credentials][:rackspace_ssh_key][0..-5]
                        end          
          puts "[Info]: ssh into #{host} as user:#{username} with key:#{private_key}"
          SshUtils.ssh_into_instance(host, username, private_key, 22)
        else
          puts "No such role found: #{role}"
          puts "Available roles: #{cloud_instances.map { |k, v| v[:tags]}.flatten.uniq}"
        end
      else
        #local mode, build roles from conf
        local_instances = YamlUtils.parse_yaml(NODES_FILE)
        host = find_fqdn_for_tag(local_instances, role) && find_fqdn_for_tag(local_instances, role).first
        if host
          username = config[:ssh_user]
          private_key = config[:ssh_key]          
          puts "[Info]: ssh into #{host} as user:#{username} with key:#{private_key}"
          SshUtils.ssh_into_instance(host, username, private_key, 22)
        else
          puts "No such role found: #{role}"
          puts "Available roles: #{cloud_instances.map { |k, v| v[:tags]}.flatten.uniq}"
        end
      end
    end
  end
end
