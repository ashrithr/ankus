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
    method_option :role,
                  :desc => 'type of node being added, "hadoop" will install datanode, tasktracker and regionserver if hbase is enabled',
                  :default => 'hadoop'
    method_option :count,
                  :desc => 'number of nodes to add to the cluster (cloud mode)',
                  :type => :numeric,
                  :default => 1
    method_option :hosts,
                  :desc => 'array of host names to add to the cluster',
                  :type => :array
    method_option :run_only,
                  :type => :boolean,
                  :default => false,
                  :desc => 'orchestrates only puppet runs accross cluster'
    def deploy
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
      if @parsed_hash.nil? or @parsed_hash.empty?
        parse_config
      end
      deployment_info(@parsed_hash)
    end

    desc 'ssh', 'SSH into instance'
    method_option :role, :required => true, :desc => 'role of the instance to ssh into'
    def ssh
      if @parsed_hash.nil? or @parsed_hash.empty?
        parse_config
      end
      ssh_into_instance options[:role], @parsed_hash
    end

    desc 'destroy', 'Destroy the cluster (only valid for cloud deployments)'
    method_option :delete_volumes,
                  :type => :boolean,
                  :default => false,
                  :desc => 'deletes volumes attached to instances as well (danger zone)'
    def destroy
      if @parsed_hash.nil? or @parsed_hash.empty?
        parse_config
      end
      raise 'Only applicable for cloud deployments' if @parsed_hash['install_mode'] == 'local'
      destroy_cluster(@parsed_hash, options)
    end

    private

    def parse_config
      @parsed_hash = ConfigParser.new(options[:config], options[:debug]).parse_config
      HadoopConfigParser.new(HADOOP_CONF, options[:debug])
      HBaseConfigParser.new(HBASE_CONF, options[:debug])
    end

    # Creates a object to interface with ankus cloud interactions
    def create_cloud_obj(parsed_hash)
      Cloud.new(
          parsed_hash[:cloud_platform],
          parsed_hash,
          parsed_hash[:cloud_credentials],
          options[:thread_pool_size],
          options[:debug],
          options[:mock]
      )
    end

    def initiate_deployment(options)
      size = `stty size 2>/dev/null` #get the size of the terminal
      cols =  if $? == 0
                size.split.map { |x| x.to_i }.reverse.first
              else
                80 # if failed to get the size, set the terminal size to default of 80 columns
              end
      if options[:mock]
        puts '*' * cols
        puts 'MOCKING'.center(cols, ' ')
        puts '*' * cols
      end
      options[:run_only] ? puts('Orchestrating puppet runs') : puts('Starting deployment')
      if @parsed_hash.nil? or @parsed_hash.empty?
        # parse the configuration file if not parsed prior to this point
        puts 'Parsing config file ...'
        parse_config
        puts 'Parsing config file ... ' + '[OK]'.green.bold
      end
      _parsed_hash = Marshal.load(Marshal.dump(@parsed_hash))

      unless options[:run_only]
        # if cloud provider is rackspace generate|store hosts file
        hosts_file = @parsed_hash[:cloud_platform] == 'rackspace' ? Tempfile.new('hosts') : nil
        hosts_file_path = @parsed_hash[:cloud_platform] == 'rackspace' ? hosts_file.path : nil

        # If deployment mode is cloud | local
        #   1. Create cloud instances based on configuration (cloud mode)
        #   2. Add hosts info to bookkeeping files
        #   3. Generate puppet nodes file (used for puppet installs | runs)
        #   4. Install puppet
        #   5. Generate Hiera and ENC data
        #   6. Kick off puppet on all instances (Orchestrate the puppet runs based on roles)
        if @parsed_hash[:install_mode] == 'cloud'
          #Kick off cloud instances and add them back to configuration hash
          Fog.mock! if options[:mock]
          cloud = create_cloud_obj(@parsed_hash)
          if options[:add_nodes]
            # if deploy option is add_nodes create a list of tags for instances to be created
            existing_clients_count = @parsed_hash[:slave_nodes_count]
            tags = []
            options[:count].times do
              tags << if @parsed_hash[:cloud_platform] == 'aws'
                        existing_clients_count += 1
                        "slaves#{existing_clients_count}"
                      elsif @parsed_hash[:cloud_platform] == 'rackspace'
                        existing_clients_count += 1
                        "slaves#{existing_clients_count}.#{@parsed_hash[:cloud_credentials][:rackspace_cluster_identifier]}.ankus.com"
                      end
            end
            @new_instances = cloud.create_instances_on_count tags #this only contains currently created instances
            nodes_fqdn_map = YamlUtils.parse_yaml(CLOUD_INSTANCES)
            nodes_fqdn_map.merge!(@new_instances)
            # update the slave_nodes_count
            _parsed_hash[:slave_nodes_count] += options[:count]
            YamlUtils.write_yaml(_parsed_hash.deep_stringify, options[:config])
          else
            nodes_fqdn_map = cloud.create_instances
          end
          YamlUtils.write_yaml(nodes_fqdn_map, CLOUD_INSTANCES)
          if options[:mock] and options[:debug]
            puts '[Debug]: ' + 'Nodes Hash'.blue
            pp nodes_fqdn_map
            puts
          end
          # @parsed_hash_with_internal_ips is a rebuild'ed hash which is similar to @parsed_hash only difference is
          # that it contains private_ips which are resolved internally by cloud instances, which is required for building
          # hiera data and enc data
          @parsed_hash, @parsed_hash_with_internal_ips = cloud.modify_config_hash(@parsed_hash, nodes_fqdn_map)
          if options[:mock] and options[:debug]
            puts '[Debug]: ' + 'Parsed Hash'.blue
            pp @parsed_hash
            puts
            puts '[Debug]: ' + 'Parsed hash with internal ip(s)'.blue
            pp @parsed_hash_with_internal_ips
          end
          Fog.unmock! if options[:mock]

          # if cloud_provider is rackspace build /etc/hosts
          if @parsed_hash[:cloud_platform] == 'rackspace'
            hosts_file.write(cloud.build_hosts(nodes_fqdn_map))
            hosts_file.close
            if options[:mock] and options[:debug]
              puts '[Debug]: ' + 'Hosts file'.blue
              puts cloud.build_hosts(nodes_fqdn_map)
            end
          end
        else
          #local mode & adding nodes
          if options[:add_nodes]
            abort '--host option is required' unless options[:hosts]
            # validate hosts
            SshUtils.sshable? options[:hosts], @parsed_hash[:ssh_user], @parsed_hash[:ssh_key]
            # aggregate the existing slaves with new slaves & add them to conf
            @parsed_hash[:slave_nodes] = @parsed_hash[:slave_nodes] | options[:hosts]
            YamlUtils.write_yaml(@parsed_hash.deep_stringify, options[:config])
          end
        end
        # generate puppet nodes file from configuration
        if @parsed_hash[:install_mode] == 'cloud'
          Inventory::Generator.new(options[:config], @parsed_hash_with_internal_ips).generate! NODES_FILE_CLOUD #for enc generate
          Inventory::Generator.new(options[:config], @parsed_hash).generate! NODES_FILE # for puppet install/runs
        else
          # for enc and puppet install/runs
          Inventory::Generator.new(options[:config], @parsed_hash).generate! NODES_FILE
        end
      else
        #Run only mode
        cloud = create_cloud_obj(@parsed_hash)
        @parsed_hash, @parsed_hash_with_internal_ips = cloud.modify_config_hash(@parsed_hash, YamlUtils.parse_yaml(CLOUD_INSTANCES))
      end

      ## create puppet_deploy object which is can install puppet & generate hiera data, enc data
      puppet_clients =  if options[:add_nodes] and @parsed_hash[:install_mode] == 'cloud'
                          @new_instances.map { |_,hostnames| hostnames.first }
                        elsif options[:add_nodes] and @parsed_hash[:install_mode] == 'local'
                          options[:hosts]
                        else
                          YamlUtils.parse_yaml(NODES_FILE)[:puppet_clients]
                        end
      puppet_master = YamlUtils.parse_yaml(NODES_FILE)[:puppet_server]
      puppet = Deploy::Puppet.new(
                puppet_master,                # puppet server
                puppet_clients,               # nodes to install puppet client on
                @parsed_hash[:ssh_key],       # ssh_key to use
                @parsed_hash,                 # parsed config hash
                options[:thread_pool_size],   # number of threads to use
                @parsed_hash[:ssh_user],      # ssh_user
                options[:debug],              # enabled debud mode
                options[:mock],               # enable mocking
                hosts_file_path               # hostfile path if cloud_provider is rackspace
              )
      unless options[:run_only]
        begin
          if options[:add_nodes]
            # install only clients
            puppet.install_puppet_clients
          else
            # install master and clients
            puppet.install_puppet
          end
          @parsed_hash[:install_mode] == 'cloud' ?
              puppet.generate_hiera(@parsed_hash_with_internal_ips) :
              puppet.generate_hiera(@parsed_hash)
          @parsed_hash[:install_mode] == 'cloud' ?
              puppet.generate_enc(@parsed_hash_with_internal_ips, NODES_FILE_CLOUD) :
              puppet.generate_enc(@parsed_hash, NODES_FILE)
        rescue SocketError
          puts '[Error]:'.red + " Problem doing ssh into servers: #{$!}"
        ensure
          # make sure to remove the temp hosts file generated if cloud provider is rackspace
          hosts_file.unlink if @parsed_hash[:cloud_platform] == 'rackspace'
        end
        if options[:add_nodes]
          puppet.run_puppet_set puppet_clients
        else
          puppet.run_puppet
          deployment_info @parsed_hash
        end
      else
        puppet.run_puppet
      end
    end

    # Refresh the cluster using updated configuration files
    def reload_deployment
      # 1. Reload Configurations
      # 2. Re-Generate Hiera data
      # 4. Re-Generate ENC data
      # 3. Re-Run puppet on all nodes
      unless YamlUtils.parse_yaml(NODES_FILE).is_a? Hash
        abort 'No cluster found to refresh'.red
      end
      parse_config if @parsed_hash.nil? or @parsed_hash.empty?
      puts 'Reloading Configurations ...'
      if @parsed_hash[:install_mode] == 'cloud'
        cloud = create_cloud_obj(@parsed_hash)
        @parsed_hash, @parsed_hash_with_internal_ips = cloud.modify_config_hash(@parsed_hash, YamlUtils.parse_yaml(CLOUD_INSTANCES))
      end
      puppet_server = YamlUtils.parse_yaml(NODES_FILE)[:puppet_server]
      puppet_clients = YamlUtils.parse_yaml(NODES_FILE)[:puppet_clients]
      puppet = Deploy::Puppet.new(
          puppet_server,
          puppet_clients,
          @parsed_hash[:ssh_key],
          @parsed_hash,
          options[:thread_pool_size],
          @parsed_hash[:ssh_user],
          options[:debug],
          options[:mock]
      )
      @parsed_hash[:install_mode] == 'cloud' ?
          puppet.generate_hiera(@parsed_hash_with_internal_ips) :
          puppet.generate_hiera(@parsed_hash)
      @parsed_hash[:install_mode] == 'cloud' ?
          puppet.generate_enc(@parsed_hash_with_internal_ips, NODES_FILE_CLOUD) :
          puppet.generate_enc(@parsed_hash, NODES_FILE)
      puts 'Initializing Refresh across cluster'.blue
      puppet.run_puppet_set(puppet_clients)
      puts 'Completed Refreshing Cluster'.blue
    end

    # Prints the cluster information
    # @param [Hash] parsed_hash => contains cluster info
    def deployment_info(parsed_hash)
      # check for files in DATA_DIR if does not exists, we can assume user hasn't deployed a cluster yet
      unless YamlUtils.parse_yaml(NODES_FILE).is_a? Hash
        puts 'No cluster details found'.red
        puts <<-EOS.undent
          Deploy a cluster by running `ankus deploy`
        EOS
        abort
      end
      hiera_data = YamlUtils.parse_yaml(HIERA_DATA_FILE)
      hbase_deploy = if parsed_hash[:hbase_deploy] == 'disabled'
                       'disabled'
                     else
                       'enabled'
                     end
      mapreduce   = if parsed_hash[:hadoop_deploy] != 'disabled' and parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
                      parsed_hash[:hadoop_deploy][:mapreduce][:type]
                    else
                      'disabled'
                    end
      cassandra_deploy =  parsed_hash[:cassandra_deploy] != 'disabled' ? 'enabled' : 'disabled'

      (cluster_info ||= '') << 'Ankus Cluster Info'.yellow_on_cyan.bold.underline << "\n"
      if parsed_hash[:hadoop_deploy] != 'disabled'
        cluster_info << "\r" << ' #'.green << " Hadoop High Availability Configuration: #{parsed_hash[:hadoop_deploy][:hadoop_ha]} \n"
        cluster_info << "\r" << ' #'.green << " MapReduce Framework: #{mapreduce} \n"
      else
        cluster_info << "\r" << ' #'.green << " Hadoop Deploy: disabled \n"
      end
      cluster_info << "\r" << ' #'.green << " HBase Deploy: #{hbase_deploy} \n"
      cluster_info << "\r" << ' #'.green << " Cassandra Deploy: #{cassandra_deploy} \n"
      cluster_info << "\r" << ' #'.green << " Security: #{parsed_hash[:security]} \n"
      cluster_info << "\r" << ' #'.green << " Monitoring(with ganglia): #{parsed_hash[:monitoring]} \n"
      cluster_info << "\r" << ' #'.green << " Altering(with nagios): #{parsed_hash[:alerting]} \n"
      cluster_info << "\r" << ' #'.green << " Log Aggregation(with Logstash): #{parsed_hash[:log_aggregation]} \n"

      (urls ||= '') << 'Access URL(s)'.bold.underline << "\n"

      cluster_info << "\n"
      cluster_info << "\r" << 'Nodes in the cluster'.bold.underline << "\n"

      if parsed_hash[:install_mode] == 'cloud'
        #cloud deployment mode
        cloud_instances = YamlUtils.parse_yaml(CLOUD_INSTANCES)

        # controller, nagios, ganglia and logstash
        controller = Hash[cloud_instances.select { |k, _| k.include? 'controller'}].values.first
        cluster_info << "\r" << ' *'.cyan << " Controller: #{controller.first} \n"
        urls << "\r" << ' %'.black << " Ganglia: http://#{controller.first}/ganglia \n" if parsed_hash[:monitoring] == 'enabled'
        if parsed_hash[:cloud_os_type].downcase == 'centos'
          urls << "\r" << ' %'.black << " Nagios: http://#{controller.first}/nagios \n" if parsed_hash[:alerting] == 'enabled'
        elsif parsed_hash[:cloud_os_type].downcase == 'ubuntu'
          urls << "\r" << ' %'.black << " Nagios: http://#{controller.first}/nagios3 \n" if parsed_hash[:alerting] == 'enabled'
        end
        urls << "\r" << ' %'.black << " LogStash: http://#{controller.first}:5601 \n" if parsed_hash[:log_aggregation] == 'enabled'

        if parsed_hash[:hadoop_deploy] != 'disabled'
          if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
            cluster_info << "\r" << ' *'.cyan << " Namenode(s): \n"
            nns = cloud_instances.select {|k, _| k.include? 'namenode'}
            nns.each do |k, v|
              cluster_info << "\r" << "\t #{k.capitalize}: #{v.first} \n"
              urls << "\r" << ' %'.black << " #{k.capitalize}: http://#{v.first}:50070 \n"
            end
          else
            namenode = Hash[cloud_instances.select { |k, _| k.include? 'namenode'}].values.first
            snn = if parsed_hash[:hadoop_deploy][:mapreduce] == 'disabled'
                    Hash[cloud_instances.select { |k, _| k.include? 'snn'}].values.first
                  else
                    Hash[cloud_instances.select { |k, _| k.include? 'jobtracker'}].values.first
                  end
            cluster_info << "\r" << ' *'.cyan << " Namenode: #{namenode.first}\n"
            cluster_info << "\r" << ' *'.cyan << " Secondary Namenode: #{snn.first}\n"
            urls << "\r" << ' %'.black << " Namenode: http://#{namenode.first}:50070 \n"
          end
          if parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
            jt = Hash[cloud_instances.select { |k, _| k.include? 'jobtracker'}].values.first
            cluster_info << "\r" << ' *'.cyan << " MapReduce Master: #{jt.first} \n"
            urls << "\r" << ' %'.black << " MapReduce Master: http://#{jt.first}:50030 \n"
            #hadoop_ecosystem
            if parsed_hash[:hadoop_deploy][:hadoop_ecosystem] and parsed_hash[:hadoop_deploy][:hadoop_ecosystem].include?('oozie')
              urls << "\r" << ' %'.black << " Oozie Console: http://#{jt.first}:11000/oozie \n"
            end
          end
          if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled' or parsed_hash[:hbase_deploy] != 'disabled'
            if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
              cluster_info << "\r" << ' *'.cyan << " Journal Quorum & ZooKeeper Quoram: \n"
            else
              cluster_info << "\r" << ' *'.cyan << " ZooKeeper Quoram: \n"
            end
            zks = cloud_instances.select { |k, _| k.include? 'zookeeper' }
            zks.each do |k, v|
              cluster_info << "\r" << "\t #{k.capitalize}: #{v.first} \n"
            end
          end
        end
        if parsed_hash[:hbase_deploy] != 'disabled'
          hms = cloud_instances.select { |k, _| k.include? 'hbasemaster'}
          hms.each do |k, v|
            cluster_info << "\r" << ' *'.cyan << " #{k.capitalize}: #{v.first} \n"
          end
          urls << "\r" << ' %'.black << " HBaseMaster: http://#{Hash[hms.select {|k,v| k.include? 'hbasemaster1'}].values.flatten.first}:60010 \n"
        end
        if options[:extended]
          if parsed_hash[:hadoop_deploy] != 'disabled' or parsed_hash[:hbase_deploy] != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Slaves: \n"
            cloud_instances.select { |k, _| k.include? 'slaves' }.each do |k, v|
              cluster_info << "\r" << "\t" << '- '.cyan << "#{k.capitalize}: #{v.first}" << "\n"
            end
          end
          if cassandra_deploy != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Cassandra Nodes: \n"
            if parsed_hash[:cassandra_deploy][:hadoop_colocation]
              #if both hadoop and cassandra is colocated, print slaves
              cloud_instances.select { |k, _| k.include? 'slaves' }.each do |k, v|
                cluster_info << "\r" << "\t" << '- '.cyan << "#{v.first}" << "\n"
              end
            else
              cloud_instances.select { |k, _| k.include? 'cassandra' }.each do |k, v|
                cluster_info << "\r" << "\t" << '- '.cyan << "#{v.first}" << "\n"
              end
            end
          end
        end
      else
        #local deployment mode
        cluster_info << "\r" << ' *'.cyan << " Controller: #{parsed_hash[:controller]}\n"
        urls << "\r" << ' %'.black << " Ganglia: http://#{parsed_hash[:controller]}/ganglia \n" if parsed_hash[:monitoring] == 'enabled'
        if hiera_data['nagios_server_ostype'].downcase == 'centos'
          urls << "\r" << ' %'.black << " Nagios: http://#{parsed_hash[:controller]}/nagios \n" if parsed_hash[:alerting] == 'enabled'
        elsif hiera_data['nagios_server_ostype'].downcase == 'ubuntu'
          urls << "\r" << ' %'.black << " Nagios: http://#{parsed_hash[:controller]}/nagios3 \n" if parsed_hash[:alerting] == 'enabled'
        end
        urls << "\r" << ' %'.black << " LogStash: http://#{parsed_hash[:controller]}:5601 \n" if parsed_hash[:log_aggregation] == 'enabled'

        if parsed_hash[:hadoop_deploy] != 'disabled'
          if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
            cluster_info << "\r" << ' *'.cyan << " Namenode(s): \n"
            cluster_info << "\r" << "\t - Active Namenode: #{parsed_hash[:hadoop_deploy][:hadoop_namenode].first} \n"
            cluster_info << "\r" << "\t - Standby Namenode: #{parsed_hash[:hadoop_deploy][:hadoop_namenode].last} \n"
            urls << "\r" << ' %'.black << " Active Namenode: http://#{parsed_hash[:hadoop_deploy][:hadoop_namenode].first}:50070 \n"
            urls << "\r" << ' %'.black << " Standby Namenode: http://#{parsed_hash[:hadoop_deploy][:hadoop_namenode].last}:50070 \n"
            cluster_info << "\r" << ' *'.cyan << " Journal Quorum: \n"
            parsed_hash[:hadoop_deploy][:journal_quorum].each do |jn|
              cluster_info << "\r" << "\t - #{jn}\n"
            end
          else
            cluster_info << "\r" << ' *'.cyan << " Namenode: #{parsed_hash[:hadoop_deploy][:hadoop_namenode].first}\n"
            cluster_info << "\r" << ' *'.cyan << " Secondary Namenode: #{parsed_hash[:hadoop_deploy][:hadoop_secondarynamenode]}\n"
            urls << "\r" << ' %'.black << " Namenode: http://#{parsed_hash[:hadoop_deploy][:hadoop_namenode].first}:50070 \n"
          end
          if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled' and parsed_hash[:hbase_deploy] != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Zookeeper Quorum: \n"
            parsed_hash[:zookeeper_quorum].each do |zk|
              cluster_info << "\r"<< "\t - #{zk} \n"
            end
          end
        end
        if parsed_hash[:hbase_deploy] != 'disabled'
          cluster_info << "\r" << ' *'.cyan << " Hbase Master: #{parsed_hash[:hbase_deploy][:hbase_master].join(',')} \n"
          urls << "\r" << ' %'.black << " Hbase Master: http://#{parsed_hash[:hbase_deploy][:hbase_master].first}:60010 \n"
        end
        cluster_info << "\r" << ' *'.cyan << " MapReduce Master: #{parsed_hash[:hadoop_deploy][:mapreduce][:master]} \n"
        if options[:extended]
          cluster_info << "\r" << ' *'.cyan << " Slaves: \n"
          parsed_hash[:slave_nodes].each do |slave|
            cluster_info << "\r" << "\t" << '- '.cyan << slave << "\n"
          end
          if parsed_hash[:cassandra_deploy] != 'disabled'
            cluster_info << "\r" << ' *'.cyan << " Cassandra Node(s): \n"
            parsed_hash[:cassandra_deploy][:cassandra_nodes].each do |cn|
              cluster_info << "\r" << "\t" << '- '.cyan << cn << "\n"
            end
          end
        end
      end
      cluster_info << "\n"
      (login_info ||= '') << "\r" << 'Login Information'.underline << "\n"
      login_info << "\r" << ' *'.cyan << " ssh into nodes using: ankus ssh --role <role> \n" <<
                                         "\r\t Ex: ankus ssh --role controller\n"
      if parsed_hash[:install_mode] == 'cloud'
        if parsed_hash[:cloud_platform] == 'aws'
          username = parsed_hash[:cloud_os_type].downcase == 'centos' ? 'root' : 'ubuntu'
          login_info << "\r" << " (or) using `ssh -i ~/.ssh/#{parsed_hash[:cloud_credentials][:aws_key]} #{username}@[host]`\n"
        elsif parsed_hash[:cloud_platform] == 'rackspace'
          login_info << "\r" << " (or) using `ssh -i #{parsed_hash[:cloud_credentials][:rackspace_ssh_key]} root@[host]`\n"
        end
      else
        username = parsed_hash[:ssh_user]
        login_info << "\r" << " (or) using `ssh -i #{parsed_hash[:ssh_key]} #{username}@[host]`\n"
      end
      puts
      puts "\r#{cluster_info.squeeze(' ')}"
      puts "\r#{urls.squeeze(' ')}"         if options[:extended]
      puts                                  if options[:extended]
      puts "\r#{login_info.squeeze(' ')}"
      puts
    end

    # destroy the instances in the cloud
    def destroy_cluster(parsed_hash, options)
      unless YamlUtils.parse_yaml(NODES_FILE).is_a? Hash
        abort 'No cluster found to delete'.red
      end
      if agree('Are you sure want to destroy the cluster ?  ')
        cloud = create_cloud_obj(parsed_hash)
        cloud.delete_instances(YamlUtils.parse_yaml(CLOUD_INSTANCES), options[:delete_volumes])
        FileUtils.rm_rf DATA_DIR
      end
    end

    def ssh_into_instance(role, parsed_hash)
      if parsed_hash[:install_mode] == 'cloud'
        #check tags and show available tags into machine
        cloud_instances = YamlUtils.parse_yaml(CLOUD_INSTANCES)
        if cloud_instances.keys.find { |e| /#{role}/ =~ e  }
          host = Hash[cloud_instances.select { |k, _| k.include? role}].values.first.first
          username = parsed_hash[:ssh_user]
          private_key = if parsed_hash[:cloud_platform] == 'aws'
                          "~/.ssh/#{parsed_hash[:cloud_credentials][:aws_key]}"
                        else
                          # rackspace instances need private file to login
                          parsed_hash[:cloud_credentials][:rackspace_ssh_key][0..-5]
                        end
          SshUtils.ssh_into_instance(host, username, private_key, 22)
        else
          puts "No such role found #{role}"
          puts "Available roles: #{cloud_instances.keys.join(',')}"
        end
      else
        #local mode, build roles from conf
        nodes_roles = {
            :controller   => parsed_hash[:controller],
            :jobtracker   => parsed_hash[:hadoop_deploy][:mapreduce][:master],
        }
        if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
          nodes_roles.merge!({ :namenode1 => parsed_hash[:hadoop_deploy][:hadoop_namenode][0],
                               :namenode2 => parsed_hash[:hadoop_deploy][:hadoop_namenode][1] })
          parsed_hash[:hadoop_deploy][:journal_quorum].each_with_index { |jn, index| nodes_roles["journalnode#{index+1}"] = jn }
        else
          nodes_roles.merge!({ :namenode => parsed_hash[:hadoop_deploy][:hadoop_namenode][0] })
        end
        if parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled' or parsed_hash[:hbase_deploy] != 'disabled'
          parsed_hash[:zookeeper_quorum].each_with_index { |zk, index| nodes_roles["zookeeper#{index+1}".to_sym] = zk }
        end
        if parsed_hash[:hbase_deploy] != 'disabled'
          parsed_hash[:hbase_deploy][:hbase_master].each_with_index { |hbm, index| nodes_roles["hbasemaster#{index+1}".to_sym] = hbm }
        end
        parsed_hash[:slave_nodes].each_with_index { |slave, index| nodes_roles["slaves#{index+1}".to_sym] = slave }

        if nodes_roles.keys.find { |e| /#{role}/ =~ e.to_s } and nodes_roles[role.to_sym] != nil
          SshUtils.ssh_into_instance(nodes_roles[role.to_sym], @parsed_hash[:ssh_user], parsed_hash[:ssh_key], 22)
        else
          puts "No such role found #{role}"
          puts "Available roles: #{nodes_roles.keys.join(',')}"
        end
      end
    end
  end
end
