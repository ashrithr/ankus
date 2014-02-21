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
  # Command line interface for ankus
  class CLI < Thor
    require 'ankus/helper'
    require 'ankus/logging'
    include Ankus

    # Setup global logging
    $logger = Log4r::Logger.new('Ankus')
    outputter = Log4r::StdoutOutputter.new('stdout')
    outputter.formatter = Log4r::PatternFormatter.new(:pattern => '%d %L %m')
    $logger.outputters = [ outputter ]
    $logger.level = Log4r::DEBUG

    # Root level command line options
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

    #
    # Root level commands
    #
    desc 'parse', 'Parse the config file for errors'
    def parse
      $logger.info "Parsing config file '#{options[:config]}' ... "
      parse_config options[:debug]
      $logger.info 'Parsing config file ... ' + '[OK]'.green
    end

    desc 'version', 'Show the version'
    def version
      puts "Version: #{Ankus::VERSION}"
    end

    desc 'deploy', 'Deploy components specified in config'
    method_option :add_nodes,
                  :desc => 'flag to specify whether to add nodes to the existing cluster',
                  :default => false
    method_option :reload,
                  :desc => 'reloads deployment with respect to any changes to configuration files',
                  :type => :boolean,
                  :default => false
    method_option :run_only,
                  :type => :boolean,
                  :default => false,
                  :desc => 'orchestrates only puppet runs across cluster'
    method_option :force,
                  :type => :boolean,
                  :default => false,
                  :desc => 'force run puppet'
    def deploy
      unless options[:reload] or options[:run_only]
        if File.exists? NODES_FILE
          if YamlUtils.parse_yaml(NODES_FILE).is_a? Hash
            $logger.error 'Deployment info exists!'
            $logger.warn 'If to update|change the deployment try using ' + 'deploy --reload'.bold
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

    desc 'pssh', 'Parallel ssh and execute set of commands'
    long_desc <<-LONGDESC
      `pssh` will perform ssh into instances and parallely executes set of commands

      You can optionally pass roles so that commands will be executed on set of nodes
      say for example, if you want to perform puppet run on slave nodes you can pass
      `--role 'slave*' --commands 'puppet agent -t'` to do so.
    LONGDESC
    method_option :role, :desc => 'set of instances to execute commands on, default: executes commands on all available instances'
    method_option :list_roles, :desc => 'list available roles', :type => :boolean
    method_option :commands, :desc => 'commands to execute', :type => :array, :required => true
    def pssh
      if @config.nil? or @config.empty?
        parse_config
      end
      pssh_commands options, @config
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
      if @config['install_mode'] == 'local'
        $logger.fatal 'Only applicable for cloud deployments'
        exit 1
      end
      destroy_cluster(@config, options)
    end

    private

    # Parses the configuration file
    # @param [TrueClass] debug whether to print verbose output during parsing the configuration file
    # @return [Hash] configuration hash to work with
    def parse_config(debug = false)
      @config = ConfigParser.new(options[:config], $logger, debug).parse_config
    end

    # Creates a cloud object which is an encapsulation for all the cloud providers
    # supported by ankus
    # @param [Hash] config configuration hash as returned by #parse_config
    # @return [Ankus::Cloud]
    def create_cloud_obj(config)
      Cloud.new(
          config[:cloud_platform],
          config,
          config[:cloud_credentials],
          $logger,
          options[:thread_pool_size],
          options[:debug],
          options[:mock]
      )
    end

    # Initializes the deployment of components based on the configuration
    # @param [Thor::Options] options method options provided by thor parser
    # @return nil
    def initiate_deployment(options)
      #size = `stty size 2>/dev/null`
      #cols =  if $? == 0
      #          size.split.map { |x| x.to_i }.reverse.first
      #        else
      #          80
      #        end
      if options[:mock]
        #puts '*' * cols
        #puts 'MOCKING'.center(cols, ' ')
        #puts '*' * cols
        $logger.info 'MOCKING deployment'.bold
      end
      options[:run_only] ? $logger.info('Orchestrating puppet runs') : $logger.info('Starting deployment')
      if @config.nil? or @config.empty?
        $logger.info 'Parsing config file ...'
        parse_config
        $logger.info 'Parsing config file ... ' + '[OK]'.green
      end

      if options[:run_only]
        #
        # => Run only mode, read config
        #
        if @config[:install_mode] == 'cloud'
          cloud = create_cloud_obj(@config)
          @config, @config_with_internal_ips = cloud.modify_cloud_config(@config, YamlUtils.parse_yaml(NODES_FILE))
        end
      else
        # if cloud provider is rackspace generate|store hosts file
        hosts_file = @config[:cloud_platform] == 'rackspace' || @config[:cloud_platform] == 'openstack' ? Tempfile.new('hosts') : nil
        hosts_file_path = @config[:cloud_platform] == 'rackspace' || @config[:cloud_platform] == 'openstack' ? hosts_file.path : nil

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
              $logger.info 'No new nodes have to be created based on the new configuration'
              exit 0
            else
              $logger.info 'New nodes have to be created based on the new configuration provided'
              $logger.info 'Creating new instances ' + "#{diff.join(',')}".blue
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
            $logger.debug 'Nodes Hash'.blue
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
            $logger.debug 'Parsed Hash'.blue
            pp @config
            puts
            $logger.debug 'Parsed hash with internal ip(s)'.blue
            pp @config_with_internal_ips
            puts
          end
          Fog.unmock! if options[:mock]

          # if cloud_provider is rackspace or openstack build /etc/hosts
          if @config[:cloud_platform] == 'rackspace' || @config[:cloud_platform] == 'openstack'
            hosts_map = cloud.build_hosts(nodes)
            hosts_file.write(hosts_map)
            hosts_file.close
            if options[:mock] and options[:debug]
              $logger.debug 'Hosts file'.blue
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
      end # unless options[:run_only]

      
      @nodes = YamlUtils.parse_yaml(NODES_FILE)

      #
      # => Crete puppet object used for installing, orchestrating puppet runs and also generating hiera and enc data.
      #
      puppet = Deploy::Puppet.new(
                @nodes,                       # puppet nodes hash
                @config[:ssh_key],            # ssh_key to use
                @config,                      # parsed config hash
                $logger,                      # logger instance
                options[:thread_pool_size],   # number of threads to use
                @config[:ssh_user],           # ssh_user
                options[:debug],              # enabled debud mode
                options[:mock],               # enable mocking
                hosts_file_path               # hostfile path if cloud_provider is rackspace
              )
      if options[:run_only]
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

        #
        # => Run only mode
        #
        puppet.run options[:force]
      else
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
          $logger.error " Cannot ssh into server: #{$!}"
        ensure
          # make sure to remove the temp hosts file generated if cloud provider is rackspace
          hosts_file.unlink if @config[:cloud_platform] == 'rackspace' || @config[:cloud_platform] == 'openstack'
        end

        #
        # => puppet run on all nodes
        #
        puppet.run

        #
        # => display deployment info
        #
        $logger.info 'Deployment complete, to check deployment information use `info` subcommand'
        # deployment_info @config unless options[:reload]
        if options[:mock] # if mocking delete the data dir contents
          FileUtils.rm_rf(Dir.glob("#{DATA_DIR}/*"))
        end
      end
    end

    # Refresh the cluster using updated configuration files
    # @return nil
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
      $logger.info 'Reloading Configurations ...'
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
      $logger.info 'Initializing Refresh across cluster'
      #
      # Force run puppet on all nodes and update 'last_run' on @nodes
      #
      puppet.run!
      $logger.info 'Completed Refreshing Cluster'
    end

    # Prints the cluster information
    # @param [Hash] config => contains cluster info
    def deployment_info(config)
      # TODO [Feature] add support for returning state of the cluster
      # check for files in DATA_DIR if does not exists, we can assume user hasn't deployed a cluster yet
      unless YamlUtils.parse_yaml(NODES_FILE).is_a? Hash
        $logger.error 'No cluster details found, to deploy a cluster use `deploy` subcommand'
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
        cluster_info << "\r" << ' #'.green << ' Hadoop High Availability Configuration:' +
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

    # Destroy the instances managed by ankus in cloud
    # @param [Hash] config configuration hash as returned by #parse_config
    # @param [Thor::Options] options method options parsed by thor
    # @return nil
    def destroy_cluster(config, options)
      unless YamlUtils.parse_yaml(NODES_FILE).is_a? Hash
        $logger.error 'No cluster found to delete'
        abort
      end
      if agree('Are you sure want to destroy the cluster, which includes deleting all instances (yes/no) ? ')
        cloud = create_cloud_obj(config)
        cloud.delete_instances(YamlUtils.parse_yaml(NODES_FILE), options[:delete_volumes])
        FileUtils.rm_rf DATA_DIR
      end
    end

    # Returns ssh user and key based on cloud or local deployment mode
    # @param [Hash] config configuration hash as returned by #parse_config
    # @return [Array] containing ssh user name and ssh key to use
    def find_ssh_user_and_key(config)
      if config[:install_mode] == 'cloud'
        pk = if config[:cloud_platform] == 'aws'
               "~/.ssh/#{config[:cloud_credentials][:aws_key]}"
             elsif config[:cloud_platform] == 'rackspace'
               # rackspace instances need private file to login
               config[:cloud_credentials][:rackspace_ssh_key][0..-5]
             elsif config[:cloud_platform] == 'openstack'
               "~/.ssh/#{config[:cloud_credentials][:os_ssh_key]}"
             end
      else
        pk = config[:ssh_key]
      end
      return config[:ssh_user], pk
    end

    # Parallel ssh into specified instances, execute commands and prints the commands stdout
    # command return code and commands stderr
    # @param [Thor::Options] options method options parsed by thor
    # @param [Hash] config configuration hash as returned by #parse_config
    # @return nil
    def pssh_commands(options, config)
      instances = YamlUtils.parse_yaml(NODES_FILE)
      roles_available = instances.map {|_,v| v[:tags]}.flatten.uniq
      roles_to_ssh = if options[:role]
                       roles_available.select{ |r| r[Regexp.new(options[:role])]}
                     else
                      roles_available
                     end
      username, private_key = find_ssh_user_and_key(config)
      if options[:list_roles]
        $logger.info "Available roles: #{roles_available}"
      else
        if options[:debug]
          $logger.debug "Performing ssh into instances specified by roles: #{roles_to_ssh}"
          $logger.debug "Commands to execute: #{options[:commands]}"
        end
        ssh_connections = ThreadPool.new(options[:thread_pool_size])
        ssh_output = []
        hosts = find_fqdn_for_tag(instances, options[:role])
        hosts.each do |host|
          ssh_connections.schedule do
            ssh_output << SshUtils.execute_ssh_cmds!(
                options[:commands],
                host,
                username,
                private_key,
                $logger,
                22,
                false
            ).merge!({'host' => host})
          end
        end
        ssh_connections.shutdown
        ssh_output.each do |host_output|
          host_output.except('host').each do |cmds_out|
            cmd = cmds_out.first
            cmd_out = cmds_out.last
            puts "[#{host_output['host']}] COMMAND: '#{cmd}' #{(cmd_out[2] == 0) ? 'SUCCESS'.blue : 'FAILURE'.red}"
            puts "[#{host_output['host']}] " + 'STDOUT ' + cmd_out[0] unless cmd_out[0].empty?
            puts "[#{host_output['host']}] " + 'STDERR ' + cmd_out[1] unless cmd_out[1].empty?
          end
        end
      end
    end

    # Invoke ssh process on the instance specified with role
    # @param [String] role => role of the instance to perform ssh
    # @param [Hash] config => configuration hash
    def ssh_into_instance(role, config)
      instances = YamlUtils.parse_yaml(NODES_FILE)
      roles_available = instances.map {|_,v| v[:tags]}.flatten.uniq
      username, private_key = find_ssh_user_and_key(config)
      host = find_fqdn_for_tag(instances, role) && find_fqdn_for_tag(instances, role).first
      if host
        $logger.info "ssh into #{host} as user:#{username} with key:#{private_key}"
        SshUtils.ssh_into_instance(host, username, private_key, 22)
      else
        $logger.warn "No such role found: #{role}. Available roles: #{roles_available}"
      end
    end
  end
end
