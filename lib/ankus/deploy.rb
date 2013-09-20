module Ankus
  module Deploy
    require 'benchmark'

    # Class to manage puppet deployments
    class Puppet
      require 'ankus/helper'
      include Ankus

      # Creates a [Ankus::Puppet] class object which manages puppet installations and puppet runs
      # @param [Hash] nodes => puppet nodes hash
      # @param [String] ssh_key => ssh key to use to log into the machines
      # @param [Hash] parsed_hash => parsed configuration file
      # @param [Integer] ssh_connections => number of concurrent processes (threads) to use for deployments
      # @param [String] ssh_user => user to log into the machine as
      # @param [Boolean] debug => if enabled will print out information to stdout
      def initialize(nodes, ssh_key, parsed_hash, ssh_connections=10, ssh_user='root', 
        debug=false, mock = false, hosts_file = nil)
        @nodes                 = nodes
        @parallel_connections  = ssh_connections
        @ssh_user              = ssh_user
        @ssh_key               = ssh_key
        @puppet_installer      = File.basename(PUPPET_INSTALLER)
        @parsed_hash           = parsed_hash
        @hosts_file            = hosts_file
        @puppet_master         = find_fqdn_for_tag(nodes, 'controller').first # FQDN of puppet server
        @puppet_clients        = #FQDN of puppet clients
                                  if parsed_hash[:install_mode] == 'local'
                                    nodes.except(@puppet_master).keys
                                  elsif parsed_hash[:cloud_platform] == 'aws'
                                    pc_client_keys =  nodes.except(find_key_for_fqdn(nodes, @puppet_master)).keys
                                    nodes.map {|k, v| v[:fqdn] if pc_client_keys.include?(k) }.compact
                                  elsif parsed_hash[:cloud_platform] == 'rackspace'
                                    pc_client_keys =  nodes.except(find_key_for_fqdn(nodes, @puppet_master)).keys
                                    nodes.map {|k, v| v[:fqdn] if pc_client_keys.include?(k) }.compact
                                  end
        @debug                 = debug
        @mock                  = mock
      end

      # Installs puppet server on node with tag 'controller' and puppet agent(s) on other nodes
      # @param [String] remote_puppet_installer_loc => path where the puppet installer is located
      def install(remote_puppet_installer_loc='/tmp')
        remote_puppet_server_cmd    = "chmod +x #{remote_puppet_installer_loc}/#{@puppet_installer} &&" + 
            " sudo sh -c '#{remote_puppet_installer_loc}/#{@puppet_installer} -s | tee #{REMOTE_LOG_DIR}/install.log'"
        remote_puppet_client_cmd    =  # assign the command to install puppet client based on the install_mode
          if @parsed_hash[:install_mode] == 'local'
            "chmod +x #{remote_puppet_installer_loc}/#{@puppet_installer} &&" + 
            " sudo sh -c '#{remote_puppet_installer_loc}/#{@puppet_installer} -c -H #{@puppet_master} |" + 
            " tee #{REMOTE_LOG_DIR}/install.log'"
          else
            puppet_server_cloud_fqdn =  if @parsed_hash[:cloud_platform] == 'aws'
                                          find_pip_for_tag(@nodes, 'controller').first
                                        elsif @parsed_hash[:cloud_platform] == 'rackspace'
                                          find_key_for_tag(@nodes, 'controller').first
                                        end
            "chmod +x #{remote_puppet_installer_loc}/#{@puppet_installer} &&" + 
            " sudo sh -c '#{remote_puppet_installer_loc}/#{@puppet_installer} -c -H #{puppet_server_cloud_fqdn} |" +
            " tee #{REMOTE_LOG_DIR}/install.log'"
          end

        if ! @mock
          #
          # Puppet Server
          #
          puppet_server_tag = find_key_for_fqdn(@nodes, @puppet_master)
          unless @nodes[puppet_server_tag][:puppet_install_status]
            validate_instances @puppet_master
            puts "\rChecking if puppet server is ssh'able ..."
            SshUtils.sshable? @puppet_master, @ssh_user, @ssh_key
            puts "\rChecking if puppet server is ssh'able ... " + '[OK]'.green.bold
            @parsed_hash[:cloud_platform] == 'rackspace' ?
              preq(@puppet_master, remote_puppet_installer_loc, @hosts_file) :
              preq(@puppet_master, remote_puppet_installer_loc)
            if @debug
              puts "\rInstalling puppet master on " + "#{@puppet_master}".blue
            else
              SpinningCursor.start do
                banner "\rInstalling puppet master ".blue
                type :dots
                message "\rInstalling puppet master ".blue + '[DONE]'.cyan
              end
            end
            puts "\r[Debug]: Found puppet installer script at #{PUPPET_INSTALLER}" if @debug
            # if controller is on same machine, install puppet master locally else send the script to controller
            # and install puppet
            if @parsed_hash[:controller] == 'localhost'
              status = ShellUtils.run_cmd_with_log!(
                  "chmod +x #{PUPPET_INSTALLER} && sudo sh -c '#{PUPPET_INSTALLER} -s'",
                  "#{REMOTE_LOG_DIR}/install.log"
              )
              unless status.success?
                puts "\r[Error]:".red + ' Failed to install puppet master'
                exit 2
                #TODO: handle rollback
              end
            else
              puts "\r[Debug]: Sending file #{PUPPET_INSTALLER} to #{@puppet_master}" if @debug
              SshUtils.upload!(PUPPET_INSTALLER, remote_puppet_installer_loc, @puppet_master, @ssh_user, @ssh_key)
              master_output = SshUtils.execute_ssh!(
                  remote_puppet_server_cmd,
                  @puppet_master,
                  @ssh_user,
                  @ssh_key,
                  22,
                  @debug
              )
              unless master_output[@puppet_master][2].to_i == 0
                puts "\r[Error]:".red + ' Failed to install puppet master'
                exit 2
              end
            end
            @nodes[puppet_server_tag][:puppet_install_status] = true
            cleanup(@puppet_master)
            SpinningCursor.stop unless @debug
          end

          #
          # Puppet Clients
          #
          # initiate concurrent threads pool - to install puppet clients all agent puppet_clients
          time = Benchmark.measure do
            ssh_connections = ThreadPool.new(@parallel_connections)
            validate_instances @puppet_clients
            @clients_output = []
            @nodes.except(puppet_server_tag).each do |node, node_info|
              SpinningCursor.start do
                banner "\rInstalling puppet agents on clients ".blue
                type :dots
                message "\rInstalling puppet agents on clients ".blue + '[DONE]'.cyan
              end            
              if ! node_info[:puppet_install_status] # Only install puppet if not already installed
                @parsed_hash[:cloud_platform] == 'rackspace' ?
                  preq(node_info[:fqdn], remote_puppet_installer_loc, @hosts_file) :
                  preq(node_info[:fqdn], remote_puppet_installer_loc)
                ssh_connections.schedule do
                  @clients_output << SshUtils.execute_ssh!(
                      remote_puppet_client_cmd,
                      node_info[:fqdn],
                      @ssh_user,
                      @ssh_key
                    )
                  node_info[:puppet_install_status] = true  #set that installing suceeded
                  cleanup(node_info[:fqdn])
                end # ssh_connections
              end # if
            end # @nodes
            ssh_connections.shutdown
            SpinningCursor.stop
          end # benchmark        
          puts "\r[Debug]: Time to install puppet clients: #{time}" if @debug
          #print output of puppet client installers on console
          if @debug
            @clients_output.each do |o|
              puts "\rSTDOUT".blue + " on #{o.keys.join}"
              puts "\r#{o.values.first[0]}"
              unless o.values.first[1].empty?
                puts "\rSTDERR".yellow + " on #{o.keys.join}"
                puts "\r#{o.values.first[1]}"
              end
            end
          end 
        else
          #
          # MOCKING
          #
          puts 'Checking if instances are ssh\'able ...'
          puts 'Checking if instances are ssh\'able ...' + '[OK]'.green.bold
          puppet_server_tag = find_key_for_fqdn(@nodes, @puppet_master)
          unless @nodes[puppet_server_tag][:puppet_install_status]
            puts "\rInstalling puppet master on #{@puppet_master}".blue
            puts "\rUsing command: #{remote_puppet_server_cmd}"
            puts "\rInstalling puppet master on #{@puppet_master}".blue + '[DONE]'.cyan
            @nodes[puppet_server_tag][:puppet_install_status] = true
          end
          ssh_connections = ThreadPool.new(@parallel_connections)
          puts "\rInstalling puppet clients".blue
          puts "\rUsing command: #{remote_puppet_client_cmd}"
          @nodes.except(puppet_server_tag).each do |node, node_info|
            if ! node_info[:puppet_install_status]
              ssh_connections.schedule do
                printf "\rInstalling puppet agent on client " + "#{node_info[:fqdn]}".blue + "\n"
                node_info[:puppet_install_status] = true
              end
            end
          end
          ssh_connections.shutdown          
        end # if ! @mock
        YamlUtils.write_yaml(@nodes, NODES_FILE)
        puts "\rInstalling puppet completed".blue      
      end # install

      # Generate hiera data required by puppet deployments & writes out to the yaml file
      # @param [Hash] parsed_hash => hash from which to generate hiera data
      def generate_hiera(parsed_hash)
        hiera_hash = {}
        # generate hiera data to local data folder first
        puts "\rGenerating hiera data required for puppet".blue
        # aggregate hadoop, hbase, all other related configurations in here into a common hash before writing out
        hiera_hash.merge!(parsed_hash.deep_stringify)
        hiera_hash.merge!(YamlUtils.parse_yaml(HADOOP_CONF))    if parsed_hash[:hadoop_deploy] != 'disabled'
        hiera_hash.merge!(YamlUtils.parse_yaml(HBASE_CONF))     if parsed_hash[:hbase_deploy] != 'disabled'
        hiera_hash.merge!(YamlUtils.parse_yaml(CASSANDRA_CONF)) if parsed_hash[:cassandra_deploy] != 'disabled'

        if parsed_hash[:hadoop_deploy] != 'disabled' or parsed_hash[:hbase_deploy] != 'disabled'
          #parse zookeeper ensemble
          if parsed_hash[:zookeeper_quorum]
            hiera_hash['zookeeper_ensemble'] = parsed_hash[:zookeeper_quorum].map { |zk| zk += ":2181" }.join(",")
            hiera_hash['zookeeper_class_ensemble'] = parsed_hash[:zookeeper_quorum].map { |zk| zk+=":2888:3888" }
          end
          #parse num_of_workers
          hiera_hash['number_of_nodes'] = parsed_hash[:slave_nodes].length
        end
        if parsed_hash[:kafka_deploy] != 'disabled' or parsed_hash[:storm_deploy] != 'disabled'
          unless hiera_hash.has_key? 'zookeeper_ensemble'
            hiera_hash['zookeeper_ensemble'] = parsed_hash[:zookeeper_quorum].map { |zk| zk += ":2181" }.join(",")
          end
          unless hiera_hash.has_key? 'zookeeper_class_ensemble'
            hiera_hash['zookeeper_class_ensemble'] = parsed_hash[:zookeeper_quorum].map { |zk| zk+=":2888:3888" }
          end
        end
        #parse journal quorum
        if parsed_hash[:hadoop_deploy] != 'disabled'
          if parsed_hash[:hadoop_deploy][:hadoop_ha] != 'disabled' and parsed_hash[:hadoop_deploy][:journal_quorum]
            hiera_hash['journal_quorum'] =  parsed_hash[:hadoop_deploy][:journal_quorum].map do |jn| 
                                              jn += ":8485"
                                            end.join(";")
          end
        end
        #parse nagios & ganglia
        if parsed_hash[:monitoring] == 'enabled'
          hiera_hash['ganglia_server'] = parsed_hash[:controller]
        end
        #log_aggregation
        if parsed_hash[:log_aggregation] == 'enabled'
          hiera_hash['logstash_server'] = parsed_hash[:controller]
        end
        #nagios server os_type is required
        if parsed_hash[:install_mode] == 'cloud'
          hiera_hash['nagios_server'] = parsed_hash[:controller]
          hiera_hash['nagios_server_ostype'] = parsed_hash[:cloud_os_type].downcase =~ /centos/ ? 'CentOS' : 'Ubuntu'
        else
          if parsed_hash[:alerting] == 'enabled'
            hiera_hash['nagios_server'] = parsed_hash[:controller]
            begin #gather info of system
              if parsed_hash[:controller] == 'localhost'
                @osinfo = `chmod +x #{GETOSINFO_SCRIPT} && #{GETOSINFO_SCRIPT}`.chomp
                if $?.success?
                  @ostype = @osinfo =~ /centos/ ? 'CentOS' : 'Ubuntu'
                else
                  @ostype = 'CentOS'
                end
              else
                SshUtils.upload!(GETOSINFO_SCRIPT, "/tmp", @puppet_master, @ssh_user, @ssh_key)
                os_type_cmd = "chmod +x /tmp/#{File.basename(GETOSINFO_SCRIPT)} &&" + 
                              " sudo sh -c '/tmp/#{File.basename(GETOSINFO_SCRIPT)}'"
                output = SshUtils.execute_ssh_cmds(
                    [os_type_cmd,
                     "rm -rf /tmp/#{File.basename(GETOSINFO_SCRIPT)}"],
                    @puppet_master,
                    @ssh_user,
                    @ssh_key,
                    22,
                    @debug
                )
                @osinfo = output[os_type_cmd][0]
                @ostype = @osinfo =~ /centos/ ? 'CentOS' : 'Ubuntu'
              end
            rescue #if script is not found, set the ostype as centos
              @ostype = 'CentOS'
            end
            hiera_hash['nagios_server_ostype'] = @ostype
          end
        end
        #security
        if parsed_hash[:security] == 'kerberos'
          hiera_hash['kerberos_kdc_server'] = @puppet_master
          hiera_hash['kerberos_realm'] = @parsed_hash[:hadoop_kerberos_realm] if @parsed_hash[:hadoop_kerberos_realm]
          hiera_hash['kerberos_domain'] = @parsed_hash[:hadoop_kerberos_domain] if @parsed_hash[:hadoop_kerberos_domain]
        end
        #hadoop_eco_system
        if parsed_hash[:hadoop_deploy] != 'disabled'
          hadoop_ecosystem = parsed_hash[:hadoop_deploy][:hadoop_ecosystem]
          if hadoop_ecosystem
            hadoop_ecosystem.each do |tool|
              hiera_hash[tool] = 'enabled'
            end
          end
        end
        #kafka
        if parsed_hash[:kafka_deploy] != 'disabled'
          hiera_hash['kafak_hosts'] = Hash.new { |hash, key| hash[key] = {} }
          parsed_hash[:kafka_deploy][:kafka_brokers].each_with_index do |broker, id|
            hiera_hash['kafak_hosts'][broker] = { 'port' => 9092, 'id' => id + 1 }
          end
        end
        #storm
        if parsed_hash[:storm_deploy] != 'disabled'
          hiera_hash['storm_nimbus_host'] = parsed_hash[:storm_deploy][:storm_master]
          hiera_hash['storm_worker_count'] = parsed_hash[:storm_deploy][:workers_count]
        end
        #Write out hiera data to file and send it to puppet server
        YamlUtils.write_yaml(hiera_hash, HIERA_DATA_FILE)
        SshUtils.upload!(HIERA_DATA_FILE, '/tmp', @puppet_master, @ssh_user, @ssh_key, 22) unless @mock
        SshUtils.execute_ssh!(
          "sudo cp /tmp/common.yaml #{HIERA_DATA_PATH} && rm -rf /tmp/common.yaml",
          @puppet_master,
          @ssh_user,
          @ssh_key
          ) unless @mock
      end

      # Generate External Node Classifier data file used by the puppet's ENC script
      # @param [Hash] parsed_hash => hash from which to generate enc data
      # @param [Hash] puppet_nodes => puppet nodes hash
      def generate_enc(parsed_hash, puppet_nodes)
        puts "\rGenerating Enc roles to host mapping".blue
        if parsed_hash[:install_mode] == 'cloud'
          puppet_master = if parsed_hash[:cloud_platform] == 'aws'
                            find_pip_for_tag(@nodes, 'controller').first
                          elsif parsed_hash[:cloud_platform] == 'rackspace'
                            find_key_for_tag(@nodes, 'controller').first
                          end
          puppet_clients = if parsed_hash[:cloud_platform] == 'aws'
                              puppet_master_tag = @nodes.map { |k, v| 
                                  k if v[:private_ip] == puppet_master 
                                }.compact.first
                              @nodes.except(puppet_master_tag).map { |k, v| v[:private_ip] }
                           elsif parsed_hash[:cloud_platform] == 'rackspace'
                              @nodes.except(puppet_master).keys
                           end
          Inventory::EncData.new(puppet_nodes, ENC_ROLES_FILE, parsed_hash, puppet_master, puppet_clients).generate
        else
          Inventory::EncData.new(puppet_nodes, ENC_ROLES_FILE, parsed_hash, @puppet_master, @puppet_clients).generate
        end
      end

      # Force run all puppet client instances without checking puppet last_run_status
      def run!
        puppet_run_cmd = "sudo sh -c 'puppet agent --onetime --verbose --no-daemonize --no-splay --ignorecache" + 
                         " --no-usecacheonfailure --logdest #{REMOTE_LOG_DIR}/puppet_run.log'"
        if ! @mock
          # send enc_data and enc_script to puppet server
          SshUtils.upload!(ENC_ROLES_FILE, '/tmp', @puppet_master, @ssh_user, @ssh_key, 22)
          SshUtils.upload!(ENC_SCRIPT, '/tmp', @puppet_master, @ssh_user, @ssh_key, 22)
          SshUtils.execute_ssh_cmds(
            ["sudo mv /tmp/roles.yaml #{ENC_PATH}",
             "sudo mv /tmp/ankus_puppet_enc #{ENC_PATH}"],
            @puppet_master,
            @ssh_user,
            @ssh_key,
            22,
            @debug
          )
        end
        puppet_parallel_run(@puppet_clients, puppet_run_cmd, 'all nodes', true)
      end

      # Kick off puppet run on all instances orchestrate runs based on configuration
      def run(force=false)
        puppet_run_cmd = "sudo sh -c 'puppet agent --onetime --verbose --no-daemonize --no-splay --ignorecache" + 
                         " --no-usecacheonfailure --logdest #{REMOTE_LOG_DIR}/puppet_run.log'"
        if ! @mock
          # send enc_data and enc_script to puppet server
          SshUtils.upload!(ENC_ROLES_FILE, '/tmp', @puppet_master, @ssh_user, @ssh_key, 22)
          SshUtils.upload!(ENC_SCRIPT, '/tmp', @puppet_master, @ssh_user, @ssh_key, 22)
          SshUtils.execute_ssh_cmds(
            ["sudo mv /tmp/roles.yaml #{ENC_PATH}",
             "sudo mv /tmp/ankus_puppet_enc #{ENC_PATH}"],
            @puppet_master,
            @ssh_user,
            @ssh_key,
            22,
            @debug
          )
        end
        #
        # => initialize puppet run in order
        #
        controller        = @parsed_hash[:controller]
        hadoop_install    = @parsed_hash[:hadoop_deploy]
        hadoop_ha         = @parsed_hash[:hadoop_deploy][:hadoop_ha] if @parsed_hash[:hadoop_deploy] != 'disabled'
        hbase_install     = @parsed_hash[:hbase_deploy]
        cassandra_install = @parsed_hash[:cassandra_deploy]
        kafka_install     = @parsed_hash[:kafka_deploy]
        storm_install     = @parsed_hash[:storm_deploy]

        if controller == 'localhost'
          puts "\rInitializing puppet run on controller".blue
          if ! @mock
            ShellUtils.run_cmd!(puppet_run_cmd)
            @nodes[find_key_for_fqdn(@nodes, 'localhost')][:puppet_run_status] = 'success'
            @nodes[find_key_for_fqdn(@nodes, 'localhost')][:last_run] = Time.now.to_i
            YamlUtils.write_yaml(@nodes, NODES_FILE)
          end
        else
          puppet_single_run(@puppet_master, puppet_run_cmd, 'controller', force)
        end

        if hadoop_ha == 'enabled' or hbase_install != 'disabled' or kafka_install != 'disabled' or 
          storm_install != 'disabled'
            #parallel puppet run on zks
            puppet_parallel_run(@parsed_hash[:zookeeper_quorum], puppet_run_cmd, 'zookeepers', force)
        end

        if hadoop_install != 'disabled'
          # if ha or hbase,
            # init puppet agent on zookeepers
          if hadoop_ha == 'enabled'
            if @parsed_hash[:hadoop_deploy][:journal_quorum]
              #parallel puppet run on jns
              puppet_parallel_run(@parsed_hash[:hadoop_deploy][:journal_quorum], puppet_run_cmd, 'journalnodes', force)
            end
            # puppet run on nns
            puppet_single_run(@parsed_hash[:hadoop_deploy][:hadoop_namenode].first, puppet_run_cmd, 'active_namenode',
              force)
            puppet_single_run(@parsed_hash[:hadoop_deploy][:hadoop_namenode].last, puppet_run_cmd, 'standby_namenode',
              force)
            #
            # => VENDOR_BUG:
            # parallel run breaks beacuse namenode2 should copy namenode1 dfs.name.dir contents which only happens 
            # after namenode1 is bootstrapped, caused beacuse of Bug 'HDFS-3752'
            # puppet_parallel_run(@parsed_hash['hadoop_namenode'], puppet_run_cmd, 'namepuppet_clients')
            #
          else
            puppet_single_run(@parsed_hash[:hadoop_deploy][:hadoop_namenode].first, puppet_run_cmd, 'namenode', force)
          end
          if hbase_install != 'disabled'
            hbase_master = @parsed_hash[:hbase_deploy][:hbase_master]
            if hbase_master.length == 1
              puts "\rInitializing hbase master"
              puppet_single_run(hbase_master.join, puppet_run_cmd, 'hbasemaster', force)
            else
              puppet_parallel_run(hbase_master, puppet_run_cmd, 'hbasemasters', force)
            end
          end

          # init puppet agent on mapreduce master
          if @parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
            puppet_single_run(@parsed_hash[:hadoop_deploy][:mapreduce][:master], puppet_run_cmd, 'mapreduce_master',
              force)
          else
            #mapreduce is disabled for cloud_deployments, snn will be on diff machine
            unless hadoop_ha == 'enabled'
              puppet_single_run(@parsed_hash[:hadoop_deploy][:hadoop_secondarynamenode], 
                puppet_run_cmd, 
                'secondary_namenode',
                force
              )
            end
          end
        end

        # Storm Nimbus
        if storm_install != 'disabled'
          puppet_single_run(@parsed_hash[:storm_deploy][:storm_master], puppet_run_cmd, 'storm_nimbus', force)
        end

        # Cassandra
        if cassandra_install != 'disabled' and ! @parsed_hash[:cassandra_deploy][:colocation]
          cassandra_seeds = @parsed_hash[:cassandra_deploy][:cassandra_seeds]
          cassandra_nodes = @parsed_hash[:cassandra_deploy][:cassandra_nodes]
          puppet_parallel_run(cassandra_seeds, puppet_run_cmd, 'cassandra_seed_node', force)
          puppet_parallel_run(cassandra_nodes, puppet_run_cmd, 'cassandra', force)
        elsif cassandra_install != 'disabled' and @parsed_hash[:cassandra_deploy][:colocation]
          if cassandra_install != 'disabled'
            puppet_parallel_run(@parsed_hash[:cassandra_deploy][:cassandra_seeds], 
              puppet_run_cmd, 
              'cassandra_seed_node',
              force
            )
          end
        end

        #Kafka
        if kafka_install != 'disabled' and ! @parsed_hash[:kafka_deploy][:colocation]
          puppet_parallel_run(@parsed_hash[:kafka_deploy][:kafka_brokers], puppet_run_cmd, 'kafka_brokers', force)
        end

        #Storm
        if storm_install != 'disabled' and ! @parsed_hash[:storm_deploy][:colocation]
          puppet_parallel_run(@parsed_hash[:storm_deploy][:storm_supervisors], puppet_run_cmd, 'kafka_worker', force)
        end

        # All hadoop & hbase slaves
        if hadoop_install != 'disabled' or hbase_install != 'disabled'
          puppet_parallel_run(@parsed_hash[:slave_nodes], puppet_run_cmd, 'slaves', force)
        end

        # hbasemasters need service refresh after region servers came online
        if @parsed_hash[:hbase_deploy] != 'disabled'
          puts "\r[Info]: Triggering refresh on hbase master(s) ..."
          hbase_master = @parsed_hash[:hbase_deploy][:hbase_master]
          if hbase_master.length == 1
            puts "\rInitializing hbase master"
            puppet_single_run(hbase_master.join, puppet_run_cmd, 'hbasemaster', force)
          else
            puppet_parallel_run(hbase_master, puppet_run_cmd, 'hbasemasters', force)
          end
        end

        # finalize puppet run on controller to refresh nagios
        if @parsed_hash[:alerting] == 'enabled'
          puts "\r[Info]: Triggering refresh on controller ..."
          if controller == 'localhost'
            unless @mock
              status = ShellUtils.run_cmd!(puppet_run_cmd)
              unless status.success?
                puts "\r[Error]:".red + ' Failed to finalize puppet run'
                #TODO handle rollback
              end
            end
          else
            puppet_single_run(@puppet_master, puppet_run_cmd, 'controller', force)
          end
        end
      end # Puppet.run

      private

      # Runs puppet on single instance
      # @param [String] instance => node on which puppet should be run
      # @param [String] puppet_run_cmd => command to run on remote client to run puppet
      # @param [String] role => role installing on remote client
      def puppet_single_run(instance, puppet_run_cmd, role, force=false)
        unless @mock
          unless @debug
            SpinningCursor.start do
              banner "\rInitializing " + "#{role}".blue + " on " + "#{instance} ".blue
              type :dots
              message "\rInitializing #{role} on " + "#{instance} ".blue + '[DONE]'.cyan
            end
          else
            puts "\rInitializing #{role} on " + "#{instance}".blue
          end
          #
          # run puppet only if the previous state it 'not_run(false)' or 'failed'
          #
          puppet_run_status = @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status]
          if force || !puppet_run_status || puppet_run_status == 'failed'
            output = SshUtils.execute_ssh!(
                puppet_run_cmd,
                instance,
                @ssh_user,
                @ssh_key,
                22,
                @debug
            )
            exit_status = output[instance][2].to_i
            unless exit_status == 0
              puts "\r[Error]: ".red + "Puppet run failed on #{instance}!, " + 
                   "Try checking the log @ '/var/log/ankus/puppet_run.log' on #{instance}"
              #exit 1
              # TODO Rollback lock
              @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status] = 'failed'
            else
              # add status to nodes hash
              @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status] = 'success'
              @nodes[find_key_for_fqdn(@nodes, instance)][:last_run] = Time.now.to_i
            end            
          end
          unless @debug
            SpinningCursor.stop
          else
            puts "\rCompleted puppet run on" + " #{instance}".blue if @debug
          end
        else
          puppet_run_status = @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status]
          if force || !puppet_run_status || puppet_run_status == 'failed'          
            puts "\rInitializing " + "#{role}".blue + " on " + "#{instance} ".blue
            @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status] = 'success'
            @nodes[find_key_for_fqdn(@nodes, instance)][:last_run] = Time.now.to_i          
          end
        end
        YamlUtils.write_yaml(@nodes, NODES_FILE) # Update nodes files with puppet run info
      end # Puppet.puppet_single_run

      # Runs puppet on instances in parallel using thread pool
      # @param [Array] instances_array => list of instances on which puppet should be run in parallel
      # @param [String] puppet_run_cmd => command to run on remote client to run puppet
      # @param [String] role => role installing on remote client
      def puppet_parallel_run(instances_array, puppet_run_cmd, role, force=false)
        if ! @mock
          SpinningCursor.start do
            banner "\rInitializing " + "#{role}".blue + " on client(s) " + "#{instances_array.join(',')} ".blue
            type :dots
            message "\rInitializing " + "#{role}".blue + " on client(s) " + "#{instances_array.join(',')} ".blue + 
                    '[DONE]'.cyan
            output :at_stop
          end
          # initiate concurrent threads pool - to install puppet clients all agent puppet_clients
          ssh_connections = ThreadPool.new(@parallel_connections)
          output = []
          time = Benchmark.measure do
            instances_array.each do |instance|
              ssh_connections.schedule do
                # run puppet installer only if the previous puppet run 'failed' or ænot_run'
                puppet_run_status = @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status]
                if force || !puppet_run_status || puppet_run_status == 'failed'
                  output << SshUtils.execute_ssh!(
                      puppet_run_cmd,
                      instance,
                      @ssh_user,
                      @ssh_key,
                      22,
                      false
                    )
                end # if
              end # ssh_connections.schedule
            end # each block
            ssh_connections.shutdown
          end
          puts "\r[Debug]: Time to run puppet on clients: #{time}" if @debug
          output.each do |o|
            instance = o.keys[0]
            exit_status = o[instance][2].to_i
            unless exit_status == 0
              puts "\r[Error]: ".red + "Puppet run failed on #{instance}!, " + 
                   "Try checking the log @ '/var/log/ankus/puppet_run.log' on #{instance}"              
              @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status] = 'failed'
            else
              # add status to nodes hash
              @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status] = 'success'
              @nodes[find_key_for_fqdn(@nodes, instance)][:last_run] = Time.now.to_i              
            end
          end
          if @debug
            output.each do |o|
              instance = o.keys[0]
              puts "\r[Debug]: Stdout on #{instance}"
              puts "\r#{o[instance][0]}"
              puts "\r[Debug]: Stderr on #{instance}"
              puts "\r#{o[instance][1]}"
              puts "\r[Debug]: (Error) Puppet run failed on #{instance}" unless o[instance][2].to_i == 0
            end
          end
          SpinningCursor.stop
        else
          instances_array.each do |instance|
            puppet_run_status = @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status]
            if force || !puppet_run_status || puppet_run_status == 'failed'
              puts "\rInitializing " + "#{role}".blue + " on client " + "#{instance}".blue
              @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status] = 'success'
              @nodes[find_key_for_fqdn(@nodes, instance)][:last_run] = Time.now.to_i
            end
          end
        end
        YamlUtils.write_yaml(@nodes, NODES_FILE)
      end # Puppet.puppet_parallel_run

      # Checks if instances are listening in ssh port by default 22
      # @param [Array] instances => list of instances to check
      # @param [Integer] port => port on which ssh is listening (default: 22)
      def validate_instances(instances, port=22)
        if instances.is_a?(String)
          unless PortUtils.port_open? instances, port
            puts "\r[Error]: Node #{instances} is not reachable on port #{port} for ssh"
            exit 1
          end
        else
          instances.each do |instance|
            unless PortUtils.port_open? instance, port
              puts "\r[Error]: Node #{instance} is not reachable on port #{port} for ssh"
              exit 1
            end
          end          
        end
      end # Puppet.validate_instances

      # Perform pre-requisite operations (creates log directories and copies over the puppet installer script)
      # before even installing puppet agent
      # @param [String] instances => instance on which preq should be performed
      # @param [String] remote_puppet_loc => location to where puppet installer script should be copied to
      def preq(instance, remote_puppet_loc, hosts_file = nil)
        puts "\rPreforming preq operations on all instance #{instance}" if @debug
        cmds =  ["sudo sh -c 'mkdir -p #{REMOTE_LOG_DIR}'",
                 "sudo sh -c 'touch #{REMOTE_LOG_DIR}/install.log'",
                 "sudo sh -c 'touch #{REMOTE_LOG_DIR}/puppet_run.log'"
        ]
        cmds << "sudo sh -c 'cp /etc/hosts /etc/hosts_backup.backup'" if hosts_file

        SshUtils.execute_ssh_cmds(
            cmds,
            instance,
            @ssh_user,
            @ssh_key,
            22, false)

        puts "\r[Debug]: Sending puppet installer script to #{instance}" if @debug
        SshUtils.upload!(PUPPET_INSTALLER, remote_puppet_loc, instance, @ssh_user, @ssh_key)
        if hosts_file
          puts "\r[Debug]: Sending hosts file to #{instance}" if @debug
          SshUtils.upload!(hosts_file, '/tmp/hosts', instance, @ssh_user, @ssh_key)
          SshUtils.execute_ssh!(
            "sudo mv /tmp/hosts /etc && chmod 644 /etc/hosts",
            instance,
            @ssh_user,
            @ssh_key
          )
        end
      end # Puppet.preq

      # Performs clean up actions (remove puppet installer script) after deployment
      # @param [String] instance => instance on which to perform cleanup
      def cleanup(instance)
        puts "\rPreforming Cleanup operations on instance: #{instance}" if @debug        
        SshUtils.execute_ssh_cmds(
            ["rm -rf /tmp/#{@puppet_installer}"],
            instance,
            @ssh_user,
            @ssh_key,
            22,
            false
        )
      end # Puppet.cleanup
    end # Puppet
  end # Deploy
end # Ankus
