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
      # @param [Log4r] log => logger object to use for logging
      # @param [Integer] ssh_connections => number of concurrent processes (threads) to use for deployments
      # @param [String] ssh_user => user to log into the machine as
      # @param [Boolean] debug => if enabled will print out information to stdout
      def initialize(nodes, ssh_key, parsed_hash, log, ssh_connections=10, ssh_user='root',
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
        @log                   = log
        @debug                 = debug
        @mock                  = mock
      end

      # Installs puppet server on node with tag 'controller' and puppet agent(s) on other nodes
      # @param [String] installer_path => path where the puppet installer is located on remote machines
      def install(installer_path='/tmp')
        remote_puppet_server_cmd    = "chmod +x #{installer_path}/#{@puppet_installer} &&" +
            " sudo sh -c '#{installer_path}/#{@puppet_installer} -s -d -p -a -w | tee #{REMOTE_LOG_DIR}/install.log'"
        remote_puppet_client_cmd    =  # assign the command to install puppet client based on the install_mode
          if @parsed_hash[:install_mode] == 'local'
            "chmod +x #{installer_path}/#{@puppet_installer} &&" +
            " sudo sh -c '#{installer_path}/#{@puppet_installer} -c -H #{@puppet_master} |" +
            " tee #{REMOTE_LOG_DIR}/install.log'"
          else
            puppet_server_cloud_fqdn =  if @parsed_hash[:cloud_platform] == 'aws'
                                          find_pip_for_tag(@nodes, 'controller').first
                                        elsif @parsed_hash[:cloud_platform] == 'rackspace'
                                          find_key_for_tag(@nodes, 'controller').first
                                        end
            "chmod +x #{installer_path}/#{@puppet_installer} &&" +
            " sudo sh -c '#{installer_path}/#{@puppet_installer} -c -H #{puppet_server_cloud_fqdn} |" +
            " tee #{REMOTE_LOG_DIR}/install.log'"
          end

        if ! @mock
          #
          # Puppet Server
          #
          puppet_server_tag = find_key_for_fqdn(@nodes, @puppet_master)
          unless @nodes[puppet_server_tag][:puppet_install_status]
            validate_instances @puppet_master
            @log.info "Checking if puppet server is ssh'able ..."
            SshUtils.sshable? @puppet_master, @ssh_user, @ssh_key
            @log.info "Checking if puppet server is ssh'able ... " + '[OK]'.green
            @parsed_hash[:cloud_platform] == 'rackspace' ?
              preq(@puppet_master, installer_path, @hosts_file) :
              preq(@puppet_master, installer_path)
            @log.info 'Installing puppet master on ' + "#{@puppet_master}".blue + ' ...'
            @log.debug "Found puppet installer script at #{PUPPET_INSTALLER}" if @debug
            # if controller is on same machine, install puppet master locally else send the script to controller
            # and install puppet
            if @parsed_hash[:controller] == 'localhost'
              status = ShellUtils.run_cmd_with_log!(
                  "chmod +x #{PUPPET_INSTALLER} && sudo sh -c '#{PUPPET_INSTALLER} -s'",
                  "#{REMOTE_LOG_DIR}/install.log"
              )
              unless status.success?
                @log.error ' Failed to install puppet master'
                exit 2
                # TODO: handle rollback
              end
            else
              @log.debug "Sending file #{PUPPET_INSTALLER} to #{@puppet_master}" if @debug
              SshUtils.upload!(PUPPET_INSTALLER, installer_path, @puppet_master, @ssh_user, @ssh_key)
              master_output = SshUtils.execute_ssh!(
                  remote_puppet_server_cmd,
                  @puppet_master,
                  @ssh_user,
                  @ssh_key,
                  @log,
                  22,
                  @debug
              )
              unless master_output[@puppet_master][2].to_i == 0
                @log.error 'Failed to install puppet master'
                exit 2
              end
            end
            @nodes[puppet_server_tag][:puppet_install_status] = true
            cleanup(@puppet_master)
            @log.info 'Installing puppet master on ' + "#{@puppet_master}".blue + ' [DONE]'.cyan
          end

          #
          # Puppet Clients
          #
          # initiate concurrent threads pool - to install puppet clients all agent puppet_clients
          time = Benchmark.measure do
            ssh_connections = ThreadPool.new(@parallel_connections)
            validate_instances @puppet_clients
            @clients_output = []
            @nodes.except(puppet_server_tag).each do |_, node_info|
              @log.info 'Installing puppet agents on all nodes ...'
              unless node_info[:puppet_install_status] # Only install puppet if not already installed
                @parsed_hash[:cloud_platform] == 'rackspace' ?
                    preq(node_info[:fqdn], installer_path, @hosts_file) :
                    preq(node_info[:fqdn], installer_path)
                ssh_connections.schedule do
                  @clients_output << SshUtils.execute_ssh!(
                      remote_puppet_client_cmd,
                      node_info[:fqdn],
                      @ssh_user,
                      @ssh_key,
                      @log
                  )
                  node_info[:puppet_install_status] = true #set that installing succeeded
                  cleanup(node_info[:fqdn])
                end # ssh_connections
              end # if
            end # @nodes
            ssh_connections.shutdown
            @log.info 'Installing puppet agents on all nodes ...' + ' [DONE]'.cyan
          end # benchmark        
          @log.debug "Time to install puppet clients: #{time}" if @debug
          #print output of puppet client installers on console
          if @debug
            @clients_output.each do |o|
              @log.debug 'STDOUT'.blue + " on #{o.keys.join}"
              puts "\r#{o.values.first[0]}" if o.values.first[0]
              unless o.values.first[1].empty?
                @log.debug 'STDERR'.yellow + " on #{o.keys.join}"
                puts "\r#{o.values.first[1]}"
              end
            end
          end 
        else
          #
          # MOCKING
          #
          @log.info 'Checking if instances are ssh\'able ...'
          @log.info 'Checking if instances are ssh\'able ...' + '[OK]'.green.bold
          puppet_server_tag = find_key_for_fqdn(@nodes, @puppet_master)
          unless @nodes[puppet_server_tag][:puppet_install_status]
            @log.info 'Installing puppet master on ' + "#{@puppet_master}".blue + ' ...'
            @log.debug "Using command: #{remote_puppet_server_cmd}" if @debug
            @log.info "Installing puppet master on #{@puppet_master}" + ' ...' + ' [DONE]'.cyan
            @nodes[puppet_server_tag][:puppet_install_status] = true
          end
          ssh_connections = ThreadPool.new(@parallel_connections)
          @log.info 'Installing puppet agents on all nodes ...'
          @log.debug "Using command: #{remote_puppet_client_cmd}" if @debug
          @nodes.except(puppet_server_tag).each do |node, node_info|
            if ! node_info[:puppet_install_status]
              ssh_connections.schedule do
                @log.info 'Installing puppet agent on client ' + "#{node_info[:fqdn]}".blue
                node_info[:puppet_install_status] = true
              end
            end
          end
          ssh_connections.shutdown
        end # if ! @mock
        YamlUtils.write_yaml(@nodes, NODES_FILE)
        @log.info 'Installing puppet on all nodes ...' + ' [DONE]'.cyan
      end # install

      # Generate hiera data required by puppet deployments & writes out to the yaml file
      # @param [Hash] parsed_hash => hash from which to generate hiera data
      def generate_hiera(parsed_hash)
        hiera_hash = {}
        # generate hiera data to local data folder first
        @log.info 'Generating hiera data required for puppet'
        # aggregate hadoop, hbase, all other related configurations in here into a common hash before writing out
        hiera_hash.merge!(parsed_hash.deep_stringify)
        hiera_hash.merge!(YamlUtils.parse_yaml(HADOOP_CONF))    if parsed_hash[:hadoop_deploy] != 'disabled'
        hiera_hash.merge!(YamlUtils.parse_yaml(HBASE_CONF))     if parsed_hash[:hbase_deploy] != 'disabled'
        hiera_hash.merge!(YamlUtils.parse_yaml(CASSANDRA_CONF)) if parsed_hash[:cassandra_deploy] != 'disabled'

        if parsed_hash[:hadoop_deploy] != 'disabled' or parsed_hash[:hbase_deploy] != 'disabled'
          #parse zookeeper ensemble
          if parsed_hash[:zookeeper_deploy] && parsed_hash[:zookeeper_deploy] != 'disabled'
            hiera_hash['zookeeper_ensemble'] = parsed_hash[:zookeeper_deploy][:quorum].map { |zk| zk += ":2181" }.join(",")
            hiera_hash['zookeeper_class_ensemble'] = parsed_hash[:zookeeper_deploy][:quorum].map { |zk| zk+=":2888:3888" }
          end
          #parse num_of_workers
          hiera_hash['number_of_nodes'] = parsed_hash[:worker_nodes].length
        end
        if parsed_hash[:kafka_deploy] != 'disabled' or 
            parsed_hash[:storm_deploy] != 'disabled' or 
            parsed_hash[:solr_deploy] != 'disabled'
          unless hiera_hash.has_key? 'zookeeper_ensemble'
            hiera_hash['zookeeper_ensemble'] = parsed_hash[:zookeeper_deploy][:quorum].map { |zk| zk += ":2181" }.join(",")
          end
          unless hiera_hash.has_key? 'zookeeper_class_ensemble'
            hiera_hash['zookeeper_class_ensemble'] = parsed_hash[:zookeeper_deploy][:quorum].map { |zk| zk+=":2888:3888" }
          end
        end
        # solr deploy
        if parsed_hash[:solr_deploy] != 'disabled'
          if parsed_hash[:solr_deploy][:hdfs_integration] == 'enabled'
            hiera_hash['hadoop_search_nodes'] = parsed_hash[:slave_nodes]
          end
        end
        #parse journal quorum
        if parsed_hash[:hadoop_deploy] != 'disabled'
          if parsed_hash[:hadoop_deploy][:ha] != 'disabled' and parsed_hash[:hadoop_deploy][:journal_quorum]
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
          hiera_hash['kerberos_realm'] = @parsed_hash[:kerberos_realm] if @parsed_hash[:kerberos_realm]
          hiera_hash['kerberos_domain'] = @parsed_hash[:kerberos_domain] if @parsed_hash[:kerberos_domain]
        end
        #hadoop_eco_system
        if parsed_hash[:hadoop_deploy] != 'disabled'
          hadoop_ecosystem = parsed_hash[:hadoop_deploy][:ecosystem]
          if hadoop_ecosystem
            hadoop_ecosystem.each do |tool|
              hiera_hash[tool] = 'enabled'
            end
          end
        end
        #kafka
        if parsed_hash[:kafka_deploy] != 'disabled'
          hiera_hash['kafka_hosts'] = Hash.new { |hash, key| hash[key] = {} }
          parsed_hash[:kafka_deploy][:brokers].each_with_index do |broker, id|
            hiera_hash['kafka_hosts'][broker] = { 'port' => 9092, 'id' => id + 1 }
          end
        end
        #storm
        if parsed_hash[:storm_deploy] != 'disabled'
          hiera_hash['storm_nimbus_host'] = parsed_hash[:storm_deploy][:master]
          hiera_hash['storm_worker_count'] = parsed_hash[:storm_deploy][:count]
        end
        # Write out hiera data to file and send it to puppet server
        if @mock
          @log.debug 'Hiera data'
          pp hiera_hash
        else
          YamlUtils.write_yaml(hiera_hash, HIERA_DATA_FILE)
          SshUtils.upload!(HIERA_DATA_FILE, '/tmp', @puppet_master, @ssh_user, @ssh_key, 22)
          SshUtils.execute_ssh!(
            "sudo cp /tmp/common.yaml #{HIERA_DATA_PATH} && rm -rf /tmp/common.yaml",
            @puppet_master,
            @ssh_user,
            @ssh_key,
            @log
            )
        end
      end

      # Generate External Node Classifier data file used by the puppet's ENC script
      # @param [Hash] parsed_hash => hash from which to generate enc data
      # @param [Hash] puppet_nodes => puppet nodes hash
      def generate_enc(parsed_hash, puppet_nodes)
        @log.info 'Generating Enc roles to host mapping'
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
          Inventory::EncData.new(puppet_nodes, ENC_ROLES_FILE, parsed_hash, puppet_master, puppet_clients, @log, @mock).generate
        else
          Inventory::EncData.new(puppet_nodes, ENC_ROLES_FILE, parsed_hash, @puppet_master, @puppet_clients, @log, @mock).generate
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
            @log,
            22,
            @debug
          )
        end
        puppet_parallel_run(@puppet_clients, puppet_run_cmd, 'all nodes', true)
      end

      # Kick off puppet run on all instances, orchestrate runs based on configuration
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
            @log,
            22,
            @debug
          )
        end
        #
        # => initialize puppet run in order
        #
        controller        = @parsed_hash[:controller]
        hadoop_install    = @parsed_hash[:hadoop_deploy]
        hadoop_ha         = @parsed_hash[:hadoop_deploy][:ha] if @parsed_hash[:hadoop_deploy] != 'disabled'
        hbase_install     = @parsed_hash[:hbase_deploy]
        cassandra_install = @parsed_hash[:cassandra_deploy]
        kafka_install     = @parsed_hash[:kafka_deploy]
        storm_install     = @parsed_hash[:storm_deploy]
        solr_install      = @parsed_hash[:solr_deploy]

        if controller == 'localhost'
          @log.info 'Initializing puppet run on controller'
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
          storm_install != 'disabled' or solr_install != 'disabled'
            #parallel puppet run on zks
            puppet_parallel_run(@parsed_hash[:zookeeper_deploy][:quorum], puppet_run_cmd, 'zookeepers', force)
        end

        if hadoop_install != 'disabled'
          # if ha or hbase,
            # init puppet agent on zookeepers
          if hadoop_ha == 'enabled'
            if @parsed_hash[:hadoop_deploy][:journal_quorum]
              #parallel puppet run on jns
              puppet_parallel_run(
                @parsed_hash[:hadoop_deploy][:journal_quorum], 
                puppet_run_cmd, 
                'journalnodes', 
                force)
            end
            # puppet run on nns
            puppet_single_run(
              @parsed_hash[:hadoop_deploy][:namenode].first,
              puppet_run_cmd, 
              'active_namenode',
              force)
            puppet_single_run(
              @parsed_hash[:hadoop_deploy][:namenode].last,
              puppet_run_cmd, 
              'standby_namenode',
              force)
            #
            # => VENDOR_BUG:
            # parallel run breaks because namenode2 should copy namenode1 dfs.name.dir contents which only happens 
            # after namenode1 is bootstrapped, caused beacuse of Bug 'HDFS-3752'
            # puppet_parallel_run(@parsed_hash['hadoop_namenode'], puppet_run_cmd, 'namepuppet_clients')
            #
          else
            puppet_single_run(
              @parsed_hash[:hadoop_deploy][:namenode].first,
              puppet_run_cmd, 
              'namenode', 
              force)
          end
          if hbase_install != 'disabled'
            hbase_master = @parsed_hash[:hbase_deploy][:master]
            if hbase_master.length == 1
              puts "\rInitializing hbase master"
              puppet_single_run(hbase_master.join, puppet_run_cmd, 'hbasemaster', force)
            else
              puppet_parallel_run(hbase_master, puppet_run_cmd, 'hbasemasters', force)
            end
          end

          # init puppet agent on mapreduce master
          if @parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
            puppet_single_run(
              @parsed_hash[:hadoop_deploy][:mapreduce][:master], 
              puppet_run_cmd, 
              'mapreduce_master',
              force)
          else
            #mapreduce is disabled for cloud_deployments, snn will be on diff machine
            unless hadoop_ha == 'enabled'
              puppet_single_run(
                @parsed_hash[:hadoop_deploy][:secondarynamenode],
                puppet_run_cmd, 
                'secondary_namenode',
                force)
            end
          end
        end

        # Storm Nimbus
        if storm_install != 'disabled'
          puppet_single_run(
            @parsed_hash[:storm_deploy][:master],
            puppet_run_cmd, 
            'storm_nimbus', 
            force)
        end

        # Cassandra
        if cassandra_install != 'disabled'
          cassandra_seeds = @parsed_hash[:cassandra_deploy][:seeds]
          cassandra_nodes = @parsed_hash[:cassandra_deploy][:nodes]
          puppet_parallel_run(cassandra_seeds, puppet_run_cmd, 'cassandra_seed_node', force)
          puppet_parallel_run(cassandra_nodes, puppet_run_cmd, 'cassandra', force)
        end

        #Kafka
        if kafka_install != 'disabled'
          puppet_parallel_run(
            @parsed_hash[:kafka_deploy][:kafka_brokers], 
            puppet_run_cmd, 
            'kafka_brokers', 
            force)
        end

        #Storm
        if storm_install != 'disabled'
          puppet_parallel_run(
            @parsed_hash[:storm_deploy][:storm_supervisors], 
            puppet_run_cmd, 
            'kafka_worker', 
            force)
        end

        # All hadoop & hbase slaves
        if hadoop_install != 'disabled' or hbase_install != 'disabled'
          if solr_install != 'disabled' # Solr hdfs integration
            puppet_single_run(@parsed_hash[:worker_nodes].first, puppet_run_cmd, 'solr_bootstrap', force)
          end
            puppet_parallel_run(@parsed_hash[:worker_nodes], puppet_run_cmd, 'slaves', force)
        end

        # hbasemasters need service refresh after region servers came online
        if @parsed_hash[:hbase_deploy] != 'disabled'
          @log.info 'Triggering refresh on hbase master(s) ...'
          hbase_master = @parsed_hash[:hbase_deploy][:master]
          if hbase_master.length == 1
            @log.info 'Initializing hbase master ...'
            puppet_single_run(hbase_master.join, puppet_run_cmd, 'hbasemaster', force)
          else
            puppet_parallel_run(hbase_master, puppet_run_cmd, 'hbasemasters', force)
          end
        end

        # finalize puppet run on controller to refresh nagios
        if @parsed_hash[:alerting] == 'enabled'
          @log.info 'Triggering refresh on controller ...'
          if controller == 'localhost'
            unless @mock
              status = ShellUtils.run_cmd!(puppet_run_cmd)
              unless status.success?
                @log.error 'Failed to finalize puppet run'
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
      # @param [Boolean] force => specifies whether to run puppet even if puppet has run previosly with out any errors
      def puppet_single_run(instance, puppet_run_cmd, role, force=false)
        unless @mock
          @log.info 'Initializing ' + "#{role}".blue + ' on ' + "#{instance} ".blue
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
                @log,
                22,
                @debug
            )
            exit_status = output[instance][2].to_i
            unless exit_status == 0
              @log.error "Puppet run failed on #{instance}!, " +
                   "Try checking the log @ '/var/log/ankus/puppet_run.log' on #{instance}"
              # exit 1
              # TODO Rollback lock
              @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status] = 'failed'
            else
              # add status to nodes hash
              @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status] = 'success'
              @nodes[find_key_for_fqdn(@nodes, instance)][:last_run] = Time.now.to_i
            end            
          end
          @log.info 'Completed puppet run on ' + "#{instance} ".blue
        else
          puppet_run_status = @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status]
          if force || !puppet_run_status || puppet_run_status == 'failed'          
            @log.info 'Initializing ' + "#{role}".blue + ' on ' + "#{instance} ".blue
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
      # @param [Boolean] force => specifies whether to run puppet even if puppet has run previosly with out any errors
      def puppet_parallel_run(instances_array, puppet_run_cmd, role, force=false)
        if ! @mock
          @log.info 'Initializing ' + "#{role}".blue + ' on client(s) ' + "#{instances_array.join(',')} ".blue + ' ...'
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
                      @log,
                      22,
                      false
                    )
                end # if
              end # ssh_connections.schedule
            end # each block
            ssh_connections.shutdown
          end
          @log.debug "Time to run puppet on clients: #{time}" if @debug
          output.each do |o|
            instance = o.keys[0]
            exit_status = o[instance][2].to_i
            unless exit_status == 0
              @log.error "Puppet run failed on #{instance}!, " +
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
              @log.debug "Stdout on #{instance}"
              puts "\r#{o[instance][0]}"
              @log.debug "Stderr on #{instance}"
              puts "\r#{o[instance][1]}"
              @log.error "Puppet run failed on #{instance}" unless o[instance][2].to_i == 0
            end
          end
          @log.info 'Initializing ' + "#{role}".blue + ' on client(s) ' + "#{instances_array.join(',')} ".blue + '[DONE]'.cyan

        else
          instances_array.each do |instance|
            puppet_run_status = @nodes[find_key_for_fqdn(@nodes, instance)][:puppet_run_status]
            if force || !puppet_run_status || puppet_run_status == 'failed'
              @log.info 'Initializing ' + "#{role}".blue + ' on client ' + "#{instance}".blue
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
            @log.error "Node #{instances} is not reachable on port #{port} for ssh"
            exit 1
          end
        else
          instances.each do |instance|
            unless PortUtils.port_open? instance, port
              @log.error "Node #{instance} is not reachable on port #{port} for ssh"
              exit 1
            end
          end          
        end
      end # Puppet.validate_instances

      # Perform pre-requisite operations (creates log directories and copies over the puppet installer script)
      # before even installing puppet agent
      # @param [String] instance => instance on which preq should be performed
      # @param [String] remote_puppet_loc => location to where puppet installer script should be copied to
      # @param [String] hosts_file => hosts file to use
      def preq(instance, remote_puppet_loc, hosts_file = nil)
        @log.debug "Preforming preq operations on instance #{instance}" if @debug
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
            @log,
            22, false)

        @log.debug "Sending puppet installer script to #{instance}" if @debug
        SshUtils.upload!(PUPPET_INSTALLER, remote_puppet_loc, instance, @ssh_user, @ssh_key)
        if hosts_file
          @log.debug "Sending hosts file to #{instance}" if @debug
          SshUtils.upload!(hosts_file, '/tmp/hosts', instance, @ssh_user, @ssh_key)
          SshUtils.execute_ssh!(
            'sudo mv /tmp/hosts /etc && chmod 644 /etc/hosts',
            instance,
            @ssh_user,
            @ssh_key,
            @log
          )
        end
      end # Puppet.preq

      # Performs clean up actions (remove puppet installer script) after deployment
      # @param [String] instance => instance on which to perform cleanup
      def cleanup(instance)
        @log.debug "Preforming Cleanup operations on instance: #{instance}" if @debug
        SshUtils.execute_ssh_cmds(
            ["rm -rf /tmp/#{@puppet_installer}"],
            instance,
            @ssh_user,
            @ssh_key,
            @log,
            22,
            false
        )
      end # Puppet.cleanup
    end # Puppet
  end # Deploy
end # Ankus
