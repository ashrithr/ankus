module Ankuscli
  module Deploy
    require 'benchmark'
    require 'ankuscli/helper'
    include Ankuscli

    # Class to manage puppet deployments
    class Puppet

      # @param [String] puppet_server => hostname of the puppet server
      # @param [Array] puppet_clients => host_names of puppet clients
      #        [String] puppet_clients => host_name of puppet client to install puppet client on it
      # @param [String] ssh_key => ssh key to use to log into the machines
      # @param [Hash] parsed_hash => parsed configuration file
      # @param [Integer] ssh_connections => number of concurrent processes (threads) to use for deployments
      # @param [String] ssh_user => user to log into the machine as
      # @param [Boolean] debug => if enabled will print out information to stdout
      def initialize(puppet_server, puppet_clients, ssh_key, parsed_hash, ssh_connections=10, ssh_user='root', debug=false, mock = false, hosts_file = nil)
        @puppet_master         = puppet_server
        @nodes                 = puppet_clients
        @parallel_connections  = ssh_connections
        @ssh_user              = ssh_user
        @ssh_key               = ssh_key
        @puppet_installer      = File.basename(PUPPET_INSTALLER)
        @parsed_hash           = parsed_hash
        @hosts_file            = hosts_file
        @debug                 = debug
        @mock                  = mock
      end

      # Installs puppet server on @puppet_master and puppet agent daemons on @nodes
      def install_puppet
        #helper variables
        remote_puppet_installer_loc = '/tmp'
        remote_puppet_server_cmd = "chmod +x #{remote_puppet_installer_loc}/#{@puppet_installer} && #{remote_puppet_installer_loc}/#{@puppet_installer} -s | tee #{REMOTE_LOG_DIR}/install.log"
        remote_puppet_client_cmd = "chmod +x #{remote_puppet_installer_loc}/#{@puppet_installer} && #{remote_puppet_installer_loc}/#{@puppet_installer} -c -H #{@puppet_master} | tee #{REMOTE_LOG_DIR}/install.log"
        if ! @mock
          #check if instances are up
          validate_instances @nodes
          all_nodes = []
          @nodes.each do |node|
            all_nodes << node
          end
          all_nodes << @puppet_master
          #check if instances are sshable
          puts "\rChecking if instances are ssh'able ..."
          SshUtils.sshable? @nodes, @ssh_user, @ssh_key
          # if puppet master is not localhost check if the instance is sshable?
          SshUtils.sshable? @puppet_master, @ssh_user, @ssh_key if @parsed_hash['install_mode'] == 'local'
          puts "\rChecking if instances are ssh'able ... " + '[OK]'.green.bold
          #get the puppet server hostname this is required for cloud, for aws to get internal_dns_name of host for accurate communication
          if @parsed_hash['install_mode'] == 'cloud'
            result = SshUtils.execute_ssh!('hostname --fqdn', @puppet_master, @ssh_user, @ssh_key)
            @puppet_server_cloud_fqdn = result[@puppet_master][0].chomp # result[host][0]
            remote_puppet_client_cmd = "chmod +x #{remote_puppet_installer_loc}/#{@puppet_installer} && #{remote_puppet_installer_loc}/#{@puppet_installer} -c -H #{@puppet_server_cloud_fqdn} | tee #{REMOTE_LOG_DIR}/install.log"
          end
          #perform preq's
          if @parsed_hash['cloud_platform'] == 'rackspace'
            preq(all_nodes, remote_puppet_installer_loc, @hosts_file)
          else
            preq(all_nodes, remote_puppet_installer_loc)
          end
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
          #if controller is on same machine, install puppet master locally else send the script to controller and install
          #puppet
          if @parsed_hash['controller'] == 'localhost'
            status = ShellUtils.run_cmd_with_log!(
                "chmod +x #{PUPPET_INSTALLER} && #{PUPPET_INSTALLER} -s",
                "#{REMOTE_LOG_DIR}/install.log"
            )
            unless status.success?
              puts "\r[Error]:".red + ' Failed to install puppet master'
              exit 2
              #TODO handle rollback
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
          SpinningCursor.stop unless @debug
          #initiate concurrent threads pool - to install puppet clients all agent nodes
          ssh_connections = ThreadPool.new(@parallel_connections)
          SpinningCursor.start do
            banner "\rInstalling puppet agents on clients ".blue
            type :dots
            message "\rInstalling puppet agents on clients ".blue + '[DONE]'.cyan
          end
          clients_output = [] # [ { 'host1' => ['stdout', 'stderr', 'exit_code'] }, { 'host2' => ['stdout', 'stderr', 'exit_code'] }, ... ]
          time = Benchmark.measure do
            @nodes.each do |instance|
              ssh_connections.schedule do
                #run puppet installer
                clients_output << SshUtils.execute_ssh!(
                    remote_puppet_client_cmd,
                    instance,
                    @ssh_user,
                    @ssh_key
                    )
                #puts "Thread #{Thread.current[:id]} finished"
              end
            end
            ssh_connections.shutdown
          end
          SpinningCursor.stop
          puts "\r[Debug]: Time to install puppet clients: #{time}" if @debug
          #print output of puppet client installers on console
          if @debug
            clients_output.each do |o|
              puts "\rSTDOUT".blue + " on #{o.keys.join}"
              puts "\r#{o.values.first[0]}"
              unless o.values.first[1].empty?
                puts "\rSTDERR".yellow + " on #{o.keys.join}"
                puts "\r#{o.values.first[1]}"
              end
            end
          end
          #clean up puppet installer script on all nodes
          cleanup(all_nodes)
        else
          #MOCKING
          puts 'Checking if instances are ssh\'able ...'
          puts 'Checking if instances are ssh\'able ...' + '[OK]'.green.bold
          SpinningCursor.start do
            banner "\rInstalling puppet master on #{@puppet_master}".blue
            type :dots
            action do
              sleep 3
            end
            message "\rInstalling puppet master on #{@puppet_master}".blue + '[DONE]'.cyan
          end
          SpinningCursor.start do
            banner "\rInstalling puppet agents on clients ".blue
            type :dots
            action do
              puts "Puppet clients: #{@nodes.join(',')}"
              sleep 3
            end
            message "\rInstalling puppet agents on clients  ".blue + '[DONE]'.cyan
          end
        end
        puts "\rInstalling puppet on all nodes completed".blue
      end

      # Install only puppet client(s)
      def install_puppet_clients
        remote_puppet_installer_loc = "/tmp"
        remote_puppet_client_cmd = "chmod +x #{remote_puppet_installer_loc}/#{@puppet_installer} && #{remote_puppet_installer_loc}/#{@puppet_installer} -c -H #{@puppet_master} | tee #{REMOTE_LOG_DIR}/install.log"
        if ! @mock
          validate_instances @nodes

          puts "\rChecking if instances are ssh'able ..."
          SshUtils.sshable? @nodes, @ssh_user, @ssh_key
          puts "\rChecking if instances are ssh'able ... " + '[OK]'.green.bold

          if @parsed_hash['install_mode'] == 'cloud'
            result = SshUtils.execute_ssh!('hostname --fqdn', @puppet_master, @ssh_user, @ssh_key)
            @puppet_server_cloud_fqdn = result[@puppet_master][0].chomp # result[host][0]
            remote_puppet_client_cmd = "chmod +x #{remote_puppet_installer_loc}/#{@puppet_installer} && #{remote_puppet_installer_loc}/#{@puppet_installer} -c -H #{@puppet_server_cloud_fqdn} | tee #{REMOTE_LOG_DIR}/install.log"
          end

          if @parsed_hash['cloud_platform'] == 'rackspace'
            preq(@nodes, remote_puppet_installer_loc, @hosts_file)
          else
            preq(@nodes, remote_puppet_installer_loc)
          end

          puts "\rInstalling puppet agent on : " + "#{@nodes.join(',')}".blue
          puts "\r[Debug]: Sending file #{PUPPET_INSTALLER} to #{@nodes.join(',')}" if @debug
          @nodes.each do |node|
            SshUtils.upload!(PUPPET_INSTALLER, remote_puppet_installer_loc, node, @ssh_user, @ssh_key)
            output = SshUtils.execute_ssh!(
                remote_puppet_client_cmd,
                node,
                @ssh_user,
                @ssh_key,
                22,
                @debug
            )
            unless output[node][2].to_i == 0
              puts "\r[Error]:".red + ' Failed to install puppet agent'
              exit 2
            end
            #print output
            if @debug
              puts "\rstdout on #{node}"
              puts "\r#{output[node][0]}"
              puts "\rstderr on #{node}"
              puts "\r#{output[node][1]}"
            end
          end
        else
          #Mocking
          puts 'Checking if instances are ssh\'able ...'
          puts 'Checking if instances are ssh\'able ...' + '[OK]'.green.bold
        end
        puts "\rInstalling puppet on node(s) #{@nodes.inspect} completed".blue
      end

      # Generate hiera data required by puppet deployments & writes out to the yaml file
      # @param [Hash] parsed_hash => hash from which to generate hiera data
      def generate_hiera(parsed_hash)
        hiera_hash = {}
        #generate hiera data to local data folder first
        puts "\rGenerating hiera data required for puppet".blue
        #aggregate hadoop, hbase, all other related configurations in here into a common hash before writing out
        hiera_hash.merge!(parsed_hash)
        hiera_hash.merge!(YamlUtils.parse_yaml(HADOOP_CONF))
        hiera_hash.merge!(YamlUtils.parse_yaml(HBASE_CONF))
        #TODO add more configs
        #parse zookeeper ensemble
        if parsed_hash['zookeeper_quorum']
          hiera_hash['zookeeper_ensemble'] = parsed_hash['zookeeper_quorum'].map { |zk| zk += ":2181" }.join(",")
          hiera_hash['zookeeper_class_ensemble'] = parsed_hash['zookeeper_quorum'].map { |zk| zk+=":2888:3888" }
        end
        #parse journal quorum
        if parsed_hash['journal_quorum']
          hiera_hash['journal_quorum'] = parsed_hash['journal_quorum'].map { |jn| jn += ":8485" }.join(",")
        end
        #parse num_of_workers
        hiera_hash['number_of_nodes'] = parsed_hash['slave_nodes'].length
        #parse nagios & ganglia
        if parsed_hash['monitoring'] == 'enabled'
          hiera_hash['ganglia_server'] = parsed_hash['controller']
        end
        #log_aggregation
        if parsed_hash['log_aggregation'] == 'enabled'
          hiera_hash['logstash_server'] = parsed_hash['controller']
        end
        #nagios server os_type is required
        if parsed_hash['install_mode'] == 'cloud'
          hiera_hash['nagios_server_ostype'] = parsed_hash['cloud_os_type'].downcase =~ /centos/ ? 'CentOS' : 'Ubuntu'
        else
          if parsed_hash['alerting'] == 'enabled'
            hiera_hash['nagios_server'] = parsed_hash['controller']
            begin #gather info of system
              if parsed_hash['controller'] == 'localhost'
                @osinfo = `chmod +x #{GETOSINFO_SCRIPT} && #{GETOSINFO_SCRIPT}`.chomp
                if $?.success?
                  @ostype = @osinfo =~ /centos/ ? 'CentOS' : 'Ubuntu'
                else
                  @ostype = 'CentOS'
                end
              else
                SshUtils.upload!(GETOSINFO_SCRIPT, "/tmp", @puppet_master, @ssh_user, @ssh_key)
                os_type_cmd = "chmod +x /tmp/#{File.basename(GETOSINFO_SCRIPT)} && /tmp/#{File.basename(GETOSINFO_SCRIPT)}"
                output = SshUtils.execute_ssh_cmds(
                    [os_type_cmd],
                    @puppet_master,
                    @ssh_user,
                    @ssh_key,
                    22,
                    @debug
                )
                @osinfo = output[os_type_cmd][0]
                @ostype = @osinfo =~ /centos/ ? 'CentOS' : 'Ubuntu'
                SshUtils.execute_ssh_cmds(["rm -rf /tmp/#{File.basename(GETOSINFO_SCRIPT)}"], @puppet_master, @ssh_user, @ssh_key, 22)
              end
            rescue #if script is not found, set the ostype as centos
              @ostype = 'CentOS'
            end
            hiera_hash['nagios_server_ostype'] = @ostype
          end
        end
        #security
        if parsed_hash['security'] == 'enabled'
          hiera_hash['kerberos_kdc_server'] = @puppet_master
          hiera_hash['kerberos_realm'] = @parsed_hash['realm_name']
          hiera_hash['kerberos_domain'] = @parsed_hash['domain_name']
        end
          #hadoop_eco_system
        hadoop_ecosystem = parsed_hash['hadoop_ecosystem']
        if hadoop_ecosystem
          hadoop_ecosystem.each do |tool|
            hiera_hash[tool] = 'enabled'
          end
        end
        #Write out hiera data to file and send it to puppet server
        YamlUtils.write_yaml(hiera_hash, HIERA_DATA_FILE)
        SshUtils.upload!(HIERA_DATA_FILE, HIERA_DATA_PATH, @puppet_master, @ssh_user, @ssh_key, 22) unless @mock
      end

      # Generate External Node Classifier data file used by the puppet's ENC script
      # @param [Hash] parsed_hash => hash from which to generate enc data
      def generate_enc(parsed_hash, nodes_file)
        puts "\rGenerating Enc roles to host mapping".blue
        Inventory::EncData.new(nodes_file, ENC_ROLES_FILE, parsed_hash).generate
      end

      # Kick off puppet run on all instances orchestrate runs based on configuration
      def run_puppet
        puppet_run_cmd = "puppet agent --server #{@puppet_master} --onetime --verbose --no-daemonize --no-splay --ignorecache --no-usecacheonfailure --logdest #{REMOTE_LOG_DIR}/puppet_run.log"
        if ! @mock
          if @parsed_hash['install_mode'] == 'cloud'
            result = SshUtils.execute_ssh!('hostname --fqdn', @puppet_master, @ssh_user, @ssh_key)
            @puppet_server_cloud_fqdn = result[@puppet_master][0].chomp
            puppet_run_cmd = "puppet agent --server #{@puppet_server_cloud_fqdn} --onetime --verbose --no-daemonize --no-splay --ignorecache --no-usecacheonfailure --logdest #{REMOTE_LOG_DIR}/puppet_run.log"
          end
          output = []
          #send enc_data and enc_script to puppet server
          SshUtils.upload!(ENC_ROLES_FILE, ENC_PATH, @puppet_master, @ssh_user, @ssh_key, 22)
          SshUtils.upload!(ENC_SCRIPT, ENC_PATH, @puppet_master, @ssh_user, @ssh_key, 22)
        end
        #initialize puppet run in order
          #1. puppet server
          #2. master nodes and parallel on worker nodes
        controller    = @parsed_hash['controller']
        hadoop_ha     = @parsed_hash['hadoop_ha']
        hbase_install = @parsed_hash['hbase_install']

        if controller == 'localhost'
          puts "\rInitializing puppet run on controller".blue
          ShellUtils.run_cmd!(puppet_run_cmd) if ! @mock
          # TODO First puppet_run on controller will fail! Fix this.
          #   Error: Could not start Service[nagios]: Execution of '/sbin/service nagios start' returned 1
          #   Error: /Stage[main]/Nagios::Server/Service[nagios]/ensure: change from stopped to running failed: Could not start Service[nagios]: Execution of '/sbin/service nagios start' returned 1
          #unless status.success?
          #  puts '[Error]:'.red + ' Failed to install puppet master'
          #end
        else
          puppet_single_run(@puppet_master, puppet_run_cmd, 'controller')
        end

        # if ha or hbase,
          # init puppet agent on zookeepers
        if hadoop_ha == 'enabled' or hbase_install == 'enabled'
          #parallel puppet run on zks
          puppet_parallel_run(@parsed_hash['zookeeper_quorum'], puppet_run_cmd, 'zookeepers')
        end
        if hadoop_ha == 'enabled'
          if @parsed_hash['journal_quorum']
            #parallel puppet run on jns
            puppet_parallel_run(@parsed_hash['journal_quorum'], puppet_run_cmd, 'journalnodes')
          end
          #parallel run puppet run on nns
          puppet_parallel_run(@parsed_hash['hadoop_namenode'], puppet_run_cmd, 'namenodes')
        else
          puppet_single_run(@parsed_hash['hadoop_namenode'].first, puppet_run_cmd, 'namenode')
        end
        if hbase_install == 'enabled'
          hbase_master = @parsed_hash['hbase_master']
          if hbase_master.length == 1
            puts "\rInitializing hbase master"
            puppet_single_run(hbase_master.join, puppet_run_cmd, 'hbasemaster')
          else
            puppet_parallel_run(hbase_master, puppet_run_cmd, 'hbasemasters')
          end
        end

        # init puppet agent on mapreduce master
        puppet_single_run(@parsed_hash['mapreduce']['master'], puppet_run_cmd, 'mapreduce_master')

        # init puppet agent on slave nodes
        puppet_parallel_run(@parsed_hash['slave_nodes'], puppet_run_cmd, 'slaves')

        # finalize puppet run on controller to refresh nagios
        if controller == 'localhost'
          unless @mock
            status = ShellUtils.run_cmd!(puppet_run_cmd)
            unless status.success?
              puts "\r[Error]:".red + ' Failed to finalize puppet run'
              #TODO handle rollback
            end
          end
        else
          puppet_single_run(@puppet_master, puppet_run_cmd, 'controller')
        end
      end

      # Kick off puppet run when a new node(s) are being commissioned to the cluster, this includes refreshing puppet master
      def run_puppet_set(nodes)
        puppet_run_cmd = "puppet agent --server #{@puppet_master} --onetime --verbose --no-daemonize --no-splay --ignorecache --no-usecacheonfailure --logdest #{REMOTE_LOG_DIR}/puppet_run.log"
        unless @mock
          if @parsed_hash['install_mode'] == 'cloud'
            result = SshUtils.execute_ssh!('hostname --fqdn', @puppet_master, @ssh_user, @ssh_key)
            @puppet_server_cloud_fqdn = result[@puppet_master][0].chomp
            puppet_run_cmd = "puppet agent --server #{@puppet_server_cloud_fqdn} --onetime --verbose --no-daemonize --no-splay --ignorecache --no-usecacheonfailure --logdest #{REMOTE_LOG_DIR}/puppet_run.log"
          end
          # send enc_roles file to puppet master
          SshUtils.upload!(ENC_ROLES_FILE, ENC_PATH, @puppet_master, @ssh_user, @ssh_key, 22)
          puts "\rInitializing puppet run on node(s) #{nodes.inspect}" if @debug
          puppet_parallel_run(nodes, puppet_run_cmd, 'refresh')
          #refresh master
          if @parsed_hash['controller'] == 'localhost'
            status = ShellUtils.run_cmd!(puppet_run_cmd)
            unless status.success?
              puts "\r[Error]:".red + ' Failed to finalize puppet run'
              #TODO handle rollback
            end
          else
            puppet_single_run(@puppet_master, puppet_run_cmd, 'controller')
          end
        end
        puts "\rCompleted puppet run on #{nodes.join(',').blue} and refreshed puppet master #{@puppet_master.blue}"
      end

      private

      # Runs puppet on single instance
      # @param [String] instance => node on which puppet should be run
      # @param [String] puppet_run_cmd => command to run on remote client to run puppet
      # @param [String] role => role installing on remote client
      def puppet_single_run(instance, puppet_run_cmd, role)
        unless @debug
          SpinningCursor.start do
            banner "\rInitializing #{role} on " + "#{instance} ".blue
            type :dots
            message "\rInitializing #{role} on " + "#{instance} ".blue + '[DONE]'.cyan
          end
        else
          puts "\rInitializing #{role} on " + "#{instance}".blue
        end
        unless @mock
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
            puts "\r[Error]: ".red + "Puppet run failed on #{instance}, aborting!"
            #exit 1
            #TODO Rollback lock
          end
        else
          sleep 3
        end
        unless @debug
          SpinningCursor.stop
        else
          puts "\rCompleted puppet run on" +" #{instance}".blue if @debug
        end
      end

      # Runs puppet on instances in parallel using thread pool
      # @param [Array] instances_array => list of instances on which puppet should be run in parallel
      # @param [String] puppet_run_cmd => command to run on remote client to run puppet
      # @param [String] role => role installing on remote client
      def puppet_parallel_run(instances_array, puppet_run_cmd, role)
        SpinningCursor.start do
          banner "\rInitializing #{role} on client(s): " + "#{instances_array.join(',')} ".blue
          type :dots
          message "\rInitializing puppet run on client(s): " + "#{instances_array.join(',')} ".blue + '[DONE]'.cyan
          output :at_stop
        end
        if ! @mock
          #initiate concurrent threads pool - to install puppet clients all agent nodes
          ssh_connections = ThreadPool.new(@parallel_connections)
          output = []
          time = Benchmark.measure do
            instances_array.each do |instance|
              ssh_connections.schedule do
                #run puppet installer
                output << SshUtils.execute_ssh!(
                    puppet_run_cmd,
                    instance,
                    @ssh_user,
                    @ssh_key,
                    22,
                    false)
              end
            end
            ssh_connections.shutdown
          end
          puts "\r[Debug]: Time to run puppet on clients: #{time}" if @debug
          #check if puppet run failed
          if @debug
            output.each do |o|
              instance = o.keys[0]
              puts "\rStdout on #{instance}"
              puts "\r#{o[instance][0]}"
              puts "\rStderr on #{instance}"
              puts "\r#{o[instance][1]}"
              puts "\r[Error]: Puppet run failed on #{instance}" unless o[instance][2].to_i == 0
            end
          end
        else
          sleep 3
        end
        SpinningCursor.stop
      end

      # Checks if instances are listening in ssh port by default 22
      # @param [Array] instances => list of instances to check
      # @param [Integer] port => port on which ssh is listening (default: 22)
      def validate_instances(instances, port=22)
        instances.each do |instance|
          unless PortUtils.port_open? instance, port
            puts "\r[Error]: Node #{instance} is not reachable on port #{port} for ssh"
            exit 1
          end
        end
      end

      # Perform pre-requisite operations (creates log directories and copies over the puppet installer script)
      # before even installing puppet agent
      # @param [Array] instances => instances list on which preq should be performed
      # @param [String] remote_puppet_loc => location to where puppet installer script should be copied to
      def preq(instances, remote_puppet_loc, hosts_file = nil)
        puts "\rPreforming preq operations on all nodes"
        ssh_connections = ThreadPool.new(@parallel_connections)
        output = []
        cmds =  ["mkdir -p #{REMOTE_LOG_DIR}",
                 "touch #{REMOTE_LOG_DIR}/install.log",
                 "touch #{REMOTE_LOG_DIR}/puppet_run.log"
        ]
        cmds << 'cp /etc/hosts /etc/hosts.backup' if hosts_file
        instances.each do |instance|
          ssh_connections.schedule do
            output << SshUtils.execute_ssh_cmds(
                cmds,
                instance,
                @ssh_user,
                @ssh_key,
                22, false)
            #send the script over to clients
            puts "\rsending file to #{instance}" if @debug
            SshUtils.upload!(PUPPET_INSTALLER, remote_puppet_loc, instance, @ssh_user, @ssh_key)
            if hosts_file
              puts "\rsending hosts file to #{instance}" if @debug
              SshUtils.upload!(hosts_file, '/etc/hosts', instance, @ssh_user, @ssh_key)
            end
          end
        end
        ssh_connections.shutdown
      end

      # Performs clean up actions (remove puppet installer script) after deployment
      # @param [Array] instances => list of instances on which to perform cleanup
      def cleanup(instances)
        puts "\rPreforming Cleanup operations on all nodes"
        ssh_connections = ThreadPool.new(@parallel_connections)
        output = []
        instances.each do |instance|
          ssh_connections.schedule do
            output << SshUtils.execute_ssh_cmds(
                ["rm -rf /tmp/#{@puppet_installer}"],
                instance,
                @ssh_user,
                @ssh_key,
                22,
                false
            )
          end
        end
        ssh_connections.shutdown
      end
    end

  end
end