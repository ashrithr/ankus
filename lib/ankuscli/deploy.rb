module Ankuscli
  module Deploy
    require 'benchmark'
    include Ankuscli

    # Class to manage puppet deployments
    class Puppet

      PUPPET_INSTALLER = File.expand_path(File.dirname(__FILE__) + '/../shell/puppet_installer.sh')
      HIERA_DATA_FILE = File.expand_path(File.dirname(__FILE__) + '/../../data/common.yaml')
      ENC_SCRIPT =  File.expand_path(File.dirname(__FILE__) + '/../../bin/ankus_puppet_enc')
      ENC_ROLES_FILE =  File.expand_path(File.dirname(__FILE__) + '/../../data/roles.yaml')
      NODES_FILE = File.expand_path(File.dirname(__FILE__) + '/../../data/nodes.yaml')
      NODES_FILE_CLOUD = File.expand_path(File.dirname(__FILE__) + '/../../data/nodes_cloud.yaml')
      GETOSINFO_SCRIPT = File.expand_path(File.dirname(__FILE__) + '../../shell/get_osinfo.sh')
      HADOOP_CONF = File.expand_path(File.dirname(__FILE__) + '/../../conf/ankus_hadoop_conf.yaml')
      ENC_PATH = %q(/etc/puppet/enc)
      HIERA_DATA_PATH = %q(/etc/puppet/hieradata)
      REMOTE_LOG_DIR = %q(/var/log/ankus)

      # @param [String] puppet_server => hostname of the puppet server
      # @param [Array] puppet_clients => host_names of puppet clients
      # @param [String] ssh_key => ssh key to use to log into the machines
      # @param [Hash] parsed_hash => parsed configuration file
      # @param [Integer] ssh_connections => number of concurrent processes (threads) to use for deployments
      # @param [String] ssh_user => user to log into the machine as
      # @param [Boolean] debug => if enabled will print out information to stdout
      def initialize(puppet_server, puppet_clients, ssh_key, parsed_hash, ssh_connections=10, ssh_user='root', debug=false)
        @puppet_master         = puppet_server
        @nodes                 = puppet_clients
        @parallel_connections  = ssh_connections
        @ssh_user              = ssh_user
        @ssh_key               = ssh_key
        @puppet_installer      = File.basename(PUPPET_INSTALLER)
        @parsed_hash           = parsed_hash
        @debug                 = debug
      end

      # Installs puppet server on @puppet_master and puppet agent daemons on @nodes
      def install_puppet
        #helper variables
        remote_puppet_installer_loc = "/tmp"
        remote_puppet_server_cmd = "chmod +x #{remote_puppet_installer_loc}/#{@puppet_installer} && #{remote_puppet_installer_loc}/#{@puppet_installer} -s | tee #{REMOTE_LOG_DIR}/install.log"
        remote_puppet_client_cmd = "chmod +x #{remote_puppet_installer_loc}/#{@puppet_installer} && #{remote_puppet_installer_loc}/#{@puppet_installer} -c -H #{@puppet_master} | tee #{REMOTE_LOG_DIR}/install.log"
        #check if instances are up
        validate_instances @nodes
        all_nodes = []
        @nodes.each do |node|
          all_nodes << node
        end
        all_nodes << @puppet_master
        #check if instances are sshable
        puts 'Checking if instances are ssh\'able ...'
        SshUtils.sshable? @nodes, @ssh_user, @ssh_key
        puts 'Checking if instances are ssh\'able ... ' + '[OK]'.green.bold
        #get the puppet server hostname this is required for cloud, for aws to get internal_dns_name of host for accurate communication
        if @parsed_hash['install_mode'] == 'cloud'
          # result[host][0]
          result = SshUtils.execute_ssh!('hostname --fqdn', @puppet_master, @ssh_user, @ssh_key)
          @puppet_server_cloud_fqdn = result[@puppet_master][0].chomp
          remote_puppet_client_cmd = "chmod +x #{remote_puppet_installer_loc}/#{@puppet_installer} && #{remote_puppet_installer_loc}/#{@puppet_installer} -c -H #{@puppet_server_cloud_fqdn} | tee #{REMOTE_LOG_DIR}/install.log"
        end
        #perform preq's
        preq(all_nodes, remote_puppet_installer_loc)
        puts 'Installing puppet master on ' + "#{@puppet_master}".blue
        puts "[Debug]: Found puppet installer script at #{PUPPET_INSTALLER}" if @debug
        #if controller is on same machine, install puppet master locally else send the script to controller and install
        #puppet
        if @parsed_hash['controller'] == 'localhost'
          status = ShellUtils.run_cmd_with_log!(
              "chmod +x #{PUPPET_INSTALLER} && #{PUPPET_INSTALLER} -s",
              "#{REMOTE_LOG_DIR}/install.log"
          )
          unless status.success?
            puts '[Error]:'.red + ' Failed to install puppet master'
            exit 2
            #TODO handle rollback
          end
        else
          puts "[Debug]: Sending file #{PUPPET_INSTALLER} to #{@puppet_master}" if @debug
          SshUtils.upload!(PUPPET_INSTALLER, remote_puppet_installer_loc, @puppet_master, @ssh_user, @ssh_key)
          output = SshUtils.execute_ssh!(
              remote_puppet_server_cmd,
              @puppet_master,
              @ssh_user,
              @ssh_key,
              22,
              @debug
          )
          unless output[@puppet_master][2].to_i == 0
            puts '[Error]:'.red + ' Failed to install puppet master'
            exit 2
          end
        end
        #initiate concurrent threads pool - to install puppet clients all agent nodes
        ssh_connections = ThreadPool.new(@parallel_connections)
        puts 'Installing puppet agents on clients: ' + "#{@nodes.join(',')}".blue
        output = []
        time = Benchmark.measure do
          @nodes.each do |instance|
            ssh_connections.schedule do
              #run puppet installer
              output << SshUtils.execute_ssh_cmds(
                  [remote_puppet_client_cmd],
                  instance,
                  @ssh_user,
                  @ssh_key,
                  22, false)
              #puts "Thread #{Thread.current[:id]} finished"
            end
          end
          ssh_connections.shutdown
        end
        puts 'Finished installing puppet clients'.blue
        puts "[Debug]: Time to install puppet clients: #{time}" if @debug
        #print output of puppet client installers on console
        if @debug
          output.each do |o|
            stdout = o[remote_puppet_client_cmd][0]
            stderr = o[remote_puppet_client_cmd][1]
            exit_status = o[remote_puppet_client_cmd][2]
            puts stdout
            puts stderr
          end
        end

        #clean up puppet installer script on all nodes
        cleanup(all_nodes)

        print 'Installing puppet on all nodes completed'.blue
      end

      # Generate hiera data required by puppet deployments & writes out to the yaml file
      # @param [Hash] parsed_hash => hash from which to generate hiera data
      def generate_hiera(parsed_hash)
        hiera_hash = {}
        #generate hiera data to local data folder first
        puts 'Generating hiera data required for puppet'.blue
        #aggregate hadoop, hbase, all other related configurations in here into a common hash before writing out
        hiera_hash.merge!(parsed_hash)
        hiera_hash.merge!(YamlUtils.parse_yaml(HADOOP_CONF))
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
        if parsed_hash['alerting'] == 'enabled'
          hiera_hash['nagios_server'] = parsed_hash['controller']
          begin #gather info of system
            if parsed_hash['controller'] == 'localhost'
              @osinfo = `chmod +x #{GETOSINFO_SCRIPT} && #{GETOSINFO_SCRIPT}`.chomp
              if $?.success?
                @ostype = @osinfo =~ /centos/ ? "CentOS" : "Ubuntu"
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
              @ostype = @osinfo =~ /centos/ ? "CentOS" : "Ubuntu"
              SshUtils.execute_ssh_cmds(["rm -rf /tmp/#{File.basename(GETOSINFO_SCRIPT)}"], @puppet_master, @ssh_user, @ssh_key, 22)
            end
          rescue #if script is not found, set the ostype as centos
            @ostype = 'CentOS'
          end
          hiera_hash['nagios_server_ostype'] = @ostype
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
        SshUtils.upload!(HIERA_DATA_FILE, HIERA_DATA_PATH, @puppet_master, @ssh_user, @ssh_key, 22)
      end

      # Generate External Node Classifier data file used by the puppet's ENC script
      # @param [Hash] parsed_hash => hash from which to generate enc data
      def generate_enc(parsed_hash, nodes_file)
        puts 'Generating Enc roles to host mapping'.blue
        Inventory::EncData.new(nodes_file, ENC_ROLES_FILE, parsed_hash).generate
      end

      # Kick off puppet run on all instances in order of the configuration
      def run_puppet
        puppet_run_cmd = "puppet agent --server #{@puppet_master} --onetime --verbose --no-daemonize --no-splay --ignorecache --no-usecacheonfailure --logdest #{REMOTE_LOG_DIR}/puppet_run.log"
        if @parsed_hash['install_mode'] == 'cloud'
          result = SshUtils.execute_ssh!('hostname --fqdn', @puppet_master, @ssh_user, @ssh_key)
          @puppet_server_cloud_fqdn = result[@puppet_master][0].chomp
          puppet_run_cmd = "puppet agent --server #{@puppet_server_cloud_fqdn} --onetime --verbose --no-daemonize --no-splay --ignorecache --no-usecacheonfailure --logdest #{REMOTE_LOG_DIR}/puppet_run.log"
        end
        output = []
        #send enc_data and enc_script to puppet server
        SshUtils.upload!(ENC_ROLES_FILE, ENC_PATH, @puppet_master, @ssh_user, @ssh_key, 22)
        SshUtils.upload!(ENC_SCRIPT, ENC_PATH, @puppet_master, @ssh_user, @ssh_key, 22)
        #initialize puppet run in order
          #1. puppet server
          #2. master nodes and parallel on worker nodes
        controller    = @parsed_hash['controller']
        hadoop_ha     = @parsed_hash['hadoop_ha']
        hbase_install = @parsed_hash['hbase_install']

        puts 'Initializing puppet run on controller'.blue
        if controller == 'localhost'
          ShellUtils.run_cmd!(puppet_run_cmd)
          # TODO First puppet run on controller will fail! Fix this.
          #   Error: Could not start Service[nagios]: Execution of '/sbin/service nagios start' returned 1
          #   Error: /Stage[main]/Nagios::Server/Service[nagios]/ensure: change from stopped to running failed: Could not start Service[nagios]: Execution of '/sbin/service nagios start' returned 1
          #unless status.success?
          #  puts '[Error]:'.red + ' Failed to install puppet master'
          #end
        else
          puppet_single_run(@puppet_master, puppet_run_cmd)
        end

        # if ha or hbase,
          # init puppet agent on zookeepers
        if hadoop_ha == 'enabled' or hbase_install == 'enabled'
          #parallel puppet run on zks
          puts 'Initializing zookeepers'
          puppet_parallel_run(@parsed_hash['zookeeper_quorum'], puppet_run_cmd)
          if @parsed_hash['journal_quorum']
            #parallel puppet run on jns
            puts 'Initializing journal nodes'
            puppet_parallel_run(@parsed_hash['journal_quorum'], puppet_run_cmd)
          end
          if hadoop_ha == 'enabled'
            #parallel run puppet run on nns
            puts 'Initializing  namenodes'
            puppet_parallel_run(@parsed_hash['hadoop_namenode'], puppet_run_cmd)
          end
          if hbase_install == 'enabled'
            hbase_master = @parsed_hash['hbase_master']
            if hbase_master.length == 1
              puts 'Initializing hbase master'
              puppet_single_run(hbase_master, puppet_run_cmd)
            else
              puts 'Initializing hbase masters'
              puppet_parallel_run(hbase_master, puppet_run_cmd)
            end
          end
        elsif hadoop_ha == 'disabled'
          puts 'Initializing namenode'
          puppet_single_run(@parsed_hash['hadoop_namenode'].first, puppet_run_cmd)
        end

        # init puppet agent on mapreduce master
        puts 'Initializing mapreduce master'
        puppet_single_run(@parsed_hash['mapreduce']['master'], puppet_run_cmd)

        # init puppet agent on slave nodes
        puts 'Initializing slave nodes'
        puppet_parallel_run(@parsed_hash['slave_nodes'], puppet_run_cmd)

        # finalize puppet run on controller to refresh nagios
        if controller == 'localhost'
          status = ShellUtils.run_cmd!(puppet_run_cmd)
          unless status.success?
            puts '[Error]:'.red + ' Failed to finalize puppet run'
            #TODO handle rollback
          end
        else
          puppet_single_run(@puppet_master, puppet_run_cmd)
        end
      end

      private

      # Runs puppet on single instance
      # @param [String] instance => node on which puppet should be run
      def puppet_single_run(instance, puppet_run_cmd)
        output = SshUtils.execute_ssh!(
            puppet_run_cmd,
            instance,
            @ssh_user,
            @ssh_key,
            22,
            @debug
        )
        exit_status = output[instance][2].to_i
        if @debug
          puts output[instance][0]
          puts output[instance][1]
        end
        unless exit_status == 0
          puts '[Error]: '.red + "Puppet run failed on #{instance}, aborting!"
          #exit 1
          #TODO Rollback lock
        end
        puts 'Completed puppet run on' +" #{instance}".blue
      end

      # Runs puppet on instances in parallel using thread pool
      # @param [Array] instances_array => list of instances on which puppet should be run in parallel
      def puppet_parallel_run(instances_array, puppet_run_cmd)
        #initiate concurrent threads pool - to install puppet clients all agent nodes
        ssh_connections = ThreadPool.new(@parallel_connections)
        puts 'Running puppet on clients: ' + "#{instances_array.join(',')}".blue if @debug
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
        puts "[Debug]: Finished puppet run on #{instances_array.join(',')}" if @debug
        puts "[Debug]: Time to install puppet clients: #{time}" if @debug
        #check if puppet run failed
        if @debug
          output.each do |o|
            instance = o.keys[0]
            puts "Stdout of #{instance}".blue
            puts o[instance][0]
            puts "Stderr of #{instance}".yellow
            puts o[instance][1]
            puts "[Error]: Puppet run failed on #{instance}" unless o[instance][2].to_i == 0
          end
        end
      end

      # Checks if instances are listening in ssh port by default 22
      # @param [Array] instances => list of instances to check
      # @param [Integer] port => port on which ssh is listening (default: 22)
      def validate_instances(instances, port=22)
        instances.each do |instance|
          unless PortUtils.port_open? instance, port
            puts "[Error]: Node #{instance} is not reachable"
            exit 1
          end
        end
      end

      # Perform pre-requisite operations (creates log directories and copies over the puppet installer script)
      # before even installing puppet agent
      # @param [Array] instances => instances list on which preq should be performed
      # @param [String] remote_puppet_loc => location to where puppet installer script should be copied to
      def preq(instances, remote_puppet_loc)
        puts 'Preforming preq operations on all nodes'
        ssh_connections = ThreadPool.new(@parallel_connections)
        output = []
        instances.each do |instance|
          ssh_connections.schedule do
            output << SshUtils.execute_ssh_cmds(
                ["mkdir -p #{REMOTE_LOG_DIR}",
                 "touch #{REMOTE_LOG_DIR}/install.log",
                 "touch #{REMOTE_LOG_DIR}/puppet_run.log"
                ],
                instance,
                @ssh_user,
                @ssh_key,
                22, false)
            #send the script over to clients
            puts "sending file to #{instance}"
            SshUtils.upload!(PUPPET_INSTALLER, remote_puppet_loc, instance, @ssh_user, @ssh_key)
          end
        end
        ssh_connections.shutdown
      end

      # Performs clean up actions (remove puppet installer script) after deployment
      # @param [Array] instances => list of instances on which to perform cleanup
      def cleanup(instances)
        puts 'Preforming Cleanup operations on all nodes'
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