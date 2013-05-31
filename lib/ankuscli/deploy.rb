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
      GETOSINFO_SCRIPT = File.expand_path(File.dirname(__FILE__) + '../../shell/get_osinfo.sh')
      HADOOP_CONF = File.expand_path(File.dirname(__FILE__) + '/../../conf/ankus_hadoop_conf.yaml')
      ENC_PATH = %q(/etc/puppet/enc)
      HIERA_DATA_PATH = %q(/etc/puppet/hieradata)
      REMOTE_LOG_DIR = %q(/var/log/ankus)

      def initialize(puppet_server, puppet_clients, ssh_key, parsed_hash, ssh_connections=10, ssh_user='root', debug=false)
        @puppet_master         = puppet_server          # puppet master
        @nodes                 = puppet_clients         # nodes to install puppet clients on
        @parallel_connections  = ssh_connections        # allow 10 concurrent processes to initiate ssh connection
        @ssh_user              = ssh_user               # ssh user to use
        @ssh_key               = ssh_key                # ssh key to use to log into machines
        @puppet_installer      = File.basename(PUPPET_INSTALLER)
        @parsed_hash           = parsed_hash
        @debug                 = debug
      end

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
            #TODO handle rollback
          end
        else
          puts "[Debug]: Sending file #{PUPPET_INSTALLER} to #{@puppet_master}" if @debug
          SshUtils.upload!(PUPPET_INSTALLER, remote_puppet_installer_loc, @puppet_master, @ssh_user, @ssh_key)
          SshUtils.execute_ssh_cmds(
              [remote_puppet_server_cmd],
              @puppet_master,
              @ssh_user,
              @ssh_key,
              22,
              @debug
          )
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
        # generate hiera data required for puppet modules
        generate_hiera(@parsed_hash)
        # generate enc data required for puppet enc bin script
        generate_enc

        #clean up puppet installer script on all nodes
        cleanup(all_nodes)

        print 'Installing puppet on all nodes completed'.blue
      end

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
        #parse journal quoram
        if parsed_hash['journal_quorum']
          hiera_hash['journal_quorum'] = parsed_hash['journal_quorum'].map { |jn| jn += ":8485" }.join(",")
        end
        #parse num_of_workers
        hiera_hash['number_of_nodes'] = parsed_hash['slave_nodes'].length
        #parse nagios & ganglia
        if parsed_hash['monitoring'] == 'enabled'
          hiera_hash['ganglia_server'] = @puppet_master
        end
        if parsed_hash['alerting'] == 'enabled'
          hiera_hash['nagios_server'] = @puppet_master
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
          hiera_hash['kerberos_realm'] = parsed_hash['realm_name']
          hiera_hash['kerberos_domain'] = parsed_hash['domain_name']
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

      def generate_enc
        puts 'Generating Enc roles to host mapping'.blue
        Inventory::EncData.new(NODES_FILE, ENC_ROLES_FILE, @parsed_hash).generate
      end

      def run_puppet
        puppet_run_cmd = "puppet agent --server #{@puppet_master} --test --logdest #{REMOTE_LOG_DIR}/puppet_run.log"
        output = []
        #send enc_data and enc_script to puppet server
        SshUtils.upload!(ENC_ROLES_FILE, ENC_PATH, @puppet_master, @ssh_user, @ssh_key, 22)
        SshUtils.upload!(ENC_SCRIPT, ENC_PATH, @puppet_master, @ssh_user, @ssh_key, 22)
        #initialize puppet run in order
          #1. puppet server
          #2. master nodes and parallel on worker nodes
        controller        = @parsed_hash['controller']
        hadoop_ha         = @parsed_hash['hadoop_ha']
        hbase_install     = @parsed_hash['hbase_install']

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
          puppet_single_run(@puppet_master)
        end

        # if ha or hbase,
          # init puppet agent on zookeepers
        if hadoop_ha == 'enabled' or hbase_install == 'enabled'
          #parallel puppet run on zks
          puts 'Initializing zookeepers'
          puppet_parallel_run(@parsed_hash['zookeeper_quoram'])
          if @parsed_hash['journal_quorum']
            #parallel puppet run on jns
            puts 'Initializing journal nodes'
            puppet_parallel_run(@parsed_hash['journal_quorum'])
          end
          if hadoop_ha == 'enabled'
            #parallel run puppet run on nns
            puts 'Initializing  namenodes'
            puppet_parallel_run(@parsed_hash['hadoop_namenode'])
          end
          if hbase_install == 'enabled'
            hbase_master = @parsed_hash['hbase_master']
            if hbase_master.length == 1
              puts 'Initializing hbase master'
              puppet_single_run(hbase_master)
            else
              puts 'Initializing hbase masters'
              puppet_parallel_run(hbase_master)
            end
          end
        elsif hadoop_ha == 'disabled'
          puts 'Initializing namenode'
          puppet_single_run(@parsed_hash['hadoop_namenode'].first)
        end

        # init puppet agent on mapreduce master
        puts 'Initializing mapreduce master'
        puppet_single_run(@parsed_hash['mapreduce']['master_node'])

        # init puppet agent on slave nodes
        puts 'Initializing slave nodes'
        puppet_parallel_run(@parsed_hash['slave_nodes'])

        # finalize puppet run on controller to refresh nagios
        if controller == 'localhost'
          status = ShellUtils.run_cmd!(puppet_run_cmd)
          unless status.success?
            puts '[Error]:'.red + ' Failed to finalize puppet run'
            #TODO handle rollback
          end
        else
          puppet_single_run(@puppet_master)
        end
      end

      private

      # run puppet on single instance
      def puppet_single_run(instance)
        puppet_run_cmd = "puppet agent --server #{@puppet_master} --test --logdest #{REMOTE_LOG_DIR}/puppet_run.log"
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

      # run puppet on instances in parallel using thread pool
      def puppet_parallel_run(instances_array)
        puppet_run_cmd = "puppet agent --server #{@puppet_master} --test --logdest #{REMOTE_LOG_DIR}/puppet_run.log"
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

      #checks if instances are listening in ssh port by default 22
      def validate_instances(instances)
        instances.each do |instance|
          unless PortUtils.port_open? instance, 22
            puts "[Error]: Node #{instance} is not reachable"
            exit 1
          end
        end
      end

      #perform pre-requisite operations before even installing puppet agent
      def preq(instances, remote_puppet_installer_loc)
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
            SshUtils.upload!(PUPPET_INSTALLER, remote_puppet_installer_loc, instance, @ssh_user, @ssh_key)
          end
        end
        ssh_connections.shutdown
      end

      #perform clean up actions after deployment
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