module Ankuscli
  module Inventory
    include Ankuscli
    # Manages server inventory based on the hash passed from configuration parser
    class Manager

    end

    # Generates server inventory files based on the hash passed from configuration parser
    class Generator
      # @param [String] config_file => path to the config file
      # @param [Hash] parsed_hash => parsed configuration hash
      def initialize(config_file, parsed_hash)
        @config_file  = config_file
        @parsed_hash  = parsed_hash
      end

      # Generates inventory (a mapping of puppet_server and puppet_client host_names), and writes out to @nodes_file
      # @param [String] nodes_file => path to nodes_file
      def generate!(nodes_file)
        YamlUtils.write_yaml(create_nodes, nodes_file)
      end

      # Generates inventory
      def generate
        create_nodes
      end

      private

      # Create a hash which contains puppet_server and puppet_clients to hostname mappings
      def create_nodes
        nodes = Array.new
        nodes_hash = Hash.new
        if @parsed_hash[:hadoop_deploy] != 'disabled'
          #namenode
          nodes.push(*@parsed_hash[:hadoop_deploy][:hadoop_namenode])
          #zookeepers
          if @parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled' or @parsed_hash[:hbase_deploy]
            nodes.push(*@parsed_hash[:zookeeper_quorum])
          end
          #mapreduce
          if @parsed_hash[:hadoop_deploy][:mapreduce] != 'disabled'
            nodes << @parsed_hash[:hadoop_deploy][:mapreduce][:master]
          else
            nodes << @parsed_hash[:hadoop_deploy][:hadoop_secondarynamenode] unless @parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
          end
          #hbase
          if @parsed_hash[:hbase_deploy] != 'disabled'
            nodes.push(*@parsed_hash[:hbase_deploy][:hbase_master])
          end
          #worker nodes
          nodes.push(*@parsed_hash[:slave_nodes])
        end
        if @parsed_hash[:cassandra_deploy] != 'disabled'
          nodes.push(*@parsed_hash[:cassandra_deploy][:cassandra_nodes])
        end
        #remove duplicates
        nodes.uniq!
        nodes.compact!  #remove nil if any
        if @parsed_hash[:controller] == 'localhost'
          nodes_hash[:puppet_server] = `hostname --fqdn`.chomp
        else
          nodes_hash[:puppet_server] = @parsed_hash[:controller]
        end
        nodes_hash[:puppet_clients] = nodes
        nodes_hash
      end
    end

    # Build yaml file of host to puppet roles mapping; used by puppet external node classifier script
    class EncData

      # @param [String] nodes_file => path of the nodes yaml file
      # @param [String] roles_file => path of the file to be created with mapping
      # @param [Hash] parsed_hash => parsed configuration file
      def initialize(nodes_file, roles_file, parsed_hash, install_mode = 'local')
        @nodes_file   = nodes_file
        @roles_file   = roles_file
        @parsed_hash  = parsed_hash
        @install_mode = install_mode
      end

      # Write out the mapping created by 'create_enc_roles()' into @roles_file
      def generate
        YamlUtils.write_yaml(create_enc_roles, @roles_file)
      end

      private

      # Create hash of nodes to roles mapping using @parsed_hash
      def create_enc_roles
        roles_hash = Hash.new
        puppet_nodes = YamlUtils.parse_yaml(@nodes_file)
        #puppet server
        @ps  = puppet_nodes[:puppet_server]   # puppet server
        @pcs = puppet_nodes[:puppet_clients]  # puppet clients
        roles_hash[@ps]                     = {}
        roles_hash[@ps]['java']             = nil
        roles_hash[@ps]['nagios::server']   = nil if @parsed_hash[:alerting] == 'enabled'
        roles_hash[@ps]['ganglia::server']  = nil if @parsed_hash[:monitoring] == 'enabled'
        roles_hash[@ps]['kerberos::server'] = nil if @parsed_hash[:security] == 'kerberos'
        roles_hash[@ps]['logstash']         = { 'role' => 'indexer' } if @parsed_hash[:log_aggregation] == 'enabled'

        #puppet clients
        hadoop_install      = @parsed_hash[:hadoop_deploy]
        if hadoop_install != 'disabled'
          namenode            = @parsed_hash[:hadoop_deploy][:hadoop_namenode]
          secondary_namenode  = @parsed_hash[:hadoop_deploy][:hadoop_secondarynamenode]
          mapreduce           = @parsed_hash[:hadoop_deploy][:mapreduce]
          mapreduce_type      = @parsed_hash[:hadoop_deploy][:mapreduce][:type] if mapreduce != 'disabled'
          mapreduce_master    = @parsed_hash[:hadoop_deploy][:mapreduce][:master] if mapreduce != 'disabled'
          hadoop_ecosystem    = @parsed_hash[:hadoop_deploy][:hadoop_ecosystem]
          slave_nodes         = @parsed_hash[:slave_nodes]
          hbase_install       = @parsed_hash[:hbase_deploy]
          hbase_master        = @parsed_hash[:hbase_deploy][:hbase_master] if hbase_install != 'disabled'
        end
        cassandra_install   = @parsed_hash[:cassandra_deploy]
        cassandra_nodes     = @parsed_hash[:cassandra_deploy][:cassandra_nodes] if cassandra_install != 'disabled'
        @pcs.each do |pc|
          roles_hash[pc] = {}
          #java
          roles_hash[pc]['java'] = nil
          if hadoop_install != 'disabled'
            #namenode
            roles_hash[pc]['hadoop::namenode'] = nil if namenode.include? pc
            #zookeepers
            if @parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled' or @parsed_hash[:hbase_deploy] != 'disabled'
              zookeepers = @parsed_hash[:zookeeper_quorum]
              #convert zookeepers array into hash with id as zookeeper and value as its id
              zookeepers_id_hash = Hash[zookeepers.map.each_with_index.to_a]
              if zookeepers.include? pc
                roles_hash[pc]['zookeeper::server'] = { 'myid' => zookeepers_id_hash[pc] }
              end
            end
            #journal nodes
            if @parsed_hash[:hadoop_deploy][:hadoop_ha] == 'enabled'
              journal_nodes = @parsed_hash[:hadoop_deploy][:journal_quorum]
              roles_hash[pc]['hadoop::journalnode'] = nil if journal_nodes.include? pc
            else
              #snn
              roles_hash[pc]['hadoop::secondarynamenode'] = nil if secondary_namenode == pc
            end
            #mapreduce
            if mapreduce != 'disabled'
              if mapreduce_type == 'mr1'
                roles_hash[pc]['hadoop::jobtracker'] = nil if mapreduce_master == pc
                roles_hash[pc]['hadoop::tasktracker'] = nil if slave_nodes.include? pc
              elsif mapreduce_type == 'mr2'
                if mapreduce_master == pc
                  roles_hash[pc]['hadoop::resourcemanager'] = nil
                  roles_hash[pc]['hadoop::jobhistoryproxyserver'] = nil
                end
                roles_hash[pc]['hadoop::nodemanager'] = nil if slave_nodes.include? pc
              end
            end
            #ecosystem
            if mapreduce_master == pc
              if hadoop_ecosystem
                #eco-system
                roles_hash[pc]['hadoop-hive'] = nil           if hadoop_ecosystem.include? 'hive'
                roles_hash[pc]['hadoop-pig'] = nil            if hadoop_ecosystem.include? 'pig'
                roles_hash[pc]['hadoop-sqoop::server'] = nil  if hadoop_ecosystem.include? 'sqoop'
                roles_hash[pc]['hadoop-sqoop::client'] = nil  if hadoop_ecosystem.include? 'sqoop'
                roles_hash[pc]['hadoop-pig'] = nil            if hadoop_ecosystem.include? 'pig'
                roles_hash[pc]['hadoop-oozie::server'] = nil  if hadoop_ecosystem.include? 'oozie'
                roles_hash[pc]['hadoop-oozie::client'] = nil  if hadoop_ecosystem.include? 'oozie'
              end
            end
            #hdfs
            roles_hash[pc]['hadoop::datanode'] = nil if slave_nodes.include? pc
            #hbase
            if hbase_install != 'disabled'
              roles_hash[pc]['hbase::master'] = nil if hbase_master.include? pc
              roles_hash[pc]['hbase::regionserver'] = nil if slave_nodes.include? pc
            end
            #security only for hadoop & hbase deployments
            roles_hash[pc]['kerberos::client'] = nil if @parsed_hash[:security] == 'kerberos'
          end
          #monitoring, alerting
          roles_hash[pc]['nagios::nrpe'] = nil if @parsed_hash[:alerting] == 'enabled'
          roles_hash[pc]['ganglia::client'] = nil if @parsed_hash[:monitoring] == 'enabled'
          ##log aggregation
          #if @parsed_hash['log_aggregation'] == 'enabled'
          #  roles_hash[pc]['logstash::lumberjack'] = {
          #    'logstash_host' => @ps,
          #    'logstash_port' => 5672,
          #    'daemon_name' => 'lumberjack_general',
          #    'field' => "general_#{pc}"
          #  }
          #end
          #cassandra
          if cassandra_install != 'disabled'
            roles_hash[pc]['cassandra'] = nil if cassandra_nodes.include? pc
          end
        end
        roles_hash
      end
    end
  end
end