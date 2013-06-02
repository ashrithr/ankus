module Ankuscli
  module Inventory
    include Ankuscli
    # Manages server inventory based on the hash passed from configuration parser
    class Manager

    end

    # Generates server inventory files based on the hash passed from configuration parser
    class Generator
      def initialize(nodes_file, config_file, parsed_hash)
        @nodes_file   = nodes_file
        @config_file  = config_file
        @parsed_hash  = parsed_hash
      end

      # Generate inventory
      def generate
        YamlUtils.write_yaml(create_nodes, @nodes_file)
      end

      private

      # create a hash which contains puppet_server and puppet_clients file
      def create_nodes
        nodes = Array.new
        nodes_hash = Hash.new
        #namenode
        nodes.push(*@parsed_hash['hadoop_namenode'])
        #zookeepers
        if @parsed_hash['hadoop_ha'] == 'enabled' or @parsed_hash['hbase_install'] == 'enabled'
          nodes.push(*@parsed_hash['zookeeper_quorum'])
        end
        #mapreduce
        nodes << @parsed_hash['mapreduce']['master_node']
        #hbase
        if @parsed_hash['hbase_install'] == 'enabled'
          nodes.push(*@parsed_hash['hbase_master'])
        end
        #worker nodes
        nodes.push(*@parsed_hash['slave_nodes'])
        #remove duplicates
        nodes.uniq!
        nodes.compact!  #remove nil if any
        if @parsed_hash['controller'] == 'localhost'
          nodes_hash['puppet_server'] = `hostname --fqdn`.chomp
        else
          nodes_hash['puppet_server'] = @parsed_hash['controller']
        end
        nodes_hash['puppet_clients'] = nodes
        nodes_hash
      end
    end

    # class to build yaml file(s) per node; used by puppet external node classifier script
    class EncData
      def initialize(nodes_file, roles_file, parsed_hash)
        @nodes_file   = nodes_file
        @roles_file   = roles_file
        @parsed_hash  = parsed_hash
      end

      def generate
        YamlUtils.write_yaml(create_enc_roles, @roles_file)
      end

      private

      def create_enc_roles
        roles_hash = Hash.new
        #puppet server
        @ps   = YamlUtils.parse_yaml(@nodes_file)['puppet_server']   # puppet server
        @pcs  = YamlUtils.parse_yaml(@nodes_file)['puppet_clients']  # puppet clients
        roles_hash[@ps] = {}
        roles_hash[@ps]['java'] = nil
        roles_hash[@ps]['nagios::server'] = nil if @parsed_hash['alerting'] == 'enabled'
        roles_hash[@ps]['ganglia::server'] = nil if @parsed_hash['monitoring'] == 'enabled'
        roles_hash[@ps]['kerberos::server'] = nil if @parsed_hash['security'] == 'enabled'

        #puppet clients
        namenode = @parsed_hash['hadoop_namenode']
        secondary_namenode = @parsed_hash['hadoop_secondarynamenode']
        mapreduce_type = @parsed_hash['mapreduce']['type']
        mapreduce_master = @parsed_hash['mapreduce']['master_node']
        slave_nodes = @parsed_hash['slave_nodes']
        hbase_install = @parsed_hash['hbase_install']
        hbase_master = @parsed_hash['hbase_master']
        @pcs.each do |pc|
          roles_hash[pc] = {}
          #java
          roles_hash[pc]['java'] = nil
          #namenode
          roles_hash[pc]['hadoop::namenode'] = nil if namenode.include?(pc)
          #zookeepers
          if @parsed_hash['hadoop_ha'] == 'enabled' or @parsed_hash['hbase_install'] == 'enabled'
            zookeepers = @parsed_hash['zookeeper_quorum']
            #convert zookeepers array into hash with id as zookeeper and value as its id
            zookeepers_id_hash = Hash[zookeepers.map.each_with_index.to_a]
            if zookeepers.include?(pc)
              roles_hash[pc]['zookeeper::server'] = { 'myid' => zookeepers_id_hash[pc] }
            end
          end
          #journal nodes
          if @parsed_hash['hadoop_ha'] == 'enabled'
            journal_nodes = @parsed_hash['journal_quorum']
            roles_hash[pc]['hadoop::journalnode'] = nil if journal_nodes.include?(pc)
          else
            #snn
            roles_hash[pc]['hadoop::secondarynamenode'] if secondary_namenode == pc
          end
          #mapreduce
          if mapreduce_type == 'mr1'
            roles_hash[pc]['hadoop::jobtracker'] = nil if mapreduce_master == pc
            roles_hash[pc]['hadoop::tasktracker'] = nil if slave_nodes.include?(pc)
          elsif mapreduce_type == 'mr2'
            if mapreduce_master == pc
              roles_hash[pc]['hadoop::resourcemanager'] = nil
              roles_hash[pc]['hadoop::jobhistoryproxyserver'] = nil
            end
            roles_hash[pc]['hadoop::nodemanager'] = nil if slave_nodes.include?(pc)
          end
          #ecosystem
          if mapreduce_master == pc
            #eco-system
            roles_hash[pc]['hadoop-hive'] = nil           if @parsed_hash['hadoop_ecosystem'].include?('hive')
            roles_hash[pc]['hadoop-pig'] = nil            if @parsed_hash['hadoop_ecosystem'].include?('pig')
            roles_hash[pc]['hadoop-sqoop'] = nil          if @parsed_hash['hadoop_ecosystem'].include?('sqoop')
            roles_hash[pc]['hadoop-pig'] = nil            if @parsed_hash['hadoop_ecosystem'].include?('pig')
            roles_hash[pc]['hadoop-oozie::server'] = nil  if @parsed_hash['hadoop_ecosystem'].include?('oozie')
            roles_hash[pc]['hadoop-oozie::client'] = nil  if @parsed_hash['hadoop_ecosystem'].include?('oozie')
          end
          #hdfs
          roles_hash[pc]['hadoop::datanode'] = nil if slave_nodes.include?(pc)
          #hbase
          if hbase_install == 'enabled'
            roles_hash[pc]['hbase::master'] = nil if hbase_master.include?(pc)
            roles_hash[pc]['hbase::regionserver'] = nil if slave_nodes.include?(pc)
          end
          #monitoring, alerting & security
          roles_hash[pc]['nagios::nrpe'] = nil if @parsed_hash['alerting'] == 'enabled'
          roles_hash[pc]['ganglia::client'] = nil if @parsed_hash['monitoring'] == 'enabled'
          roles_hash[pc]['kerberos::client'] = nil if @parsed_hash['security'] == 'enabled'
        end
        roles_hash
      end
    end
  end
end