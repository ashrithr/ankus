module Ankus
  module Inventory
    include Ankus

    # Generates server inventory files based on the hash passed from configuration parser
    class Generator
      # @param [String] config_file => path to the config file
      # @param [Hash] config => parsed configuration hash
      def initialize(config)
        @config  = config
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

      # Creates node definitions for the servers
      # @return [Hash] => Hash of node definitions as follows
      # { :node_tag(fully_qualified_domain_name) =>
      #   {
      #    :fqdn                  =>  "fully_qualified_domain_name (or) public ip",
      #    :private_ip            =>  '',
      #    :config                =>  {:os_type=>"CentOS", :volumes=>0, :volume_size=>250, :cores => 2, :ram => 4},
      #    :puppet_install_status =>  null,
      #    :puppet_run_status     =>  null,
      #    :last_run              =>  null,
      #    :tags                  =>  ["list of tags for this node"]
      #   }
      # }
      def create_nodes
        nodes_hash =  if File.exists?(NODES_FILE) && YamlUtils.parse_yaml(NODES_FILE).is_a?(Hash)
                        YamlUtils.parse_yaml(NODES_FILE)
                      else 
                        Hash.new
                      end
        @config = @config.deep_symbolize
        # Controller
        if @config[:controller] == 'localhost'
          add_or_update_node(nodes_hash, `hostname --fqdn`, 'controller')
        else
          add_or_update_node(nodes_hash, @config[:controller], 'controller')
        end
        # Hadoop and HBase
        if @config[:hadoop_deploy] != 'disabled'
          @config[:hadoop_deploy][:hadoop_namenode].each_with_index do |nn, i|
            add_or_update_node(nodes_hash, nn, "namenode#{i+1}")
          end
          if @config[:hadoop_deploy][:hadoop_ha] == 'enabled' or @config[:hbase_deploy] != 'disabled'
            @config[:zookeeper_quorum].each_with_index do |zk, i|
              add_or_update_node(nodes_hash, zk, "zookeeper#{i+1}") 
            end
          end
          if @config[:hadoop_deploy][:mapreduce] != 'disabled'
            add_or_update_node(nodes_hash, @config[:hadoop_deploy][:mapreduce][:master], "jobtracker") 
          end
          if @config[:hadoop_deploy][:hadoop_ha] == 'disabled'
            add_or_update_node(nodes_hash, @config[:hadoop_deploy][:hadoop_secondarynamenode], "secondarynamenode") 
          end
          if @config[:hbase_deploy] != 'disabled'
            @config[:hbase_deploy][:hbase_master].each_with_index do |hm, i|
              add_or_update_node(nodes_hash, hm, "hbasemaster#{i+1}")   
            end
          end
          @config[:slave_nodes].each_with_index do |hw, i|
            add_or_update_node(nodes_hash, hw, "slaves#{i+1}")
          end          
        end
        # Cassandra
        if @config[:cassandra_deploy] != 'disabled'
          @config[:cassandra_deploy][:cassandra_nodes].each_with_index do |cn, i|
            add_or_update_node(nodes_hash, cn, "cassandra#{i+1}")
          end
        end
        # Kafka
        if @config[:kafka_deploy] != 'disabled'
          @config[:kafka_deploy][:kafka_brokers].each_with_index do |kn, i|
            add_or_update_node(nodes_hash, kn, "kafka#{i+1}")
          end
        end
        if @config[:storm_deploy] != 'disabled'
          @config[:storm_deploy][:storm_supervisors].each_with_index do |sp, i|
            add_or_update_node(nodes_hash, sp, "storm#{i+1}")
          end
          add_or_update_node(nodes_hash, @config[:storm_deploy][:storm_master], 'stormnimbus')
        end
        if @config[:kafka_deploy] != 'disabled' or @config[:storm_deploy] != 'disabled'
          @config[:zookeeper_quorum].each_with_index do |zk, i|
            add_or_update_node(nodes_hash, zk, "zookeeper#{i+1}") 
          end          
        end
        if @config[:solr_deploy] != 'disabled'
          @config[:solr_deploy][:solr_nodes].each_with_index do |sn, i|
            add_or_update_node(nodes_hash, sn, "solr#{i+1}")
          end
        end

        nodes_hash
      end # end create_nodes

      # Create abstraction around node object
      def create_node(fqdn, tags)
        {
          :fqdn => fqdn,
          :private_ip => '',
          :config => fetch_host_info(fqdn),
          :puppet_install_status => false,
          :puppet_run_status => false,
          :last_run => '',
          :tags => tags
        }        
      end #end create_node

      # Either creates a new node definition or if node already exists updates the node tag
      def add_or_update_node(nodes, fqdn, tag)
        existing_nodes = []
        nodes.each do |k,v|
          existing_nodes << v[:fqdn]
        end
        existing_nodes.uniq!
        if existing_nodes.include? fqdn
          nodes[fqdn][:tags] << tag unless nodes[fqdn][:tags].include?(tag)
        else
          nodes[fqdn] = create_node(fqdn, [tag])
        end
        return nodes
      end      

      # Get the host configuration such as number of cores, amount of ram for given node
      def fetch_host_info(fqdn)
        {
          :ram => 0,
          :cores => 0
        }
      end
    end

    # Build yaml file of host to puppet roles mapping; used by puppet external node classifier script
    class EncData

      # @param [String] nodes_file => path of the nodes yaml file
      # @param [String] roles_file => path of the file to be created with mapping
      # @param [Hash] config => parsed configuration file
      # @param [String] puppet_server => fqdn of puppet server
      # @param [Array] puppet_clients => list of puppet clients
      def initialize(nodes_file, roles_file, config, puppet_server, puppet_clients)
        @nodes_file   = nodes_file
        @roles_file   = roles_file
        @config       = config
        @ps           = puppet_server
        @pcs          = puppet_clients
      end

      # Write out the mapping created by 'create_enc_roles()' into @roles_file
      def generate
        YamlUtils.write_yaml(create_enc_roles, @roles_file)
      end

      private

      # Create hash of nodes to roles mapping using @config
      def create_enc_roles
        roles_hash = Hash.new

        roles_hash[@ps]                     = {}
        # roles_hash[@ps]['java']             = nil
        roles_hash[@ps]['nagios::server']   = nil if @config[:alerting] == 'enabled'
        roles_hash[@ps]['ganglia::server']  = nil if @config[:monitoring] == 'enabled'
        roles_hash[@ps]['kerberos::server'] = nil if @config[:security] == 'kerberos'
        roles_hash[@ps]['logstash']         = { 'role' => 'indexer' } if @config[:log_aggregation] == 'enabled'

        # puppet clients
        hadoop_install      = @config[:hadoop_deploy]
        if hadoop_install != 'disabled'
          namenode            = @config[:hadoop_deploy][:hadoop_namenode]
          secondary_namenode  = @config[:hadoop_deploy][:hadoop_secondarynamenode]
          mapreduce           = @config[:hadoop_deploy][:mapreduce]
          mapreduce_type      = @config[:hadoop_deploy][:mapreduce][:type] if mapreduce != 'disabled'
          mapreduce_master    = @config[:hadoop_deploy][:mapreduce][:master] if mapreduce != 'disabled'
          hadoop_ecosystem    = @config[:hadoop_deploy][:hadoop_ecosystem]
          slave_nodes         = @config[:slave_nodes]
          hbase_install       = @config[:hbase_deploy]
          hbase_master        = @config[:hbase_deploy][:hbase_master] if hbase_install != 'disabled'
        end
        cassandra_install   = @config[:cassandra_deploy]
        cassandra_nodes     = @config[:cassandra_deploy][:cassandra_nodes] if cassandra_install != 'disabled'
        solr_install        = @config[:solr_deploy]
        solr_nodes          = @config[:solr_deploy][:solr_nodes] if solr_install != 'disabled'
        kafka_install       = @config[:kafka_deploy]
        kafka_brokers       = @config[:kafka_deploy][:kafka_brokers] if kafka_install != 'disabled'
        storm_install       = @config[:storm_deploy]
        storm_master        = @config[:storm_deploy][:storm_master] if storm_install != 'disabled'
        storm_supervisors   = @config[:storm_deploy][:storm_supervisors] if storm_install != 'disabled'
        @pcs.each do |pc|
          roles_hash[pc] = {}
          #java
          roles_hash[pc]['java'] = nil
          if hadoop_install != 'disabled'
            #namenode
            roles_hash[pc]['hadoop::namenode'] = nil if namenode.include? pc
            #zookeepers
            if @config[:hadoop_deploy][:hadoop_ha] == 'enabled' or @config[:hbase_deploy] != 'disabled' or
                @config[:solr_deploy] != 'disabled' or @config[:kafka_deploy] != 'disabled' or
                @config[:storm_deploy] != 'disabled'
              zookeepers = @config[:zookeeper_quorum]
              #convert zookeepers array into hash with id as zookeeper and value as its id
              zookeepers_id_hash = Hash[zookeepers.map.each_with_index.to_a]
              if zookeepers.include? pc
                roles_hash[pc]['zookeeper::server'] = { 'myid' => zookeepers_id_hash[pc] }
              end
            end
            #journal nodes
            if @config[:hadoop_deploy][:hadoop_ha] == 'enabled'
              journal_nodes = @config[:hadoop_deploy][:journal_quorum]
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
            roles_hash[pc]['kerberos::client'] = nil if @config[:security] == 'kerberos'
          end
          #monitoring, alerting
          roles_hash[pc]['nagios::nrpe'] = nil if @config[:alerting] == 'enabled'
          roles_hash[pc]['ganglia::client'] = nil if @config[:monitoring] == 'enabled'
          ##log aggregation
          #if @config['log_aggregation'] == 'enabled'
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
          if solr_install != 'disabled'
            if solr_install[:hdfs_integration] != 'disabled'
              roles_hash[pc]['hadoop-search::server'] = nil if solr_nodes.include? pc
            else
              roles_hash[pc]['solr::server'] = nil if solr_nodes.include? pc
            end
          end
          if kafka_install != 'disabled'
            roles_hash[pc]['kafka::server'] = nil if kafka_brokers.include? pc
          end
          if storm_install != 'disabled'
            roles_hash[pc]['storm::worker'] = nil if storm_supervisors.include? pc
            roles_hash[pc]['storm::nimbus'] = nil if storm_master.include? pc
            roles_hash[pc]['storm::ui'] = nil if storm_master.include? pc
          end
        end
        roles_hash
      end
    end
  end
end
