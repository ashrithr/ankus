module Ankuscli

  # ConfigParser parses the configuration file of ankus and returns a hash to process upon
  class ConfigParser
    include Ankuscli

    # Creates a configParser object with specified file_path, and a parsed_hash object
    #
    # file_path:: path to the ankuscli configuration file
    #
    def initialize(file_path)
      @config_file = file_path
      @parsed_hash = {}
    end

    # Parses the configuration file, validates it and returns a hash
    # @return [Hash]
    def parse_config
      @parsed_hash = YamlUtils.parse_yaml(@config_file)
      validator(@parsed_hash)
      @parsed_hash
    rescue
      exit 1
    end

    private

    # Validates the loaded configuration file
    def validator(hash_to_validate)
      #validate install_mode, it can be 'local|cloud' modes
      if hash_to_validate['install_mode'] == 'local'
        local_validator(hash_to_validate)
      elsif hash_to_validate['install_mode'] == 'cloud'
        cloud_validator(hash_to_validate)
      elsif hash_to_validate['install_mode'].nil?
        puts '[Error]:'.red + ' install_mode cannot be null'
        exit 1
      else
        puts <<-EOF
          [Error]: Not supported install mode
          Supported modes: local | cloud
          ex: install_mode: local
        EOF
      end
    end

    # Validations specific to local install_mode
    def local_validator(hash_to_validate)
      puts 'calling local validator'
      #required:
        #controller:
      if hash_to_validate['controller'].nil? or hash_to_validate['controller'].empty?
        puts '[Error]:'.red + ' controller is required for local install_mode'
        exit 1
      end
        #root_ssh_key
      if hash_to_validate['root_ssh_key'].nil? or hash_to_validate['root_ssh_key'].empty?
        puts '[Error]:'.red + ' root_ssh_key is required for local install_mode'
        exit 1
      else
        #check if root_ssh_key has valid key path
        if File.exists? File.expand_path(hash_to_validate['root_ssh_key'])
          common_validator(hash_to_validate)
        else
          puts '[Error]:'.red + " root_ssh_key: #{hash_to_validate['root_ssh_key']} does not exists"
          exit 1
        end
      end
    end

    # Validations specific to cloud install_mode
    def cloud_validator(hash_to_validate)
      puts 'calling cloud validator'
      #TODO validate cloud credentials
      common_validator(hash_to_validate)
    end

    # Validates params which are common for both local and cloud install_modes
    def common_validator(hash_to_validate)
      puts 'calling common validator'
      install_mode = hash_to_validate['install_mode']
      hadoop_ha = hash_to_validate['hadoop_ha']
      hbase_install = hash_to_validate['hbase_install']
      hadoop_ecosystem = hash_to_validate['hadoop_ecosystem']
      mapreduce = hash_to_validate['mapreduce']
      mapreduce_type = hash_to_validate['mapreduce']['type']
      mapreduce_master = hash_to_validate['mapreduce']['master_node']
      valid_hadoop_ecosystem = %w(hive pig sqoop oozie hue flume)
      security = hash_to_validate['security']
      monitoring = hash_to_validate['monitoring']
      alerting = hash_to_validate['alerting']

      if hadoop_ha.nil? or hadoop_ha.empty?
        puts '[Error]:'.red + ' hadoop_ha is required parameter and it should be either enabled|disabled'
        exit 1
      elsif ! %w(enabled disabled).include?(hadoop_ha)
        puts '[Error]:'.red ' invalid value for hadoop_ha, valid values are enabled|disabled'
        exit 1
      end

      if install_mode == 'local'
        #validate slave nodes
        slave_nodes = hash_to_validate['slave_nodes']
        if slave_nodes.nil? or slave_nodes.empty?
          puts '[Error]:'.red + ' slave_nodes are required in local install_mode'
          exit 1
        elsif ! slave_nodes.kind_of?(Array)
          puts '[Error]:'.red + ' Expecting list of slave nodes'
          exit 1
        end
      end

      #mapreduce framework, it can be ignored if setting up hbase-centric cluster
      #if hbase_install == 'disabled'
      #  puts '[Error]: Invalid mapreduce type' unless %w(mr1 mr2).include?(mapreduce_type)
      #  if mapreduce_master.nil? or mapreduce_master.empty?
      #    puts '[Error]: mapreduce_master is required'
      #    exit 1
      #  end
      #end
      #if mapreduce option is set then mapreduce_type and mapreduce_master are required
      if mapreduce
        puts '[Error]:'.red + ' Invalid mapreduce type' unless %w(mr1 mr2).include?(mapreduce_type)
        if mapreduce_master.nil? or mapreduce_master.empty?
          puts '[Error]:'.red + ' mapreduce_master is required'
          exit 1
        end
      end

      #hadoop_ecosystem
      if hadoop_ecosystem
        hadoop_ecosystem.each do |tool|
          unless valid_hadoop_ecosystem.include?(tool)
            puts '[Error]:'.red + "hadoop_ecosystem can support #{valid_hadoop_ecosystem}"
            puts "  #{tool} specified cannot be part of deployment yet!"
            exit 1
          end
        end
      end

      #security
      if security.nil? or security.empty?
        puts '[Error]:'.red + ' security is required parameter, valid values: enabled|disabled'
        exit 1
      elsif ! %w(simple kerberos).include?(security)
        puts '[Error]:'.red + ' invalid value for security, valid values: simple|kerberos'
        exit 1
      end
      if security == 'enabled'
        #if security is enabled
        realm_name = hash_to_validate['hadoop_kerberos_realm']
        domain_name = hash_to_validate['hadoop_kerberos_domain']
        if realm_name.nil? or realm_name.empty?
          puts '[Error]: '.red + 'kerberos realm name is required if security is enabled'
          exit 1
        end
        if domain_name.nil? or domain_name.empty?
          puts '[Error]: '.red + 'kerberos domain name is required if security is enabled'
          exit 1
        end
      end

      #monitoring
      if monitoring.nil? or monitoring.empty?
        puts '[Error]:'.red + ' monitoring is required parameter, valid values: enabled|disabled'
        exit 1
      elsif ! %w(enabled disabled).include?(monitoring)
        puts '[Error]:'.red + ' invalid value for monitoring, valid values: enabled|disabled'
      end

      #alerting
      if alerting.nil? or alerting.empty?
        puts '[Error]:'.red + ' alerting is required parameter, valid values: enabled|disabled'
        exit 1
      elsif ! %w(enabled disabled).include?(alerting)
        puts '[Error]:'.red + ' invalid value for alerting, valid values: enabled|disabled'
      end

      #admin_email
      if alerting and alerting == 'enabled'
        admin_email = hash_to_validate['admin_email']
        if admin_email.nil? or admin_email.empty?
          puts '[Error]:'.red + ' admin_email is required parameter, valid values: enabled|disabled'
          exit 1
        end
      end

      #hbase_install
      if hbase_install.nil? or hbase_install.empty?
        puts '[Error]:'.red + ' hbase_install is required parameter, valid values: enabled|disabled'
        exit 1
      elsif ! %w(enabled disabled).include?(hbase_install)
        puts '[Error]:'.red + ' invalid value for hbase_install, valid values: enabled|disabled'
      end

      #call hadoop validator
      if install_mode == 'local'
        hadoop_namenode = hash_to_validate['hadoop_namenode']
        zookeeper_quorum = hash_to_validate['zookeeper_quorum']
        journal_quorum = hash_to_validate['journal_quorum']
        hadoop_snn = hash_to_validate['hadoop_secondarynamenode']
        hadoop_validator(hadoop_ha, hadoop_namenode, hadoop_snn, mapreduce_type, mapreduce_master, zookeeper_quorum, journal_quorum, slave_nodes)
        if hbase_install == 'enabled'
          hbase_master = hash_to_validate['hbase_master']
          hbase_validator(hbase_master, zookeeper_quorum)
        end
      end

    end

    # Validates hadoop related conf params for local install_mode
    def hadoop_validator(hadoop_ha, hadoop_namenode, hadoop_snn, mapreduce_type, mapreduce_master, zookeeper_quorum, journal_quorum, slave_nodes)
      puts 'calling hadoop validator'
      if hadoop_ha == 'enabled'
        #### HA Specific
        unless hadoop_namenode.length == 2
          puts '[Error]:'.red + ' in hadoop ha, two namenode\'s are required'
          exit 1
        end
        #namenodes and zookeepers cannot co-exist
        zookeeper_quorum.each do |zk|
          if hadoop_namenode.include?(zk)
            puts '[Error]:'.red + ' zookeeper and namenode cannot co-exist on same machine'
            exit 1
          end
          if slave_nodes.include?(zk)
            puts '[Error]:'.red + ' zookeeper and datanode cannot co-exist on same machine'
            exit 1
          end
        end
        #journal nodes and zookeepers cannot coexist as well
        journal_quorum.each do |jn|
          if hadoop_namenode.include?(jn)
            puts '[Error]:'.red + ' journalnode and namenode cannot co-exist'
            exit 1
          end
          if slave_nodes.include?(jn)
            puts '[Error]:'.red + ' journalnode and datanode cannot co-exist on same machine'
            exit 1
          end
        end
        #check if namenode's are reachable
        hadoop_namenode.each do |namenode|
          unless Ankuscli::PortUtils.port_open?(namenode, 22, 2)
            puts '[Error]:'.red + "namenode: #{namenode} is not reachable"
            exit 1
          end
        end
        #namenodes cannot be same
        if hadoop_namenode.uniq.length != hadoop_namenode.length
          puts '[Error]:'.red + ' namenode\'s cannot be the same in ha deployment mode'
          exit 1
        end
        #check zookeepers and journal_nodes for oddity
        puts '[Warn]:'.yellow + 'zookeepers should be odd number to handle failover\'s, please update when possible' unless zookeeper_quorum.length % 2 == 1
        puts '[Warn]:'.yellow + 'journal nodes should be odd number to handle failover\'s, please update when possible' unless journal_quorum.length % 2 == 1
        #zookeepers cannot be same
        if zookeeper_quorum.uniq.length != zookeeper_quorum.length
          puts '[Error]:'.red + ' zookeeper\'s cannot be the same'
          exit 1
        end
        #journal nodes cannot be same
        if journal_quorum.uniq.length != journal_quorum.length
          puts '[Error]:'.red + ' journal node\'s cannot be the same'
          exit 1
        end
        #check if zookeeper's & journal node's are reachable
        zookeeper_quorum.each do |zk|
          unless Ankuscli::PortUtils.port_open?(zk, 22, 2)
            puts '[Error]:'.red + "zookeeper: #{zk} is not reachable"
            exit 1
          end
        end
        journal_quorum.each do |jn|
          unless Ankuscli::PortUtils.port_open?(jn, 22, 2)
            puts '[Error]:'.red + "journal node: #{jn} is not reachable"
            exit 1
          end
        end
      else
        #### NON-HA Specific
        #check for one namenode
        unless hadoop_namenode.length == 1
          puts '[Warn]:'.yellow + ' Expecting one namenode for non-ha deployment mode'
        end
        namenode = if hadoop_namenode.kind_of?(Array)
                     hadoop_namenode.first
                   else
                     hadoop_namenode
                   end
        if hadoop_snn.nil? or hadoop_snn.empty?
          puts '[Warn]:'.yellow + ' No secondary namenode host found, its recommended to use one'
        else
          unless Ankuscli::PortUtils.port_open?(hadoop_snn, 22, 2)
            puts '[Error]:'.red + " snn: #{hadoop_snn} is not reachable"
            exit 1
          end
        end
        unless Ankuscli::PortUtils.port_open?(namenode, 22, 2)
          puts '[Error]:'.red + " namenode:#{namenode} is not reachable"
          exit 1
        end
      end
      #mr framework
      if mapreduce_type
        #check for master_node is alive
        unless Ankuscli::PortUtils.port_open?(mapreduce_master, 22, 2)
          puts '[Error]:'.red + " mapreduce_master:#{mapreduce_master} is not reachable"
          exit 1
        end
      end
    end

    # Validates hbase related conf params for local install_mode
    def hbase_validator(hbase_master, zookeeper_quorum)
      #hbase_master
      if hbase_master.kind_of?(Array)
        hbase_master.each do |hm|
          unless Ankuscli::PortUtils.port_open?(hm, 22, 2)
            puts '[Error]:'.red + " hbase_master: #{hm} is not reachable"
            exit 1
          end
        end
      end
      #zookeeper_quorum
      puts "[Warn]: zookeepers should be odd number to handle failover's, please update when possible" unless zookeeper_quorum.length % 2 == 1
      if zookeeper_quorum.kind_of?(Array)
        zookeeper_quorum.each do |zk|
          unless Ankuscli::PortUtils.port_open?(zk, 22, 2)
            puts '[Error]:'.red + " zookeeper: #{zk} is not reachable"
            exit 1
          end
        end
      end
    end
  end

  #class to parse ankus_hadoop_config.yaml
  class HadoopConfigParser
    def initialize(hadoop_conf)

    end
  end
end