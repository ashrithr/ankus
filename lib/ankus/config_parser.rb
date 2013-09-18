module Ankus

  # ConfigParser: parses the configuration file of ankus and returns a hash to process upon
  class ConfigParser
    require 'ankus/helper'
    include Ankus

    # Creates a configParser object with specified file_path, and a parsed_hash object
    # @param [String] file_path => path to the configuration file to parse
    # @param [Boolean] debug => if enabled will log info to stdout
    def initialize(file_path, debug=false)
      @config_file = file_path
      @parsed_hash = {}
      @debug = debug
      @errors_count = 0
    end

    # Parses the configuration file, validates it and returns a hash
    # @return [Hash] @parsed_hash => parsed configuraion hash
    def parse_config
      @parsed_hash = Settings.load! @config_file
      validate @parsed_hash
      unless @errors_count == 0
        puts "\rNumber of Errors: #{@errors_count}"
        puts 'Parsing config file ... ' + '[Failed]'.red.bold
        raise(Ankus::Errors::ParseError.new("\rParsing Configuration Failed".red))
      end
      create_req_files
      @parsed_hash
    rescue Ankus::Errors::ParseError, Ankus::Errors::ParseError::NoKey
      puts "#{$!.message} (#{$!.class})"
      exit
    rescue
      puts "#{$!.message} (#{$!.class})"
      puts $@ if @debug
      exit
    end

    private

    # Validates the loaded configuration file
    # @param [Hash] hash_to_validate => hash to validate
    def validate(hash_to_validate)
      unless hash_to_validate
        puts '[Error]: '.red + 'config file is empty!'
        @errors_count += 1
      end
      #validate if basic comfiguration parameters are present or not
      ANKUS_CONF_MAIN_KEYS.each do |key|
        unless hash_to_validate.include?(key)
          puts '[Error]: '.red + "Required key: '#{key}' is not present in the configuration file"
          @errors_count += 1
        end
      end
      #validate install_mode, it can be 'local|cloud' modes
      case @parsed_hash[:install_mode]
      when 'local'
        local_validator hash_to_validate
      when 'cloud'
        cloud_validator hash_to_validate
      when nil
        puts '[Error]:'.red + " 'install_mode' cannot be empty"
        @errors_count += 1        
      else
        puts <<-EOF.undent
          [Error]: Not supported install mode
          Supported modes: local | cloud
          ex: install_mode: local
        EOF
      end
    end

    # Creates set of files and directories required by ankus
    def create_req_files
      Dir.mkdir DATA_DIR                unless File.exists? DATA_DIR
      FileUtils.touch NODES_FILE        unless File.exists? NODES_FILE
      FileUtils.touch NODES_FILE_CLOUD  unless File.exists? NODES_FILE_CLOUD
      FileUtils.touch CLOUD_INSTANCES   unless File.exists? CLOUD_INSTANCES
      FileUtils.touch ENC_ROLES_FILE    unless File.exists? ENC_ROLES_FILE
      FileUtils.touch HIERA_DATA_FILE   unless File.exists? HIERA_DATA_FILE
    end

    # Validations specific to local install_mode
    # @param [Hash] hash_to_validate => hash to validate
    def local_validator(hash_to_validate)
      puts '[Debug]: Calling local validator' if @debug
      #controller:
      if hash_to_validate[:controller].nil? or hash_to_validate[:controller].empty?
        puts '[Error]:'.red + " 'controller' is required for local install_mode"
        @errors_count += 1
      end
      #ssh_key
      if hash_to_validate[:ssh_key].nil? or hash_to_validate[:ssh_key].empty?
        puts '[Error]:'.red + " 'ssh_key' is required for local install_mode"
        @errors_count += 1
      else
        #check if ssh_key has valid key path
        unless File.exists? File.expand_path(hash_to_validate[:ssh_key])
          puts '[Error]:'.red + " 'ssh_key': #{hash_to_validate[:ssh_key]} does not exists"
          @errors_count += 1
        end
      end
      #ssh_user
      if hash_to_validate[:ssh_user].nil? or hash_to_validate[:ssh_user].empty?
        puts '[Debug]: \'ssh_user\' is not specified assuming ssh_user as \'root\'' if @debug
        hash_to_validate[:ssh_user] = 'root'
      end
      #volumes
      if hash_to_validate[:storage_dirs].nil? or hash_to_validate[:storage_dirs].empty?
        puts '[Error]: '.red + "''storage_dirs' is a required property"
        @errors_count += 1
      elsif ! hash_to_validate[:storage_dirs].is_a? Array
        puts '[Error]: '.red + "expecting list(array) of 'storage_dirs'"
        @errors_count += 1
      else
        #validate absolute path
        require 'pathname'
        hash_to_validate[:storage_dirs].each do |dir|
          unless Pathname.new(dir).absolute?
            puts '[Error]: '.red "Invalid absolute path found in 'storage_dirs' (#{dir})"
            @errors_count += 1
          end
        end
      end

      # call common validator which inturn will call other validators and gets back to check
      # if hosts are up or not
      common_validator(hash_to_validate)

      # force user to use hostname instead of ipaddress
      nodes = Inventory::Generator.new(@config_file, @parsed_hash).generate
      ( all_nodes ||= [] ) << nodes[:puppet_server]
      nodes[:puppet_clients].each {|pc| all_nodes << pc }
      all_nodes.each do |node|
        unless node =~ HOSTNAME_REGEX
          puts '[Error]: '.red + "Expecting hostname got ipaddress @ #{node}".red
          @errors_count += 1
        end
      end
      all_nodes.each do |node|
        unless Ankus::PortUtils.port_open?(node, 22, 2)
          puts '[Error]: '.red + "Node: #{node} is not reachable"
          @errors_count += 1
        end
      end
    end

    # Validations specific to cloud install_mode
    # @param [Hash] hash_to_validate => hash to validate
    def cloud_validator(hash_to_validate)
      puts '[Debug]: Calling cloud validator' if @debug
      cloud_platform = hash_to_validate[:cloud_platform]
      cloud_credentials = hash_to_validate[:cloud_credentials]
      cloud_os_type = hash_to_validate[:cloud_os_type]
      volumes = hash_to_validate[:volumes]

      # cloud platform => aws, rackspace
      if cloud_platform.nil? or cloud_platform.empty?
        puts '[Error]:'.red + " 'cloud_platform' is required for cloud install_mode"
        @errors_count += 1
      elsif ! %w(aws rackspace).include?(cloud_platform)
        puts '[Error]:'.red + " invalid value for 'cloud_platform', supported values are aws|rackspace"
        @errors_count += 1
      end

      # cloud credentials
      if cloud_credentials.nil? or cloud_credentials.empty?
        puts '[Error]:'.red + " 'cloud_credentials' is required for cloud install_mode"
        @errors_count += 1
      elsif ! cloud_credentials.is_a?(Hash)
        puts '[Error]:'.red + " 'cloud_credentials' is malformed, look sample cloud config for example"
        @errors_count += 1
      end
      if cloud_platform == 'aws'
        valid_credentials = { :aws_access_id => '',
                              :aws_secret_key => '',
                              :aws_machine_type => '',
                              :aws_region => '',
                              :aws_key => ''
        }
        unless cloud_credentials.keys.sort == valid_credentials.keys.sort
          puts '[Error]:'.red + " 'cloud_credentials' is malformed/invalid, look sample cloud config for example"
          @errors_count += 1
        end
        if cloud_credentials[:aws_secret_key].length == 0
          puts '[Error]: '.red + 'aws_secret_key are missing'
          @errors_count += 1
        elsif cloud_credentials[:aws_access_id].length == 0
          puts '[Error]: '.red + 'aws_access_id are missing'
          @errors_count += 1
        end
        if cloud_credentials[:aws_sec_groups]
          unless cloud_credentials[:aws_sec_groups].is_a?(Array)
            puts '[Error]: '.red + 'expecting list(array) representation of groups for \'aws_sec_groups\''
            @errors_count += 1
          end
        end

        # validate aws connection
        puts '[Debug]: Validating aws connection' if @debug
        aws = Aws.new(cloud_credentials[:aws_access_id], 
          cloud_credentials[:aws_secret_key], 
          cloud_credentials[:aws_region]
          )
        unless aws.valid_connection?(aws.create_connection)
          puts '[Error]: '.red + 'failed establishing connection to aws, check your credentials'
          exit 2
        end
      elsif cloud_platform == 'rackspace'
        valid_credentials = {
                              :rackspace_username => '',
                              :rackspace_api_key => '',
                              :rackspace_instance_type => '',
                              :rackspace_ssh_key => '',
                              :rackspace_cluster_identifier => ''
                            }
        unless cloud_credentials.keys.sort == valid_credentials.keys.sort
          puts '[Error]:'.red + " 'cloud_credentials' is malformed/invalid, look sample cloud config for example"
          @errors_count += 1
        end
        if cloud_credentials[:rackspace_username].length == 0
          puts '[Error]: '.red + 'rackspace_username are missing'
          @errors_count += 1
        elsif cloud_credentials[:rackspace_api_key].length == 0
          puts '[Error]: '.red + 'rackspace_api_key are missing'
          @errors_count += 1
        end
        #validate ssh key
        if cloud_credentials[:rackspace_ssh_key].nil? or cloud_credentials[:rackspace_ssh_key].empty?
          puts '[Error]:'.red + ' rackspace_ssh_key is required'
          @errors_count += 1
        else
          #check if ssh_key has valid key path
          unless File.exists? File.expand_path(cloud_credentials[:rackspace_ssh_key])
            puts '[Error]:'.red + " ssh_key: #{cloud_credentials[:rackspace_ssh_key]} does not exists"
            @errors_count += 1
          end
        end
        # validate cluster identifier
        if cloud_credentials[:rackspace_cluster_identifier].length == 0
          puts '[Debug]: rackspace_cluster_identifier is not set, using the default: \'ops\''
          hash_to_validate[:rackspace_cluster_identifier] = 'ops'
        else
          hash_to_validate[:rackspace_cluster_identifier] = cloud_credentials[:rackspace_cluster_identifier]
        end
        # validate connection
        rackspace = Rackspace.new(cloud_credentials[:rackspace_api_key], cloud_credentials[:rackspace_username])
        unless rackspace.valid_connection?(rackspace.create_connection)
          puts '[Error]:'.red + ' failed establishing connection to rackspace, check your credentials'
        end
      end

      # cloud os type to boot
      if cloud_os_type.nil? or cloud_os_type.empty?
        puts '[Error]:'.red + " 'cloud_os_type' is required for cloud install_mode"
        @errors_count += 1
      elsif ! %w(centos ubuntu).include?(cloud_os_type.downcase)
        puts '[Error]:'.red + " supported 'cloud_os_type' values are centos|ubuntu"
        @errors_count += 1
      end

      # volumes => Hash of volumes count and size
      if volumes.nil? or volumes.empty?
        puts '[Error]: '.red + 'volumes should be specified'
        @errors_count += 1
      elsif volumes == 'disabled'
        puts '[Debug]: ' + '(Warning)'.yellow + ' No volumes will be created and attached to instances' if @debug
      elsif ! volumes.is_a? Hash
        puts '[Error]: '.red + "unrecognized value set for 'volumes' : #{volumes}"
        @errors_count += 1
      end
      if volumes and volumes != 'disabled' and volumes.is_a? Hash
        if cloud_platform == 'aws'
          #volumes type
          if volumes[:type].nil? or volumes[:type].empty?
            puts '[Error]: '.red + "type of the volumes is required 'type'"
            @errors_count += 1
          elsif ! %w(ebs io1).include? volumes[:type]
            puts '[Error]: '.red + "invalid value found for volume type (#{volumes[:type]}, valid values are 'ebs' or 'instancestore')"
            @errors_count += 1
          end
          #iops
          if volumes[:type] and volumes[:type] == 'io1'
            if volumes[:iops].nil?
              puts '[Error]: '.red + "'iops' rate is required if type of volume being booted is io1"
              @errors_count += 1
            elsif ! volumes[:iops].is_a? Numeric
              puts '[Error]: '.red + "iops rate should be of type numeric 'iops'"
              @errors_count += 1
            elsif ! volumes[:iops].between?(1, 4000)
              puts '[Error]: '.red + "iops rate should be in between 1-4000 'iops'"
              @errors_count += 1
            end
          end
          #volumes count
          if volumes[:count].nil?
            puts '[Error]: '.red + "count of the volumes is required 'count'"
            @errors_count += 1
          elsif ! volumes[:count].is_a? Numeric
            puts '[Error]: '.red + "count of the volumes should be of type numeric 'count'"
            @errors_count += 1
          elsif volumes[:count] == 0
            puts '[Error]: '.red + "volumes count should be > 0, if you dont want volumes to be mounted use 'volumes: disabled'"
            @errors_count += 1
          end
          #volumes size
          if volumes[:size].nil?
            puts '[Error]: '.red + "size of the volumes is required 'size'"
            @errors_count += 1
          elsif ! volumes[:size].is_a? Numeric
            puts '[Error]: '.red + "'size' of the volumes should be of type numeric"
            @errors_count += 1
          elsif volumes[:size] == 0
            puts '[Error]: '.red + "volumes size should be > 0, if you dont want volumes to be mounted use 'volumes: disabled'"
            @errors_count += 1
          end
        elsif cloud_platform == 'rackspace'
          #volumes type
          if volumes[:type].nil? or volumes[:type].empty?
            puts '[Error]: '.red + "type of the volumes is required 'type'"
            @errors_count += 1
          elsif ! %w(blockstore).include? volumes[:type]
            puts '[Error]: '.red + "invalid value found for volume type (#{volumes[:type]}, valid value is 'blockstore')"
            @errors_count += 1
          end
          #volumes count
          if volumes[:count].nil?
            puts '[Error]: '.red + "count of the volumes is required 'count'"
            @errors_count += 1
          elsif ! volumes[:count].is_a? Numeric
            puts '[Error]: '.red + "count of the volumes should be of type numeric 'count'"
            @errors_count += 1
          elsif volumes[:count] == 0
            puts '[Error]: '.red + "volumes count should be > 0, if you dont want volumes to be mounted use 'volumes: disabled'"
            @errors_count += 1
          end
          #volumes size
          if volumes[:size].nil?
            puts '[Error]: '.red + "size of the volumes is required 'size'"
            @errors_count += 1
          elsif ! volumes[:size].is_a? Numeric
            puts '[Error]: '.red + "'size' of the volumes should be of type numeric"
            @errors_count += 1
          elsif volumes[:size] == 0
            puts '[Error]: '.red + "volumes size should be > 0, if you dont want volumes to be mounted use 'volumes: disabled'"
            @errors_count += 1
          end
        end
        puts "\r[Debug]: Instances will be booted with '#{volumes[:count]}' volumes of type(#{volumes[:type]}) each with size(#{volumes[:size]}GB)" if @debug
      end

      #add ssh_user to hash
      hash_to_validate[:ssh_user] =  if cloud_os_type.downcase == 'centos'
                                        'root'
                                      elsif cloud_os_type.downcase == 'ubuntu' and cloud_platform.downcase == 'aws'
                                        'ubuntu'
                                      else
                                        'root'
                                      end

      common_validator(hash_to_validate)
    end

    # Validates params which are common for both local and cloud install_modes
    # @param [Hash] hash_to_validate => hash to validate
    def common_validator(hash_to_validate)
      puts '[Debug]: Calling common validator' if @debug
      install_mode = hash_to_validate[:install_mode]
      security = hash_to_validate[:security]
      monitoring = hash_to_validate[:monitoring]
      alerting = hash_to_validate[:alerting]
      log_aggregation = hash_to_validate[:log_aggregation]

      #security
      if security.nil? or security.empty?
        puts '[Error]:'.red + " 'security' is required parameter, valid values: enabled|disabled"
        @errors_count += 1
      elsif ! %w(simple kerberos).include?(security)
        puts '[Error]:'.red + " invalid value for 'security', valid values: simple|kerberos"
        @errors_count += 1
      end
      if security == 'kerberos'
        #if security is enabled
        realm_name = hash_to_validate[:hadoop_kerberos_realm]
        domain_name = hash_to_validate[:hadoop_kerberos_domain]
        if realm_name.nil? or realm_name.empty?
          puts '[Debug]: ' + 'Kerberos realm name is not provided, using default realm name' if @debug
        end
        if domain_name.nil? or domain_name.empty?
          puts '[Debug]: ' + 'Kerberos domain name is not provided, using default domain name' if @debug
        end
      end

      #monitoring
      if monitoring.nil? or monitoring.empty?
        puts '[Error]:'.red + " 'monitoring' is required parameter, valid values: enabled|disabled"
        @errors_count += 1
      elsif ! %w(enabled disabled).include?(monitoring)
        puts '[Error]:'.red + " invalid value for 'monitoring', valid values: enabled|disabled"
      end

      #alerting
      if alerting.nil? or alerting.empty?
        puts '[Error]:'.red + " 'alerting' is required parameter, valid values: enabled|disabled"
        @errors_count += 1
      elsif ! %w(enabled disabled).include?(alerting)
        puts '[Error]:'.red + " invalid value for 'alerting', valid values: enabled|disabled"
      end

      #admin_email
      if alerting and alerting == 'enabled'
        admin_email = hash_to_validate[:admin_email]
        if admin_email.nil? or admin_email.empty?
          puts '[Error]:'.red + " 'admin_email' is required parameter, valid values: enabled|disabled"
          @errors_count += 1
        end
      end

      #log_aggregation
      if log_aggregation.nil? or log_aggregation.empty?
        puts '[Error]:'.red + " 'log_aggregation' is required parameter, valid values: enabled|disabled"
      elsif ! %w(enabled disabled).include?(log_aggregation)
        puts '[Error]:'.red + " invalid value for 'log_aggregation', valid values: enabled|disabled"
      end

      #call hadoop validator
      if hash_to_validate[:hadoop_deploy] != 'disabled'
        # call hadoop_validator
        hadoop_validator hash_to_validate
      end

      if hash_to_validate[:hbase_deploy] != 'disabled'
        hbase_validator hash_to_validate
      end

      zookeeper_validator hash_to_validate

      cassandra_validator hash_to_validate

      kafka_validator hash_to_validate

      storm_validator hash_to_validate

      #Check to see if all the deploy options are disabled if so raise
      if ANKUS_CONF_DEPLOY_KEYS.map { |e| hash_to_validate[e] }.uniq.length == 1
        puts '[Error]:'.red + " All the deploy(s) are disabled, atleast one deploy should be configured"
        @errors_count += 1
      end
    end

    # Validates hadoop related conf params for local install_mode
    # @param [String] hash_to_validate
    def hadoop_validator(hash_to_validate)
      puts '[Debug]: calling hadoop validator' if @debug

      hadoop_ha = hash_to_validate[:hadoop_deploy][:hadoop_ha]
      hbase_install = hash_to_validate[:hbase_deploy]
      hadoop_ecosystem = hash_to_validate[:hadoop_deploy][:hadoop_ecosystem]
      valid_hadoop_ecosystem = %w(hive pig sqoop oozie hue flume)
      hadoop_namenode = hash_to_validate[:hadoop_deploy][:hadoop_namenode]
      zookeeper_quorum = hash_to_validate[:zookeeper_quorum]
      journal_quorum = hash_to_validate[:hadoop_deploy][:journal_quorum]
      hadoop_snn = hash_to_validate[:hadoop_deploy][:hadoop_secondarynamenode]
      mapreduce = hash_to_validate[:hadoop_deploy][:mapreduce]
      slave_nodes_count = hash_to_validate[:slave_nodes_count]
      if mapreduce != 'disabled'
        mapreduce_type = hash_to_validate[:hadoop_deploy][:mapreduce][:type]
        mapreduce_master = hash_to_validate[:hadoop_deploy][:mapreduce][:master]
      end
      slave_nodes = hash_to_validate[:slave_nodes]
      install_mode = hash_to_validate[:install_mode]

      if hadoop_ha.nil? or hadoop_ha.empty?
        puts '[Error]:'.red + " 'hadoop_ha' is required parameter and it should be either enabled|disabled"
        @errors_count += 1
      elsif ! %w(enabled disabled).include?(hadoop_ha)
        puts '[Error]:'.red " invalid value for 'hadoop_ha', valid values are enabled|disabled"
        @errors_count += 1
      end

      if install_mode == 'local'
        #validate slave nodes
        slave_nodes = hash_to_validate[:slave_nodes]
        if slave_nodes.nil? or slave_nodes.empty?
          puts '[Error]:'.red + " 'slave_nodes' are required in local install_mode"
          @errors_count += 1
        elsif ! slave_nodes.kind_of?(Array)
          puts '[Error]:'.red + " Expecting list(array) representation of 'slave_nodes'"
          @errors_count += 1
        end
        if hadoop_ha == 'enabled'
          if zookeeper_quorum.nil? or zookeeper_quorum.empty?
            puts '[Error]: '.red + "'zookeeper_quorum' is required for hadoop_ha deployment"
            @errors_count += 1
          end
        end
      else
        #if cloud, validate slave_nodes_count
        if slave_nodes_count.nil?
          puts '[Error]: '.red + "number of slave nodes is required for hadoop deployment ('slave_nodes_count')"
          @errors_count += 1
        elsif ! slave_nodes_count.is_a?(Numeric)
          puts '[Error]: '.red + "expecting numeric value for 'slave_nodes_count'"
          @errors_count += 1
        elsif slave_nodes_count == 0
          puts '[Error]: '.red + "'slave_nodes_count' cannot be 0"
          @errors_count += 1
        end
        if hadoop_ha == 'enabled'
          if hash_to_validate[:zookeeper_quorum_count].nil?
            puts '[Error]: '.red + "'zookeeper_quorum_count' is required for hadoop_ha deployment"
            @errors_count += 1
          end
        end
      end

      #MapReduce
      if install_mode == 'local'
        #if mapreduce option is set then mapreduce_type and mapreduce_master are required
        if mapreduce != 'disabled'
          mapreduce_type = mapreduce[:type]
          mapreduce_master = mapreduce[:master]
          puts '[Error]:'.red + ' Invalid mapreduce type' unless %w(mr1 mr2).include?(mapreduce_type)
          if mapreduce_master.nil? or mapreduce_master.empty?
            puts '[Error]:'.red + " 'mapreduce_master' is required"
            @errors_count += 1
          end
        end
      else
        if mapreduce.nil? or mapreduce.empty?
          puts '[Error]: '.red + 'mapreduce should be specified'
          @errors_count += 1
        elsif mapreduce == 'disabled'
          puts '[Debug]: ' + '(Warning)'.yellow + ' Mapreduce is disabled, no mapreduce daemons will be installed' if @debug
        elsif ! mapreduce.is_a? Hash
          puts '[Error]: '.red + "unrecognized value set for 'mapreduce' : #{mapreduce}"
          @errors_count += 1
        elsif mapreduce and (mapreduce[:type].nil? or mapreduce[:type].empty?)
          puts '[Error]: '.red + 'Mapreduce type is not specified, valid values are mr1|mr2'
          @errors_count += 1
        end
      end

      #hadoop_ecosystem
      if hadoop_ecosystem
        hadoop_ecosystem.each do |tool|
          unless valid_hadoop_ecosystem.include?(tool)
            puts '[Error]:'.red + "'hadoop_ecosystem' can support #{valid_hadoop_ecosystem}"
            puts "  #{tool} specified cannot be part of deployment yet!"
            @errors_count += 1
          end
        end
      end

      if install_mode == 'local'
        if hadoop_ha == 'enabled'
          #### HA Specific
          unless hadoop_namenode.length == 2
            puts '[Error]:'.red + " if 'hadoop_ha' ie enabled, two namenode(s) are required"
            @errors_count += 1
          end
          #namenodes and zookeepers cannot co-exist
          zookeeper_quorum.each do |zk|
            if hadoop_namenode.include?(zk)
              puts '[Error]:'.red + ' zookeeper and namenode cannot co-exist on same machine'
              @errors_count += 1
            end
            if slave_nodes.include?(zk)
              puts '[Error]:'.red + ' zookeeper and datanode cannot co-exist on same machine'
              @errors_count += 1
            end
          end
          #journal nodes and zookeepers cannot coexist as well
          journal_quorum.each do |jn|
            if hadoop_namenode.include?(jn)
              puts '[Error]:'.red + ' journalnode and namenode cannot co-exist'
              @errors_count += 1
            end
            if slave_nodes.include?(jn)
              puts '[Error]:'.red + ' journalnode and datanode cannot co-exist on same machine'
              @errors_count += 1
            end
          end
          #namenodes cannot be same
          if hadoop_namenode.uniq.length != hadoop_namenode.length
            puts '[Error]:'.red + ' namenode\'s cannot be the same in ha deployment mode'
            @errors_count += 1
          end
          #check journal_nodes for oddity
          unless journal_quorum.length % 2 == 1
            puts '[Error]:'.red + 'journal nodes should be odd number to handle failover\'s, please update'
            @errors_count += 1
          end
          #zookeepers cannot be same
          if zookeeper_quorum.uniq.length != zookeeper_quorum.length
            puts '[Error]:'.red + ' zookeeper\'s cannot be the same'
            @errors_count += 1
          end
          #journal nodes cannot be same
          if journal_quorum.uniq.length != journal_quorum.length
            puts '[Error]:'.red + ' journal node\'s cannot be the same'
            @errors_count += 1
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
          end
        end
      else
        if hadoop_ha == 'enabled'
          zookeeper_quorum_count = hash_to_validate[:zookeeper_quorum_count]
          if zookeeper_quorum_count.nil? or zookeeper_quorum_count == 0
            puts '[Error]: '.red + "'zookeeper_quorum_count' is required"
            @errors_count += 1
          end
        end
      end
    end

    # Validates hbase related conf params
    # @param [Hash] hash_to_validate
    def hbase_validator(hash_to_validate)
      install_mode = hash_to_validate[:install_mode]
      hadoop_install = hash_to_validate[:hadoop_deploy]
      hbase_install = hash_to_validate[:hbase_deploy]
      hbase_master = hash_to_validate[:hbase_deploy][:hbase_master]
      zookeeper_quorum = hash_to_validate[:zookeeper_quorum]
      #hbase_install
      if hbase_install.nil? or hbase_install.empty?
        puts '[Error]:'.red + " 'hbase_deploy' is required parameter, valid values: hash|disabled"
        @errors_count += 1
      elsif hbase_install == 'disabled'
        puts '[Debug]: HBase deploy is disabled'
      elsif ! hbase_install.is_a? Hash
        puts '[Error]: '.red + "unrecognized value set for 'hbase_deploy' : #{hbase_install}"
        @errors_count += 1
      end

      # hadoop is required
      if hadoop_install.nil? or hadoop_install.empty?
        puts '[Error]:'.red + " 'hadoop_deploy' is required for hbase deployments"
        @errors_count += 1
      elsif hadoop_install == 'disabled'
        puts '[Error]:'.red + " 'hadoop_deploy' should be enabled for hbase deployments"
        @errors_count += 1
      end

      if install_mode == 'cloud'
        if hbase_install and (hbase_install[:hbase_master_count].nil? or hbase_install[:hbase_master_count].to_i == 0)
          puts '[Error]:'.red + " invalid value for 'hbase_master_count'"
          @errors_count += 1
        end
        if hash_to_validate[:zookeeper_quorum_count].nil?
          puts '[Error]: '.red + "'zookeeper_quorum_count' is required for hbase deployment"
          @errors_count += 1
        end        
      else
        if hbase_install and (hbase_install[:hbase_master].nil? or hbase_install[:hbase_master].empty?)
          puts '[Error]:'.red + " invalid value for 'hbase_master'"
          @errors_count += 1
        end
        if hbase_install != 'disabled'
          hbase_master = hbase_install[:hbase_master]
          if hbase_master.nil? or hbase_master.empty?
            puts '[Error]: '.red + "'hbase_master' is required"
            @errors_count += 1
          elsif ! hbase_master.kind_of?(Array)
            puts '[Error]: '.red + "'hbase_master' should be of type array"
            @errors_count += 1
          end
          if zookeeper_quorum.nil? or zookeeper_quorum.empty?
            puts '[Error]: '.red + "'zookeeper_quorum' is required for hbase deployments"
            @errors_count += 1
          elsif ! zookeeper_quorum.kind_of?(Array)
            puts '[Error]: '.red + "'zookeeper_quorum' should be of type array"
            @errors_count += 1
          end
        end
      end
    end

    # Validates zookeeper configuration
    def zookeeper_validator(hash_to_validate)
      install_mode = hash_to_validate[:install_mode]
      hadoop_ha = hash_to_validate[:hadoop_deploy][:hadoop_ha] if hash_to_validate[:hadoop_deploy] != 'disabled'
      hbase_install = hash_to_validate[:hbase_deploy]
      kafka_install = hash_to_validate[:kafka_deploy]
      storm_install = hash_to_validate[:storm_deploy]
      if hadoop_ha == 'enabled' or hbase_install != 'disabled' or kafka_install != 'disabled' or storm_install != 'disabled'
        if install_mode == 'local'
          zookeeper_quorum = hash_to_validate[:zookeeper_quorum]
          if zookeeper_quorum.nil? or zookeeper_quorum.empty?
            puts '[Error]: '.red + "'zookeeper_quorum' is required for deployment types: 'hadoop_ha' or 'hbase_deploy' or 'kafka_deploy' or 'storm_deploy'"
            @errors_count += 1
          else
            unless zookeeper_quorum.length % 2 == 1
              puts '[Error]:'.red + 'zookeeper nodes should be odd number to handle failover\'s, please update'
              @errors_count += 1
            end
          end
        elsif install_mode == 'cloud'
          zookeeper_quorum = hash_to_validate[:zookeeper_quorum_count]
          if zookeeper_quorum.nil?
            puts '[Error]: '.red + "'zookeeper_quorum' is required for deployment types: 'hadoop_ha' or 'hbase_deploy' or 'kafka_deploy' or 'storm_deploy'"
            @errors_count += 1
          else
            unless zookeeper_quorum % 2 == 1
              puts '[Error]:'.red + 'zookeeper nodes should be odd number to handle failover\'s, please update'
              @errors_count += 1          
            end
          end
        end
      end
    end

    # Validate cassandra realted conf params
    # @param [Hash] hash_to_validate
    def cassandra_validator(hash_to_validate)
      cassandra_deploy = hash_to_validate[:cassandra_deploy]
      if cassandra_deploy.nil? or cassandra_deploy.empty?
        puts '[Error]:'.red + " 'cassandra_deploy' is required parameter, valid values: hash|disabled"
        @errors_count += 1
      elsif cassandra_deploy == 'disabled'
        puts '[Debug]: cassandra deployment is disabled' if @debug
      elsif ! cassandra_deploy.is_a? Hash
        puts '[Error]: '.red + "unrecognized value set for 'cassandra_deploy' : #{cassandra_deploy}"
        @errors_count += 1
      end

      if hash_to_validate[:install_mode] == 'local'
        if cassandra_deploy != 'disabled'
          cassandra_nodes = cassandra_deploy[:cassandra_nodes]
          if cassandra_nodes.nil? or cassandra_nodes.empty?
            puts '[Error]: '.red + "'cassandra_nodes' should contain list of fqdn(s) on which to deploy cassandra"
            @errors_count += 1
          elsif ! cassandra_nodes.is_a? Array
            puts '[Error]: '.red + "Excepting list (array) of nodes for 'cassandra_nodes'"
            @errors_count += 1
          end
          cassandra_seeds = cassandra_deploy[:cassandra_seeds]
          if cassandra_seeds.nil? or cassandra_seeds.empty?
            puts '[Error]: '.red + "'cassandra_seeds' should contain list of fqdn(s) which act as cassandra seed nodes"
            @errors_count += 1
          elsif ! cassandra_seeds.is_a? Array
            puts '[Error]: '.red + "Excepting list (array) of fqdn(s) for 'cassandra_seeds'"
            @errors_count += 1
          end
        end
      else
        if cassandra_deploy != 'disabled'
          colocate = cassandra_deploy[:colocate]
          if colocate.nil?
            puts "[Debug]: defaulting colocate for cassandra"
            hash_to_validate[:cassandra_deploy][:colocate] = false
          elsif ! (colocate.is_a? TrueClass or colocate.is_a? FalseClass)
            puts '[Error]: '.red + "invalid value found for 'colocate', valid values are yes|no"
            @errors_count += 1
          end
          if ! colocate
            number_of_instances = cassandra_deploy[:number_of_instances]
            if number_of_instances.nil?
              puts '[Error]: '.red + "'number_of_instances' is a required param for cassandra_deploy if colocate is disabled"
              @errors_count += 1
            elsif ! number_of_instances.is_a? Numeric
              puts '[Error]: '.red + "expecting numeric value for 'number_of_instances' in cassandra_deploy"
              @errors_count += 1
            end
          end
          cassandra_seeds_count = cassandra_deploy[:number_of_seeds]
          if cassandra_seeds_count.nil?
            puts '[Debug]: ' + "'number_of_seeds' is not provided cassandra_deploy defaulting to 1" if @debug
            hash_to_validate[:cassandra_deploy][:number_of_seeds] = 1
          elsif ! cassandra_seeds_count.is_a? Numeric
            puts '[Error]: '.red + "expecting numeric value for 'number_of_seeds' in cassandra_deploy"
            @errors_count += 1
          end
        end
      end
    end #cassandra_validator

    # Validate kafka realted conf params
    # @param [Hash] hash_to_validate
    def kafka_validator(hash_to_validate)
      kafka_deploy = hash_to_validate[:kafka_deploy]
      if kafka_deploy.nil? or kafka_deploy.empty?
        puts '[Error]:'.red + " 'kafka_deploy' is required parameter, valid values: hash|disabled"
        @errors_count += 1
      elsif kafka_deploy == 'disabled'
        puts '[Debug]: kafka deployment is disabled' if @debug
      elsif ! kafka_deploy.is_a? Hash
        puts '[Error]: '.red + "unrecognized value set for 'kafka_deploy' : #{kafka_deploy}"
        @errors_count += 1
      end

      if hash_to_validate[:install_mode] == 'local'
        if kafka_deploy != 'disabled'
          kafka_nodes = kafka_deploy[:kafka_nodes]
          if kafka_nodes.nil? or kafka_nodes.empty?
            puts '[Error]: '.red + "'kafka_nodes' should contain list of fqdn(s) on which to install kafka package"
            @errors_count += 1
          elsif ! kafka_nodes.is_a? Array
            puts '[Error]: '.red + "Excepting list (array) of nodes for 'kafka_nodes'"
            @errors_count += 1
          end
          kafka_brokers = kafka_deploy[:kafka_brokers]
          if kafka_brokers.nil? or kafka_brokers.empty?
            puts '[Error]: '.red + "'kafka_brokers' should contain list of fqdn(s) which act as kafka broker nodes"
            @errors_count += 1
          elsif ! kafka_brokers.is_a? Array
            puts '[Error]: '.red + "Excepting list (array) of fqdn(s) for 'kafka_brokers'"
            @errors_count += 1
          end
        end
      else
        #cloud deploy
        if kafka_deploy != 'disabled'
          colocate = kafka_deploy[:colocate]
          if colocate.nil?
            puts "[Debug]: defaulting colocate for kafka"
            hash_to_validate[:kafka_deploy][:colocate] = false  
          elsif ! (colocate.is_a? TrueClass or colocate.is_a? FalseClass)
            puts '[Error]: '.red + "invalid value found for 'colocate', valid values are yes|no"
            @errors_count += 1
          end
          if ! colocate
            number_of_instances = kafka_deploy[:number_of_instances]
            if number_of_instances.nil?
              puts '[Error]: '.red + "'number_of_instances' is a required key for kafka_deploy if colocate is disabled"
              @errors_count += 1
            elsif ! number_of_instances.is_a? Numeric
              puts '[Error]: '.red + "expecting numeric value for 'number_of_instances' in kafka_deploy hash"
              @errors_count += 1
            end
          end
          kafka_brokers_count = kafka_deploy[:number_of_brokers]
          if kafka_brokers_count.nil?
            puts '[Debug]: ' + "'number_of_brokers' is not provided for kafka_deploy defaulting to 1" if @debug
            hash_to_validate[:kafka_deploy][:number_of_brokers] = 1
          elsif ! kafka_brokers_count.is_a? Numeric
            puts '[Error]: '.red + "expecting numeric value for 'number_of_brokers' in kafka_deploy hash"
            @errors_count += 1
          end
        end
      end
    end #kafka_validator

    # Validate storm realted conf params
    # @param [Hash] hash_to_validate
    def storm_validator(hash_to_validate)
      storm_deploy = hash_to_validate[:storm_deploy]
      if storm_deploy.nil? or storm_deploy.empty?
        puts '[Error]:'.red + " 'storm_deploy' is required parameter, valid values: hash|disabled"
        @errors_count += 1
      elsif storm_deploy == 'disabled'
        puts '[Debug]: storm deployment is disabled' if @debug
      elsif ! storm_deploy.is_a? Hash
        puts '[Error]: '.red + "unrecognized value set for 'storm_deploy' : #{storm_deploy}"
        @errors_count += 1
      end

      if hash_to_validate[:install_mode] == 'local'
        if storm_deploy != 'disabled'
          storm_supervisors = storm_deploy[:storm_supervisors]
          if storm_supervisors.nil? or storm_supervisors.empty?
            puts '[Error]: '.red + "'storm_supervisors' should contain list of fqdn(s) on which to deploy storm supervisor daemons"
            @errors_count += 1
          elsif ! storm_supervisors.is_a? Array
            puts '[Error]: '.red + "Excepting list (array) of nodes for 'storm_supervisors'"
            @errors_count += 1
          end
          storm_master = storm_deploy[:storm_master]
          if storm_master.nil? or storm_master.empty?
            puts '[Error]: '.red + "'storm_master' should contain a fqdn which act as storm master node"
            @errors_count += 1
          end
          storm_workers_count = storm_deploy[:workers_count]
          if ! storm_workers_count.is_a? Numeric
            puts '[Error]: '.red + "'storm_workers_count' should contain number of worker processes each supervisor should run"
            @errors_count += 1
          end
        end
      else
        #cloud deploy
        if storm_deploy != 'disabled'
          colocate = storm_deploy[:colocate]
          if colocate.nil?
            puts "[Debug]: defaulting colocate for kafka"
            hash_to_validate[:storm_deploy][:colocate] = false
          elsif ! (colocate.is_a? TrueClass or colocate.is_a? FalseClass)
            puts '[Error]: '.red + "invalid value found for 'colocate', valid values are yes|no"
            @errors_count += 1
          end
          if ! colocate
            number_of_supervisors = storm_deploy[:number_of_supervisors]
            if number_of_supervisors.nil?
              puts '[Error]: '.red + "'number_of_supervisors' is a required key for storm_deploy if colocate is disabled"
              @errors_count += 1
            elsif ! number_of_supervisors.is_a? Numeric
              puts '[Error]: '.red + "expecting numeric value for 'number_of_supervisors' in storm_deploy hash"
              @errors_count += 1
            end
          end
          storm_workers_count = storm_deploy[:workers_count]
          if ! storm_workers_count.is_a? Numeric
            puts '[Error]: '.red + "'workers_count' should contain number of worker processes each supervisor should run"
            @errors_count += 1
          end
        end
      end
    end #storm_validator
  end

  #class to parse hadoop configuration
  class HadoopConfigParser
    def initialize(hadoop_conf_file, debug = false)
      puts "[Debug]: Validating hadoop conf" if debug
      hadoop_conf = YamlUtils.parse_yaml(hadoop_conf_file).keys
      unless HADOOP_CONF_KEYS.all?{|key| hadoop_conf.include?(key)}
        puts "[Error]: Required keys are not present in #{hadoop_conf_file}"
        puts "Required keys: #{HADOOP_CONF_KEYS}"
        @errors_count += 1
      end
      diff_keys = hadoop_conf - HADOOP_CONF_KEYS
      unless diff_keys.empty?
        puts "[Debug]: Following keys were added additionally by the user to #{hadoop_conf_file}: #{diff_keys}" if debug
      end
    end
  end

  #parse hbase configuration
  class HBaseConfigParser
    def initialize(hbase_conf_file, debug = false)
      puts "[Debug]: Validating hbase conf" if debug
      hbase_conf = YamlUtils.parse_yaml(hbase_conf_file).keys
      unless HBASE_CONF_KEYS.all?{|key| hbase_conf.include?(key) }
        puts "[Error]: Required keys are not present in #{hbase_conf_file}"
        puts "Required keys: #{HBASE_CONF_KEYS}"
        @errors_count += 1
      end
      diff_keys = hbase_conf - HBASE_CONF_KEYS
      unless diff_keys.empty?
        puts "[Debug]: Following keys were added additionally by the user to #{hbase_conf_file}: #{diff_keys}" if debug
      end
    end
  end
end
