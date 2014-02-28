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
  # Parses the configuration file of ankus and returns a hash to process upon
  class ConfigParser
    require 'ankus/helper'
    require 'pathname'
    include Ankus

    # Creates a configParser object with specified file_path, and a parsed_hash object
    # @param [String] file_path => path to the configuration file to parse
    # @param [Boolean] debug => if enabled will log info to stdout
    def initialize(file_path, log, debug=false, mock = false)
      @config_file  = file_path
      @parsed_hash  = {}
      @log          = log
      @debug        = debug
      @mock         = mock
      @errors_count = 0
    end

    # Parses the configuration file, validates it and returns a hash
    # @return [Hash] @parsed_hash => parsed configuration hash
    def parse_config
      @parsed_hash = Settings.load! @config_file
      validate @parsed_hash
      HadoopConfigParser.new(HADOOP_CONF, @log, @debug)
      HBaseConfigParser.new(HBASE_CONF, @log, @debug)
      unless @errors_count == 0
        @log.error "Number of Errors: #{@errors_count}"
        @log.error 'Parsing config file ... ' + '[Failed]'.red
        raise(Ankus::Errors::ParseError.new("\rParsing Configuration Failed".red))
      end
      create_req_files
      @parsed_hash
    rescue Ankus::Errors::ParseError, Ankus::Errors::ParseError::NoKey
      @log.error "#{$!.message} (#{$!.class})"
      exit
    rescue
      @log.error "#{$!.message} (#{$!.class})"
      puts $@ if @debug
      exit
    end

    private

    # Validates the loaded configuration file
    # @param [Hash] hash_to_validate => hash to validate
    def validate(hash_to_validate)
      unless hash_to_validate
        @log.error 'Config file is empty!'
        @errors_count += 1
      end
      # validate if basic configuration parameters are present or not
      ANKUS_CONF_MAIN_KEYS.each do |key|
        unless hash_to_validate.include?(key)
          @log.error "Required key: '#{key}' is not present in the configuration file"
          @errors_count += 1
        end
      end
      # validate install_mode, it can be 'local|cloud' modes
      case @parsed_hash[:install_mode]
      when 'local'
        local_validator hash_to_validate
      when 'cloud'
        cloud_validator hash_to_validate
      when nil
        @log.error "Property 'install_mode' cannot be empty"
        @errors_count += 1        
      else
        @log.error 'Not supported install mode, supported modes: local|cloud'
      end
    end

    # Creates set of files and directories required by ankus
    def create_req_files
      Dir.mkdir DATA_DIR                unless File.exists? DATA_DIR
      FileUtils.touch NODES_FILE        unless File.exists? NODES_FILE
      FileUtils.touch ENC_ROLES_FILE    unless File.exists? ENC_ROLES_FILE
      FileUtils.touch HIERA_DATA_FILE   unless File.exists? HIERA_DATA_FILE
    end

    # Validations specific to local install_mode
    # @param [Hash] hash_to_validate => hash to validate
    def local_validator(hash_to_validate)
      @log.debug 'Calling local validator' if @debug
      #controller:
      if hash_to_validate[:controller].nil? or hash_to_validate[:controller].empty?
        @log.error "Property 'controller' is required for local install_mode"
        @errors_count += 1
      end
      #ssh_key
      if hash_to_validate[:ssh_key].nil? or hash_to_validate[:ssh_key].empty?
        @log.error "Property 'ssh_key' is required for local install_mode"
        @errors_count += 1
      else
        #check if ssh_key has valid key path
        unless File.exists? File.expand_path(hash_to_validate[:ssh_key])
          @log.error "Property 'ssh_key': #{hash_to_validate[:ssh_key]} does not exists"
          @errors_count += 1
        end
      end
      #ssh_user
      if hash_to_validate[:ssh_user].nil? or hash_to_validate[:ssh_user].empty?
        @log.debug 'Property \'ssh_user\' is not specified assuming ssh_user as \'root\'' if @debug
        hash_to_validate[:ssh_user] = 'root'
      end

      common_validator(hash_to_validate)

      # force user to use hostname instead of ip address
      nodes = Inventory::Generator.new(@parsed_hash).generate
      nodes.keys.each do |node|
        unless node =~ HOSTNAME_REGEX
          @log.error "Expecting hostname got ip-address @ #{node}".red
          @errors_count += 1
        end
      end
      unless @mock
        nodes.keys.each do |node|
          unless Ankus::PortUtils.port_open?(node, 22, 2)
            @log.error "Node: #{node} is not reachable"
            @errors_count += 1
          end
        end
        nodes.keys.each do |node|
          begin
            Ankus::SshUtils.sshable?(node, hash_to_validate[:ssh_user], hash_to_validate[:ssh_key])
          rescue
            @log.error "Cannot ssh into instance '#{node}' with user: #{hash_to_validate[:ssh_user]} and " +
            "key: #{hash_to_validate[:ssh_key]}"
            @errors_count += 1
          end
        end
      end
    end

    # Validations specific to cloud install_mode
    # @param [Hash] hash_to_validate => hash to validate
    def cloud_validator(hash_to_validate)
      @log.debug 'Calling cloud validator' if @debug
      cloud_platform = hash_to_validate[:cloud_platform]
      cloud_credentials = hash_to_validate[:cloud_credentials]
      cloud_os_type = hash_to_validate[:cloud_os_type]

      # cloud platform => aws, rackspace
      if cloud_platform.nil? or cloud_platform.empty?
        @log.error "Property 'cloud_platform' is required for cloud install_mode"
        @errors_count += 1
      elsif ! %w(aws rackspace openstack).include?(cloud_platform)
        @log.error "Invalid value for 'cloud_platform', supported platforms are 'aws','rackspace' and 'openstack'"
        @errors_count += 1
      end

      # cloud credentials
      if cloud_credentials.nil? or cloud_credentials.empty?
        @log.error "Property 'cloud_credentials' is required for cloud install_mode"
        @errors_count += 1
      elsif ! cloud_credentials.is_a?(Hash)
        @log.error "Property 'cloud_credentials' is malformed, look sample cloud config for example"
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
          @log.error "Property 'cloud_credentials' is malformed/invalid, look sample cloud config for example"
          @errors_count += 1
        end
        if cloud_credentials[:aws_secret_key].length == 0
          @log.error 'Property aws_secret_key is missing'
          @errors_count += 1
        elsif cloud_credentials[:aws_access_id].length == 0
          @log.error 'Property aws_access_id is missing'
          @errors_count += 1
        end
        if cloud_credentials[:aws_sec_groups]
          unless cloud_credentials[:aws_sec_groups].is_a?(Array)
            @log.error 'Expecting list(array) representation of groups for \'aws_sec_groups\''
            @errors_count += 1
          end
        end

        # validate aws connection
        @log.debug 'Validating aws connection' if @debug
        aws = Aws.new(cloud_credentials[:aws_access_id], 
          cloud_credentials[:aws_secret_key], 
          cloud_credentials[:aws_region],
          @log
          )
        unless aws.valid_connection?(aws.create_connection)
          @log.error 'Failed establishing connection to aws, check your credentials'
          @errors_count += 1
        end
      elsif cloud_platform == 'rackspace'
        valid_credentials = {
                              :rackspace_username => '',
                              :rackspace_api_key => '',
                              :rackspace_instance_type => '',
                              :rackspace_ssh_key => '',
                              :cluster_identifier => ''
                            }
        unless cloud_credentials.keys.sort == valid_credentials.keys.sort
          @log.error "Property 'cloud_credentials' is malformed/invalid, look sample cloud config for example"
          @errors_count += 1
        end
        if cloud_credentials[:rackspace_username].length == 0
          @log.error 'Property rackspace_username is missing'
          @errors_count += 1
        elsif cloud_credentials[:rackspace_api_key].length == 0
          @log.error 'Property rackspace_api_key is missing'
          @errors_count += 1
        end
        #validate ssh key
        if cloud_credentials[:rackspace_ssh_key].nil? or cloud_credentials[:rackspace_ssh_key].empty?
          @log.error 'Property rackspace_ssh_key is required'
          @errors_count += 1
        else
          #check if ssh_key has valid key path
          unless File.exists? File.expand_path(cloud_credentials[:rackspace_ssh_key])
            @log.error "SSH key file: #{cloud_credentials[:rackspace_ssh_key]} does not exists"
            @errors_count += 1
          end
        end
        # validate cluster identifier
        if cloud_credentials[:cluster_identifier].length == 0
          @log.debug 'Rackspace cluster_identifier is not set, using the default: \'ops\''
          hash_to_validate[:cluster_identifier] = 'ops'
        else
          hash_to_validate[:cluster_identifier] = cloud_credentials[:cluster_identifier]
        end
        # validate connection
        rackspace = Ankus::Rackspace.new(cloud_credentials[:rackspace_api_key], cloud_credentials[:rackspace_username], @log)
        unless rackspace.valid_connection?(rackspace.create_connection)
          @log.error 'Failed establishing connection to rackspace, check your credentials'
        end
      elsif cloud_platform == 'openstack'
        valid_credentials = {
            :os_auth_url => '',
            :os_username => '',
            :os_password => '',
            :os_tenant => '',
            :os_flavor => '',
            :os_ssh_key => '',
            :os_ssh_user => '',
            :os_sec_groups => '',
            :os_image_ref => '',
            :cluster_identifier => ''
        }
        unless cloud_credentials.keys.sort == valid_credentials.keys.sort
          @log.error "Property 'cloud_credentials' is malformed/invalid, look sample cloud config for example"
          @errors_count += 1
        end
        if cloud_credentials[:os_auth_url].length == 0
          @log.error 'Property os_auth_url is missing'
          @errors_count += 1
        end
        if cloud_credentials[:os_username].length == 0
          @log.error 'Property os_username is missing'
          @errors_count += 1
        end
        if cloud_credentials[:os_password].length == 0
          @log.error 'Property os_username is missing'
          @errors_count += 1
        end
        if cloud_credentials[:os_tenant].length == 0
          @log.error 'Property os_tenant is missing'
          @errors_count += 1
        end
        if cloud_credentials[:os_flavor].nil?
          @log.error 'Property os_flavor_ref is missing'
          @errors_count += 1
        #elsif ! cloud_credentials[:os_flavor].is_a?(Numeric)
        #  @log.error "Property os_flavor_ref should be of type integer, instead got #{cloud_credentials[:os_flavor_ref].class}"
        #  @errors_count += 1
        end
        if cloud_credentials[:os_image_ref].length == 0
          @log.error 'Property os_image_ref is missing'
          @errors_count += 1
        end
        # validate ssh key and user
        if cloud_credentials[:os_ssh_key].nil? or cloud_credentials[:os_ssh_key].empty?
          @log.error 'Property os_key is required'
          @errors_count += 1
        end
        if cloud_credentials[:os_ssh_user].nil? or cloud_credentials[:os_ssh_user].empty?
          @log.error 'Property os_user is required'
          @errors_count += 1
        end
        # validate security groups
        if cloud_credentials[:os_sec_groups].nil? or cloud_credentials[:os_sec_groups].empty?
          @log.error 'Property os_sec_groups is required'
          @errors_count += 1
        elsif ! cloud_credentials[:os_sec_groups].is_a?(Array)
          @log.error "Exception a array for os_sec_groups instead got '#{cloud_credentials[:os_sec_groups].class}'"
          @errors_count += 1
        end
        # validate cluster identifier
        if cloud_credentials[:cluster_identifier].length == 0
          @log.debug 'Rackspace cluster_identifier is not set, using the default: \'ops\''
          hash_to_validate[:cluster_identifier] = 'ops'
        else
          hash_to_validate[:cluster_identifier] = cloud_credentials[:cluster_identifier]
        end
        # validate connection
        if @errors_count == 0
          openstack = Ankus::Openstack.new(
              cloud_credentials[:os_auth_url],
              cloud_credentials[:os_username],
              cloud_credentials[:os_password],
              cloud_credentials[:os_tenant],
              @log)
          begin
            unless openstack.valid_connection?(openstack.create_connection)
              @log.error 'Failed establishing connection to openstack, check your credentials'
            end
          rescue Excon::Errors::Timeout
            @log.error 'Cannot establish connection to openstack. Reason: ' + "#{$!.message} (#{$!.class})"
            @log.error 'Please check the url is reachable'
            exit 1
          end
        end
      end

      # cloud os type to boot
      if cloud_os_type.nil? or cloud_os_type.empty?
        @log.error "Property 'cloud_os_type' is required for cloud install_mode"
        @errors_count += 1
      elsif ! %w(centos ubuntu).include?(cloud_os_type.downcase)
        @log.error "Supported 'cloud_os_type' values are centos|ubuntu"
        @errors_count += 1
      end

      #add ssh_user to hash
      hash_to_validate[:ssh_user] =  if cloud_platform == 'openstack'
                                       cloud_credentials[:os_ssh_user]
                                     else
                                       if cloud_os_type.downcase == 'centos'
                                         'root'
                                       elsif cloud_os_type.downcase == 'ubuntu' and cloud_platform.downcase == 'aws'
                                         'ubuntu'
                                       else
                                         'root'
                                       end
                                     end
      common_validator(hash_to_validate)
    end

    # Validates volumes configuration for cloud deployments
    # @param [Hash] volumes => volumes hash to validate
    def validate_volumes(volumes, cloud_platform, deploy_mode)
      if volumes and volumes != 'disabled' and volumes.is_a? Hash
        if cloud_platform == 'aws'
          #volumes type
          if volumes[:type].nil? or volumes[:type].empty?
            @log.error "Type of the volumes is required 'type'"
            @errors_count += 1
          elsif ! %w(ebs io1).include? volumes[:type]
            @log.error "invalid value found for volume type '#{volumes[:type]}' (valid values are 'ebs' or 'io1')"
            @errors_count += 1
          end
          #iops
          if volumes[:type] and volumes[:type] == 'io1'
            if volumes[:iops].nil?
              @log.error "Property 'iops' rate is required if type of volume being booted is io1"
              @errors_count += 1
            elsif ! volumes[:iops].is_a? Numeric
              @log.error "Property 'iops' rate should be of type numeric"
              @errors_count += 1
            elsif ! volumes[:iops].between?(1, 4000)
              @log.error "Property 'iops' rate should be in between 1-4000"
              @errors_count += 1
            end
          end
          #volumes count
          if volumes[:count].nil?
            @log.error "Count of the volumes is required 'count'"
            @errors_count += 1
          elsif ! volumes[:count].is_a? Numeric
            @log.error "Count of the volumes should be of type numeric 'count'"
            @errors_count += 1
          elsif volumes[:count] == 0
            @log.error "Volumes count should be > 0, if you dont want volumes to be mounted use 'volumes: disabled'"
            @errors_count += 1
          end
          #volumes size
          if volumes[:size].nil?
            @log.error "Size of the volumes is required 'size'"
            @errors_count += 1
          elsif ! volumes[:size].is_a? Numeric
            @log.error "Property 'size' of the volumes should be of type numeric"
            @errors_count += 1
          elsif volumes[:size] == 0
            @log.error "Volumes size should be > 0, if you dont want volumes to be mounted use 'volumes: disabled'"
            @errors_count += 1
          end
        elsif cloud_platform == 'rackspace' or cloud_platform == 'openstack'
          #volumes type
          if volumes[:type].nil? or volumes[:type].empty?
            @log.error "Type of the volumes is required 'type'"
            @errors_count += 1
          elsif ! %w(blockstore).include? volumes[:type]
            @log.error "Invalid value found for volume type (#{volumes[:type]}, valid value is 'blockstore')"
            @errors_count += 1
          end
          #volumes count
          if volumes[:count].nil?
            @log.error "Count of the volumes is required 'count'"
            @errors_count += 1
          elsif ! volumes[:count].is_a? Numeric
            @log.error "Count of the volumes should be of type numeric 'count'"
            @errors_count += 1
          elsif volumes[:count] == 0
            @log.error "Volumes count should be > 0, if you dont want volumes to be mounted use 'volumes: disabled'"
            @errors_count += 1
          end
          #volumes size
          if volumes[:size].nil?
            @log.error "Size of the volumes is required 'size'"
            @errors_count += 1
          elsif ! volumes[:size].is_a? Numeric
            @log.error "Property 'size' of the volumes should be of type numeric"
            @errors_count += 1
          elsif volumes[:size] == 0
            @log.error "Volumes size should be > 0, if you dont want volumes to be mounted use 'volumes: disabled'"
            @errors_count += 1
          end
        end
        @log.debug "Instances will be booted with '#{volumes[:count]}' volumes of type(#{volumes[:type]}) each with " +
                       "size(#{volumes[:size]}GB)" if @debug
      else
        @log.warn "Volumes configuration disabled for #{deploy_mode}" if @debug
      end
    end

    # Validates params which are common for both local and cloud install_modes
    # @param [Hash] hash_to_validate => hash to validate
    def common_validator(hash_to_validate)
      @log.debug 'Calling common validator' if @debug
      security = hash_to_validate[:security]
      monitoring = hash_to_validate[:monitoring]
      alerting = hash_to_validate[:alerting]
      log_aggregation = hash_to_validate[:log_aggregation]

      #security
      if security.nil? or security.empty?
        @log.error "Property 'security' is required parameter, valid values: enabled|disabled"
        @errors_count += 1
      elsif ! %w(simple kerberos).include?(security)
        @log.error "Invalid value for 'security', valid values: simple|kerberos"
        @errors_count += 1
      end
      if security == 'kerberos'
        #if security is enabled
        realm_name = hash_to_validate[:kerberos_realm]
        domain_name = hash_to_validate[:kerberos_domain]
        if realm_name.nil? or realm_name.empty?
          @log.debug 'Kerberos realm name is not provided, using default realm name' if @debug
        end
        if domain_name.nil? or domain_name.empty?
          @log.debug 'Kerberos domain name is not provided, using default domain name' if @debug
        end
      end

      #monitoring
      if monitoring.nil? or monitoring.empty?
        @log.error "Property 'monitoring' is required parameter, valid values: enabled|disabled"
        @errors_count += 1
      elsif ! %w(enabled disabled).include?(monitoring)
        @log.error "Invalid value for 'monitoring', valid values: enabled|disabled"
      end

      #alerting
      if alerting.nil? or alerting.empty?
        @log.error "Property 'alerting' is required parameter, valid values: enabled|disabled"
        @errors_count += 1
      elsif ! %w(enabled disabled).include?(alerting)
        @log.error "Property invalid value for 'alerting', valid values: enabled|disabled"
        @errors_count += 1
      end

      #admin_email
      if alerting and alerting == 'enabled'
        admin_email = hash_to_validate[:admin_email]
        if admin_email.nil? or admin_email.empty?
          @log.error "Property 'admin_email' is required parameter when altering is enabled"
          @errors_count += 1
        end
      end

      #log_aggregation
      if log_aggregation.nil? or log_aggregation.empty?
        @log.error "Property 'log_aggregation' is required parameter, valid values: enabled|disabled"
        @errors_count += 1
      elsif ! %w(enabled disabled).include?(log_aggregation)
        @log.error "Invalid value for 'log_aggregation', valid values: enabled|disabled"
        @errors_count += 1
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

      solr_validator hash_to_validate

      kafka_validator hash_to_validate

      storm_validator hash_to_validate

      #Check to see if all the deploy options are disabled if so raise
      if ANKUS_CONF_DEPLOY_KEYS.map { |e| hash_to_validate[e] }.uniq.length == 1
        @log.error 'All the deploy(s) are disabled, at least one deploy should be configured'
        @errors_count += 1
      end
    end

    # Validates hadoop related conf params for local install_mode
    # @param [String] hash_to_validate
    def hadoop_validator(hash_to_validate)
      @log.debug 'Calling hadoop validator' if @debug

      hadoop_ha = hash_to_validate[:hadoop_deploy][:ha]
      hadoop_ecosystem = hash_to_validate[:hadoop_deploy][:ecosystem]
      valid_hadoop_ecosystem_cdh = %w(hive pig sqoop oozie hue impala)
      valid_hadoop_ecosystem_hdp = %w(hive pig sqoop oozie hue tez)
      mapreduce = hash_to_validate[:hadoop_deploy][:mapreduce]
      zookeeper = hash_to_validate[:zookeeper_deploy]
      install_mode = hash_to_validate[:install_mode]

      if hadoop_ha.nil? or hadoop_ha.empty?
        @log.error "Property 'ha' is required parameter and it should be either enabled|disabled"
        @errors_count += 1
      elsif ! %w(enabled disabled).include?(hadoop_ha)
        @log.error "Invalid value for 'ha', valid values are enabled|disabled"
        @errors_count += 1
      end

      # worker nodes and zookeeper validations
      if install_mode == 'local' # Local deployment
        slave_nodes = hash_to_validate[:worker_nodes]
        if slave_nodes.nil? or slave_nodes.empty?
          @log.error "Property 'worker_nodes' is required in 'local' install_mode"
          @errors_count += 1
        elsif ! slave_nodes.kind_of?(Array)
          @log.error "Expecting list(array) representation of 'worker_nodes'"
          @errors_count += 1
        end
        if hadoop_ha == 'enabled'
          if zookeeper.nil? or zookeeper.empty?
            @log.error "Property 'zookeeper_deploy' is required for hadoop high availability deployment"
            @errors_count += 1
          else
            zookeeper_quorum = hash_to_validate[:zookeeper_deploy][:quorum]
            if zookeeper_quorum.nil? or zookeeper_quorum.empty?
              @log.error "Property 'quorum' of 'zookeeper_deploy' is required for hadoop ha deployment"
              @errors_count += 1
            end
          end
        end
      else # Cloud deployment
        slave_nodes_count = hash_to_validate[:worker_nodes_count]
        if slave_nodes_count.nil?
          @log.error "Number of worker nodes is required for hadoop deployment ('worker_nodes_count')"
          @errors_count += 1
        elsif ! slave_nodes_count.is_a?(Numeric)
          @log.error "Expecting numeric value for 'worker_nodes_count'"
          @errors_count += 1
        elsif slave_nodes_count == 0
          @log.error "Property 'worker_nodes_count' cannot be 0"
          @errors_count += 1
        end
        if hadoop_ha == 'enabled'
          if zookeeper.nil? or zookeeper.empty?
            @log.error "Property 'zookeeper_deploy' is required for hadoop high availability deployment"
            @errors_count += 1
          else
            zookeeper_quorum_count = hash_to_validate[:zookeeper_deploy][:quorum_count]
            if zookeeper_quorum_count.nil?
              @log.error "Property 'quorum_count' of 'zookeeper_deploy' is required for hadoop_ha deployment"
              @errors_count += 1
            end
          end
        end
      end

      # hadoop packages source validation
      hadoop_packages_source = hash_to_validate[:hadoop_deploy][:packages_source]
      if hadoop_packages_source
        unless %w(cdh hdp).include?(hadoop_packages_source)
          @log.error "'packages_source' can be either 'cdh' or 'hdp'"
          @errors_count += 1
        end
      else
        hash_to_validate[:hadoop_deploy][:packages_source] = 'cdh'
      end

      # MapReduce validations
      if install_mode == 'local' # Local deployment
        # mapreduce_type and mapreduce_master are required for mapreduce deployments
        if mapreduce.nil? or mapreduce.empty?
          @log.error 'Mapreduce should be specified'
          @errors_count += 1
        end
        if mapreduce != 'disabled'
          mapreduce_type = mapreduce[:type]
          mapreduce_master = mapreduce[:master]
          @log.error 'Invalid mapreduce type' unless %w(mr1 mr2).include?(mapreduce_type)
          if mapreduce_master.nil? or mapreduce_master.empty?
            @log.error "Property 'master' of 'mapreduce' is required"
            @errors_count += 1
          end
          if mapreduce_type.nil? or mapreduce_type.empty?
            @log.error 'Mapreduce type is not specified, valid values are mr1|mr2'
            @errors_count += 1
          end
        else
          @log.warn 'Mapreduce is disabled, no mapreduce daemons will be installed' if @debug
        end
      else # Cloud deployment
        if mapreduce.nil? or mapreduce.empty?
          @log.error 'Mapreduce should be specified'
          @errors_count += 1
        elsif mapreduce == 'disabled'
          @log.warn 'Mapreduce is disabled, no mapreduce daemons will be installed' if @debug
        elsif ! mapreduce.is_a? Hash
          @log.error + "Unrecognized value set for 'mapreduce' : #{mapreduce}"
          @errors_count += 1
        elsif mapreduce and (mapreduce[:type].nil? or mapreduce[:type].empty?)
          @log.error 'Mapreduce type is not specified, valid values are mr1|mr2'
          @errors_count += 1
        end
      end

      if mapreduce && mapreduce != 'disabled'
        if hash_to_validate[:hadoop_deploy][:packages_source] == 'hdp' and mapreduce[:type] == 'mr1'
          @log.error 'HDP deployments does not support mapreduce v1 try using \'mr2\' (yarn)'
          @errors_count += 1
        end
      end

      # hadoop_ecosystem validations
      if hadoop_ecosystem
        hadoop_ecosystem.each do |tool|
          if hash_to_validate[:hadoop_deploy][:packages_source] == 'cdh'
            unless valid_hadoop_ecosystem_cdh.include?(tool)
              @log.error "'ecosystem' can support #{valid_hadoop_ecosystem_cdh}"
              @log.error "  #{tool} specified cannot be part of deployment yet!"
              @errors_count += 1
            end
          else
            unless valid_hadoop_ecosystem_hdp.include?(tool)
              @log.error "'ecosystem' can support #{valid_hadoop_ecosystem_hdp}"
              @log.error "  #{tool} specified cannot be part of deployment yet!"
              @errors_count += 1
            end
          end
        end
      end

      if install_mode == 'local' # Local deployment
        hadoop_namenode = hash_to_validate[:hadoop_deploy][:namenode]
        journal_quorum = hash_to_validate[:hadoop_deploy][:journal_quorum]
        hadoop_snn = hash_to_validate[:hadoop_deploy][:secondarynamenode]
        slave_nodes = hash_to_validate[:worker_nodes]
        if hadoop_ha == 'enabled' #### HA Specific validations
          unless hadoop_namenode.length == 2
            @log.error 'For hadoop ha deployments, two namenode(s) are required'
            @errors_count += 1
          end
          # namenode and zookeeper daemon cannot co-exist
          zookeeper_quorum = hash_to_validate[:zookeeper_deploy][:quorum]
          zookeeper_quorum.each do |zk|
            if hadoop_namenode.include?(zk)
              @log.error 'Zookeeper and namenode cannot co-exist on same machine'
              @errors_count += 1
            end
            if slave_nodes.include?(zk)
              @log.error 'Zookeeper and datanode cannot co-exist on same machine'
              @errors_count += 1
            end
          end
          # journalnode and namenode daemons cannot coexist
          journal_quorum.each do |jn|
            if hadoop_namenode.include?(jn)
              @log.error 'Journalnode and namenode cannot co-exist'
              @errors_count += 1
            end
            if slave_nodes.include?(jn)
              @log.error 'Journalnode and datanode cannot co-exist on same machine'
              @errors_count += 1
            end
          end
          # namenode cannot be same
          if hadoop_namenode.uniq.length != hadoop_namenode.length
            @log.error 'Namenode\'s cannot be the same in ha deployment mode'
            @errors_count += 1
          end
          # check journal_nodes for oddity
          unless journal_quorum.length % 2 == 1
            @log.error 'Journal nodes should be odd number to handle failover\'s, please update'
            @errors_count += 1
          end
          # zookeepers cannot be same
          if zookeeper_quorum.uniq.length != zookeeper_quorum.length
            @log.error 'Zookeeper\'s cannot be the same'
            @errors_count += 1
          end
          # journal nodes cannot be same
          if journal_quorum.uniq.length != journal_quorum.length
            @log.error 'Journal node\'s cannot be the same'
            @errors_count += 1
          end
        else #### NON-HA Specific
          #check for one namenode
          unless hadoop_namenode.length == 1
            @log.error 'Expecting one namenode for non-ha specific deployment mode'
            @errors_count += 1
          end
          if hadoop_snn.nil? or hadoop_snn.empty?
            @log.warn 'No secondary namenode host found, its recommended to use one'
          end
        end
      end

      # Volumes|Directories configuration
      if install_mode == 'local'
        data_dirs = hash_to_validate[:hadoop_deploy][:data_dirs]
        if data_dirs && ! data_dirs.is_a?(Array)
          @log.error "Expecting property 'data_dirs' of 'hadoop_deploy' to be array instead got #{data_dirs.class}"
          @errors_count += 1
        else
          data_dirs && data_dirs.each do |dir|
            unless Pathname.new(dir).absolute?
              @log.error "Invalid absolute path found in 'storage_dirs' (#{dir})"
              @errors_count += 1
            end
          end
        end
        master_dirs = hash_to_validate[:hadoop_deploy][:master_dirs]
        if master_dirs && ! master_dirs.is_a?(Array)
          @log.error "Expecting property 'master_dirs' of 'hadoop_deploy' to be array instead got #{master_dirs.class}"
          @errors_count += 1
        else
          master_dirs && master_dirs.each do |dir|
            unless Pathname.new(dir).absolute?
              @log.error "Invalid absolute path found in 'storage_dirs' (#{dir})"
              @errors_count += 1
            end
          end
        end
      else # Cloud deployment
        worker_volumes = hash_to_validate[:hadoop_deploy][:worker_volumes]
        master_volumes = hash_to_validate[:hadoop_deploy][:master_volumes]
        validate_volumes(worker_volumes, hash_to_validate[:cloud_platform], 'hadoop worker nodes')
        validate_volumes(master_volumes, hash_to_validate[:cloud_platform], 'hadoop master nodes')
      end
    end

    # Validates hbase related conf params
    # @param [Hash] hash_to_validate
    def hbase_validator(hash_to_validate)
      install_mode = hash_to_validate[:install_mode]
      hadoop_install = hash_to_validate[:hadoop_deploy]
      hbase_install = hash_to_validate[:hbase_deploy]
      #hbase_install
      if hbase_install.nil? or hbase_install.empty?
        @log.error "Property 'hbase_deploy' is required parameter, valid values: hash|disabled"
        @errors_count += 1
      elsif hbase_install == 'disabled'
        @log.debug 'HBase deploy is disabled' if @debug
      elsif ! hbase_install.is_a? Hash
        @log.error "Unrecognized value set for 'hbase_deploy' : #{hbase_install}"
        @errors_count += 1
      end

      # hadoop is required
      if hadoop_install.nil? or hadoop_install.empty?
        @log.error "Property 'hadoop_deploy' is required for hbase deployments"
        @errors_count += 1
      elsif hadoop_install == 'disabled'
        @log.error "Property 'hadoop_deploy' should be enabled for hbase deployments"
        @errors_count += 1
      end

      if install_mode == 'cloud'
        if hbase_install and (hbase_install[:master_count].nil? or hbase_install[:master_count].to_i == 0)
          @log.error "Invalid value for property 'master_count' of 'hbase_deploy'"
          @errors_count += 1
        end
        if hbase_install && hash_to_validate[:zookeeper_deploy][:quorum_count].nil?
          @log.error "Property 'quorum_count' of 'zookeeper_deploy' is required for hbase deployment"
          @errors_count += 1
        end        
      else # Local deployment
        if hbase_install and (hbase_install[:master].nil? or hbase_install[:master].empty?)
          @log.error "Invalid value for property 'master' of 'hbase_deploy'"
          @errors_count += 1
        end
        if hbase_install != 'disabled'
          hbase_master = hbase_install[:master]
          if hbase_master.nil? or hbase_master.empty?
            @log.error "Property 'master' of 'hbase_deploy' is required"
            @errors_count += 1
          elsif ! hbase_master.kind_of?(Array)
            @log.error "Property 'master' of 'hbase_deploy' should be of type array"
            @errors_count += 1
          end
          zookeeper_quorum = hash_to_validate[:zookeeper_deploy][:quorum]
          if zookeeper_quorum.nil? or zookeeper_quorum.empty?
            @log.error "Property 'quorum' of 'zookeeper_deploy' is required for hbase deployments"
            @errors_count += 1
          elsif ! zookeeper_quorum.kind_of?(Array)
            @log.error "Property 'quorum' of 'zookeeper_deploy' should be of type array"
            @errors_count += 1
          end
        end
      end
    end

    # Validates zookeeper configuration
    def zookeeper_validator(hash_to_validate)
      install_mode = hash_to_validate[:install_mode]
      hadoop_ha = hash_to_validate[:hadoop_deploy][:ha] if hash_to_validate[:hadoop_deploy] != 'disabled'
      hbase_install = hash_to_validate[:hbase_deploy]
      kafka_install = hash_to_validate[:kafka_deploy]
      storm_install = hash_to_validate[:storm_deploy]
      solr_install  = hash_to_validate[:solr_deploy]
      if hadoop_ha == 'enabled' or hbase_install != 'disabled' or kafka_install != 'disabled' or storm_install != 'disabled' or solr_install != 'disabled'
        if install_mode == 'local'
          zookeeper_deploy = hash_to_validate[:zookeeper_deploy]
          if zookeeper_deploy.nil? or zookeeper_deploy.empty?
            @log.error "'zookeeper_deploy' is required for deployment types: 'hadoop_ha' or 'hbase_deploy' or 'solr_deploy' or 'kafka_deploy' or 'storm_deploy'"
            @errors_count += 1
          elsif zookeeper_deploy == 'disabled'
            @log.error "'zookeeper_deploy' is required for deployment types: 'hadoop_ha' or 'hbase_deploy' or 'solr_deploy' or 'kafka_deploy' or 'storm_deploy'"
            @errors_count += 1
          else
            zookeeper_quorum = zookeeper_deploy[:quorum]
            if zookeeper_quorum.nil? or zookeeper_quorum.empty?
              @log.error "Property 'quorum' of 'zookeeper_deploy' is required"
              @errors_count += 1
            else
              unless zookeeper_quorum.length % 2 == 1
                @log.error 'zookeeper nodes should be odd number to handle failover\'s, please update'
                @errors_count += 1
              end
            end
          end
        elsif install_mode == 'cloud'
          zookeeper_deploy = hash_to_validate[:zookeeper_deploy]
          if zookeeper_deploy.nil? or zookeeper_deploy.empty?
            @log.error "'zookeeper_deploy' is required for deployment types: 'hadoop_ha' or 'hbase_deploy' or 'solr_deploy' or 'kafka_deploy' or 'storm_deploy'"
            @errors_count += 1
          elsif zookeeper_deploy == 'disabled'
            @log.error "'zookeeper_deploy' is required for deployment types: 'hadoop_ha' or 'hbase_deploy' or 'solr_deploy' or 'kafka_deploy' or 'storm_deploy'"
            @errors_count += 1
          else
            zookeeper_quorum = zookeeper_deploy[:quorum_count]
            if zookeeper_quorum.nil? or zookeeper_quorum.empty?
              @log.error "Property 'quorum_count' of 'zookeeper_deploy' is required"
              @errors_count += 1
            else
              unless zookeeper_quorum % 2 == 1
                @log.error 'zookeeper nodes should be odd number to handle failover\'s, please update'
                @errors_count += 1
              end
            end
          end
        end
      end
    end

    # Validate cassandra related configuration parameters
    # @param [Hash] hash_to_validate
    def cassandra_validator(hash_to_validate)
      @log.debug 'Cassandra validator initialized' if @debug
      cassandra_deploy = hash_to_validate[:cassandra_deploy]
      if cassandra_deploy.nil? or cassandra_deploy.empty?
        @log.error " 'cassandra_deploy' is required parameter, valid values: hash|disabled"
        @errors_count += 1
      elsif cassandra_deploy == 'disabled'
        @log.debug 'Cassandra deployment is disabled' if @debug
      elsif ! cassandra_deploy.is_a? Hash
        @log.error "Unrecognized value set for 'cassandra_deploy' : #{cassandra_deploy}"
        @errors_count += 1
      end

      if hash_to_validate[:install_mode] == 'local'
        if cassandra_deploy != 'disabled'
          cassandra_nodes = cassandra_deploy[:nodes]
          if cassandra_nodes.nil? or cassandra_nodes.empty?
            @log.error "Property 'nodes' of 'cassandra_deploy' should contain list of fqdn(s) on which to deploy cassandra"
            @errors_count += 1
          elsif ! cassandra_nodes.is_a? Array
            @log.error "Excepting list (array) of nodes for 'cassandra_nodes'"
            @errors_count += 1
          end
          cassandra_seeds = cassandra_deploy[:seeds]
          if cassandra_seeds.nil? or cassandra_seeds.empty?
            @log.error "Property 'seeds' of 'cassandra_deploy' should contain list of fqdn(s) which act as cassandra seed nodes"
            @errors_count += 1
          elsif ! cassandra_seeds.is_a? Array
            @log.error "Excepting list (array) of fqdn(s) for 'cassandra_seeds'"
            @errors_count += 1
          end
          # storage dirs
          data_dirs = hash_to_validate[:cassandra_deploy][:data_dirs]
          if data_dirs
            if data_dirs.is_a?(Array)
              data_dirs && data_dirs.each do |dir|
                unless Pathname.new(dir).absolute?
                  @log.error "Invalid absolute path found in 'data_dirs' (#{dir})"
                  @errors_count += 1
                end
              end
            else
              @log.error "Expecting property 'data_dirs' of 'cassandra_deploy' to be array instead got #{data_dirs.class}"
              @errors_count += 1
            end
          else
            hash_to_validate[:cassandra_deploy][:data_dirs] = [ '/var/lib/cassandra/data' ]
          end
          commitlog_dirs = hash_to_validate[:cassandra_deploy][:commitlog_dirs]
          if commitlog_dirs
            if commitlog_dirs.is_a?(Array)
              commitlog_dirs && commitlog_dirs.each do |dir|
                unless Pathname.new(dir).absolute?
                  @log.error "Invalid absolute path found in 'commitlog_dirs' (#{dir})"
                  @errors_count += 1
                end
              end
            else
              @log.error "Expecting property 'commitlog_dirs' of 'cassandra_deploy' to be array instead got #{commitlog_dirs.class}"
              @errors_count += 1
            end
          else
            hash_to_validate[:cassandra_deploy][:commitlog_dirs] = '/var/lib/cassandra/commitlog'
          end
          saved_caches_dirs = hash_to_validate[:cassandra_deploy][:saved_caches_dirs]
          if saved_caches_dirs
            if saved_caches_dirs.is_a?(Array)
              saved_caches_dirs && saved_caches_dirs.each do |dir|
                unless Pathname.new(dir).absolute?
                  @log.error "Invalid absolute path found in 'saved_caches_dirs' (#{dir})"
                  @errors_count += 1
                end
              end
            else
              @log.error "Expecting property 'saved_caches_dirs' of 'cassandra_deploy' to be array instead got #{saved_caches_dirs.class}"
              @errors_count += 1
            end
          else
            hash_to_validate[:cassandra_deploy][:saved_caches_dirs] = '/var/lib/cassandra/saved_caches'
          end

          #if hash_to_validate[:storage_dirs].size < 2
          #  @log.warn 'Its recommended to use minimum of 2 disks for cassandra deployments, one for data dir and other'+
          #            ' for commit log'
          #end
          ## cassandra storage directories
          #hash_to_validate[:cassandra_data_dirs] = if hash_to_validate[:storage_dirs].size > 1
          #                                           hash_to_validate[:storage_dirs][0..hash_to_validate[:storage_dirs].size-2]
          #                                        else
          #                                          hash_to_validate[:storage_dirs]
          #                                        end
          #hash_to_validate[:cassandra_commitlog_dir] = if hash_to_validate[:storage_dirs].size > 1
          #                                               hash_to_validate[:storage_dirs].last
          #                                            else
          #                                              hash_to_validate[:storage_dirs]
          #                                            end
          #hash_to_validate[:cassandra_saved_cache_dir] = hash_to_validate[:cassandra_commitlog_dir]
        end
      else # Cloud deployment
        if cassandra_deploy != 'disabled'
          collocate = cassandra_deploy[:collocate]
          if collocate.nil?
            hash_to_validate[:cassandra_deploy][:collocate] = false
          elsif ! (collocate.is_a? TrueClass or collocate.is_a? FalseClass)
            @log.error "Invalid value found for 'collocate' for 'cassandra_deploy', valid values are yes|no"
            @errors_count += 1
          end
          unless collocate
            number_of_instances = cassandra_deploy[:number_of_instances]
            if number_of_instances.nil?
              @log.error "Property 'number_of_instances' is a required param for 'cassandra_deploy' if collocate is disabled"
              @errors_count += 1
            elsif ! number_of_instances.is_a? Numeric
              @log.error "Expecting numeric value at 'number_of_instances' for 'cassandra_deploy'"
              @errors_count += 1
            end
          end
          cassandra_seeds_count = cassandra_deploy[:number_of_seeds]
          if cassandra_seeds_count.nil?
            @log.debug "'number_of_seeds' is not provided cassandra_deploy defaulting to 1" if @debug
            hash_to_validate[:cassandra_deploy][:number_of_seeds] = 1
          elsif ! cassandra_seeds_count.is_a? Numeric
            @log.error "expecting numeric value for 'number_of_seeds' in cassandra_deploy"
            @errors_count += 1
          end
          validate_volumes(cassandra_deploy[:volumes], hash_to_validate[:cloud_platform], 'cassandra nodes')
        end
      end
    end #cassandra_validator

    # Validate solr related conf params
    # @param [Hash] hash_to_validate
    def solr_validator(hash_to_validate)
      @log.debug 'Calling solr validator' if @debug
      solr_deploy = hash_to_validate[:solr_deploy]
      if solr_deploy.nil? or solr_deploy.empty?
        @log.error "'solr_deploy' is required parameter, valid values: hash|disabled"
        @errors_count += 1
      elsif solr_deploy == 'disabled'
        @log.debug 'Solr deployment is disabled' if @debug
      elsif ! solr_deploy.is_a? Hash
        @log.error "Unrecognized value set for 'solr_deploy' : #{solr_deploy}"
        @errors_count += 1
      end

      # TODO Remove this and add new module of solr that supports non-hdfs-deployments
      if solr_deploy != 'disabled' && solr_deploy[:hdfs_integration] == 'disabled'
        @log.error '[Not Implemented]'.red + 'Feature not yet implemented, work is in progress'
        @errors_count += 1
      end

      if hash_to_validate[:install_mode] == 'local'
        if solr_deploy != 'disabled'
          hdfs_integration = solr_deploy[:hdfs_integration]
          if hdfs_integration.nil? or hdfs_integration.empty?
            @log.error "'hdfs_integration' should be either enabled or disabled"
            @errors_count += 1
          elsif ! %w(enabled disabled).include?(hdfs_integration)
            @log.error "Invalid value for 'hdfs_integration', valid values are either: 'enabled' or 'disabled'"
            @errors_count += 1
          end
          if hdfs_integration == 'disabled'
            solr_nodes = solr_deploy[:nodes]
            if solr_nodes.nil? or solr_nodes.empty?
              @log.error "Property 'nodes' of 'solr_deploy' should contain list of fqdn(s) on which to deploy solr"
              @errors_count += 1
            elsif ! solr_nodes.is_a? Array
              @log.error "Excepting list (array) of nodes for 'nodes' of 'solr_deploy'"
              @errors_count += 1
            end          
          else # hdfs integration enabled, collocate solr on hadoop_nodes
            if hash_to_validate[:hadoop_deploy] == 'disabled'
              @log.error "'hdfs_integration' requires a valid hadoop deployment"
              @errors_count += 1
            end
            solr_nodes = solr_deploy[:nodes]
            if solr_nodes.nil? or solr_nodes.empty?
              @log.error "Property 'nodes' of 'solr_deploy' should contain list of fqdn(s) on which to deploy solr"
              @errors_count += 1
            elsif ! solr_nodes.is_a? Array
              @log.error "Excepting list (array) of nodes for 'nodes' of 'solr_deploy'"
              @errors_count += 1
            end            
          end
        end
      else # Cloud deploy
        if solr_deploy != 'disabled'
          hdfs_integration = solr_deploy[:hdfs_integration]
          if hdfs_integration.nil? or hdfs_integration.empty?
            @log.error "'hdfs_integration' should be either enabled or disabled"
            @errors_count += 1
          elsif ! %w(enabled disabled).include?(hdfs_integration)
            @log.error "Invalid value for 'hdfs_integration', valid values are either: 'enabled' or 'disabled'"
            @errors_count += 1
          end
          if hdfs_integration == 'disabled'
            number_of_instances = solr_deploy[:number_of_instances]
            if number_of_instances.nil?
              @log.error "'number_of_instances' is required when 'hdfs_integration' is disabled"
              @errors_count += 1
            elsif ! number_of_instances.is_a? Numeric
              @log.error "'number_of_instances' should be of type Numeric"
              @errors_count += 1
            end
          else
            if hash_to_validate[:hadoop_deploy] == 'disabled'
              @log.error "'hdfs_integration' requires a valid hadoop deployment"
              @errors_count += 1
            end  
          end
        end
      end
    end #solr_validator

    # Validate kafka realted conf params
    # @param [Hash] hash_to_validate
    def kafka_validator(hash_to_validate)
      kafka_deploy = hash_to_validate[:kafka_deploy]
      if kafka_deploy.nil? or kafka_deploy.empty?
        @log.error "'kafka_deploy' is required parameter, valid values: hash|disabled"
        @errors_count += 1
      elsif kafka_deploy == 'disabled'
        @log.debug 'Kafka deployment is disabled' if @debug
      elsif ! kafka_deploy.is_a? Hash
        @log.error "unrecognized value set for 'kafka_deploy' : #{kafka_deploy}"
        @errors_count += 1
      end

      if hash_to_validate[:install_mode] == 'local'
        if kafka_deploy != 'disabled'
          # kafka_nodes = kafka_deploy[:kafka_nodes]
          # if kafka_nodes.nil? or kafka_nodes.empty?
          #   puts '[Error]: '.red + "'kafka_nodes' should contain list of fqdn(s) on which to install kafka package"
          #   @errors_count += 1
          # elsif ! kafka_nodes.is_a? Array
          #   puts '[Error]: '.red + "Excepting list (array) of nodes for 'kafka_nodes'"
          #   @errors_count += 1
          # end
          kafka_brokers = kafka_deploy[:brokers]
          if kafka_brokers.nil? or kafka_brokers.empty?
            @log.error "Property 'brokers' of 'kafka_deploy' should contain list of fqdn(s) which act as kafka broker nodes"
            @errors_count += 1
          elsif ! kafka_brokers.is_a? Array
            @log.error "Excepting list (array) of fqdn(s) for 'kafka_brokers'"
            @errors_count += 1
          end
        end
      else # Cloud deploy
        if kafka_deploy != 'disabled'
          collocate = kafka_deploy[:collocate]
          if collocate.nil?
            @log.debug 'Defaulting collocate for kafka'
            hash_to_validate[:kafka_deploy][:collocate] = false  
          elsif ! (collocate.is_a? TrueClass or collocate.is_a? FalseClass)
            @log.error "Invalid value found for 'collocate', valid values are yes|no"
            @errors_count += 1
          end
          if ! collocate
            number_of_instances = kafka_deploy[:number_of_instances]
            if number_of_instances.nil?
              @log.error "'number_of_instances' is a required key for kafka_deploy if collocate is disabled"
              @errors_count += 1
            elsif ! number_of_instances.is_a? Numeric
              @log.error "expecting numeric value for 'number_of_instances' in kafka_deploy hash"
              @errors_count += 1
            end
          end
          kafka_brokers_count = kafka_deploy[:number_of_brokers]
          if kafka_brokers_count.nil?
            @log.debug "'number_of_brokers' is not provided for kafka_deploy defaulting to 1" if @debug
            hash_to_validate[:kafka_deploy][:number_of_brokers] = 1
          elsif ! kafka_brokers_count.is_a? Numeric
            @log.error "Expecting numeric value for 'number_of_brokers' in kafka_deploy hash"
            @errors_count += 1
          end
        end
      end
    end #kafka_validator

    # Validate storm related conf params
    # @param [Hash] hash_to_validate
    def storm_validator(hash_to_validate)
      storm_deploy = hash_to_validate[:storm_deploy]
      if storm_deploy.nil? or storm_deploy.empty?
        @log.error "'storm_deploy' is required parameter, valid values: hash|disabled"
        @errors_count += 1
      elsif storm_deploy == 'disabled'
        @log.debug 'Storm deployment is disabled' if @debug
      elsif ! storm_deploy.is_a? Hash
        @log.error "Unrecognized value set for 'storm_deploy' : #{storm_deploy}"
        @errors_count += 1
      end

      if hash_to_validate[:install_mode] == 'local'
        if storm_deploy != 'disabled'
          storm_supervisors = storm_deploy[:supervisors]
          if storm_supervisors.nil? or storm_supervisors.empty?
            @log.error "'storm_supervisors' should contain list of fqdn(s) on which to deploy storm supervisor daemons"
            @errors_count += 1
          elsif ! storm_supervisors.is_a? Array
            @log.error "Excepting list (array) of nodes for 'storm_supervisors'"
            @errors_count += 1
          end
          storm_master = storm_deploy[:master]
          if storm_master.nil? or storm_master.empty?
            @log.error "'storm_master' should contain a fqdn which act as storm master node"
            @errors_count += 1
          end
          storm_workers_count = storm_deploy[:workers_count]
          unless storm_workers_count.is_a? Numeric
            @log.error "'storm_workers_count' should contain number of worker processes each supervisor should run"
            @errors_count += 1
          end
        end
      else
        #cloud deploy
        if storm_deploy != 'disabled'
          collocate = storm_deploy[:collocate]
          if collocate.nil?
            @log.debug 'Defaulting collocate for kafka'
            hash_to_validate[:storm_deploy][:collocate] = false
          elsif ! (collocate.is_a? TrueClass or collocate.is_a? FalseClass)
            @log.error "Invalid value found for 'collocate', valid values are yes|no"
            @errors_count += 1
          end
          if ! collocate
            number_of_supervisors = storm_deploy[:number_of_supervisors]
            if number_of_supervisors.nil?
              @log.error "'number_of_supervisors' is a required key for storm_deploy if collocate is disabled"
              @errors_count += 1
            elsif ! number_of_supervisors.is_a? Numeric
              @log.error "Expecting numeric value for 'number_of_supervisors' in storm_deploy hash"
              @errors_count += 1
            end
          end
          storm_workers_count = storm_deploy[:workers_count]
          unless storm_workers_count.is_a? Numeric
            @log.error "'workers_count' should contain number of worker processes each supervisor should run"
            @errors_count += 1
          end
        end
      end
    end #storm_validator
  end

  #class to parse hadoop configuration
  class HadoopConfigParser
    def initialize(hadoop_conf_file, log, debug = false)
      log.debug 'Validating hadoop conf' if debug
      hadoop_conf = YamlUtils.parse_yaml(hadoop_conf_file).keys
      unless HADOOP_CONF_KEYS.all?{|key| hadoop_conf.include?(key)}
        log.error "Required keys are not present in #{hadoop_conf_file}"
        log.error "Missing keys: #{HADOOP_CONF_KEYS - hadoop_conf}"
        exit 1
      end
      diff_keys = hadoop_conf - HADOOP_CONF_KEYS
      unless diff_keys.empty?
        log.debug "Following keys were added additionally to #{hadoop_conf_file}: #{diff_keys}" if debug
      end
    end
  end

  #parse hbase configuration
  class HBaseConfigParser
    def initialize(hbase_conf_file, log, debug = false)
      log.debug 'Validating hbase conf' if debug
      hbase_conf = YamlUtils.parse_yaml(hbase_conf_file).keys
      unless HBASE_CONF_KEYS.all?{|key| hbase_conf.include?(key) }
        log.error "Required keys are not present in #{hbase_conf_file}"
        log.error "Missing keys: #{HBASE_CONF_KEYS - hbase_conf}"
        exit 1
      end
      diff_keys = hbase_conf - HBASE_CONF_KEYS
      unless diff_keys.empty?
        log.debug "Following keys were added additionally to #{hbase_conf_file}: #{diff_keys}" if debug
      end
    end
  end
end
