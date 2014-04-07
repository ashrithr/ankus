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

    # Creates a configParser object
    # @param [String] file_path => path to the configuration file to parse
    # @param [Boolean] debug => if enabled will log info to stdout
    def initialize(file_path, log, verbose=false, mock = false)
      @config_file  = file_path
      @parsed_hash  = {}
      @verbose      = verbose
      @log          = log.dup
      @log.level    = verbose ? Log4r::DEBUG : Log4r::INFO
      @mock         = mock
      @errors_count = 0
    end

    def config_logger(*args)
      @log.error args.join(' ')
      @errors_count += 1
    end

    # Parses the configuration file, validates it and returns a hash
    # @return [Hash] @parsed_hash parsed configuration hash
    # @raises Ankus::Errors::ParseError, Ankus::Errors::ParseError::NoKey
    def parse_config
      @parsed_hash = Settings.load! @config_file
      validate @parsed_hash
      HadoopConfigParser.new(HADOOP_CONF, @log)
      HBaseConfigParser.new(HBASE_CONF, @log)
      unless @errors_count == 0
        @log.error "Number of Errors: #{@errors_count}"
        raise Ankus::Errors::ParseError.new "Failed parsing config"
      end
      create_req_files!
      return @parsed_hash
    rescue Ankus::Errors::ParseError, Ankus::Errors::ParseError::NoKey => ex
      @log.error ex.message
      ex.backtrace.each { |line| @log.error "\t#{line}" }
      exit
    end

    private
    # Checks to see if the required key for the deployment is present in the
    # config file and optionally yields the value if the key is present
    # @param [Symbol] key to validate against configuration hash
    # @param [Symbol] data type the key must be in (supports validation agains
    #   String, fixnum, TrueClass, FalseClass, Hash, Array)
    def requires(key, type = :string)
      h = @parsed_hash
      val = h.deep_return(key)
      if val
        # p "Entered: #{type}, got: #{val.class} for key: #{key}"
        case type
        when :string
          if val.class != String
            config_logger "Property('#{key}') should be of type string"
          elsif val.class == String && val.empty?
            config_logger "Property('#{key}') of type string cannot be empty"
          else
            yield(key, val) if block_given?
          end
        when :fixnum
          if val.class != Fixnum
            config_logger "Property('#{key}') should be of type fixnum"
          else
            yield(key, val) if block_given?
          end
        when :boolean
          if [TrueClass, FalseClass].include?(val.class)
            yield(key, val) if block_given?
          else
            config_logger "Property('#{key}') should be of type boolean"
          end
        when :array
          if val.class != Array
            config_logger "Property('#{key}') should be of type 'array'"
          elsif val.class == Array && val.empty?
            config_logger "Property('#{key}') of type array cannot be empty"
          else
            yield(key, val) if block_given?
          end
        when :hash
          if val.class != Hash
            config_logger "Property('#{key}') should be of type 'hash'"
          elsif val.class == Hash && val.empty?
            config_logger "Property('#{key}') of type hash cannot be empty"
          else
            yield(key, val) if block_given?
          end
        else
          config_logger "Caught unparsable key #{key}"
        end
      else
        config_logger "Property '#{key}' is required"
      end
    end

    # Validates the loaded configuration file
    # @param [Hash] config => hash to validate
    def validate(config)
      if config.empty?
        raise(Ankus::Errors::ParseError.new('Config file is empty!'.red))
      end
      # validate if basic configuration parameters are present or not
      ANKUS_CONF_MAIN_KEYS.each do |key|
        unless config.include?(key)
          @log.error "Missing property: '#{key}' is required"
          @errors_count += 1
        end
      end

      # validate if the keys in config file are valid (nested validation)
      flat_hash(config).keys.flatten.each do |key_to_validate|
        unless ANKUS_CONF_VALID_KEYS.include?(key_to_validate)
          config_logger "Unrecognized Property: '#{key_to_validate}'"
        end
      end

      requires :install_mode, :string do |k, v|
        unless %w(local cloud).include?(v)
          config_logger "Un-supported install mode: #{v} found for '#{k}'"
        end
      end

      # validate install_mode, it can be 'local|cloud' modes
      case @parsed_hash[:install_mode]
      when 'local'
        local_validator config
      when 'cloud'
        cloud_validator config
      else
        @log.error "Un-supported install mode: #{@parsed_hash[:install_mode]}"
      end
    end

    # Creates set of files and directories required by ankus
    def create_req_files!
      Dir.mkdir DATA_DIR                unless File.exists? DATA_DIR
      FileUtils.touch NODES_FILE        unless File.exists? NODES_FILE
      FileUtils.touch ENC_ROLES_FILE    unless File.exists? ENC_ROLES_FILE
      FileUtils.touch HIERA_DATA_FILE   unless File.exists? HIERA_DATA_FILE
    end

    # Validations specific to local install_mode
    # @param [Hash] config => hash to validate
    def local_validator(config)
      @log.debug 'Initializing local mode validator'

      requires :controller, :string
      requires :ssh_key, :string
      requires :ssh_user, :string do |k, v|
        unless File.exists?(File.expand_path(v))
          config_logger "Path specified in property '#{k}': #{v} does not exists"
        end
      end

      common_validator(config)

      # force user to use hostname instead of ip address
      nodes = Inventory::Generator.new(@parsed_hash).generate
      nodes.keys.each do |node|
        unless node =~ HOSTNAME_REGEX
          config_logger "Expecting hostname got ip-address @ #{node}," \
                        ' replace ip_address with hostname'
        end
      end

      #
      # TODO move this part of validation to deployment
      #
      unless @mock
        nodes.keys.each do |node|
          unless Ankus::Util::PortUtils.port_open?(node, 22, 2)
            @log.error "Node: #{node} is not reachable"
            @errors_count += 1
          end
        end
        nodes.keys.each do |node|
          begin
            Util::SshUtils.sshable?(node, config[:ssh_user], config[:ssh_key])
          rescue
            @log.error "Cannot ssh into instance '#{node}' with user: #{config[:ssh_user]} and " +
            "key: #{config[:ssh_key]}"
            @errors_count += 1
          end
        end
      end
    end # local_validator

    def validate_aws_credentials_hash(credentials)
      requires :aws_secret_key, :string
      requires :aws_access_id,  :string
      requires :aws_sec_groups, :array

      valid_credentials = {
          aws_access_id: '',
          aws_secret_key: '',
          aws_machine_type: '',
          aws_region: '',
          aws_key: '',
          aws_sec_groups: ''
      }
      unless credentials.keys.sort == valid_credentials.keys.sort
        config_logger "Property 'cloud_credentials' is malformed/invalid, " \
                            'look sample cloud config for example'
      end
    end

    def validate_rs_credentials_hash(credentials)
      requires :rackspace_username,           :string
      requires :rackspace_api_key,            :string
      requires :rackspace_cluster_identifier, :string
      requires :rackspace_ssh_key, :string do |rsshk, rsshkv|
        unless File.exists?(File.expand_path(rsshkv))
          config_logger "SSH key file: #{rsshkv} does not exists"
        end
      end

      valid_credentials = {
          rackspace_username: '',
          rackspace_api_key: '',
          rackspace_instance_type: '',
          rackspace_ssh_key: '',
          cluster_identifier: ''
      }
      unless credentials.keys.sort == valid_credentials.keys.sort
        config_logger "Property 'cloud_credentials' is malformed/invalid, " \
                            'look sample cloud config file for example'
      end
    end

    def validate_os_credentials_hash(credentials)
      requires :os_auth_url,        :string
      requires :os_username,        :string
      requires :os_password,        :string
      requires :os_tenant,          :string
      requires :os_flavor,          :fixnum
      requires :os_image_ref,       :string
      requires :os_ssh_key,         :string
      requires :os_ssh_user,        :string
      requires :os_sec_groups,      :array
      requires :cluster_identifier, :string

      valid_credentials = {
          os_auth_url: '',
          os_username: '',
          os_password: '',
          os_tenant: '',
          os_flavor: '',
          os_ssh_key: '',
          os_ssh_user: '',
          os_sec_groups: '',
          os_image_ref: '',
          cluster_identifier: ''
      }
      unless credentials.keys.sort == valid_credentials.keys.sort
        config_logger "Property 'cloud_credentials' is malformed/invalid," \
                            ' look sample cloud config for example'
      end
    end


    # Validations specific to cloud install_mode
    # @param [Hash] config => hash to validate
    def cloud_validator(config)
      @log.debug 'Initializing cloud validator'

      requires :cloud_platform, :string do |cp, cpv|
        unless %w(aws openstack rackspace).include?(cpv)
          config_logger "Invalid value for '#{cp}', supported" \
                        " platforms are 'aws','rackspace' and 'openstack'"
        end
        requires :cloud_credentials, :hash do |cc, ccv|

          if cpv == 'aws'
            validate_aws_credentials_hash(ccv)
          elsif cpv == 'rackspace'
            validate_rs_credentials_hash(ccv)
          elsif cpv == 'openstack'
            validate_os_credentials_hash(ccv)
          end
        end
      end

      requires :cloud_os_type, :string do |_, cosv|
        unless %w(centos ubuntu).include?(cosv.downcase)
          config_logger "Unsupported os_type found: #{cosv}. Supported os's" \
                       ' are centos & ubuntu'
        end
      end
      common_validator(config)
    end

    # Validates volumes configuration for cloud deployments
    # @param [Hash] volumes => volumes hash to validate
    def validate_volumes(volumes, cloud_platform, deploy_mode)
      if volumes && volumes != 'disabled' && volumes.is_a?(Hash)
        @log.debug 'Initializing volume config validator'

        requires :type, :string do |_, vtv|
          if cloud_platform == 'aws'
            unless %w(ebs io1).include?(vtv)
              config_logger "Invalid value('#{vtv}') found for volume type" \
                           "valid values are 'ebs' and 'io1'"
            end
            if vtv == 'io1'
              requires :iops, :fixnum do |iops, iopsv|
                unless iopsv.between?(1, 4000)
                  config_logger "Invlaid value for #{iops}('#{iopsv}')." \
                                " Valid value should be in between 1-4000"
                end
              end
            end
          elsif cloud_platform == 'rackspace' || cloud_platform == 'openstack'
            requires :type, :string do |vt, vtv|
              unless %w(blockstore).include?(vtv)
                config_logger "Ivalid value found for volume type"\
                              " #{vt}('#{vtv}'), valid value is 'blockstore'"
              end
            end
          end
        end
        requires :count, :fixnum do |vc, vcv|
          if vcv == 0 || vcv < 0
            config_logger "Property #{vc}(volumes count) should be > 0"
          end
        end
        requires :size, :fixnum do |vs, vsv|
          if vsv == 0 || vcv < 0
            config_logger "Property #{vs}(size of the volume) should be > 0"
          end
        end
        @log.debug "Instances will be booted with '#{volumes[:count]}' " \
                   "volumes of type(#{volumes[:type]}) each with " \
                   "size(#{volumes[:size]}GB)"
      else
        @log.debug "Volumes configuration disabled for #{deploy_mode}"
      end
    end

    # Validates params which are common for both local and cloud install_modes
    # @param [Hash] config => hash to validate
    def common_validator(config)
      @log.debug 'Initializing common validator'

      requires :security, :string do |sk, skv|
        unless %w(simple kerberos).include?(skv)
          config_logger "Invalid value for '#{sk}', valid: simple|kerberos"
        end
        if skv == 'kerberos'
          requires :kerberos_realm, :string
          requires :kerberos_domain, :string
        end
      end
      requires :monitoring, :string do |mk, mkv|
        unless %w(enabled disabled).include?(mkv)
          config_logger "Invalid value for '#{mk}', valid: enabled|disabled"
        end
      end
      requires :alerting, :string do |ak, akv|
        unless %w(enabled disabled).include?(akv)
          config_logger "Invalid value for '#{ak}', valid: enabled|disabled"
        end
        requires :admin_email, :string if akv == 'enabled'
      end
      requires :log_aggregation, :string do |lak, lakv|
        unless %w(enabled disabled).include?(lakv)
          config_logger "Invalid value for '#{lak}', valid: enabled|disabled"
        end
      end

      hadoop_validator(config) if config[:hadoop_deploy] != 'disabled'
      hbase_validator(config) if config[:hbase_deploy] != 'disabled'
      zookeeper_validator(config) if config[:zookeeper_deploy] != 'disabled'
      cassandra_validator(config) if config[:cassandra_deploy] != 'disabled'
      solr_validator(config) if config[:solr_deploy] != 'disabled'
      kafka_validator(config) if config[:kafka_deploy] != 'disabled'
      storm_validator(config) if config[:storm_deploy] != 'disabled'

      #Check to see if all the deploy options are disabled if so raise
      if ANKUS_CONF_DEPLOY_KEYS.map { |e| config[e] }.uniq.length == 1
        config_logger "All the deploys(#{ANKUS_CONF_DEPLOY_KEYS.join(',')})"\
            ' are disabled, at least one deploy should be configured'
      end
    end

    # Validates hadoop related conf params for local install_mode
    # @param [String] config
    def hadoop_validator(config)
      @log.debug 'Initializing hadoop validator'
      install_mode = config[:install_mode]

      requires :hadoop_deploy, :hash do
        # Hadoop ha
        requires :ha, :string do |hak, hakv|
          unless %w(enabled disabled).include?(hakv)
            config_logger "Invalid value for '#{hak}', valid values are: " \
                          "enabled|disabled"
          end
          # HA enabled
          if hakv == 'enabled'
            # Zookeepers
            requires :zookeeper_deploy, :hash do |zkd, zdkv|
              if install_mode == 'local'
                requires :quorum, :array do |zkq, zkqv|
                  unless zkqv.length % 2 == 1
                    config_logger "Please provide odd number of zookeeper nodes"
                  end
                end
              elsif install_mode == 'cloud'
                requires :quorum_count, :fixnum do |zkqc, zkqcv|
                  unless zkqcv % 2 == 1
                    config_logger "Please provide odd number of zookeeper nodes"
                  end
                end
              end
            end
            # Journal nodes
            if install_mode == 'local'
              requires :journal_quorum, :array do |jq, jqv|
                unless jqv.length % 2 == 1
                  config_logger "Please provide odd number of journal nodes"
                end
              end
            end
          end
          if install_mode == 'local'
            # Namenode's
            requires :namenode, :array do |nn, nnv|
              if hakv == 'enabled' && nnv.length != 2
                config_logger "2 namenode's should be specified for ha deploy"
              elsif hakv == 'disabled' && nnv.length != 1
                config_logger "For non-ha deployments only provide 1 namenode"
              end
            end
            # SNN
            requires :secondarynamenode, :string if hakv == 'disabled'
          end
        end
        # Packages source
        requires :packages_source, :string do |psk, pskv|
          if %w(hdp cdh).include?(pskv)
            # Ecosystem tools
            hadoop_ecosystem = config[:hadoop_deploy][:ecosystem]
            valid_hadoop_ecosystem_cdh = %w(hive pig sqoop oozie hue impala)
            valid_hadoop_ecosystem_hdp = %w(hive pig sqoop oozie hue tez)
            if hadoop_ecosystem
              hadoop_ecosystem.each do |tool|
                if pskv == 'cdh'
                  unless valid_hadoop_ecosystem_cdh.include?(tool)
                    config_logger "Invalid ecosytem tool('#{tool}')" \
                                  "valid values: #{valid_hadoop_ecosystem_cdh}"
                  end
                elsif pskv == 'hdp'
                  unless valid_hadoop_ecosystem_hdp.include?(tool)
                    config_logger "Invalid ecosytem tool('#{tool}')" \
                                  "valid values: #{valid_hadoop_ecosystem_hdp}"
                  end
                end
              end
            end
          else
            config_logger "Invlid package source '#{pskv}', valid values" \
                          " are 'cdh' or 'hdp'"
          end
        end
        # MapReduce
        case config[:hadoop_deploy][:mapreduce]
        when Hash
          requires :mapreduce, :hash do
            requires :type, :string do |mrtk, mrtkv|
              unless %w(mr1 mr2).include?(mrtkv)
                config_logger "Invalid value for '#{mrtk}'(#{mrtkv})," \
                             " valid values are : mr1(mapreduce) & mr2(yarn)"
              end
              # mr master for local mode
              requires :master, :string if install_mode == 'local'
              # hdp supports only yarn
              if config[:hadoop_deploy][:packages_source] == 'hdp' && mrtkv == 'mr1'
                config_logger "HDP deployments does not support mr1"
              end
            end
          end
        when String
          requires :mapreduce, :string
        else
          config_logger 'Unrecognized value for mapreduce'
        end

        # Workers
        if install_mode == 'local'
          requires :worker_nodes, :array
        elsif install_mode == 'cloud'
          requires :worker_nodes_count, :fixnum do |wnk, wnkv|
            if wnkv == 0 || wnkv < 0
              config_logger 'Worker nodes should be > 0'
            end
          end
        end

        # Volumes|Directories configuration
        if install_mode == 'local'
          requires :data_dirs, :array do |dd, ddv|
            ddv.each do |dir|
              unless Pathname.new(dir).absolute?
                config_logger "Invalid absolute path found in '#{dd}'(#{dir})"
              end
            end
          end
          requires :master_dirs, :array do |md, mdv|
            mdv.each do |dir|
              unless Pathname.new(dir).absolute?
                config_logger "Invalid absolute path found in '#{md}'(#{dir})"
              end
            end
          end
        else # Cloud deployment
          validate_volumes(
            config[:hadoop_deploy][:worker_volumes],
            config[:cloud_platform],
            'hadoop worker nodes'
          )
          validate_volumes(
            config[:hadoop_deploy][:master_volumes],
            config[:cloud_platform],
            'hadoop master nodes'
          )
        end
      end
    end

    # Validates hbase related conf params
    # @param [Hash] config
    def hbase_validator(config)
      @log.debug "Initializing hbase validator"
      install_mode = config[:install_mode]

      requires :hbase_deploy, :hash do |hb, hbv|
        requires :hadoop_deploy, :hash
        if install_mode == 'cloud'
          requires :master_count, :fixnum do |hbm, hbmv|
            unless hbmv == 0 || hbmv < 0
              config_logger "HBase master count should be > 0"
            end
          end
          requires :quorum_count, :fixnum do |zkc, zkcv|
            unless zkcv % 2 == 1
              config_logger "Please provide odd number of zookeeper nodes"
            end
          end

        else # Local
          requires :master, :array do |hm, hmv|
            unless hmv.length == 0 || hmv.length < 0
              config_logger "Provide atleast one hbase master"
            end
          end
          requires :quorum, :array do |zkq, zkqv|
            unless zkqv.length % 2 == 1
              config_logger "Please provide odd number of zookeepers"
            end
          end
        end
      end
    end

    # Validates zookeeper configuration
    def zookeeper_validator(config)
      install_mode = config[:install_mode]
      hadoop_ha = config[:hadoop_deploy][:ha] if config[:hadoop_deploy] != 'disabled'
      hbase_install = config[:hbase_deploy]
      kafka_install = config[:kafka_deploy]
      storm_install = config[:storm_deploy]
      solr_install  = config[:solr_deploy]
      if hadoop_ha == 'enabled' || hbase_install != 'disabled' ||
        kafka_install != 'disabled' || storm_install != 'disabled' ||
        solr_install != 'disabled'
        requires :zookeeper_deploy, :hash do
          if install_mode == 'local'
            requires :quorum, :array do |zkq, zkqv|
              unless zkqv.length % 2 == 1
                config_logger 'Provide odd number of zookeeper nodes to' \
                              'handle failovers'
              end
            end
          else
            requires :quorum_count, :fixnum do |zkq, zkqv|
              unless zkqv % 2 ==  1
                config_logger 'Provide odd number of zookeeper nodes to' \
                              'handle failovers'
              end
            end
          end
        end
      end
    end

    # Validate cassandra related configuration parameters
    # @param [Hash] config
    def cassandra_validator(config)
      @log.debug 'Initializing cassandra validator'

      requires :cassandra_deploy, :hash do |cd, cdv|
        if config[:install_mode] == 'local'
          requires :nodes, :array do |cn, cnv|
            requires :seeds, :array do |cs, csv|
              csv.each do |seed|
                unless cnv.include?(seed)
                  config_logger "Seed: '#{seed}' does not belong to '#{cnv}'"
                end
              end
            end
          end
          requires :data_dirs, :array do |cdd, cddv|
            cddv.each do |dir|
              unless Pathname.new(dir).absolute?
                  config_error "Invalid absolute path found in" \
                               " 'data_dirs'(#{dir})"
              end
            end
          end
          requires :commitlog_dirs, :array do |cld, cldv|
            cldv.each do |dir|
              unless Pathname.new(dir).absolute?
                  config_error "Invalid absolute path found in" \
                               " 'data_dirs'(#{dir})"
              end
            end
          end
          requires :saved_caches_dirs, :array do |scd, scdv|
            scdv.each do |dir|
              unless Pathname.new(dir).absolute?
                  config_error "Invalid absolute path found in" \
                               " 'data_dirs'(#{dir})"
              end
            end
          end

        else # Cloud
          colocate = (config[:cassandra_deploy][:colocate] ||= false)
          if colocate
            requires :colocate, :boolean
          else
            requires :number_of_instances, :fixnum do |cn, cnv|
              requires :number_of_seeds, :fixnum do |cs, csv|
                if csv > cnv
                  config_logger "Cassandra seeds should be less than nodes"
                end
              end
            end
          end
        end
      end
    end #cassandra_validator

    # Validate solr related conf params
    # @param [Hash] config
    def solr_validator(config)
      @log.debug 'Initializing solr validator'
      requires :solr_deploy, :hash do |sd, sdv|
        requires :hdfs_integration, :string do |sh, shv|
          unless %w(enabled disabled).include?(shv)
            config_logger "Unrecognized value set for #{sh}('#{shv}')" \
                          " valid values are enabled|disabled"
          end
          if shv == 'disabled'
            # TODO fix me
            config_logger "[WIP] Sorry, feature is not yet ready."
          else
            if config[:hadoop_deploy] == 'disabled'
              config_logger "Solr HDFS integration requires 'hadoop_deploy'" \
                            " enabled"
            end
          end
        end

        if config[:install_mode] == 'local'
          requires :nodes, :array
        else # cloud
          requires :number_of_instances, :fixnum
        end
      end # solr_deploy
    end #solr_validator

    # Validate kafka realted conf params
    # @param [Hash] config
    def kafka_validator(config)
      @log.debug 'Initializing kafka validator'
      requires :kafka_deploy, :hash do |kd, kdv|
        if config[:install_mode] == 'local'
          requires :brokers, :array
        else
          colocate = (kdv[:colocate] ||= false)
          if colocate
            requires :colocate, :boolean
          end
          requires :number_of_brokers, :fixnum
        end
      end
    end #kafka_validator

    # Validate storm related conf params
    # @param [Hash] config
    def storm_validator(config)
      @log.debug 'Initializing storm validator'
      requires :storm_deploy, :hash do |sd, sdv|
        if config[:install_mode] == 'local'
          requires :supervisors, :array
          requires :master, :string
          requires :workers_count, :fixnum
        else
          colocate = (sdv[:colocate] ||= false)
          if colocate
            requires :colocate, :boolean
          end
          requires :number_of_supervisors, :fixnum
          requires :workers_count, :fixnum
        end
      end
    end #storm_validator
  end

  #class to parse hadoop configuration
  class HadoopConfigParser
    def initialize(hadoop_conf_file, log, debug = false)
      log.debug 'Validating hadoop conf' if debug
      hadoop_conf = Util::YamlUtils.parse_yaml(hadoop_conf_file).keys
      unless HADOOP_CONF_KEYS.all?{ |key| hadoop_conf.include?(key) }
        log.error "Required keys are not present in #{hadoop_conf_file}"
        log.error "Missing keys: #{HADOOP_CONF_KEYS - hadoop_conf}"
        exit 1
      end
      diff_keys = hadoop_conf - HADOOP_CONF_KEYS_COMPLETE
      unless diff_keys.empty?
        log.debug "Following keys were added additionally to" \
                  " #{hadoop_conf_file}: #{diff_keys}" if debug
      end
    end
  end

  #parse hbase configuration
  class HBaseConfigParser
    def initialize(hbase_conf_file, log, debug = false)
      log.debug 'Validating hbase conf' if debug
      hbase_conf = Util::YamlUtils.parse_yaml(hbase_conf_file).keys
      unless HBASE_CONF_KEYS.all?{ |key| hbase_conf.include?(key) }
        log.error "Required keys are not present in #{hbase_conf_file}"
        log.error "Missing keys: #{HBASE_CONF_KEYS - hbase_conf}"
        exit 1
      end
      diff_keys = hbase_conf - HBASE_CONF_KEYS
      unless diff_keys.empty?
        log.debug "Following keys were added additionally to" \
                  " #{hbase_conf_file}: #{diff_keys}" if debug
      end
    end
  end
end
