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

=begin
  Helper module for ankus
=end
module Ankus
  #Constants
  DATA_DIR          = File.expand_path(File.dirname(__FILE__) + '/../../.data')
  DEFAULT_CONFIG    = File.expand_path(File.dirname(__FILE__) + '/../../conf/ankus_conf.yaml')
  NODES_FILE        = "#{DATA_DIR}/nodes.yaml"
  ENC_ROLES_FILE    = "#{DATA_DIR}/roles.yaml"
  HIERA_DATA_FILE   = "#{DATA_DIR}/common.yaml"
  PUPPET_INSTALLER  = File.expand_path(File.dirname(__FILE__) + '/../shell/puppet_installer.sh')
  ENC_SCRIPT        = File.expand_path(File.dirname(__FILE__) + '/../../bin/ankus_puppet_enc')
  GETOSINFO_SCRIPT  = File.expand_path(File.dirname(__FILE__) + '../../shell/get_osinfo.sh')
  HADOOP_CONF       = File.expand_path(File.dirname(__FILE__) + '/../../conf/ankus_hadoop_conf.yaml')
  HBASE_CONF        = File.expand_path(File.dirname(__FILE__) + '/../../conf/ankus_hbase_conf.yaml')
  CASSANDRA_CONF    = File.expand_path(File.dirname(__FILE__) + '/../../conf/ankus_cassandra_conf.yaml')
  ENC_PATH          = %q(/etc/puppet/enc)
  HIERA_DATA_PATH   = %q(/etc/puppet/hieradata)
  REMOTE_LOG_DIR    = %q(/var/log/ankus)

  HOSTNAME_REGEX    = /^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$/

  ANKUS_CONF_MAIN_KEYS = [
    :install_mode,
    :hadoop_deploy,
    :hbase_deploy,
    :cassandra_deploy,
    :solr_deploy,
    :kafka_deploy,
    :storm_deploy,
    :zookeeper_deploy,
    :security,
    :monitoring,
    :alerting,
    :log_aggregation
  ]

  ANKUS_CONF_DEPLOY_KEYS = [
    :hadoop_deploy,
    :hbase_deploy,
    :cassandra_deploy,
    :solr_deploy,
    :kafka_deploy,
    :storm_deploy,
    :zookeeper_deploy
  ]

  ANKUS_CONF_VALID_KEYS = [
    :install_mode,
    :cloud_platform,
    :cloud_credentials,
    :aws_access_id,
    :aws_secret_key,
    :aws_machine_type,
    :aws_region,
    :aws_key,
    :os_auth_url,
    :os_username,
    :os_password,
    :os_tenant,
    :os_flavor,
    :os_ssh_key,
    :os_ssh_user,
    :os_sec_groups,
    :os_image_ref,
    :cluster_identifier,
    :rackspace_username,
    :rackspace_api_key,
    :rackspace_instance_type,
    :rackspace_ssh_key,
    :cluster_identifier,
    :cloud_os_type,
    :hadoop_deploy,
    :packages_source,
    :ha,
    :mapreduce,
    :type,
    :ecosystem,
    :worker_volumes,
    :master_volumes,
    :type,
    :iops,
    :size,
    :count,
    :namenode,
    :secondarynamenode,
    :journal_quorum,
    :data_dirs,
    :master_dirs,
    :hbase_deploy,
    :master,
    :master_count,
    :zookeeper_deploy,
    :quorum,
    :dirs,
    :quorum_count,
    :worker_nodes_count,
    :worker_nodes,
    :solr_deploy,
    :hdfs_integration,
    :number_of_instances,
    :cassandra_deploy,
    :collocate,
    :number_of_instances,
    :number_of_seeds,
    :kafka_deploy,
    :number_of_brokers,
    :storm_deploy,
    :nodes,
    :number_of_supervisors,
    :workers_count,
    :security,
    :kerberos_realm,
    :kerberos_domain,
    :monitoring,
    :alerting,
    :admin_email,
    :log_aggregation
  ]

  HADOOP_CONF_KEYS_COMPLETE = %w{
    hadoop_heap_size
    yarn_heapsize
    hadoop_namenode_opts
    hadoop_jobtracker_opts
    hadoop_secondarynamenode_opts
    hadoop_datanode_opts
    hadoop_tasktracker_opts
    hadoop_balancer_opts
    yarn_resourcemanager_opts
    yarn_nodemanager_opts
    yarn_proxyserver_opts
    hadoop_job_historyserver_opts
    hadoop_snappy_codec
    hadoop_config_fs_inmemory_size_mb
    hadoop_config_io_file_buffer_size
    hadoop_config_hadoop_tmp_dir
    hadoop_ha_nameservice_id
    hadoop_config_dfs_replication
    hadoop_config_dfs_block_size
    hadoop_config_io_bytes_per_checksum
    hadoop_config_fs_trash_interval
    hadoop_config_dfs_permissions_supergroup
    hadoop_config_dfs_datanode_max_transfer_threads
    hadoop_config_dfs_datanode_du_reserved
    hadoop_config_dfs_datanode_balance_bandwidthpersec
    hadoop_config_dfs_permissions_enabled
    hadoop_config_namenode_handler_count
    hadoop_config_dfs_namenode_safemode_threshold_pct
    hadoop_config_dfs_namenode_replication_min
    hadoop_config_dfs_namenode_safemode_extension
    hadoop_config_dfs_df_interval
    hadoop_config_dfs_client_block_write_retries
    hadoop_config_mapred_child_java_opts
    hadoop_config_io_sort_mb
    hadoop_config_io_sort_factor
    hadoop_config_mapred_map_sort_spill_percent
    hadoop_config_mapred_job_tracker_handler_count
    hadoop_config_mapred_map_tasks_speculative_execution
    hadoop_config_mapred_reduce_parallel_copies
    hadoop_config_mapred_reduce_tasks_speculative_execution
    hadoop_config_mapred_tasktracker_map_tasks_maximum
    hadoop_config_mapred_tasktracker_reduce_tasks_maximum
    hadoop_config_tasktracker_http_threads
    hadoop_config_use_map_compression
    hadoop_config_mapred_reduce_slowstart_completed_maps
    hadoop_config_mapred_reduce_tasks
    hadoop_namenode_port
    hadoop_resourcemanager_port
    hadoop_resourcetracker_port
    hadoop_resourcescheduler_port
    hadoop_resourceadmin_port
    hadoop_resourcewebapp_port
    hadoop_proxyserver_port
    hadoop_jobhistory_port
    hadoop_jobhistory_webapp_port
    hadoop_jobtracker_port
    hadoop_tasktracker_port
    hadoop_datanode_port
    hadoop_config_yarn_nodemanager_resource_memory_mb
    hadoop_config_yarn_scheduler_minimum_allocation_mb
    hadoop_config_yarn_scheduler_maximum_allocation_mb
    hadoop_config_mapreduce_map_memory_mb
    hadoop_config_mapreduce_reduce_memory_mb
    hadoop_config_mapreduce_map_java_opts
    hadoop_config_mapreduce_reduce_java_opts
    hadoop_config_yarn_nodemanager_vmem_pmem_ratio
    hadoop_config_mapreduce_task_io_sort_mb
    hadoop_config_mapreduce_task_io_sort_factor
    hadoop_config_mapreduce_reduce_shuffle_parallelcopies
  }

  HADOOP_CONF_KEYS = %w{
    hadoop_heap_size
    yarn_heapsize
    hadoop_namenode_opts
    hadoop_jobtracker_opts
    hadoop_secondarynamenode_opts
    hadoop_datanode_opts
    hadoop_tasktracker_opts
    hadoop_balancer_opts
    yarn_resourcemanager_opts
    yarn_nodemanager_opts
    yarn_proxyserver_opts
    hadoop_job_historyserver_opts
    hadoop_snappy_codec
    hadoop_config_fs_inmemory_size_mb
    hadoop_config_io_file_buffer_size
    hadoop_config_hadoop_tmp_dir
    hadoop_ha_nameservice_id
    hadoop_config_dfs_replication
    hadoop_config_dfs_block_size
    hadoop_config_io_bytes_per_checksum
    hadoop_config_fs_trash_interval
    hadoop_config_dfs_permissions_supergroup
    hadoop_config_dfs_datanode_max_transfer_threads
    hadoop_config_dfs_datanode_du_reserved
    hadoop_config_dfs_datanode_balance_bandwidthpersec
    hadoop_config_dfs_permissions_enabled
    hadoop_config_namenode_handler_count
    hadoop_config_dfs_namenode_safemode_threshold_pct
    hadoop_config_dfs_namenode_replication_min
    hadoop_config_dfs_namenode_safemode_extension
    hadoop_config_dfs_df_interval
    hadoop_config_dfs_client_block_write_retries
    hadoop_namenode_port
    hadoop_resourcemanager_port
    hadoop_resourcetracker_port
    hadoop_resourcescheduler_port
    hadoop_resourceadmin_port
    hadoop_resourcewebapp_port
    hadoop_proxyserver_port
    hadoop_jobhistory_port
    hadoop_jobhistory_webapp_port
    hadoop_jobtracker_port
    hadoop_tasktracker_port
    hadoop_datanode_port
  }

  HBASE_CONF_KEYS = %w{
    hbase_master_java_heap_size_max
    hbase_master_java_heap_size_new
    hbase_master_gc_tuning_options
    hbase_master_gc_log_opts
    hbase_regionserver_java_heap_size_max
    hbase_regionserver_java_heap_size_new
    hbase_regionserver_gc_tuning_opts
    hbase_regionserver_gc_log_opts
    hbase_regionserver_lease_period
    hbase_regionserver_handler_count
    hbase_regionserver_split_limit
    hbase_regionserver_msg_period
    hbase_regionserver_log_flush_period
    hbase_regionserver_logroll_period
    hbase_regionserver_split_check_period
    hbase_regionserver_worker_period
    hbase_regionserver_balancer_period
    hbase_regionserver_balancer_slop
    hbase_regionserver_max_filesize
    hbase_regionserver_hfile_block_size
    hbase_regionserver_required_codecs
    hbase_regionserver_block_cache_size
    hbase_regionserver_hash_type
    hbase_zookeeper_max_client_connections
    hbase_client_write_buffer
    hbase_client_pause_period_ms
    hbase_client_retry_count
    hbase_client_scanner_prefetch_rows
    hbase_client_max_keyvalue_size
    hbase_memstore_flush_upper_heap_pct
    hbase_memstore_flush_lower_heap_pct
    hbase_memstore_flush_size_trigger
    hbase_memstore_preflush_trigger
    hbase_memstore_flush_stall_trigger
    hbase_memstore_mslab_enabled
    hbase_compaction_files_trigger
    hbase_compaction_pause_trigger
    hbase_compaction_pause_time
    hbase_compaction_max_combine_files
    hbase_compaction_period
    hbase_master_port
    hbase_master_dash_port
    hbase_master_jmx_dash_port
    hbase_regionserver_port
    hbase_regionserver_dash_port
    hbase_regionserver_jmx_dash_port
  }

  AWS_INSTANCE_TYPES = {
      'm1.small'    => { :cpu => 1, :memory => 1.7, :instance_storage => { :count => 1, :size => 160 } },
      'm1.medium'   => { :cpu => 1, :memory => 3.75, :instance_storage => { :count => 1, :size => 410 } },
      'm1.large'    => { :cpu => 2, :memory => 7.5, :instance_storage => { :count => 2, :size => 420 } },
      'm1.xlarge'   => { :cpu => 4, :memory => 15, :instance_storage => { :count => 4, :size => 420 } },
      'm3.medium'   => { :cpu => 1, :memory => 3.75, :instance_storage => { :count => 1, :size => 4 } },
      'm3.large'    => { :cpu => 2, :memory => 7, :instance_storage => { :count => 1, :size => 32 } },
      'm3.xlarge'   => { :cpu => 4, :memory => 15, :instance_storage => { :count => 2, :size => 40 } },
      'm3.2xlarge'  => { :cpu => 8, :memory => 30, :instance_storage => { :count => 2, :size => 80 } },
      'm2.xlarge'   => { :cpu => 2, :memory => 17.1, :instance_storage => { :count => 1, :size => 420 } },
      'm2.2xlarge'  => { :cpu => 4, :memory => 34.2, :instance_storage => { :count => 1, :size => 850 } },
      'm2.4xlarge'  => { :cpu => 8, :memory => 68.4, :instance_storage => { :count => 2, :size => 840 } },
      'hi1.4xlarge' => { :cpu => 16, :memory => 60.5, :instance_storage => { :count => 2, :size => 1024 } },
      'hi1.8xlarge' => { :cpu => 16, :memory => 117, :instance_storage => { :count => 24, :size => 2048 } },
      'c1.medium'   => { :cpu => 2, :memory => 1.7, :instance_storage => { :count => 1, :size => 350 } },
      'c1.xlarge'   => { :cpu => 8, :memory => 7, :instance_storage => { :count => 4, :size => 420 } },
      'c3.large'    => { :cpu => 2, :memory => 3.75, :instance_storage => { :count => 2, :size => 16 } },
      'c3.xlarge'   => { :cpu => 4, :memory => 7.5, :instance_storage => { :count => 2, :size => 40 } },
      'c3.2xlarge'  => { :cpu => 8, :memory => 15, :instance_storage => { :count => 2, :size => 80 } },
      'c3.4xlarge'  => { :cpu => 16, :memory => 30, :instance_storage => { :count => 2, :size => 160 } },
      'c3.8xlarge'  => { :cpu => 32, :memory => 60, :instance_storage => { :count => 2, :size => 320 } },
  }

  RS_INSTANCE_TYPES = {
      '2'                 => { :cpu => 1, :memory => 0.512, :system_disk => { :size => 20 } },
      '3'                 => { :cpu => 1, :memory => 1, :system_disk => { :size => 40 } },
      '4'                 => { :cpu => 2, :memory => 2, :system_disk => { :size => 80 } },
      '5'                 => { :cpu => 2, :memory => 4, :system_disk => { :size => 160 } },
      '6'                 => { :cpu => 4, :memory => 8, :system_disk => { :size => 320 } },
      '7'                 => { :cpu => 6, :memory => 15, :system_disk => { :size => 620 } },
      '8'                 => { :cpu => 8, :memory => 30, :system_disk => { :size => 1200 } },
      'performance1-1'    => { :cpu => 1, :memory => 1, :system_disk => { :size => 20 } },
      'performance1-2'    => { :cpu => 2, :memory => 2, :system_disk => { :size => 40 }, :data_disk => {:count => 1, :size => 20} },
      'performance1-4'    => { :cpu => 4, :memory => 4, :system_disk => { :size => 40 }, :data_disk => {:count => 1, :size => 40} },
      'performance1-8'    => { :cpu => 8, :memory => 8, :system_disk => { :size => 40 }, :data_disk => {:count => 1, :size => 80} },
      'performance2-15'   => { :cpu => 4, :memory => 15, :system_disk => { :size => 40 }, :data_disk => {:count => 1, :size => 150} },
      'performance2-30'   => { :cpu => 8, :memory => 30, :system_disk => { :size => 40 }, :data_disk => {:count => 1, :size => 300} },
      'performance2-60'   => { :cpu => 16, :memory => 60, :system_disk => { :size => 40 }, :data_disk => {:count => 2, :size => 300} },
      'performance2-90'   => { :cpu => 24, :memory => 90, :system_disk => { :size => 40 }, :data_disk => {:count => 3, :size => 300} },
      'performance2-120'  => { :cpu => 32, :memory => 120, :system_disk => { :size => 40 }, :data_disk => {:count => 4, :size => 300} },

  }

  #
  # Helper functions to lookup values from NODES hash based on various params
  #

  # Returns fqdn for input tag
  # @param [Hash] nodes to search for tag in
  # @param [tag] tag to search
  # @return [Array] || nil
  def find_fqdn_for_tag(nodes, tag)
    found_clients = []
    nodes.each do |k, v|
       found_clients << k if v[:tags].grep(/^#{tag}/).any?
    end
    if found_clients.length == 0
      nil
    else
      found_clients.map { |k| nodes[k][:fqdn] }
    end
  end

  # Returns private_ip for input tag
  # @param [Hash] nodes to search for tag in
  # @param [tag] tag to search
  # @return [Array] || nil
  def find_pip_for_tag(nodes, tag)
    found_clients = []
    nodes.each do |k, v|
       found_clients << k if v[:tags].grep(/^#{tag}/).any?
    end
    if found_clients.length == 0
      nil
    else
      found_clients.map { |k| nodes[k][:private_ip] }
    end
  end

  # Return hash key for input tag
  # @param [Hash] nodes to search for tag in
  # @param [tag] tag to search
  # @return [Array] || nil
  def find_key_for_tag(nodes, tag)
    found_clients = []
    nodes.each do |k, v|
      found_clients << k if v[:tags].grep(/^#{tag}/).any?
    end
    if found_clients.length == 0
      nil
    else
      found_clients
    end
  end

  # Returns nodes hash key for the input fqdn
  # @param [Hash] nodes to search for tag in
  # @param [fqdn] fqdn to search
  # @return [String] => tag
  def find_key_for_fqdn(nodes, fqdn)
    nodes.select { |k, v| k if v[:fqdn] == fqdn }.keys.first
  end

  # Returns nodes hash key for the input private ip
  # @param [Hash] nodes to search for tag in
  # @return [String] => pip private ip to lookup
  def find_key_for_pip(nodes, pip)
    nodes.select { |k, v| k if v[:private_ip] == pip }.keys.first
  end

  # Converts a nested hash to flat hash
  # @param [Hash] nested hash to convert
  # @param [Array] grouped nested keys
  # @return [Hash] flattenend hash
  def flat_hash(hash, k = [])
    return {k => hash} unless hash.is_a?(Hash)
    hash.inject({}){ |h, v| h.merge! flat_hash(v[-1], k + [v[0]]) }
  end

  #
  # Helper Commands
  #
  def hadoop_search_commands
    puts <<-END.gsub(/^ {6}/, '')
      Usage: solrctl

      * To generate solr config dir
        - solrctl instancedir --generate $HOME/{COLLECTION_NAME}
      * To upload the instancedir to zookeeper
        - solrctl instancedir --create {COLLECTION_NAME} $HOME/{COLLECTION_NAME}
      * To create the collection, with number of shards specified
        - solrctl collection --create {COLLECTION_NAME} -s {NUM_OF_SHARDS}
      * To create the collection, with number of shards and number of replicas specified
        - solrctl collection --create {COLLECTION_NAME} -s {NUM_OF_SHARDS} -r {NUM_OF_REPLICAS}
    END
  end
end

# Monkey Patch some methods to ruby core classes
class String
  # Unindent string, useful indenting here-docs
  def undent
    gsub(/^.{#{slice(/^ +/).length}}/, '')
  end
end

class Hash
  # Converts all the keys to symbols from strings
  def deep_symbolize
    target = dup
    target.inject({}) do |memo, (key, value)|
      value = value.deep_symbolize if value.is_a?(Hash)
      memo[(key.to_sym rescue key) || key] = value
      memo
    end
  end

  # Converts all the keys to strings from symbols
  def deep_stringify
    target = dup
    target.inject({}) do |memo, (key, value)|
      value = value.deep_stringify if value.is_a?(Hash)
      memo[(key.to_s rescue key) || key] = value
      memo
    end
  end

  # Return a hash that includes everything but the given keys
  def except(*keys)
    dup.except!(*keys)
  end

  # Replaces the hash without the given keys.
  def except!(*keys)
    keys.each { |key| delete(key) }
    self
  end

  # Find the difference between two hashes
  def diff(other)
    self.keys.inject({}) do |memo, key|
      unless self[key] == other[key]
        memo[key] = [self[key], other[key]]
      end
      memo
    end
  end

  # retunrs value for a key nested deep in the hash
  def deep_find(key)
    if key?(key)
      true
    else
      self.values.inject(nil) do |memo, v|
        memo ||= v.deep_find(key) if v.respond_to?(:deep_find)
      end
    end
  end
end

#
# Backport features to ruby 1.8.7
#
if RUBY_VERSION < '1.9'
  class Symbol
    include Comparable

    def <=>(other)
      self.to_s <=> other.to_s
    end
  end
end
