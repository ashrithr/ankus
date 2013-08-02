=begin
  Helper module for ankus
=end
module Ankus
  #Constants
  DATA_DIR          = File.expand_path(File.dirname(__FILE__) + '/../../.data')
  DEFAULT_CONFIG    = File.expand_path(File.dirname(__FILE__) + '/../../conf/ankus_conf.yaml')
  NODES_FILE        = "#{DATA_DIR}/nodes.yaml"
  NODES_FILE_CLOUD  = "#{DATA_DIR}/nodes_cloud.yaml"
  CLOUD_INSTANCES   = "#{DATA_DIR}/cloud_instances.yaml"
  ENC_ROLES_FILE    =  "#{DATA_DIR}/roles.yaml"
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
    :security,
    :monitoring,
    :alerting,
    :log_aggregation,
  ]

  HADOOP_CONF_KEYS = %w{
    hadoop_heap_size
    hadoop_namenode_opts
    hadoop_jobtracker_opts
    hadoop_secondarynamenode_opts
    hadoop_datanode_opts
    hadoop_tasktracker_opts
    hadoop_balancer_opts
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
end

# Monkey Patch some methods to ruby core classes
class String
  def undent
    gsub(/^.{#{slice(/^ +/).length}}/, '')
  end
end

class Hash
  def deep_symbolize
    target = dup
    target.inject({}) do |memo, (key, value)|
      value = value.deep_symbolize if value.is_a?(Hash)
      memo[(key.to_sym rescue key) || key] = value
      memo
    end
  end

  def deep_stringify
    target = dup
    target.inject({}) do |memo, (key, value)|
      value = value.deep_stringify if value.is_a?(Hash)
      memo[(key.to_s rescue key) || key] = value
      memo
    end
  end
end
