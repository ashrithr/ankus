=begin
  Helper module for ankuscli
=end
module Ankuscli
  #Constants
  DATA_DIR = File.expand_path(File.dirname(__FILE__) + '/../../.data')
  DEFAULT_CONFIG = File.expand_path(File.dirname(__FILE__) + '/../../conf/ankus_conf.yaml')
  NODES_FILE = "#{DATA_DIR}/nodes.yaml"
  NODES_FILE_CLOUD = "#{DATA_DIR}/nodes_cloud.yaml"
  CLOUD_INSTANCES = "#{DATA_DIR}/cloud_instances.yaml"
  ENC_ROLES_FILE =  "#{DATA_DIR}/roles.yaml"
  HIERA_DATA_FILE = "#{DATA_DIR}/common.yaml"

  PUPPET_INSTALLER = File.expand_path(File.dirname(__FILE__) + '/../shell/puppet_installer.sh')
  ENC_SCRIPT =  File.expand_path(File.dirname(__FILE__) + '/../../bin/ankus_puppet_enc')
  GETOSINFO_SCRIPT = File.expand_path(File.dirname(__FILE__) + '../../shell/get_osinfo.sh')
  HADOOP_CONF = File.expand_path(File.dirname(__FILE__) + '/../../conf/ankus_hadoop_conf.yaml')
  ENC_PATH = %q(/etc/puppet/enc)
  HIERA_DATA_PATH = %q(/etc/puppet/hieradata)
  REMOTE_LOG_DIR = %q(/var/log/ankus)

  class String
    def undent
      gsub(/^.{#{slice(/^ +/).length}}/, '')
    end
  end
end