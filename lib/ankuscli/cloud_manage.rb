=begin
  Class to manage cloud instances, create/delete
=end

module Ankuscli
  require 'erb'
  class Cloud
    # Create a new Cloud class object
    # @param [String] provider => Cloud service provider; aws|rackspace
    # @param [Hash] parsed_config => Configuration that has been already parsed from cloud_configuration file
    # @param [Hash] cloud_credentials => Credentials configurations
    #     if aws: cloud_credentials => { aws_access_id: '', aws_secret_key: '', aws_machine_type: 'm1.large', aws_region: 'us-west-1', aws_key: 'ankuscli' }
    #     if rackspace: cloud_credentials => { rackspace_username: '', rackspace_api_key: '', rackspace_instance_type: '', rackspace_ssh_key: '~/.ssh/id_rsa.pub' }
    # @param [Integer] thread_pool_size => number of threads to use to perform instance creation, volume attachements
    # @param [Boolean] debug => if enabled will print more info to stdout
    # @param [Boolean] mock => if enabled will mock fog, instead of creating actual instances
    def initialize(provider, parsed_config, cloud_credentials, thread_pool_size = 10, debug = false, mock = false)
      @provider = provider || parsed_config['cloud_platform']
      @cloud_os = parsed_config['cloud_os_type'] || 'CentOS'
      @parsed_hash = parsed_config
      @credentials = cloud_credentials
      @debug = debug
      @thread_pool_size = thread_pool_size
      @mock = mock
      raise unless @credentials.is_a?(Hash)
    end

    # Parse cloud_configuration; create instances and return instance mappings
    # @return [Hash] nodes:
    #   for aws cloud, nodes: { 'tag' => [public_dns_name, private_dns_name], 'tag' => [public_dns_name, private_dns_name], ... }
    #   for rackspace, nodes: { 'tag(fqdn)' => [public_ip_address, private_ip_address], ... }
    def create_instances
      num_of_slaves = @parsed_hash['slave_nodes_count']
      num_of_zks = @parsed_hash['zookeeper_quorum_count']
      slave_nodes_disk_size = @parsed_hash['slave_nodes_storage_capacity'] || 0
      nodes_created = {}
      nodes_to_create = {}

      if @provider == 'aws'
        #calculate number of disks and their size
        if slave_nodes_disk_size.nil? or slave_nodes_disk_size.to_i == 0
          #assume user do not want any extra volumes
          @volumes_count = 0
          @volume_size = 0
        else
          # user wants extra volumes
          @volume_count = 4
          @volume_size = slave_nodes_disk_size / @volume_count
        end
        #create controller
        nodes_to_create['controller'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
        # if ha is enabled
        if @parsed_hash['hadoop_ha'] == 'enabled'
          nodes_to_create['namenode1'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
          nodes_to_create['namenode2'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
          nodes_to_create['jobtracker'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
          num_of_zks.times do |i|
            nodes_to_create["zookeeper#{i+1}"] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
          end
          num_of_slaves.times do |i|
            nodes_to_create["slaves#{i+1}"] = { :os_type => @cloud_os, :volumes => @volume_count, :volume_size => @volume_size }
          end
        else
          # if ha is not enabled
          nodes_to_create['namenode'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
          nodes_to_create['jobtracker'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 } #JT and SNN
          num_of_slaves.times do |i|
            nodes_to_create["slaves#{i+1}"] = { :os_type => @cloud_os, :volumes => @volume_count, :volume_size => @volume_size }
          end
        end
        nodes_created = create_on_aws(nodes_to_create, @credentials, @thread_pool_size)

      elsif @provider == 'rackspace'
        #calculate number of disks and their size
        if slave_nodes_disk_size.nil? or slave_nodes_disk_size.to_i == 0
          #assume user do not want any extra volumes
          @volumes_count = 0
          @volume_size = 0
        else
          # attach extra volumes
          if slave_nodes_disk_size.to_i > 400
            @volume_count = 4
            @volume_size = slave_nodes_disk_size / @volume_count
          else
            @volume_size = 100
            @volume_count = slave_nodes_disk_size.to_i / 100
          end
        end
        #create controller
        nodes_to_create['controller.ankus.com'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
        # if ha is enabled
        if @parsed_hash['hadoop_ha'] == 'enabled'
          nodes_to_create['namenode1.ankus.com'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
          nodes_to_create['namenode2.ankus.com'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
          nodes_to_create['jobtracker.ankus.com'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
          num_of_zks.times do |i|
            nodes_to_create["zookeeper#{i+1}.ankus.com"] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
          end
          num_of_slaves.times do |i|
            nodes_to_create["slaves#{i+1}.ankus.com"] = { :os_type => @cloud_os, :volumes => @volume_count, :volume_size => @volume_size }
          end
        else
          # if ha is not enabled
          nodes_to_create['namenode.ankus.com'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 }
          nodes_to_create['jobtracker.ankus.com'] = { :os_type => @cloud_os, :volumes => 0, :volume_size => 50 } #JT and SNN
          num_of_slaves.times do |i|
            nodes_to_create["slaves#{i+1}.ankus.com"] = { :os_type => @cloud_os, :volumes => @volume_count, :volume_size => @volume_size }
          end
        end
        nodes_created = create_on_rackspace(nodes_to_create, @credentials, @thread_pool_size)
      end
      #returns parse nodes hash
      nodes_created
    end

    # Modifies the original parsed_config hash to look more like the local install mode
    # @param [Hash] parsed_hash => original parsed hash generated from configuration file
    # @param [Hash] nodes_hash => nodes hash generated by create_on_aws method in this class
    # @return if rackspace [Hash] parsed_hash => which can be used same as local install_mode
    #         if aws [Hash, Hash] parsed_hash, parsed_internal_ips => which can be used same as local install_mode
    def modify_config_hash(parsed_hash, nodes_hash)
      parsed_hash_internal_ips = Marshal.load(Marshal.dump(parsed_hash))
      #things to add back to parsed_hash:
      # root_ssh_key:
      # controller:
      # hadoop_namenode: []
      # hadoop_secondarynamenode: if hadoop_ha == 'disabled'
      # zookeeper_quorum: []
      # journal_quorum: []
      # mapreduce['master']:
      # slave_nodes: []
      # hbase_master: [] if hbase_install == enabled
      parsed_hash['root_ssh_key'] = if @provider == 'aws'
                                      File.expand_path('~/.ssh') + '/' + @credentials['aws_key']
                                    elsif @provider == 'rackspace'
                                      File.split(File.expand_path(@credentials['rackspace_ssh_key'])).first + '/' +
                                          File.basename(File.expand_path(@credentials['rackspace_ssh_key']), '.pub')
                                    end
      parsed_hash['controller'] = nodes_hash.map { |k,v| v.first if k =~ /controller/ }.compact.first
      parsed_hash['hadoop_namenode'] = nodes_hash.map { |k,v| v.first if k =~ /namenode/ }.compact
      parsed_hash['mapreduce']['master'] = nodes_hash.map { |k,v| v.first if k =~ /jobtracker/ }.compact.first
      parsed_hash['hadoop_secondarynamenode'] = nodes_hash.map { |k,v| v.first if k =~ /jobtracker/ }.compact.first if parsed_hash['hadoop_ha'] == 'disabled'
      parsed_hash['slave_nodes'] = nodes_hash.map { |k,v| v.first if k =~ /slaves/ }.compact
      parsed_hash['zookeeper_quorum'] = nodes_hash.map { |k,v| v.first if k =~ /zookeeper/ }.compact if parsed_hash['hadoop_ha'] == 'enabled' or parsed_hash['hbase_install'] == 'enabled'
      parsed_hash['journal_quorum'] = nodes_hash.map { |k,v| v.first if k =~ /zookeeper/ }.compact if parsed_hash['hadoop_ha'] == 'enabled'
      parsed_hash['hbase_master'] = nodes_hash.map { |k,v| v.first if k =~ /hbasemaster/ }.compact if parsed_hash['hbase_install'] == 'enabled'

      #hash with internal ips
      if @provider == 'aws' # internal_ips
        parsed_hash_internal_ips['root_ssh_key'] = File.expand_path('~/.ssh') + '/' + @parsed_hash['cloud_credentials']['aws_key']
        parsed_hash_internal_ips['controller'] = nodes_hash.map { |k,v| v.last if k =~ /controller/ }.compact.first
        parsed_hash_internal_ips['hadoop_namenode'] = nodes_hash.map { |k,v| v.last if k =~ /namenode/ }.compact
        parsed_hash_internal_ips['mapreduce']['master'] = nodes_hash.map { |k,v| v.last if k =~ /jobtracker/ }.compact.first
        parsed_hash_internal_ips['hadoop_secondarynamenode'] = nodes_hash.map { |k,v| v.last if k =~ /jobtracker/ }.compact.first if parsed_hash['hadoop_ha'] == 'disabled'
        parsed_hash_internal_ips['slave_nodes'] = nodes_hash.map { |k,v| v.last if k =~ /slaves/ }.compact
        parsed_hash_internal_ips['zookeeper_quorum'] = nodes_hash.map { |k,v| v.last if k =~ /zookeeper/ }.compact if parsed_hash['hadoop_ha'] == 'enabled' or parsed_hash['hbase_install'] == 'enabled'
        parsed_hash_internal_ips['journal_quorum'] = nodes_hash.map { |k,v| v.last if k =~ /zookeeper/ }.compact if parsed_hash['hadoop_ha'] == 'enabled'
        parsed_hash_internal_ips['hbase_master'] = nodes_hash.map { |k,v| v.last if k =~ /hbasemaster/ }.compact if parsed_hash['hbase_install'] == 'enabled'
      elsif @provider == 'rackspace' # fqdn
        parsed_hash_internal_ips['root_ssh_key'] = File.split(File.expand_path(@credentials['rackspace_ssh_key'])).first + '/' +
                                                        File.basename(File.expand_path(@credentials['rackspace_ssh_key']), '.pub')
        parsed_hash_internal_ips['controller'] = nodes_hash.map { |k,v| k if k =~ /controller/ }.compact.first
        parsed_hash_internal_ips['hadoop_namenode'] = nodes_hash.map { |k,v| k if k =~ /namenode/ }.compact
        parsed_hash_internal_ips['mapreduce']['master'] = nodes_hash.map { |k,v| k if k =~ /jobtracker/ }.compact.first
        parsed_hash_internal_ips['hadoop_secondarynamenode'] = nodes_hash.map { |k,v| k if k =~ /jobtracker/ }.compact.first if parsed_hash['hadoop_ha'] == 'disabled'
        parsed_hash_internal_ips['slave_nodes'] = nodes_hash.map { |k,v| k if k =~ /slaves/ }.compact
        parsed_hash_internal_ips['zookeeper_quorum'] = nodes_hash.map { |k,v| k if k =~ /zookeeper/ }.compact if parsed_hash['hadoop_ha'] == 'enabled' or parsed_hash['hbase_install'] == 'enabled'
        parsed_hash_internal_ips['journal_quorum'] = nodes_hash.map { |k,v| k if k =~ /zookeeper/ }.compact if parsed_hash['hadoop_ha'] == 'enabled'
        parsed_hash_internal_ips['hbase_master'] = nodes_hash.map { |k,v| k if k =~ /hbasemaster/ }.compact if parsed_hash['hbase_install'] == 'enabled'
      end
      return parsed_hash, parsed_hash_internal_ips
    end

    # Create servers on aws using Ankuscli::Aws
    # @param [Hash] nodes_to_create => hash of nodes to create with their info as shown below
    #      { 'node_tag' => { :os_type => cloud_os_type, :volumes => 2, :volume_size => 50 }, ... }
    # @param [Hash] credentials: {  aws_access_id: '', aws_secret_key: '', aws_machine_type: 'm1.large', aws_region: 'us-west-1', aws_key: 'ankuscli'}
    # @param [Integer] thread_pool_size => size of the thread pool
    # @return [Hash] results => { 'instance_tag' => [public_dns_name, private_dns_name], ... }
    def create_on_aws(nodes_to_create, credentials, thread_pool_size)
      #defaults
      threads_pool = Ankuscli::ThreadPool.new(thread_pool_size)
      key = credentials['aws_key'] || 'ankuscli'
      groups = credentials['aws_sec_groups'] || %w(ankuscli)
      flavor_id = credentials['aws_machine_type'] || 'm1.large'
      aws = Ankuscli::Aws.new(credentials['aws_access_id'], credentials['aws_secret_key'], credentials['aws_region'], @mock)
      conn = aws.create_connection
      results = {}

      if aws.valid_connection?(conn)
        puts 'successfully connected to aws'.green if @debug
      else
        puts '[Error]'.red + ' failed connecting to aws'
        exit 1
      end

      puts 'Creating servers with tags: ' + "#{nodes_to_create.keys.join(',')}".blue
      #hash to store server object to tag mapping { tag => server_obj }, used for attaching volumes
      server_objects = {}
      nodes_to_create.each do |tag, info|
        server_objects[tag] = aws.create_server!(conn,
                                                 tag,
                                                 :key => key,
                                                 :groups => groups,
                                                 :flavor_id => flavor_id,
                                                 :os_type => info[:os_type],
                                                 :num_of_vols => info[:volumes],
                                                 :vol_size => info[:volume_size]
        )
      end
      #wait for servers to get created (:state => running)
      aws.wait_for_servers(server_objects.values)
      #wait for the boot to complete
      aws.complete_wait(server_objects.values, @cloud_os) #TODO: this method is taking forever, find another way to make sure volumes are properly mounted
      #build the return string
      nodes_to_create.each do |tag, info|
        # fill in return hash
        results[tag] = [ server_objects[tag].dns_name, server_objects[tag].private_dns_name ]
      end
      if ! @mock
        puts 'Partitioning/Formatting attached volumes'.blue
        #parition and format attached disks using thread pool
        nodes_to_create.each do |tag, info|
          threads_pool.schedule do
            #build partition script
            partition_script = gen_partition_script(info[:volumes], true)
            tempfile = Tempfile.new('partition')
            tempfile.write(partition_script)
            tempfile.close
            # wait for the server to be ssh'able
            Ankuscli::SshUtils.wait_for_ssh(server_objects[tag].dns_name, 'root', File.expand_path('~/.ssh') + "/#{key}")
            # upload and execute the partition script on the remote machine
            SshUtils.upload!(
                tempfile.path,
                '/tmp',
                server_objects[tag].dns_name,
                'root',
                File.expand_path('~/.ssh') + "/#{key}",
                22,
                @debug
            )
            output = Ankuscli::SshUtils.execute_ssh!(
                "chmod +x /tmp/#{File.basename(tempfile.path)} && sudo sh -c '/tmp/#{File.basename(tempfile.path)} | tee /var/log/bootstrap_volumes.log'",
                server_objects[tag].dns_name,
                'root',
                File.expand_path('~/.ssh') + "/#{key}",
                22,
                @debug)
            tempfile.unlink #delete the tempfile
            if @debug
              puts "Stdout on #{server_objects[tag].dns_name}"
              puts output[server_objects[tag].dns_name][0]
              puts "Stdout on #{server_objects[tag].dns_name}"
              puts output[server_objects[tag].dns_name][1]
              puts "Exit code from #{server_objects[tag].dns_name}: #{output[server_objects[tag].dns_name][2]}"
            end
          end
        end
        threads_pool.shutdown

        puts '[Debug]: Finished creating and attaching volumes' if @debug
      else
        # pretend doing some work while mocking
        puts 'Partitioning/Formatting attached volumes'.blue
        nodes_to_create.each do
          threads_pool.schedule do
            sleep 5
          end
        end
        threads_pool.shutdown
      end
      results
    end

    # Create servers on rackspace using Ankuscli::RackSpace
    # @param [Hash] nodes_to_create => hash of nodes to create with their info as shown below
    #      { 'node_tag' => { :os_type => cloud_os_type, :volumes => 2, :volume_size => 100 }, ... }
    # @param [Hash] #cloud_credentials: { rackspace_username: , rackspace_api_key: , rackspace_instance_type: ,rackspace_ssh_key: '~/.ssh/id_rsa.pub' }
    # @param [Integer] thread_pool_size => size of the thread pool
    # @return [Hash] results => { 'instance_tag(fqdn)' => [public_ip_address, private_ip_address], ... }
    def create_on_rackspace(nodes_to_create, credentials, thread_pool_size)
      threads_pool = Ankuscli::ThreadPool.new(thread_pool_size)
      api_key = credentials['rackspace_api_key']
      username = credentials['rackspace_username']
      machine_type = credentials['rackspace_instance_type'] || 4
      public_ssh_key_path = credentials['rackspace_ssh_key'] || '~/.ssh/id_rsa.pub'
      ssh_key_path = File.split(public_ssh_key_path).first + '/' + File.basename(public_ssh_key_path, '.pub')

      puts "[Debug]: Using ssh_key #{ssh_key_path}" if @debug

      rackspace = Ankuscli::Rackspace.new(api_key, username, @mock)
      conn = rackspace.create_connection
      results = {}

      puts 'Creating servers with tags: ' + "#{nodes_to_create.keys.join(',')}".blue
      #hash to store server object to tag mapping { tag => server_obj }, used for attaching volumes
      server_objects = {}
      nodes_to_create.each do |tag, info|
        server_objects[tag] = rackspace.create_server!(conn, tag, public_ssh_key_path, machine_type, info[:os_type])
      end

      #wait for servers to get created (:state => ACTIVE)
      rackspace.wait_for_servers(server_objects.values)
      #build the return string
      nodes_to_create.each do |tag, info|
        # fill in return hash
        results[tag] = [ server_objects[tag].public_ip_address, server_objects[tag].private_ip_address ]
      end
      #Attach Volumes
      if ! @mock
        puts 'Partitioning/Formatting attached volumes'.blue
        #parition and format attached disks using thread pool
        nodes_to_create.each do |tag, info|
          threads_pool.schedule do
            if info[:volumes] > 0
              # attach specified volumes to server
              rackspace.attach_volumes!(server_objects[tag], info[:volumes], info[:volume_size])
              #build partition script
              partition_script = gen_partition_script(info[:volumes])
              tempfile = Tempfile.new('partition')
              tempfile.write(partition_script)
              tempfile.close
              # wait for the server to be ssh'able
              Ankuscli::SshUtils.wait_for_ssh(server_objects[tag].public_ip_address, 'root', File.expand_path(ssh_key_path))
              # upload and execute the partition script on the remote machine
              SshUtils.upload!(
                  tempfile.path,
                  '/tmp',
                  server_objects[tag].public_ip_address,
                  'root',
                  File.expand_path(ssh_key_path),
                  22,
                  @debug
              )
              output = Ankuscli::SshUtils.execute_ssh!(
                  "chmod +x /tmp/#{File.basename(tempfile.path)} && sudo sh -c '/tmp/#{File.basename(tempfile.path)} | tee /var/log/bootstrap_volumes.log'",
                  server_objects[tag].public_ip_address,
                  'root',
                  File.expand_path(ssh_key_path),
                  22,
                  @debug)
              tempfile.unlink #delete the tempfile
              if @debug
                puts "Stdout on #{server_objects[tag].public_ip_address}"
                puts output[server_objects[tag].public_ip_address][0]
                puts "Stdout on #{server_objects[tag].public_ip_address}"
                puts output[server_objects[tag].public_ip_address][1]
                puts "Exit code from #{server_objects[tag].public_ip_address}: #{output[server_objects[tag].public_ip_address][2]}"
              end
            end
          end
        end
        threads_pool.shutdown
        puts '[Debug]: Finished creating and attaching volumes' if @debug
      else
        #MOCKING
        # pretend doing some work while mocking
        puts 'Partitioning/Formatting attached volumes'.blue
        nodes_to_create.each do
          threads_pool.schedule do
            sleep 5
          end
        end
        threads_pool.shutdown
      end
      results
    end

    # Builds and returns a shell script for partitioning and resizing root volume(s)
    # @param [Integer] number_of_volumes => number of volumes to partition & mount, this number is used to grep the
    #                                       value from /proc/partitions
    # @param [Boolean] resize_root_vol => whether to resize th root partition or not
    # @return [ERB] build out shell script
    def gen_partition_script(number_of_volumes, resize_root_vol = false)
      resize_root = resize_root_vol ? 0 : 1
      template = <<-END.gsub(/^ {6}/, '')
      #!/bin/bash
      RESIZE_ROOT=<%= resize_root %>
      if [ $RESIZE_ROOT -eq 0 ]; then
      echo "Resizing the root partition"
      resize2fs /dev/`cat /proc/partitions | awk '/xvd*/ {print $4}' | head -n1`
      fi
      NUM_OF_VOLS=<%= number_of_volumes %>
      if [ $NUM_OF_VOLS -ne 0 ]; then
      DEVICES=`cat /proc/partitions | awk '/xvd*/ {print $4}' | tail -n<%= number_of_volumes %>`
      echo "Formatting and mounting initiated"
      count=1
      for dev in $DEVICES; do
      echo "Formatting and mounting $dev"
      fdisk -u /dev/$dev << EOF
      n
      p
      1


      w
      EOF
      mkfs.ext4 /dev/${dev}1
      data_dir=$((count++))
      mkdir -p /data/${data_dir}
      mount /dev/${dev}1 /data/${data_dir}
      done
      fi
      END
      ERB.new(template).result(binding)
    end

    # Builds /etc/hosts file @ file path specified
    # @param [Hash] nodes_ips_map => { 'tag(fqdn)' => [public_ip_address, private_ip_address], ... }
    def build_hosts(nodes_ips_map)
      hosts_string = ''
      hosts_string << '127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4' << "\n"
      nodes_ips_map.each do |fqdn, ip_map|
        hosts_string << "#{ip_map.last}\t#{fqdn}\t#{fqdn.split('.').first}" << "\n"
      end
      hosts_string
    end
  end
end