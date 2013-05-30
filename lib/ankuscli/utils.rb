module Ankuscli
  require 'timeout'
  require 'net/ssh'
  require 'net/scp'
  require 'thread'

  # ShellUtils - wrapper around shell
  class ShellUtils
    class << self
      # run a command using system and return status($?.success), pid($?.pid)
      def run_cmd!(command)
        system(command)
        $?
      end

      # run a command using system and write the stdout and stderr to a log file specified
      def run_cmd_with_log!(command, log_file, file_write_mode = 'a')
        if RUBY_VERSION < "1.9"
          #capture older stdout
          begin
            old_out = $stdout.dup
            old_err = $stderr.dup
            $stdout.reopen(log_file, file_write_mode)
            $stderr.reopen(log_file, file_write_mode)
            system(command)
            return $?
          ensure
            $stdout.reopen(old_out)
            $stderr.reopen(old_err)
          end
        else
          system(command, :out => [log_file, file_write_mode], :err => [log_file, file_write_mode])
          $?
        end
      end
    end
  end

  # Thread pool class (does not handle synchronization). Allows to perform:
  #   new(size) - creates a thread pool of a given size
  #   schedule(*args, &job) - schedules a new job to be executed
  #   shutdown - shuts down all threads (after they finish working)
  #
  # Usage:
  #   p = Pool.new(10)
  #   20.times do |i|
  #     p.schedule do
  #       sleep rand(4) + 2
  #       puts "Job #{i} finished by thread #{Thread.current[:id]}"
  #     end
  #   end
  #   p.shutdown
  class ThreadPool
    def initialize(size)
      @size = size
      @jobs = Queue.new

      @pool = Array.new(@size) do |i|
        Thread.new do
          Thread.current[:id] = i
          catch(:exit) do
            loop do
              job, args = @jobs.pop
              job.call(*args)
            end
          end
        end
      end
    end

    def schedule(*args, &block)
      @jobs << [block, args]
    end

    def shutdown
      @size.times do
        schedule { throw :exit }
      end
      @pool.map(&:join)
    end
  end

  class PortUtils
    class << self

      # Check to see if the port is open on a given host
      def port_open?(ip, port, seconds=2)
        Timeout::timeout(seconds) do
          begin
            TCPSocket.new(ip, port).close
            true
          rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError
            false
          end
        end
      rescue Timeout::Error
        false
      end

    end
  end

  class IpUtils
    class << self

      # Validates if an address is ipv4 or not
      def valid_ipv4?(addr)
        if /\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z/ =~ addr
          return $~.captures.all? {|i| i.to_i < 256}
        end
        false
      end

    end
  end

  class YamlUtils
    class << self

      # parses the yaml file and returns a hash
      def parse_yaml(input_file)
        YAML.load_file(input_file)
      rescue ArgumentError, Psych::SyntaxError
        puts "Failed parsing config file: #{$!}"
      end

      # write out hash to a yaml file
      def write_yaml(hash, output_file)
        FileUtils.touch(output_file) unless File.exists? File.expand_path(output_file)
        File.open(output_file, 'w') { |f| f.write(hash.to_yaml) }
      end

    end
  end

  class SshUtils
    class << self

      # check if password less ssh has been setup by executing simple echo on ssh'ed side
      def sshable?(nodes_arr, ssh_user, ssh_key, port=22)
        nodes_arr.each do |instance|
          `ssh -t -t -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o BatchMode=yes -p #{port} -i #{ssh_key} #{ssh_user}@#{instance} "echo" &>/dev/null`
          unless $?.success?
            puts '[Error]:'.red + " cannot ssh into instance: #{instance}"
            exit 1
          end
        end
      end

      # execute single command on remote machine over ssh protocol using net-ssh
      # output:: array of stdout, stderr, exit_code of command
      def execute_ssh!(command, host, ssh_user, ssh_key, ssh_port=22, debug=false)
        begin
          result = {}
          Net::SSH.start(host, ssh_user, :port => ssh_port, :keys => ssh_key, :auth_methods => %w(publickey)) do |ssh|
            result[host] = ssh_exec!(ssh, command, debug)
          end
        rescue Net::SSH::HostKeyMismatch => e
          e.remember_host!
          retry
        rescue StandardError => e
          return e.to_s
        end
        result
      end

      # execute list of commands on remote machine over ssh protocol using net-ssh
      # input:: commands [Array]
      #         host
      #         ssh_user
      #         ssh_key
      #         ssh_port
      # output:: results: hash of commands and their respective stdout, stderr, exit_code respectively
      def execute_ssh_cmds(commands, host, ssh_user, ssh_key, ssh_port=22, debug=false)
        begin
          results = {}
          begin
            Net::SSH.start(host, ssh_user, :port => ssh_port, :keys => ssh_key, :auth_methods => %w(publickey)) do |ssh|

              commands.each { |command|
                puts "\nRunning " + "#{command}".blue + ' on server ' + "#{host}".blue if debug
                results[command] = ssh_exec!(ssh, command, debug)
                if debug
                  command_output = results[command]
                  #unless command_output[0].empty?
                  #  puts "\nSTDOUT:".green
                  #  puts "#{command_output[0]}"
                  #end

                  #unless command_output[1].empty?
                  #  puts "\nSTDERR:".red
                  #  puts "#{command_output[1]}"
                  #end

                  puts 'EXIT CODE: '.yellow + "#{command_output[2]}"
                end
              }
            end
          rescue Net::SSH::HostKeyMismatch => e
            e.remember_host!
            retry
          rescue StandardError => e
            return e.to_s
          end
        end
        results
      end

      # execute single command on remote server and capture its stdout, stderr, exit_code
      # input: ssh_object from Net::SSH
      #        command
      # return: stdout_data, stderr_data, exit_code
      def ssh_exec!(ssh, command, debug)
        stdout_data = ''
        stderr_data = ''
        exit_code = nil

        ssh.open_channel do |channel|
          channel.exec(command) do |chl, success|
            unless success
              abort 'FAILED: couldn\'t execute command (ssh.channel.exec)'
            end

            channel.on_data do |ch, data|
              if debug
                puts "[#{ssh.host}]: ".blue + data
                stdout_data += "[#{ssh.host}]: ".blue + data
              else
                stdout_data += data
              end
            end

            channel.on_extended_data do |ch,type,data|
              if debug
                puts "[#{ssh.host}]: ".yellow + data
                stderr_data += "[#{ssh.host}]: ".yellow + data
              else
                stderr_data += data
              end
            end

            channel.on_request("exit-status") do |ch,data|
              exit_code = data.read_long
            end
          end
        end
        ssh.loop
        [stdout_data, stderr_data, exit_code]
      end

      # scp a file to target system
      def upload!(source_file, dest_path, host, ssh_user, ssh_key, ssh_port=22)
        begin
          Net::SSH.start(host, ssh_user, :port => ssh_port, :keys => ssh_key, :auth_methods => %w(publickey)) do |ssh|
            ssh.scp.upload!(source_file, dest_path) #do |ch, name, sent, total|
            #  puts "\r#{name}: #{(sent.to_f * 100 / total.to_f).to_i}%"
            #end
          end
        rescue Net::SSH::HostKeyMismatch => e
          e.remember_host!
          retry
        rescue StandardError => e
          e.to_s
        end
      end

    end
  end

end