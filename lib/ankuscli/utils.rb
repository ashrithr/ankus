module Ankuscli
  require 'timeout'
  require 'net/ssh'
  require 'net/scp'
  require 'thread'
  require 'timeout'

  # ShellUtils - wrapper around shell
  class ShellUtils
    class << self
      # Run a command using system
      # @param [String] command => command to execute
      # @return [Kernel::SystemExit] status($?.success), pid($?.pid)
      def run_cmd!(command)
        system(command)
        $?
      end

      # Run a command using system and write the stdout and stderr to a log file specified
      # @param [String] command => command to execute
      # @param [String] log_file => path of the log file to write to
      # @param [Char] file_write_mode => mode to use to write to the file (default: append)
      # @return [Kernel::SystemExit] used $?.success $?.pid
      def run_cmd_with_log!(command, log_file, file_write_mode = 'a')
        if RUBY_VERSION < '1.9'
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
      # @param [String] ip => ip_address of the host
      # @param [String] port => port to check
      # @param [Integer] seconds => timeout in seconds
      # @return [Boolean] true|false
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
      # @param [String] addr => address to validate
      # @return [Boolean] true|false
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

      # Parses the yaml file and returns a hash
      # @param [String] input_file => yaml file path to parse
      def parse_yaml(input_file)
        YAML.load_file(input_file)
      rescue ArgumentError, Psych::SyntaxError
        puts "Failed parsing config file: #{$!}"
      end

      # Write out hash to a yaml file
      # @param [Hash] hash => hash to write out to the file
      # @param [String] output_file => file to write out the hash to
      def write_yaml(hash, output_file)
        FileUtils.touch(output_file) unless File.exists? File.expand_path(output_file)
        File.open(output_file, 'w') { |f| f.write(hash.to_yaml) }
      end

    end
  end

  class SshUtils
    class << self

      # Check if password less ssh has been setup by executing simple echo on ssh'ed side
      # @param [Array] nodes_arr => array of nodes to check
      # @param [String] ssh_user => user to perform ssh as
      # @param [String] ssh_key  => ssh key to use
      # @param [Integer] port    => ssh port (default: 22)
      # @return nil
      # @raises if instance cannot be ssh'ed into
      def sshable?(nodes_arr, ssh_user, ssh_key, port=22)
        nodes_arr.each do |instance|
          `ssh -t -t -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o BatchMode=yes -o UserKnownHostsFile=/dev/null -p #{port} -i #{ssh_key} #{ssh_user}@#{instance} "echo" &>/dev/null`
          unless $?.success?
            raise "Cannot ssh in to instance: #{instance}"
          end
        end
      end

      # Wait until a nodes can be sshable, only used for cloud instances
      # @param [String] node => instance to check and wait
      # @param [String] ssh_user => user to perform ssh as
      # @param [String] ssh_key => ssh key to use
      def wait_for_ssh(node, ssh_user, ssh_key)
        Timeout::timeout(600) do
          begin
            sshable?([node], ssh_user, ssh_key)
          rescue
            #puts "Cannot ssh into #{node}, retrying in 10 seconds"
            sleep 10
            retry
          end
        end
      rescue Timeout::Error
        raise 'It took more than 10 mins for the servers to complete boot, this generally does not happen.'
      end

      # Execute single command on remote machine over ssh protocol using net-ssh gem
      # @param [String] command => command to execute on the remote machine
      # @param [String] host => ipaddress|hostname on which to execute the command on
      # @param [String] ssh_user => user to ssh as
      # @param [String] ssh_key => private ssh key to use
      # @param [Integer] ssh_port => ssh port (default:22)
      # @param [Boolean] debug => if enabled will print out the output of the command to stdout
      # @return [Hash] { 'host' => [stdout, stderr, exit_code] }
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
          puts e.to_s if debug
          return e.to_s
        end
        result
      end

      # Execute list of commands on remote machine over ssh protocol using net-ssh
      # @param [Array] commands => commands to execute on remote machine
      # @param [String] host => host on which the commands should be executed
      # @param [String] ssh_user => user to ssh as
      # @param [String] ssh_key => private ssh key to use
      # @param [Integer] ssh_port => ssh port (default:22)
      # @param [Boolean] debug => if enabled will print out the output of the command to stdout
      # @return [Hash] { 'command' => [stdout, stderr, exit_code], 'command' => [stdout, stderr, exit_code], ... }
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

      # Execute single command on remote server and capture its stdout, stderr, exit_code
      # @param [Net::SSH] ssh => net-ssh object to process on
      # @param [String] command => command to execute
      # @param [Boolean] debug => append hostname to command output if enabled
      # @return [Array] => [stdout, stderr, exit_code]
      def ssh_exec!(ssh, command, debug=false)
        stdout_data = ''
        stderr_data = ''
        exit_code = nil

        ssh.open_channel do |ch|
          ch.request_pty do |channel, succ| #for running sudo commands, a psuedo-tty is required
            abort 'FAILED: Could not request a psuedo-tty' unless succ
            channel.exec(command) do |chl, success|
              unless success
                abort 'FAILED: could not execute command (ssh.channel.exec)'
              end

              channel.on_data do |ch, data|
                stdout_data += data
              end

              channel.on_extended_data do |ch,type,data|
                stderr_data += data
              end

              channel.on_request("exit-status") do |ch,data|
                exit_code = data.read_long
              end
            end
          end
        end
        ssh.loop
        [stdout_data, stderr_data, exit_code]
      end

      # Upload a file to remote system using ssh protocol
      # @param [String] source_file => path of the file to upload
      # @param [String] dest_path => path on the remote machine
      # @param [String] host => hostname | ip_address of the remote machine
      # @param [String] ssh_user => user name to ssh as
      # @param [String] ssh_key => ssh private key to use
      # @param [Integer] ssh_port => ssh port (default: 22)
      # @return nil
      def upload!(source_file, dest_path, host, ssh_user, ssh_key, ssh_port=22, debug = false)
        begin
          Net::SSH.start(host, ssh_user, :port => ssh_port, :keys => ssh_key, :auth_methods => %w(publickey)) do |ssh|
            ssh.scp.upload!(source_file, dest_path) do |ch, name, sent, total|
              puts "\r#{name}: #{(sent.to_f * 100 / total.to_f).to_i}%" if debug
            end
          end
        rescue Net::SSH::HostKeyMismatch => e
          e.remember_host!
          retry
        rescue StandardError => e
          puts e.to_s
        end
      end

    end
  end

end