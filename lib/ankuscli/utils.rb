module Ankuscli
  require 'timeout'
  require 'net/ssh'
  require 'net/scp'
  require 'thread'
  require 'timeout'
  require 'pathname'

  # ShellUtils - wrapper around shell
  class ShellUtils
    class << self

      # Drop in replacement for Kernel.exec which addresses a specific issue
      # in some operating systems which causes `exec` to fail if there is more
      # than one system thread. In that case, `safe_exec` automatically falls
      # back to forking.
      # @param [String] command  => command to execute
      # @param [Array] args => additional arguments to the command
      def safe_exec(command, *args)
        rescue_from = []
        rescue_from << Errno::EOPNOTSUPP if defined?(Errno::EOPNOTSUPP)
        rescue_from << Errno::E045 if defined?(Errno::E045)
        rescue_from << SystemCallError
        fork_instead = false
        begin
          pid = nil
          pid = fork if fork_instead
          Kernel.exec(command, *args) if pid.nil?
          Process.wait(pid) if pid
        rescue *rescue_from
          # We retried already, raise the issue and be done
          raise if fork_instead

          # The error manifested itself, retry with a fork.
          fork_instead = true
          retry
        end
      end

      # Run a command using Kernel.system
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
      #        [String] nodes_arr => node to check
      # @param [String] ssh_user => user to perform ssh as
      # @param [String] ssh_key  => ssh key to use
      # @param [Integer] port    => ssh port (default: 22)
      # @return nil
      # @raises if instance cannot be ssh'ed into
      def sshable?(nodes_arr, ssh_user, ssh_key, port=22)
        if nodes_arr.is_a? String
          `ssh -t -t -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o BatchMode=yes -o UserKnownHostsFile=/dev/null -p #{port} -i #{ssh_key} #{ssh_user}@#{nodes_arr} "echo" &>/dev/null`
          unless $?.success?
            raise "Cannot ssh in to instance: #{instance}"
          end
        else
          nodes_arr.each do |instance|
            `ssh -t -t -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o BatchMode=yes -o UserKnownHostsFile=/dev/null -p #{port} -i #{ssh_key} #{ssh_user}@#{instance} "echo" &>/dev/null`
            unless $?.success?
              raise "Cannot ssh in to instance: #{instance}"
            end
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
                puts "\r[Debug]: Running '#{command}' on server '#{host}'" if debug
                results[command] = ssh_exec!(ssh, command, debug)
                if debug
                  command_output = results[command]
                  puts "[Debug]: Exit code of running '#{command}' is: #{command_output[2]}"
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

              channel.on_data do |_, data|
                stdout_data += data
                data.lines.map(&:chomp).each { |d| puts "\r[#{ssh.host}]:".blue + "#{d}" }if debug
              end

              channel.on_extended_data do |_,type,data|
                stderr_data += data
                data.lines.map(&:chomp).each { |d| puts "\r[#{ssh.host}]:".yellow + "#{d}" }if debug
              end

              channel.on_request('exit-status') do |_,data|
                exit_code = data.read_long
              end
            end
          end
        end
        ssh.loop
        [stdout_data, stderr_data, exit_code]
      end

      # This returns the file permissions as a string from an octal number.
      # @param [Fixnum] octal
      # @return [String] => string format of file permissions like 600, 755, ..
      def from_octal(octal)
        perms = sprintf('%o', octal)
        perms.reverse[0..2].reverse
      end

      # Checks that the permissions for a private key are valid, and fixes
      # them if possible. SSH requires that permissions on the private key
      # are 0600 on POSIX based systems.
      # @param [String] key_path => path of the ssh private key
      def check_key_permissions(key_path)
        path_name = Pathname.new(File.expand_path(key_path))
        stat = path_name.stat

        unless stat.owned?
          # The SSH key must be owned by ourselves
          raise "File not owned by user, #{key_path}"
        end

        if from_octal(stat.mode) != '600'
          puts 'Attempting to correct key permissions to 0600'
          path_name.chmod(0600)

          # Re-stat the file to get the new mode, and verify it worked
          stat = key_path.stat
          if from_octal(stat.mode) != '600'
            raise "failed to change the permissions on #{key_path}"
          end
        end
      rescue Errno::EPERM
        raise 'bad permissions'
      end

      # Establish a ssh pipeline into an instance, halts the running of this process
      # and replaces it with full-fledged SSH shell into remote machine
      # @param [String] host => hostname to ssh into
      # @param [String] username => username to perform ssh as
      # @param [String] private_key_path => path to the ssh key
      # @param [Fixnum] port => port on which ssh is listening
      # @param [Hash] opts => additional params
      def ssh_into_instance(host, username, private_key_path, port, opts={})
        # check the permission on private_key_path and try to fix it
        check_key_permissions private_key_path
        # ssh command line options
        command_options = [
            '-p', port.to_s,
            '-o', 'LogLevel=FATAL',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-i', File.expand_path(private_key_path).to_s]
        command_options += %w(-o ForwardAgent=yes) if opts[:forward_agent]
        command_options.concat(opts[:extra_args]) if opts[:extra_args]
        # Build up the host string for connecting
        host_string = host
        host_string = "#{username}@#{host_string}"
        command_options.unshift(host_string)
        ShellUtils.safe_exec('ssh', *command_options)
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
              puts "\r[Debug]: #{name} -> #{(sent.to_f * 100 / total.to_f).to_i}%" if debug
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