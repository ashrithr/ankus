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

require 'net/ssh'
require 'net/scp'
require 'timeout'
require 'pathname'

module Ankus
  module Util
    class SshUtils
      # Check if password less ssh has been setup by executing simple echo
      # @param [Array] nodes_arr => array of nodes to check
      #        [String] nodes_arr=> node to check
      # @param [String] ssh_user => user to ssh as
      # @param [String] ssh_key  => ssh key to use
      # @param [Integer] port    => ssh port (default: 22)
      # @return [TrueClass]
      # @raises if instance cannot be ssh'ed into
      def self.sshable?(nodes_arr, ssh_user, ssh_key, port = 22)
        if nodes_arr.is_a? String
          out, err, status = Util::ShellUtils.system_quietly(
            'ssh -t -t -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o' +
            " BatchMode=yes -o UserKnownHostsFile=/dev/null -p #{port} " +
            "-i #{ssh_key} #{ssh_user}@#{nodes_arr}" +
            " \"echo\"")
          if (status.exitstatus != 0 ||
              (err && err.chomp =~ /Permission denied/))
            fail "Cannot ssh in to instance: #{nodes_arr} with username:" +
                  " #{ssh_user} and key: #{ssh_key}. Reason: #{err}"
          elsif out && out.chomp =~ /Please login as the user/
            fail "Cannot ssh into instance: #{nodes_arr} with username:" +
                  " #{ssh_user} and key: #{ssh_key}. Reason: #{out}"
          else
            return true
          end
        else
          nodes_arr.each do |instance|
            out, err, status = Util::ShellUtils.system_quietly(
              'ssh -t -t -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o' +
              " BatchMode=yes -o UserKnownHostsFile=/dev/null -p #{port}" +
              " -i #{ssh_key} #{ssh_user}@#{instance}" +
              " \"echo\"")
            if (status.exitstatus != 0 ||
                (err && err.chomp =~ /Permission denied/))
              fail "Cannot ssh in to instance: #{instance} with user:" +
                    " #{ssh_user} and key: #{ssh_key}. Reason: #{err}"
            elsif out && out.chomp =~ /Please login as the user/
              fail "Cannot ssh into instance: #{nodes_arr} with username:" +
                    " #{ssh_user} and key: #{ssh_key}. Reason: #{out}"
            else
              return true
            end
          end
        end
      end

      # Wait until a node becomes sshable, sanity check for cloud instances
      # @param [String] node => instance to check and wait
      # @param [String] ssh_user => user to perform ssh as
      # @param [String] ssh_key => ssh key to use
      def self.wait_for_ssh(node, ssh_user, ssh_key, timeout = 600)
        Timeout.timeout(timeout) do
          begin
            sshable?(node, ssh_user, ssh_key)
          rescue
            # cannot ssh into the instance retry in 10 seconds
            sleep 10
            retry
          end
        end
      rescue Timeout::Error
        fail "It took more than #{timeout} seconds waiting for servers to" +
              " become ssh'able. Aborting!!!"
      end

      # Execute single command on remote machine over ssh protocol (net-ssh)
      # @param [String] command => command to execute on the remote machine
      # @param [String] host => [ipaddress|hostname] on which to execute the
      #   command on
      # @param [String] ssh_user => user to ssh as
      # @param [String] ssh_key => private ssh key to use
      # @param [Log4r] log => logger instance to use
      # @param [Integer] ssh_port => ssh port (default:22)
      # @param [Boolean] debug => if enabled will print out the output of the
      #   command to stdout
      # @param [Boolean] sudo => specify whether to run a command using sudo
      # @param [Boolean] keep_alive => specifies to keep connection open using
      #   keep-alive packets
      # @return [Hash] { 'host' => [stdout, stderr, exit_code] }
      def self.execute_ssh!(
        command,
        host,
        ssh_user,
        ssh_key,
        log,
        ssh_port = 22,
        sudo = false,
        keep_alive = false
      )
        begin
          result = {}
          Net::SSH.start(
            host,
            ssh_user,
            :port => ssh_port,
            :keys => ssh_key,
            :auth_methods => %w(publickey)
          ) do |ssh|
            result[host] = ssh_exec!(ssh, command, log, sudo, keep_alive)
          end
        rescue Net::SSH::HostKeyMismatch => e
          e.remember_host!
          retry
        rescue StandardError => e
          puts e.to_s
          return e.to_s
        end
        result
      end

      # Execute list of commands on remote machine over ssh protocol (net-ssh)
      # @param [Array] commands => commands to execute on remote machine
      # @param [String] host => host on which the commands should be executed
      # @param [String] ssh_user => user to ssh as
      # @param [String] ssh_key => private ssh key to use
      # @param [Log4r] log => logger instance
      # @param [Integer] ssh_port => ssh port (default:22)
      # @param [Boolean] debug => if enabled will print out the output of the
      #   command to stdout
      # @param [Boolean] sudo => specify whether to run a command using sudo
      # @param [Boolean] keep_alive => specifies to keep connection open using
      #   keep-alive packets
      # @return [Hash]
      #   {
      #     'command' => [stdout, stderr, exit_code],
      #     'command' => [stdout, stderr, exit_code],
      #     ...
      #   }
      def self.execute_ssh_cmds!(
        commands,
        host,
        ssh_user,
        ssh_key,
        log,
        ssh_port = 22,
        sudo = false,
        keep_alive = false
      )
        begin
          results = {}
          begin
            Net::SSH.start(
              host,
              ssh_user,
              :port => ssh_port,
              :keys => ssh_key,
              :auth_methods => %w(publickey)
            ) do |ssh|
              commands.each do |command|
                log.debug "Running '#{command}' on server '#{host}'"
                results[command] = ssh_exec!(
                  ssh,
                  command,
                  log,
                  sudo,
                  keep_alive
                )
                log.debug "Exit code of running '#{command}' is:" \
                          " #{results[command][2]}"
              end
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

      # Establish a ssh pipeline into an instance, halts the running of this
      # process
      # and replaces it with full-fledged SSH shell into remote machine
      # @param [String] host => hostname to ssh into
      # @param [String] username => username to perform ssh as
      # @param [String] private_key_path => path to the ssh key
      # @param [Fixnum] port => port on which ssh is listening
      # @param [Hash] opts => additional params
      def self.ssh_into_instance(
        host,
        username,
        private_key_path,
        port,
        opts = {}
      )
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
        Util::ShellUtils.safe_exec('ssh', *command_options)
      end

      # Upload a file to remote system using ssh protocol
      # @param [String] source_file => path of the file to upload
      # @param [String] dest_path => path on the remote machine
      # @param [String] host => hostname | ip_address of the remote machine
      # @param [String] ssh_user => user name to ssh as
      # @param [String] ssh_key => ssh private key to use
      # @param [Log4r] log => logger instance
      # @param [Integer] ssh_port => ssh port (default: 22)
      # @param [Boolean] debug => verbose output
      # @return nil
      def self.upload!(
        source_file,
        dest_path,
        host,
        ssh_user,
        ssh_key,
        log,
        ssh_port = 22
      )
        Net::SSH.start(
          host,
          ssh_user,
          :port => ssh_port,
          :keys => ssh_key,
          :auth_methods => %w(publickey)
        ) do |ssh|
          ssh.scp.upload!(source_file, dest_path) do |ch, name, sent, total|
            log.debug "#{name} -> #{(sent.to_f * 100 / total.to_f).to_i}%"
          end
        end
      rescue Net::SSH::HostKeyMismatch => e
        e.remember_host!
        retry
      rescue StandardError => e
        puts e.to_s
      end

      # Execute single command on remote server and capture its stdout,
      # stderr, exit_code
      # @param [Net::SSH] ssh => net-ssh object to process on
      # @param [String] command => command to execute
      # @param [Log4r] log => logger instance to use
      # @param [Boolean] debug => append hostname to command output if enabled
      # @return [Array] => [stdout, stderr, exit_code]
      def self.ssh_exec!(
        ssh,
        command,
        log,
        sudo = false,
        keep_alive = false
      )
        stdout_data = ''
        stderr_data = ''
        exit_code = nil

        # Set the shell to execute
        # shell_cmd = 'bash -l' # pass this as parameter
        # if sudo
        #   # -E preserve environment
        #   # -H set the HOME environment variables
        #   shell_cmd = "sudo -E -H #{shell_cmd}"
        # end

        shell_cmd = command
        if sudo
          shell_cmd = "sudo -E -H #{shell_cmd}"
        end

        # open ssh connection to execute the command
        connection = ssh.open_channel do |ch|
          # for running sudo commands on RedHat based instances for a password
          # less sudo user with 'Defaults requiretty' enabled, a psuedo-tty is
          # required
          ch.request_pty do |channel, success|
            unless success
              log.warn 'Could not request a psuedo-tty, trying to continue.'
            end
          end

          ch.exec(shell_cmd) do |channel, success|
            log.error "Could not execute command #{command}" unless success

            channel.on_data do |_, data|
              stdout_data += data
              data.lines.map(&:chomp).each do |d|
                log.debug "[#{ssh.host}]:".blue + "#{d}"
              end
            end

            channel.on_extended_data do |_, type, data|
              stderr_data += data
              data.lines.map(&:chomp).each do |d|
                log.debug "[#{ssh.host}]:".yellow + "#{d}"
              end
            end

            channel.on_request('exit-status') do |_, data|
              exit_code = data.read_long
              # close the channel, as we got he exit code.
              # This fixes hanging issues
              connection.close
            end

            # Set the terminal
            # channel.send_data("export TERM=vt100\n")

            # Send the command
            # channel.send_data("#{command}\n")

            # Exit the channel else this will hang
            # channel.send_data("exit\n")

            # Send EOF to let the server its done
            channel.eof!
          end
        end

        begin
          # Keep sending keep-alive packets to avoid connections closing on
          # long-running scripts
          if keep_alive
            keep_alive = Thread.new do
              loop do
                sleep 5
                # log.debug 'Sending SSH keep alive'
                ssh.send_global_request('keep-alive@openssh.com')
              end
            end
          end

          begin
            connection.wait
          rescue IOError
            log.warn 'SSH connection closed unexpectedly.'
          end
        ensure
          # kill the thread sending keep-alive packets
          keep_alive.kill if keep_alive
        end
        [stdout_data, stderr_data, exit_code]
      end

      # This returns the file permissions as a string from an octal number.
      # @param [Fixnum] octal
      # @return [String] => string format of file permissions like 600, 755, ..
      def self.from_octal(octal)
        perms = sprintf('%o', octal)
        perms.reverse[0..2].reverse
      end

      # Checks that the permissions for a private key are valid, and fixes
      # them if possible. SSH requires that permissions on the private key
      # are 0600 on POSIX based systems.
      # @param [String] key_path => path of the ssh private key
      def self.check_key_permissions(key_path)
        path_name = Pathname.new(File.expand_path(key_path))
        stat = path_name.stat

        unless stat.owned?
          # The SSH key must be owned by ourselves
          fail "File not owned by user, #{key_path}"
        end

        if from_octal(stat.mode) != '600'
          puts 'Attempting to correct key permissions to 0600'
          path_name.chmod(0600)

          # Re-stat the file to get the new mode, and verify it worked
          stat = key_path.stat
          if from_octal(stat.mode) != '600'
            fail "failed to change the permissions on #{key_path}"
          end
        end
      rescue Errno::EPERM
        raise 'bad permissions'
      end
    end
  end
end
