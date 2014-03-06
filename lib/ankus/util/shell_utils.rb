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

require 'open3'

module Ankus
  module Util
    # Wrapper class to execute shell commands
    class ShellUtils
      # Drop in replacement for Kernel.exec which addresses a specific issue
      # in some operating systems which causes `exec` to fail if there is more
      # than one system thread. In that case, `safe_exec` automatically falls
      # back to forking.
      # @param [String] command  => command to execute
      # @param [Array] args => additional arguments to the command
      def self.safe_exec(command, *args)
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
      def self.run_cmd!(command)
        system(command)
        $?
      end

      # Run a command using system and write the stdout and stderr to a log
      # file specified
      # @param [String] command => command to execute
      # @param [String] log_file => path of the log file to write to
      # @param [Char] file_write_mode => mode to use to write to the file
      #   (default: append)
      # @return [Kernel::SystemExit] used $?.success $?.pid
      def self.run_cmd_with_log!(command, log_file, file_write_mode = 'a')
        if RUBY_VERSION < '1.9'
          # capture older stdout
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
          system(
            command,
            :out => [log_file, file_write_mode],
            :err => [log_file, file_write_mode]
          )
          return $?
        end
      end

      # Runs a command on shell and returns stdout, stderr, and its exit status
      # @param [VarArgs] comands to execute
      # @return stdout, stderr and exit_status
      def self.system_quietly(*cmd)
        exit_status = nil
        err = nil
        out = nil
        Open3.popen3(*cmd) do |stdin, stdout, stderr, wait_thread|
          err = stderr.gets(nil)
          out = stdout.gets(nil)
          [stdin, stdout, stderr].each { |stream| stream.send('close') }
          exit_status = wait_thread.value
        end
        return out, err, exit_status
      rescue Errno::ENOENT
        err = 'Command not found'
        exit_status = '255'
        return out, err, exit_status
      end
    end
  end
end
