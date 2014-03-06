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

require 'timeout'

module Ankus
  module Util
    # Utility class to validate port's
    class PortUtils
      # Check to see if the port is open on a given host
      # @param [String] ip => ip_address of the host
      # @param [String] port => port to check
      # @param [Integer] seconds => timeout in seconds
      # @return [Boolean] true|false
      def self.port_open?(ip, port, seconds = 2)
        Timeout.timeout(seconds) do
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
end
