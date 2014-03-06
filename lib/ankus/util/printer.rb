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

module Ankus
  module Util
    # Wrapper around print method to emulate log events
    class Printer
      @time = Time.now.strftime('%Y-%m-%d %H:%M:%S')
      def self.info(*args)
        print "\r#{@time} " + '[Info]'.blue + ':: ' + args.join(' ') + "\n"
      end

      def self.debug(*args)
        print "\r#{@time} " + '[Debug]: '.cyan + ':: ' + args.join(' ') + "\n"
      end

      def self.warn(*args)
        print "\r#{@time} " + '[Warn]'.yellow + ':: ' + args.join(' ') + "\n"
      end

      def self.error(*args)
        print "\r#{@time} " + '[Error]'.red + ':: ' + args.join(' ') + "\n"
      end
    end
  end
end
