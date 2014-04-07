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
  module Errors
    class Error < StandardError
      def initialize(msg, data = nil)
        super(msg)
        @data = data
      end

      # def message
      #   @message + "extra_info: #{@data}"
      # end
    end

    class NotImplemented < Ankus::Errors::Error; end
    class ParseError < Ankus::Errors::Error; end
    class ParseError::NoKey < Ankus::Errors::Error; end
  end
end
