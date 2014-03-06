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
    class YamlUtils
      # Parses the yaml file and returns a hash
      # @param [String] input_file => yaml file path to parse
      def self.parse_yaml(input_file)
        YAML.load_file(input_file)
      rescue ArgumentError, Psych::SyntaxError
        puts "Failed parsing config file: #{$!}"
      end

      # Write out hash to a yaml file
      # @param [Hash] hash => hash to write out to the file
      # @param [String] output_file => file to write out the hash to
      def self.write_yaml(hash, output_file)
        unless File.exists? File.expand_path(output_file)
          FileUtils.touch(output_file)
        end
        File.open(output_file, 'w') { |f| f.write(hash.to_yaml) }
      end
    end
  end
end
