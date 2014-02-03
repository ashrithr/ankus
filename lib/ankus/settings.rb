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

=begin
  Module to load settings from configuration files
  Usage: Ankus::Settings.load!("config/appdata/example.yml")
         Ankus::Settings.emails[:admin]
=end
module Ankus
  module Settings

    extend self

    @_settings = {}
    attr_reader :_settings

    def load!(filename, options = {})
      begin
        loaded_file = YAML.load_file(filename)
      rescue ArgumentError, Psych::SyntaxError
        puts "Failed parsing config file: #{$!}"
      end
      raise(Ankus::Errors::ParseError.new("\rInvalid Yaml Syntax".red)) if ! loaded_file.is_a? Hash
      new_sets = loaded_file.deep_symbolize
      new_sets = new_sets[options[:env].to_sym] if options[:env] && new_sets[options[:env].to_sym]
      deep_merge!(@_settings, new_sets)
    end

    # Deep merging of hashes
    def deep_merge!(target, data)
      merger = proc{|_, v1, v2| Hash === v1 && Hash === v2 ? v1.merge(v2, &merger) : v2 }
      target.merge! data, &merger
    end

    # Magic happens here
    def method_missing(name, *args, &block)
      @_settings[name.to_sym] || raise(Ankus::Errors::ParseError::NoKey, "unknown configuration key #{name}", caller)
    end
  end
end
