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
