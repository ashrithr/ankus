# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ankus/version'

Gem::Specification.new do |spec|
  spec.name          = 'ankus'
  spec.version       = Ankus::VERSION
  spec.authors       = ['ashrith']
  spec.email         = ['ashrith@cloudwick.com']
  spec.summary       = %q{Ankus is a deployment & orchestration tool for
                          big-data frameworks in cloud and on-premise}
  spec.description   = "#{spec.summary}"
  spec.homepage      = 'https://github.com/ashrithr/ankus'
  spec.license       = 'Apache 2.0'

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']
  spec.bindir        = 'bin'

  spec.add_development_dependency 'bundler', '~> 1.3'
  spec.add_development_dependency 'rake'
  spec.add_runtime_dependency 'thor'
  spec.add_runtime_dependency 'multi_json'
  spec.add_runtime_dependency 'fog'
  spec.add_runtime_dependency 'unf'
  spec.add_runtime_dependency 'log4r'
  spec.add_runtime_dependency 'highline'
  spec.add_runtime_dependency 'colored'
  spec.add_runtime_dependency 'net-ssh'
  # spec.add_runtime_dependency 'passenger', '3.0.18'
  spec.add_runtime_dependency 'google-api-client'
end
