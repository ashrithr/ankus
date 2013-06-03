# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ankuscli/version'

Gem::Specification.new do |spec|
  spec.name          = 'ankuscli'
  spec.version       = Ankuscli::VERSION
  spec.authors       = ['ashrith']
  spec.email         = ['ashrith@cloudwick.com']
  spec.summary       = %q{Command line interface for Ankus (big data deployment and management utility)}
  spec.description   = "#{spec.summary}"
  spec.homepage      = ''
  spec.license       = 'MIT'

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
  spec.add_runtime_dependency 'colored'
  spec.add_runtime_dependency 'net-ssh'
  spec.add_runtime_dependency 'passenger', '3.0.18'
end
