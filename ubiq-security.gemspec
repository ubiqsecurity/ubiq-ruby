require_relative 'lib/ubiq/version'

Gem::Specification.new do |spec|
  spec.name          = "ubiq-security"
  spec.version       = Ubiq::VERSION
  spec.authors       = ["Ubiq Security, Inc."]
  spec.email         = ["support@ubiqsecurity.com"]

  spec.summary       = %q{Ruby Client Library for accessing the Ubiq Platform}
  spec.description   = "Provide data encryption to any application with a couple of API calls.  " \
                       "See https://www.ubiqsecurity.com for details."
  spec.homepage      = "https://dev.ubiqsecurity.com/docs/ruby-library"
  spec.license       = "Nonstandard"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.3.0")

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://gitlab.com/ubiqsecurity/ubiq-ruby"
  spec.metadata["changelog_uri"] = "https://gitlab.com/ubiqsecurity/ubiq-ruby/-/blob/master/README.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features|example)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.add_runtime_dependency 'rb-readline', '~> 0.2', '>= 0.2'
  spec.add_runtime_dependency 'httparty', '~> 0.15', '>= 0.15'
end
