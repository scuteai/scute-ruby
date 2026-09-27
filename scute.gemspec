# frozen_string_literal: true

require_relative "lib/scute/version"

Gem::Specification.new do |spec|
  spec.name = "scute"
  spec.version = Scute::VERSION
  spec.authors = ["Scute"]
  spec.summary = "Scute for Ruby: authorization for your app's users and guardrails for the agents you build."
  spec.description = "Permission checks, data filters and access requests against Scute's engine, " \
                     "plus a harness of guards (permissions, verification, approvals, grounding, budgets, content) around your agents."
  spec.homepage = "https://github.com/scuteai/scute-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"
  spec.metadata = { "rubygems_mfa_required" => "true", "source_code_uri" => spec.homepage }
  spec.files = Dir["lib/**/*.rb", "README.md", "LICENSE", "CHANGELOG.md"]
  spec.require_paths = ["lib"]
end
