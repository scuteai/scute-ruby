# frozen_string_literal: true

require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)
task default: :spec

namespace :live do
  RSpec::Core::RakeTask.new(:specs) do |t|
    t.pattern = "spec/live/**/*_spec.rb"
    t.rspec_opts = "--order defined --format documentation"
  end
end

desc "Run the live suite against a real Scute API (SCUTE_LIVE_* or .sdk-live/ruby.env; see README)"
task :live do
  require_relative "spec/live/support/env"

  if (reason = ScuteLive::Env.missing_reason)
    puts "scute live suite skipped: #{reason}"
    next
  end

  ENV["SCUTE_LIVE"] = "1"
  Rake::Task["live:specs"].invoke
end
