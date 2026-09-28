# frozen_string_literal: true

# The live suite: scute-ruby against a real Scute API (no fakes). Run it with
# `bundle exec rake live`; `bundle exec rspec` leaves it out (see spec_helper).
require "scute"
require_relative "support/env"
require_relative "support/redactor"
require_relative "support/api"
require_relative "support/crypto"
require_relative "support/world"
require_relative "support/rack_app"

module ScuteLive
  module_function

  def enabled? = ENV["SCUTE_LIVE"] == "1"
  def config = @config ||= Env.config
  def world = @world ||= World.new(config)
  def world? = !@world.nil?

  # What the examples see.
  module Helpers
    def world = ScuteLive.world
    def client = world.client
    def api = world.api
    def app_id = world.config.app_id
    def rack = ScuteLive::RackApp.new(client)
  end
end

RSpec.configure do |config|
  config.include ScuteLive::Helpers, :live
  next unless ScuteLive.enabled?

  # Nothing secret reaches the output, whatever an example prints.
  config.output_stream = ScuteLive::RedactingIO.new(config.output_stream)

  if (reason = ScuteLive::Env.missing_reason)
    config.before(:context, :live) { skip("scute live suite skipped: #{reason}") }
  else
    config.after(:suite) do
      next unless ScuteLive.world?

      problems = ScuteLive.world.cleanup!
      note = if problems.empty?
               "scute live: cleaned up run #{ScuteLive.world.run_id}"
             else
               "scute live: cleanup of run #{ScuteLive.world.run_id} left #{problems.size} thing(s):\n  #{problems.join("\n  ")}"
             end
      RSpec.configuration.reporter.message(ScuteLive::Redactor.redact(note))
    end
  end
end
