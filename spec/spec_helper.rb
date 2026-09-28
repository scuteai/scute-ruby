# frozen_string_literal: true

require "scute"
require_relative "support/fake_scute"

RSpec.configure do |config|
  config.include ScuteHelpers
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
  # spec/live runs against a real API, only through `rake live` (it sets SCUTE_LIVE=1).
  config.filter_run_excluding :live unless ENV["SCUTE_LIVE"] == "1"
end
