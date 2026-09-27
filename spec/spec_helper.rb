# frozen_string_literal: true

require "scute"
require_relative "support/fake_scute"

RSpec.configure do |config|
  config.include ScuteHelpers
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
end
