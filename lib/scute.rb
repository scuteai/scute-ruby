# frozen_string_literal: true

require_relative "scute/version"
require_relative "scute/errors"
require_relative "scute/http"
require_relative "scute/client"
require_relative "scute/authz"
require_relative "scute/agents"
require_relative "scute/authorization"
require_relative "scute/harness"
require_relative "scute/harness/decision"
require_relative "scute/harness/convention"
require_relative "scute/harness/call"
require_relative "scute/harness/store"
require_relative "scute/harness/human_steps"
require_relative "scute/harness/run"
require_relative "scute/harness/guards"
require_relative "scute/harness/human_tools"
require_relative "scute/harness/adapters/ruby_llm"

# Scute for Ruby: authorization checks for your app's users, and a harness
# of guards around the agents you build.
module Scute
end
