# frozen_string_literal: true

require_relative "live_helper"

# The decision log is written by a job, so rows show up a moment after the
# check. scute-ruby has no method to read it: GET /v1/apps/:app_id/authz/decisions.
RSpec.describe "Live: the decision log (read over HTTP)", :live, order: :defined do
  before(:context) do
    world.authz_settings! # every allow is logged while the suite runs (log_allow_rate 1)
    @log = { user: world.user(:logged, roles: ["viewer"]) }
  end

  def rows(query)
    world.eventually("decision log rows for #{query.keys.join(', ')}") do
      found = api.get!(world.apps("/authz/decisions?#{URI.encode_www_form(query.merge(limit: 50))}"))["decisions"]
      yield(found) ? found : nil
    end
  end

  def summary(found) = found.map { |r| r.values_at("permission", "resource", "decision", "reason") }

  it "has a row for each check made with scute-ruby, allows and denies" do
    user_id = @log[:user]["id"]
    client.authz.check(user_id: user_id, action: "read", resource: "invoice:LOG-1")
    client.authz.check(user_id: user_id, action: "delete", resource: "account:LOG-1")

    found = rows(user_id: user_id) { |r| r.size >= 2 }

    expect(summary(found)).to include(%w[invoice:read invoice:LOG-1 allow role_grant],
                                      %w[account:delete account:LOG-1 deny no_role_grants_permission])
  end

  it "has the agent's checks too, with its task" do
    agent = world.agent("support")
    run = world.harness(agent["slug"]).run(acts_for: @log[:user]["id"], task: { actions: %w[invoice:read invoice:void] })
    run.check("read_invoice", invoice_id: "LOG-2")
    run.check("void_invoice", invoice_id: "LOG-2")

    found = rows(task_id: run.task_id) { |r| r.size >= 2 }

    expect(found).to all(include("task_id" => run.task_id, "agent_id" => agent["id"], "user_id" => @log[:user]["id"]))
    expect(summary(found)).to include(%w[invoice:read invoice:LOG-2 allow role_grant],
                                      %w[invoice:void invoice:LOG-2 deny no_role_grants_permission])
  end
end
