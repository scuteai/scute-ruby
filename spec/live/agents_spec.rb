# frozen_string_literal: true

require_relative "live_helper"

RSpec.describe "Live: agents and the harness", :live, order: :defined do
  before(:context) do
    agent = world.agent("support")
    @agents = { slug: agent["slug"], registered: agent, human: world.user(:agent_human, roles: ["billing"]) }
  end

  # Other specs use the agent too: never leave it suspended.
  after(:context) do
    client.agents.resume(@agents[:slug]) if @agents && client.agents.get(@agents[:slug])["status"] != "active"
  end

  let(:slug) { @agents[:slug] }
  let(:human) { @agents[:human] }
  let(:harness) { world.harness(slug) }

  def run_for(actions = nil)
    harness.run(acts_for: human["id"], task: actions ? { actions: actions } : {})
  end

  it "registers the agent (agents.create); its roles are its ceiling" do
    expect(@agents[:registered]).to include("slug" => slug, "status" => "active", "roles" => ["support_agent"])
    expect(client.agents.get(slug)).to include("slug" => slug, "orphaned" => true)
    expect(client.agents.list.map { |a| a["slug"] }).to include(slug)
  end

  it "mints a task for the person it works for (run.token), with a signed delegation" do
    run = run_for(%w[invoice:read invoice:refund invoice:void])
    task_id = run.task_id

    expect(client.agents.tasks(slug, status: "open").map { |t| t["id"] }).to include(task_id)
    me = run.whoami
    expect(me).to include("acts_for" => human["id"], "task" => task_id)
    expect(me["ceiling"]).to include("invoice:read", "invoice:refund", "invoice:void")

    jwks = api.get!(world.auth("/.well-known/jwks.json"), as: :public)
    delegation = ScuteLive::Crypto.verify_rs256(client.agents.assertion(slug, task_id)["assertion"], jwks)
    expect(delegation).to include("sub" => human["id"], "act" => { "sub" => "agent:#{slug}" })
  end

  it "lets a call through that the agent, the person and the task all allow (check, wrap)" do
    run = run_for(%w[invoice:read])

    expect(run.check("read_invoice", { invoice_id: "INV-1" }).kind).to eq(:proceed)
    read = run.wrap("read_invoice") { |args| { "invoice" => args[:invoice_id] } }
    expect(read.call(invoice_id: "INV-1")).to eq("invoice" => "INV-1")
  end

  it "denies outside the task, and beyond the agent's roles" do
    outside = run_for(%w[invoice:read]).check("void_invoice", { invoice_id: "INV-1" })
    expect(outside.kind).to eq(:deny)
    expect(outside.decision.reason).to eq("outside_task")

    beyond = run_for.check("delete_account", { account_id: "1" })
    expect(beyond.kind).to eq(:deny)
    expect(beyond.decision.reason).to eq("agent_role")

    blocked = run_for(%w[invoice:read]).wrap("void_invoice") { raise "the tool ran" }
    expect(blocked.call(invoice_id: "INV-1")).to start_with("Not allowed")
  end

  it "steps up through human steps with a test identity (424242)" do
    run = run_for(%w[invoice:refund])
    first = run.check("refund_invoice", { invoice_id: "INV-2" })
    expect(first.kind).to eq(:verify)

    started = run.start_verification(verdict: first)
    expect(started).to include("status" => "pending", "method" => "email_otp")
    expect(started["say"]).to include("***@example.com")

    expect(run.submit_code("000000")["status"]).to eq("pending")
    expect(run.submit_code(ScuteLive::World::CODE)).to include("status" => "completed", "say" => "Thanks, you're verified.")
    expect(run.check("refund_invoice", { invoice_id: "INV-2" }).kind).to eq(:proceed)
  end

  it "files a reviewer approval for the exact call; once approved, that call runs" do
    run = run_for(%w[invoice:void])
    first = run.check("void_invoice", { invoice_id: "INV-3", amount: 10 })
    expect(first.kind).to eq(:approve)
    request_id = first.decision.approve[:request_id]
    expect(request_id).to be_a(String)
    expect(run.approval_status(request_id)).to include("status" => "pending", "details" => { "invoice_id" => "INV-3", "amount" => 10 })

    client.authz.decide_request(request_id, :approve, note: "live #{world.run_id}")

    expect(run.check("void_invoice", { invoice_id: "INV-3", amount: 10 }).kind).to eq(:proceed)
  end

  # scute-ruby has no property methods: they're made over HTTP (POST /v1/apps/:app_id/properties).
  describe "properties" do
    before(:context) do
      @props = { secret: "live-#{SecureRandom.hex(12)}", stripe: "#{world.prefix}-stripe", signer: "#{world.prefix}-signer" }
      ScuteLive::Redactor.remember(@props[:secret])
      world.property(@props[:stripe], kind: "secret", value: @props[:secret], agents: [@agents[:slug]])
      world.property(@props[:signer], kind: "keypair", algorithm: "RS256", agents: [@agents[:slug]])
    end

    it "reads a secret inside a tool (run.property)" do
      value = run_for(%w[invoice:read]).property(@props[:stripe])

      expect(value == @props[:secret]).to be(true)
    end

    it "signs claims (run.sign), and the JWS verifies with the property's JWKS" do
      signed = run_for(%w[invoice:read]).sign(@props[:signer], claims: { "sub" => "live", "amount" => 10 })
      jwks = api.get!(world.auth("/properties/#{@props[:signer]}/jwks.json"), as: :public)

      expect(signed).to include("alg" => "RS256")
      claims = ScuteLive::Crypto.verify_rs256(signed["jws"], jwks)
      expect(claims).to include("sub" => "live", "amount" => 10, "iss" => "#{app_id}/properties/#{@props[:signer]}")
    end

    it "signs bytes (run.sign data:), and the signature verifies with the public key" do
      signed = run_for(%w[invoice:read]).sign(@props[:signer], data: ScuteLive::Crypto.b64("hello from #{world.prefix}"))
      jwk = api.get!(world.auth("/properties/#{@props[:signer]}/jwks.json"), as: :public)["keys"].first

      expect(ScuteLive::Crypto.rsa_key(jwk).verify("SHA256", ScuteLive::Crypto.unb64(signed["signature"]), "hello from #{world.prefix}")).to be(true)
    end
  end

  it "completes and revokes tasks (run.complete!, run.revoke!)" do
    done = run_for(%w[invoice:read])
    gone = run_for(%w[invoice:read])
    ids = [done.task_id, gone.task_id]
    done.complete!
    gone.revoke!

    statuses = client.agents.tasks(slug).to_h { |t| [t["id"], t["status"]] }
    expect(statuses.values_at(*ids)).to eq(%w[completed revoked])
    expect { done.token }.to raise_error(Scute::APIError) { |e| expect(e.code).to eq("task_closed") }
  end

  it "suspends the agent (every task ends) and resumes it" do
    run = run_for(%w[invoice:read])
    expect(run.check("read_invoice", { invoice_id: "INV-4" }).kind).to eq(:proceed)

    expect(client.agents.suspend(slug)).to include("status" => "suspended")
    expect(run.check("read_invoice", { invoice_id: "INV-4" }).kind).to eq(:deny)

    expect(client.agents.resume(slug)).to include("status" => "active")
    expect(run_for(%w[invoice:read]).check("read_invoice", { invoice_id: "INV-4" }).kind).to eq(:proceed)
  end

  it "pauses an agent with a budget of 2 on its 3rd action" do
    budget_slug = world.agent("budget")["slug"]
    updated = client.agents.update(budget_slug, settings: { budget: { max_actions: 2, window_minutes: 1440 } })
    expect(updated.dig("settings", "budget")).to include("max_actions" => 2)

    run = world.harness(budget_slug).run(task: { actions: %w[invoice:read] }) # on its own: invoice:read is autonomous_allowed
    verdicts = Array.new(3) { |i| run.check("read_invoice", { invoice_id: "INV-B#{i}" }) }

    expect(verdicts.map(&:kind)).to eq(%i[proceed proceed deny])
    expect(verdicts.last.decision.reason).to eq("budget_exceeded")
    expect(client.agents.get(budget_slug)).to include("status" => "suspended", "suspended_reason" => a_string_including("budget"))

    # The run is over for good: it never mints a new task for the paused agent.
    expect(run.snapshot["closed"]).to be(true)
    expect { run.token }.to raise_error(Scute::APIError) { |e| expect(e.code).to eq("task_closed") }
    expect(client.agents.resume(budget_slug)).to include("status" => "active")
    expect(run.check("read_invoice", { invoice_id: "INV-B3" }).kind).to eq(:deny)
    expect(client.agents.tasks(budget_slug).size).to eq(1)
  end

  describe "plans, previews, tool drift and decoys" do
    # The API routes for these are merged but not deployed on scute-api-v2
    # yet. Remove this hook once they are.
    before { skip("waits for the API deploy") }

    it "files a plan for two calls; once it's approved, each runs once (run.request_plan, run.plan_status)" do
      run = run_for(%w[invoice:void])
      plan = run.request_plan([{ tool: "void_invoice", args: { invoice_id: "INV-P1" } },
                               { tool: "void_invoice", args: { invoice_id: "INV-P2" } }], reason: "#{world.prefix}: two voids")
      expect(plan).to include("status" => "pending")
      expect(plan["steps"].map { |step| step["needs"] }).to eq(%w[approval approval])

      client.authz.decide_request(plan["id"], :approve, note: "live #{world.run_id}")

      expect(run.check("void_invoice", { invoice_id: "INV-P1" }).kind).to eq(:proceed)
      expect(run.check("void_invoice", { invoice_id: "INV-P2" }).kind).to eq(:proceed)
      expect(run.plan_status["steps"].map { |step| step["used"] }).to eq([true, true])
      expect(run.check("void_invoice", { invoice_id: "INV-P1" }).kind).not_to eq(:proceed) # each step runs once
    end

    it "previews a call without using anything up (run.preview)" do
      run = run_for(%w[invoice:refund])

      expect(run.preview("refund_invoice", { invoice_id: "INV-P3" })).to be_step_up
      expect(run.check("refund_invoice", { invoice_id: "INV-P3" }).kind).to eq(:verify)
    end

    it "reports the tool definitions and notices one that changed (run.report_tools)" do
      run = world.harness(world.agent("drift")["slug"]).run(task: { actions: %w[invoice:read] })
      tool = { name: "refund_invoice", description: "Refund an invoice", input_schema: { type: "object" } }

      expect(run.report_tools([tool])).to include("known" => 1, "changed" => [])
      expect(run.report_tools([tool])).to include("known" => 1, "changed" => [])
      expect(run.report_tools([tool.merge(description: "Refund an invoice, then something else")])).to include("changed" => ["refund_invoice"])
    end

    it "refuses a decoy tool, and Scute pauses the agent (Scute::Guards.decoy)" do
      slug = world.agent("decoy")["slug"]
      guards = [Scute::Guards.decoy(["export_all_customers"]), Scute::Guards.permissions]
      run = world.harness(slug, guards: guards).run(task: { actions: %w[invoice:read] })

      verdict = run.check("export_all_customers", {})

      expect(verdict.decision.reason).to eq("decoy_called")
      expect(run.snapshot["closed"]).to be(true)
      expect(client.agents.get(slug)).to include("status" => "suspended")
      expect(client.agents.resume(slug)).to include("status" => "active")
    end
  end
end
