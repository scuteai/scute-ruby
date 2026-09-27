# frozen_string_literal: true

RSpec.describe Scute::Harness do
  let(:check_path) { "/v1/auth/app1/agent/check" }
  let(:mint_path) { "/v1/apps/app1/authz/agents/support-bot/tasks" }

  describe "naming convention" do
    it "maps tool names to permissions" do
      expect(Scute::Harness::ToolSpec.permission_for("refund_invoice")).to eq("invoice:refund")
      expect(Scute::Harness::ToolSpec.permission_for("resetUserMfa")).to eq("user_mfa:reset")
      expect(Scute::Harness::ToolSpec.permission_for("search")).to eq("search")
    end

    it "finds the object and attributes in the arguments, with overrides" do
      h = harness(FakeScute.new, tools: { send_money: { permission: "payment:create", key: :to, tier: :high }, get_weather: false })

      expect(h.spec("refund_invoice").resource(invoice_id: 42, amount: 90, note: { x: 1 }))
        .to eq(type: "invoice", key: "42", attributes: { amount: 90 })
      expect(h.spec("reset_user_mfa").resource(userMfaId: "u1")).to eq(type: "user_mfa", key: "u1")
      expect(h.spec("send_money")).to have_attributes(permission: "payment:create", action: "create", tier: :high)
      expect(h.spec("send_money").resource(to: "acct9", amount: 5)).to eq(type: "payment", key: "acct9", attributes: { amount: 5 })
      expect(h.spec("get_weather").permission).to be_nil
    end
  end

  describe "permissions guard" do
    it "starts the task once, lazily, and asks the engine with the action and object" do
      fake = FakeScute.new
      run = harness(fake).run(acts_for: "user1", task: { actions: ["invoice:refund"], ref: "T-9" })

      threads = [Thread.new { run.check("refund_invoice", { invoice_id: 42, amount: 90 }) }, Thread.new { run.check("read_invoice", { id: 1 }) }]
      expect(threads.map(&:value).map(&:kind)).to eq(%i[proceed proceed])

      expect(fake.paths(mint_path).size).to eq(1)
      expect(fake.paths(mint_path).first.body).to include("acts_for" => "user1", "actions" => ["invoice:refund"], "ref" => "T-9")
      refund = fake.paths(check_path).find { |c| c.body["action"] == "refund" }
      expect(refund.auth).to eq("Bearer sct_token1")
      expect(refund.body["resource"]).to eq("type" => "invoice", "key" => "42", "attributes" => { "amount" => 90 })
    end

    it "maps engine answers and tells the model what to do next" do
      answers = {
        "delete" => { decision: "deny", reason: "agent_role", explanation: "Support bot can't delete invoice 1: none of its roles allow it." },
        "pay" => { decision: "allow_with_step_up", step_up: { method: "entra_push", authorizes_action: "invoice:pay" } }
      }
      run = harness(FakeScute.new(decide: ->(body, _) { answers[body["action"]] })).run(acts_for: "user1")

      denied = run.check("delete_invoice", { id: 1 })
      expect(denied.kind).to eq(:deny)
      expect(denied.decision).to have_attributes(reason: "agent_role", guard: "permissions")
      expect(denied.message).to eq("Not allowed: Support bot can't delete invoice 1: none of its roles allow it. Don't retry it; tell the person.")

      verify = run.check("pay_invoice", { id: 1 })
      expect(verify.kind).to eq(:verify)
      expect(verify.decision.verify).to eq(method: "entra_push", permission: "invoice:pay")
    end

    it "fails closed when Scute can't be reached" do
      fake = FakeScute.new
      fake.down = true
      v = harness(fake).run(acts_for: "user1").check("refund_invoice", { id: 1 })

      expect(v.kind).to eq(:deny)
      expect(v.decision.reason).to eq("guard_error")
      expect(v.results.first.error).to be_a(Scute::ConnectionError)
    end

    it "verifies the person with the task token and carries the proof into the next check" do
      fake = FakeScute.new(decide: lambda { |body, _|
        next nil if body["challenge"] == "ch_ok"

        { decision: "allow_with_step_up", say: "Before I do that, I need to verify it's you.",
          step_up: { method: "any", authorizes_action: "invoice:pay" } }
      })
      h = Scute::Harness.new(agent: "support-bot", app_id: "app1", secret: nil, base_url: "https://scute.test", transport: fake)
      run = h.run(token: "sct_from_backend")

      first = run.check("pay_invoice", { id: 1 })
      expect([first.kind, first.say]).to eq([:verify, "Before I do that, I need to verify it's you."])
      expect { run.start_verification(verdict: first) }.to raise_error(ArgumentError, /verification method/)

      expect(run.start_verification(method: "email_otp")["say"]).to eq("I've emailed a code to a***@example.com. What's the code?")
      started = fake.paths("/v1/auth/app1/agent/verifications").first
      expect([started.auth,
              started.body]).to eq(["Bearer sct_from_backend", { "method" => "email_otp", "permission" => "invoice:pay", "session_id" => "sess1" }])

      expect(run.submit_code("000000")).to include("status" => "pending", "remaining_attempts" => 2,
                                                   "say" => "That code didn't work. Want to try again?")
      expect(run.verified_at).to be_nil
      expect(run.submit_code("123456")["status"]).to eq("completed")
      expect(run.verified_at).to be > 0

      expect(run.check("pay_invoice", { id: 1 }).kind).to eq(:proceed)
      expect(fake.paths(check_path).last.body).to include("challenge" => "ch_ok", "session_id" => "sess1")
    end

    it "records a push once it's approved" do
      fake = FakeScute.new
      run = harness(fake).run(acts_for: "user1")
      run.start_verification(method: "entra_push", permission: "invoice:pay")

      expect { run.complete_verification }.to raise_error(Scute::APIError, /Not verified yet \(pending\)/)
      fake.verification_status = "completed"
      run.complete_verification
      expect(run.snapshot["challenges"]).to eq("invoice:pay" => "ch_ok")
    end

    it "rejects a verification Scute doesn't accept" do
      run = harness.run(acts_for: "user1")

      expect { run.complete_verification("ch_forged") }.to raise_error(Scute::APIError, /doesn't verify this person/)
      expect(run.verified_at).to be_nil
    end

    it "files the reviewer approval once and goes through once it's approved" do
      fake = FakeScute.new
      fake.decide = lambda { |body, _|
        body["approval"] && fake.request_status == "approved" ? nil : { decision: "allow_with_approval", explanation: "Needs a reviewer." }
      }
      run = harness(fake).run(acts_for: "user1")

      pending = run.check("refund_invoice", { invoice_id: 42, amount: 900 })
      expect(pending.kind).to eq(:approve)
      expect(pending.decision.approve).to eq(by: :reviewer, request_id: "req1")
      expect(pending.message).to match(/The request is filed \(id req1\)/)
      expect(pending.say).to eq("I've asked for approval. I'll let you know when there's an answer.")
      expect(fake.paths("/v1/auth/app1/agent/approvals").first.body)
        .to include("action" => "refund", "resource" => { "type" => "invoice", "key" => "42", "attributes" => { "amount" => 900 } },
                    "reason" => "refund_invoice (invoice_id 42, amount 900)")
      expect(run.approval_status("req1")["say"]).to eq("Still waiting.")

      fake.request_status = "approved"
      expect(run.check("refund_invoice", { invoice_id: 42, amount: 900 }).kind).to eq(:proceed)
      expect(fake.paths(check_path).last.body["approval"]).to eq("req1")
      expect(run.snapshot["approvals"]).to eq({})
    end

    it "files nothing while observing, and doesn't claim a filing that didn't happen" do
      fake = FakeScute.new(decide: ->(*) { { decision: "allow_with_approval", explanation: "Needs a reviewer." } })

      observed = harness(fake, mode: :observe).run(acts_for: "user1").check("refund_invoice", { id: 1 })
      expect(observed.kind).to eq(:proceed)
      expect(observed.results.first.decision.kind).to eq(:approve)

      unfiled = harness(fake, guards: [Scute::Guards.permissions(file_requests: false)]).run(acts_for: "user1").check("refund_invoice", { id: 1 })
      expect(unfiled.message).to eq("Needs a reviewer. Tell the person it needs a reviewer's approval.")
      expect(fake.paths("/v1/auth/app1/agent/approvals")).to be_empty
    end
  end

  describe "runs" do
    it "resume from the store by id without a new task" do
      fake = FakeScute.new
      h = harness(fake)
      h.run(id: "chat-1", acts_for: "user1").check("read_invoice", { id: 1 })
      h.run(id: "chat-1", acts_for: "user1").check("read_invoice", { id: 2 })

      expect(fake.paths(mint_path).size).to eq(1)
      expect(fake.paths(check_path).map(&:auth)).to eq(["Bearer sct_token1"] * 2)
    end

    it "start a new task when the old one expired, but never after it was closed" do
      fake = FakeScute.new(ttl: 1)
      run = harness(fake).run(acts_for: "user1")
      2.times { run.check("read_invoice", { id: 1 }) }
      expect(fake.paths(mint_path).size).to eq(2)

      closed = FakeScute.new(decide: ->(*) { { decision: "deny", reason: "task_closed", explanation: "This task is revoked; start a new one." } })
      run2 = harness(closed).run(acts_for: "user1")
      expect(run2.check("read_invoice", { id: 1 }).kind).to eq(:deny)
      expect { run2.token }.to raise_error(Scute::APIError, /task is closed/)
    end

    it "use a task token from your backend without the secret" do
      fake = FakeScute.new
      h = Scute::Harness.new(agent: "support-bot", app_id: "app1", secret: nil, base_url: "https://scute.test", transport: fake)

      expect(h.run(token: "sct_from_backend").check("read_invoice", { id: 1 }).kind).to eq(:proceed)
      expect(fake.paths(check_path).first.auth).to eq("Bearer sct_from_backend")
      expect(fake.paths(mint_path)).to be_empty

      v = h.run(acts_for: "user1").check("read_invoice", { id: 1 })
      expect(v.kind).to eq(:deny)
      expect(v.results.first.error.message).to match(/SCUTE_SECRET/)
    end

    it "pass the parent task to a sub-agent's task" do
      fake = FakeScute.new
      h = harness(fake)
      parent = h.run(acts_for: "user1")
      h.run(acts_for: "user1", parent: parent).check("read_invoice", { id: 1 })

      expect(fake.paths(mint_path).map { |m| m.body["parent_task_id"] }).to eq([nil, "task1"])
    end

    it "revoke their task and end the session" do
      fake = FakeScute.new
      run = harness(fake).run(acts_for: "user1")
      run.check("read_invoice", { id: 1 })
      run.session
      run.revoke!

      expect(fake.seen.last(2).map(&:path)).to eq(["/v1/auth/app1/agent/sessions/sess1/end", "#{mint_path}/task1/revoke"])
      expect { run.token }.to raise_error(Scute::APIError, /closed/)
    end

    it "list the tools inside the task's ceiling" do
      run = harness(FakeScute.new(ceiling: ["invoice:read"]), tools: { get_weather: false }).run(acts_for: "user1")

      expect(run.allowed_tools(%w[read_invoice refund_invoice get_weather])).to eq(%w[read_invoice get_weather])
    end
  end

  describe "combining guards" do
    it "lets the strictest enforced decision win, verify above approve, transforms carried" do
      h = harness(FakeScute.new, guards: [
                    Scute::Guards.define("a") { |c| c.approve("confirm") },
                    Scute::Guards.define("v") { |c| c.verify("verify") },
                    Scute::Guards.define("t") { |c| c.transform(c.args.merge(x: 1)) }
                  ])
      v = h.run.check("read_invoice", {})

      expect([v.kind, v.decision.guard, v.args]).to eq([:verify, "v", { x: 1 }])
    end

    it "shows later guards the transformed arguments and stops at the first deny" do
      seen = []
      later = []
      h = harness(FakeScute.new, guards: [
                    Scute::Guards.define("cap") { |c| c.transform(c.args.merge(amount: [c.args[:amount], 100].min)) },
                    Scute::Guards.define("look") { |c| (seen << c.args[:amount]) && nil },
                    Scute::Guards.define("no") { |c| c.deny("no") },
                    Scute::Guards.define("later") { |_| (later << 1) && nil }
                  ])

      expect(h.run.check("refund_invoice", { "amount" => 900 }).kind).to eq(:deny)
      expect(seen).to eq([100])
      expect(later).to be_empty
    end

    it "never blocks in observe or monitor, alerts on monitor, and fails closed only when enforced" do
      alerts = []
      h = harness(FakeScute.new, on_alert: ->(e) { alerts << e }, guards: [
                    Scute::Guards.define("o", mode: :observe) { |c| c.deny("o") },
                    Scute::Guards.define("m", mode: :monitor) { |c| c.guide("m") },
                    Scute::Guards.define("e", mode: :observe) { |_| raise "boom" }
                  ])
      v = h.run.check("x", {})

      expect(v.kind).to eq(:proceed)
      expect(v.results.map { |r| r.decision.kind }).to eq(%i[deny guide deny])
      expect(alerts.map { |a| a[:guard] }).to eq(["m"])

      enforced = harness(FakeScute.new, guards: [Scute::Guards.define("e") { |_| raise "boom" }])
      expect(enforced.run.check("x", {}).decision.reason).to eq("guard_error")

      wrong = harness(FakeScute.new, guards: [Scute::Guards.define("w") { |_| true }])
      expect(wrong.run.check("x", {}).results.first.error).to be_a(TypeError)
    end

    it "reports every decision, and a raising hook changes nothing" do
      events = []
      h = harness(FakeScute.new, guards: [Scute::Guards.define("g") { |c| c.guide("ask first", "custom") }],
                                 on_decision: ->(e) { (events << e) && raise("hook broke") })

      expect(h.run(id: "r1").check("refund_invoice", { amount: 5 }, id: "call1").kind).to eq(:guide)
      expect(events.first).to include(run: "r1", agent: "support-bot", tool: "refund_invoice", call_id: "call1",
                                      phase: :before, kind: :guide, guard: "g", reason: "custom")
    end

    it "wraps a block" do
      h = harness(FakeScute.new, guards: [Scute::Guards.define("small") { |c| c.guide("Keep it under 100.") if c.args[:amount] > 100 }])
      run = h.run
      refund = run.wrap("refund_invoice") { |args| "refunded #{args[:amount]}" }

      expect(refund.call(amount: 50)).to eq("refunded 50")
      expect(refund.call(amount: 500)).to eq("Keep it under 100.")
      expect(run.snapshot["calls"]).to eq(1)
    end

    it "needs an agent" do
      expect { Scute::Harness.new(agent: "", app_id: "a") }.to raise_error(Scute::ConfigurationError, /agent/)
    end
  end
end
