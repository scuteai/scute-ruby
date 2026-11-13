# frozen_string_literal: true

RSpec.describe Scute::Client do
  let(:fake) { FakeScute.new }
  let(:client) { described_class.new(app_id: "app1", secret: "sk_test", base_url: "https://scute.test/", transport: fake) }

  it "checks a user's permission and wraps the answer" do
    d = client.authz.check(user_id: "user1", action: "read", resource: "invoice:42")

    expect(d).to be_allowed
    expect(d).to have_attributes(permission: "invoice:read", roles: ["clerk"])
    expect(fake.seen.last).to have_attributes(verb: :post, path: "/v1/auth/app1/authz/check", auth: "Bearer sk_test")
    expect(fake.seen.last.body).to eq("user_id" => "user1", "action" => "read", "resource" => "invoice:42")
  end

  it "checks in batches of at most 100" do
    results = client.authz.check_batch([{ user_id: "u", action: "read" }, { user_id: "u", action: "delete" }])

    expect(results.map(&:allowed?)).to eq([true, false])
    expect { client.authz.check_batch(Array.new(101) { { user_id: "u", action: "read" } }) }.to raise_error(ArgumentError)
  end

  it "escapes path and query values" do
    client.authz.permissions("user 1/x", resource: "document:42")

    expect(fake.seen.last.path).to eq("/v1/auth/app1/authz/users/user%201%2Fx/permissions")
  end

  it "starts a step-up from a decision" do
    decision = Scute::Authz::Decision.from_api("decision" => "allow_with_step_up", "permission" => "invoice:pay",
                                               "step_up" => { "method" => "any", "authorizes_action" => "invoice:pay" })

    expect { client.authz.start_step_up(user_id: "user1", decision: decision) }.to raise_error(ArgumentError, /method/)
    challenge = client.authz.start_step_up(user_id: "user1", decision: decision, method: "email_otp")

    expect(challenge["token"]).to eq("ch_ok")
    expect(fake.seen.last.body).to eq("purpose" => "step_up", "method" => "email_otp", "app_user_id" => "user1",
                                      "metadata" => { "authorizes_action" => "invoice:pay" })
  end

  it "files and decides access requests" do
    expect(client.authz.create_request("user1", action: "refund", resource: "invoice:42")["id"]).to eq("req1")
    expect(client.authz.decide_request("req1", :approve)["status"]).to eq("approved")
    expect { client.authz.decide_request("req1", :maybe) }.to raise_error(ArgumentError)
  end

  it "starts and lists agent tasks" do
    task = client.agents.start_task("support-bot", acts_for: "user1", actions: ["invoice:read"], ttl: 600)

    expect(task["token"]).to eq("sct_token1")
    expect(fake.seen.last.body).to eq("acts_for" => "user1", "actions" => ["invoice:read"], "ttl_seconds" => 600)
    expect(client.agents.tasks("support-bot", status: "open").first["query"]).to eq("status=open")
  end

  it "raises the API's error with its code" do
    expect { client.http.request(:post, "/v1/auth/app1/agent/sessions/sess1/verified", bearer: "sct_x", body: { challenge: "nope" }) }
      .to raise_error(Scute::APIError) { |e| expect([e.status, e.code, e.message]).to eq([422, "challenge_invalid", "That challenge doesn't verify this person"]) }
  end

  it "retries reads once on a network error, and never a write" do
    attempts = 0
    flaky = lambda do |*|
      attempts += 1
      raise Errno::ECONNRESET if attempts == 1

      [200, '{"ok":true}']
    end
    http = Scute::HTTP.new(base_url: "https://scute.test", transport: flaky)
    expect(http.request(:get, "/x", bearer: "t")).to eq("ok" => true)

    attempts = 0
    expect { http.request(:post, "/x", bearer: "t") }.to raise_error(Scute::ConnectionError)
    expect(attempts).to eq(1)
  end

  it "needs an app id, and the secret for management calls" do
    expect { described_class.new(app_id: nil) }.to raise_error(Scute::ConfigurationError, /app id/)
    no_secret = described_class.new(app_id: "app1", secret: nil, transport: fake)
    expect { no_secret.authz.check(user_id: "u", action: "read") }.to raise_error(Scute::ConfigurationError, /secret key/)
  end

  it "reads each kind of decision" do
    kinds = %w[read pay approve delete].to_h { |a| [a, client.authz.check(user_id: "user1", action: a, resource: "invoice:1")] }

    expect(kinds.transform_values { |d| [d.allowed?, d.step_up?, d.needs_approval?, d.denied?] }).to eq(
      "read" => [true, false, false, false], "pay" => [false, true, false, false],
      "approve" => [false, false, true, false], "delete" => [false, false, false, true]
    )
    expect(kinds["pay"].step_up).to eq("method" => "any", "authorizes_action" => "invoice:pay")
    expect(kinds["approve"].approval).to eq("by" => "reviewer")
    expect(kinds["delete"].explanation).to eq("Ada can't delete invoices.")
  end

  describe "thin wrappers" do
    let(:recorded) { [] }
    let(:recording) do
      seen = recorded
      Class.new do
        define_method(:call) do |method, url, headers, body|
          seen << { verb: method, path: URI(url).path, query: URI(url).query, auth: headers["Authorization"],
                    body: body && JSON.parse(body) }
          [200, "{}"]
        end
      end.new
    end
    let(:wrapped) { described_class.new(app_id: "app1", secret: "sk_test", base_url: "https://scute.test", transport: recording) }

    {
      "users.get" => [->(c) { c.users.get("u 1") }, :get, "/v1/app1/users/u%201", nil],
      "users.invite" => [->(c) { c.users.invite("bob@example.com", meta: { plan: "pro" }) }, :post, "/v1/app1/users/invite",
                         { "identifier" => "bob@example.com", "user_meta" => { "plan" => "pro" } }],
      "users.activate" => [->(c) { c.users.activate("user1") }, :post, "/v1/app1/users/user1/activate", nil],
      "users.delete" => [->(c) { c.users.delete("user1") }, :delete, "/v1/app1/users/user1", nil],
      "sessions.revoke" => [->(c) { c.sessions.revoke("user1", "ses/1") }, :delete, "/v1/app1/users/user1/sessions/ses%2F1", nil],
      "authz.authorized_users" => [->(c) { c.authz.authorized_users(action: "read", limit: 5) }, :get,
                                   "/v1/auth/app1/authz/authorized-users", nil],
      "authz.filter" => [->(c) { c.authz.filter(user_id: "user1", action: "read", resource_type: "invoice") }, :post,
                         "/v1/auth/app1/authz/filter", { "user_id" => "user1", "action" => "read", "resource_type" => "invoice" }],
      "authz.snapshot" => [->(c) { c.authz.snapshot }, :get, "/v1/apps/app1/authz/snapshot", nil],
      "authz.requests" => [->(c) { c.authz.requests(status: "pending") }, :get, "/v1/apps/app1/authz/requests", nil],
      "authz.decide_request (deny)" => [->(c) { c.authz.decide_request("req1", :deny, note: "no") }, :post,
                                        "/v1/apps/app1/authz/requests/req1/deny", { "note" => "no" }],
      "agents.create" => [->(c) { c.agents.create(slug: "bot", owner_user_id: "user1", roles: ["support"]) }, :post,
                          "/v1/apps/app1/authz/agents", { "slug" => "bot", "owner_user_id" => "user1", "roles" => ["support"] }],
      "agents.get" => [->(c) { c.agents.get("bot") }, :get, "/v1/apps/app1/authz/agents/bot", nil],
      "agents.update" => [->(c) { c.agents.update("bot", name: "Bot") }, :patch, "/v1/apps/app1/authz/agents/bot", { "name" => "Bot" }],
      "agents.delete" => [->(c) { c.agents.delete("bot") }, :delete, "/v1/apps/app1/authz/agents/bot", nil],
      "agents.suspend" => [->(c) { c.agents.suspend("bot") }, :post, "/v1/apps/app1/authz/agents/bot/suspend", nil],
      "agents.resume" => [->(c) { c.agents.resume("bot") }, :post, "/v1/apps/app1/authz/agents/bot/resume", nil],
      "agents.complete_task" => [->(c) { c.agents.complete_task("bot", "t1") }, :post, "/v1/apps/app1/authz/agents/bot/tasks/t1/complete", nil],
      "agents.assertion" => [->(c) { c.agents.assertion("bot", "t1") }, :get, "/v1/apps/app1/authz/agents/bot/tasks/t1/assertion", nil]
    }.each do |name, (call, verb, path, body)|
      it "#{name} sends #{verb.upcase} #{path} with the secret key" do
        call.call(wrapped)

        expect(recorded.size).to eq(1)
        expect(recorded.first).to include(verb: verb, path: path, auth: "Bearer sk_test", body: body)
      end
    end

    it "puts the filters in the query" do
      wrapped.authz.authorized_users(action: "read", resource: "invoice:1", limit: 5)
      wrapped.authz.requests(status: "pending", user_id: "user1")
      wrapped.authz.requests

      expect(recorded.map { |r| r[:query] }).to eq(["action=read&resource=invoice%3A1&limit=5", "status=pending&user_id=user1", nil])
    end
  end
end
