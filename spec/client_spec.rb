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
end
