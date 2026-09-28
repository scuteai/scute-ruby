# frozen_string_literal: true

require "spec_helper"

module AuthSpecKeys
  KEY = OpenSSL::PKey::RSA.generate(2048)
  OTHER_KEY = OpenSSL::PKey::RSA.generate(2048)
end

RSpec.describe "Authentication" do
  let(:fake) { FakeScute.new.tap { |f| f.signing_keys = [[AuthSpecKeys::KEY, "k1"]] } }
  let(:now) { Time.at(1_800_000_000) }
  let(:clock) { -> { now } }
  let(:client) { Scute::Client.new(app_id: "app1", secret: "sk_test", base_url: "https://scute.test", transport: fake) }
  let(:tokens) { Scute::Tokens.new(client, clock: clock) }

  def b64(data) = Base64.urlsafe_encode64(data, padding: false)

  def jwt(key: AuthSpecKeys::KEY, header: { alg: "RS256", typ: "JWT" }, **claims)
    body = { uuid: "user1", aid: "app1", wid: "ws1", exp: now.to_i + 600 }.merge(claims).compact
    signed = "#{b64(JSON.generate(header))}.#{b64(JSON.generate(body))}"
    "#{signed}.#{b64(key.sign('SHA256', signed))}"
  end

  def reason_for(token, verifier = tokens)
    verifier.verify(token)
    nil
  rescue Scute::InvalidToken => e
    e.reason
  end

  describe Scute::Tokens do
    it "verifies a session token with the app's keys" do
      session = tokens.verify(jwt)

      expect(session).to have_attributes(user_id: "user1", app_id: "app1", workspace_id: "ws1",
                                         expires_at: Time.at(now.to_i + 600), actor: nil)
      expect(session).not_to be_impersonated
      expect(session.authz_context).to eq({})
      expect(fake.paths("/v1/auth/app1/.well-known/jwks.json").size).to eq(1)
    end

    it "refuses what isn't a live session of this app" do
      expect(reason_for(nil)).to eq(:missing)
      expect(reason_for("nope")).to eq(:malformed)
      expect(reason_for(jwt(key: AuthSpecKeys::OTHER_KEY))).to eq(:signature)
      expect(reason_for(jwt(exp: now.to_i - 31))).to eq(:expired)
      expect(reason_for(jwt(exp: nil))).to eq(:malformed)
      expect(reason_for(jwt(aid: "app_other"))).to eq(:wrong_app)
      expect(reason_for(jwt(m2m: true))).to eq(:not_a_user)
      expect(reason_for(jwt(uuid: nil))).to eq(:not_a_user)
    end

    it "only takes RS256 (no alg none, no HMAC with the public key)" do
      claims = b64(JSON.generate(uuid: "user1", aid: "app1", exp: now.to_i + 600))
      none = "#{b64(JSON.generate(alg: 'none'))}.#{claims}."
      expect(reason_for(none)).to eq(:malformed).or eq(:algorithm)

      header = b64(JSON.generate(alg: "HS256"))
      hmac = OpenSSL::HMAC.digest("SHA256", AuthSpecKeys::KEY.public_key.to_pem, "#{header}.#{claims}")
      expect(reason_for("#{header}.#{claims}.#{b64(hmac)}")).to eq(:algorithm)
    end

    it "allows a little clock skew" do
      expect(reason_for(jwt(exp: now.to_i - 10))).to be_nil
    end

    it "doesn't re-read the keys more than once a minute for unknown signatures" do
      tokens.verify(jwt)
      3.times { expect(reason_for(jwt(key: AuthSpecKeys::OTHER_KEY, header: { alg: "RS256", kid: "k9" }))).to eq(:signature) }

      expect(fake.paths("/v1/auth/app1/.well-known/jwks.json").size).to eq(1)
    end

    it "re-reads keys after a rotation once the minute has passed" do
      t = now
      verifier = Scute::Tokens.new(client, clock: -> { t })
      verifier.verify(jwt)
      fake.signing_keys = [[AuthSpecKeys::OTHER_KEY, "k2"]]
      t = now + 61

      expect(verifier.verify(jwt(key: AuthSpecKeys::OTHER_KEY, exp: t.to_i + 600)).user_id).to eq("user1")
    end

    it "reads who is really acting in a session started as the user" do
      actor = { "kind" => "backend", "email" => "support@acme.test" }
      session = tokens.verify(jwt(imp: true, act: actor))

      expect(session).to be_impersonated
      expect(session.actor).to eq(actor)
      expect(session.authz_context).to eq("impersonated" => true, "actor" => actor)
    end

    it "asks Scute when remote: true, so a revoked session fails" do
      token = jwt
      expect(tokens.verify(token, remote: true).user_id).to eq("user1")

      fake.revoked << token
      expect { tokens.verify(token, remote: true) }.to raise_error(Scute::InvalidToken) { |e| expect(e.reason).to eq(:revoked) }
      expect(tokens.verify(token).user_id).to eq("user1") # locally it still verifies until it expires
    end

    it "learns the app's public id when configured with the internal id" do
      uuid_client = Scute::Client.new(app_id: "7f1c0000-0000-4000-8000-000000000001", secret: "sk_test",
                                      base_url: "https://scute.test", transport: fake)
      verifier = Scute::Tokens.new(uuid_client, clock: clock)

      expect(verifier.verify(jwt).app_id).to eq("app1")
      expect(verifier.public_app_id).to eq("app1")
    end
  end

  describe "users and sessions" do
    it "manages users with the secret key" do
      expect(client.users.list(page: 2)["query"]).to eq("page=2")
      expect(client.users.create("ada@example.com", meta: { plan: "pro" })["user"]).to include("identifier" => "ada@example.com")
      client.users.deactivate("user1")
      client.users.update("user1", user_meta: { plan: "team" })

      expect(fake.seen.map { |s| [s.verb, s.path] }).to include([:post, "/v1/app1/users/user1/deactivate"],
                                                                [:patch, "/v1/app1/users/user1"])
      expect(fake.seen.last.auth).to eq("Bearer sk_test")
    end

    def searches = fake.paths("/v1/app1/users").map { |s| URI.decode_www_form(s.query.to_s).to_h }

    it "finds a user by identifier exactly, through the loose user search" do
      expect(client.users.find_by_identifier(" ADA@example.com ")["id"]).to eq("user1") # on page 2 of the search
      expect(client.users.find_by_identifier("+1 (415) 555-0100")["id"]).to eq("user4")
      expect(client.users.find_by_identifier("14155550101")["id"]).to eq("user5")

      expect(searches.map { |q| q.values_at("q", "page", "limit") }).to eq(
        [%w[ada@example.com 1 100], %w[ada@example.com 2 100], %w[14155550100 1 100], %w[14155550101 1 100], %w[14155550101 2 100]]
      )
      expect(fake.seen.map(&:auth).uniq).to eq(["Bearer sk_test"])
    end

    it "finds nobody without making anyone" do
      expect(client.users.find_by_identifier("ada@example.co")).to be_nil # a near miss isn't a match
      expect(client.users.find_by_identifier("+1 415 555 0199")).to be_nil
      expect(searches.map { |q| q["page"] }).to eq(%w[1 2 3 1 2 3]) # every page, then stop

      expect(client.users.find_by_identifier("  ")).to be_nil
      expect(client.users.find_by_identifier("n/a")).to be_nil
      expect(client.users.find_by_identifier(nil)).to be_nil
      expect(fake.seen.size).to eq(6) # nothing to search for: no call
      expect(fake.seen.map(&:path)).to all(eq("/v1/app1/users"))
    end

    it "stops the search after a bounded number of pages" do
      fake.people = Array.new(40) { |n| { id: "u#{n}", email: "ada#{n}@example.com", phone: nil } }

      expect(client.users.find_by_identifier("ada@example.com")).to be_nil
      expect(fake.seen.size).to eq(Scute::Users::API::FIND_MAX_PAGES)
    end

    it "starts, lists and ends sessions as a user" do
      started = client.users.impersonate("user1", reason: "Ticket 4411", actor: { email: "support@acme.test" }, minutes: 15)

      expect(started).to include("access" => "imp.access", "session_id" => "ses1")
      expect(fake.seen.last.body).to eq("reason" => "Ticket 4411", "minutes" => 15, "actor" => { "email" => "support@acme.test" })
      expect(client.users.impersonations("user1")).to eq([{ "session_id" => "ses1" }])
      expect(client.users.stop_impersonating("user1", session_id: "ses1")).to eq("ended" => 1)
      expect(fake.seen.last.query).to eq("session_id=ses1")
    end

    it "uses the user's own tokens for their session" do
      client.sessions.current_user("tok")
      expect(fake.seen.last.headers).to include("X-Authorization" => "tok")
      expect(fake.seen.last.headers).not_to have_key("Authorization")

      expect(client.sessions.refresh("r1")["seen_refresh"]).to eq("r1")
      expect { client.sessions.sign_out("tok") }.not_to raise_error
      expect(fake.seen.last).to have_attributes(verb: :delete, path: "/v1/auth/app1/current_user")
      expect(client.sessions.list("user1")).to eq([{ "id" => "ses1" }])
      expect(fake.seen.last).to have_attributes(auth: "Bearer sk_test", path: "/v1/app1/users/user1/sessions")
      expect(fake.seen.last.headers).not_to have_key("X-Authorization") # the secret key alone
    end
  end

  describe Scute::Authentication do
    let(:controller_class) do
      Class.new do
        include Scute::Authentication
        include Scute::Authorization

        attr_reader :request

        def initialize(request, client)
          @request = request
          @scute_client = client
        end
      end
    end

    def request(headers: {}, cookies: {})
      Struct.new(:headers, :cookies).new(headers, cookies)
    end

    def controller(**) = controller_class.new(request(**), client).tap { |c| c.scute_client.instance_variable_set(:@tokens, tokens) }

    it "reads the token from X-Authorization, a bearer header, or the SDK cookie" do
      expect(controller(headers: { "X-Authorization" => jwt }).scute_user_id).to eq("user1")
      expect(controller(headers: { "Authorization" => "Bearer #{jwt}" }).scute_user_id).to eq("user1")
      expect(controller(cookies: { "sc-access-token__app1" => jwt }).scute_user_id).to eq("user1")
    end

    it "raises Unauthenticated with the reason" do
      expect { controller.scute_authenticate! }.to raise_error(Scute::Unauthenticated) { |e| expect(e.reason).to eq(:missing) }
      expired = controller(headers: { "X-Authorization" => jwt(exp: now.to_i - 100) })
      expect { expired.scute_authenticate! }.to raise_error(Scute::Unauthenticated) { |e| expect(e.reason).to eq(:expired) }
      expect(expired.scute_session).to be_nil
      expect(expired).not_to be_scute_signed_in
    end

    it "checks permissions as the signed-in user, telling Scute about impersonation" do
      c = controller(headers: { "X-Authorization" => jwt(imp: true, act: { "kind" => "backend", "email" => "s@acme.test" }) })
      c.scute_authenticate!

      c.scute_authorize!("read", "invoice:1", context: { "channel" => "web", "impersonated" => false })

      expect(fake.seen.last.body).to include(
        "user_id" => "user1",
        "context" => { "channel" => "web", "impersonated" => true, "actor" => { "kind" => "backend", "email" => "s@acme.test" } }
      )
    end

    it "leaves the context alone in a normal session" do
      c = controller(headers: { "X-Authorization" => jwt })
      c.scute_authorize!("read", "invoice:1", context: { "channel" => "web" })

      expect(fake.seen.last.body["context"]).to eq("channel" => "web")
    end
  end
end
