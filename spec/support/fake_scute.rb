# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "time"

# A small stand-in for the Scute API endpoints the SDK calls, as a transport.
class FakeScute
  Seen = Data.define(:verb, :path, :body, :auth, :headers, :query)

  attr_reader :seen
  attr_accessor :request_status, :ttl, :ceiling, :decide, :down, :verification_status, :signing_keys, :revoked

  def initialize(decide: nil, ceiling: %w[invoice:read invoice:refund], request_status: "pending", ttl: 1800)
    @decide = decide
    @ceiling = ceiling
    @request_status = request_status
    @ttl = ttl
    @seen = []
    @tasks = 0
    @verification_status = "pending"
    @signing_keys = []
    @revoked = []
  end

  def paths(path) = seen.select { |s| s.path == path }

  def call(method, url, headers, body)
    raise Errno::ECONNREFUSED, "fake" if down

    path = URI(url).path
    query = URI(url).query
    parsed = body ? JSON.parse(body) : nil
    auth = headers["Authorization"]
    seen << Seen.new(verb: method, path: path, body: parsed, auth: auth, headers: headers, query: query)
    route(method, path, query, parsed, auth, headers)
  end

  private

  def json(data, status = 200) = [status, JSON.generate(data)]

  def jwk(key, kid)
    { kty: "RSA", kid: kid, use: "sig", alg: "RS256",
      n: Base64.urlsafe_encode64(key.n.to_s(2), padding: false), e: Base64.urlsafe_encode64(key.e.to_s(2), padding: false) }
  end

  def route(method, path, query, body, auth, headers = {})
    secret = auth == "Bearer sk_test"
    task = auth.to_s.start_with?("Bearer sct_")
    session = headers["X-Authorization"]

    case [method, path]
    in [:get, "/v1/auth/app1/.well-known/jwks.json" | "/v1/auth/7f1c0000-0000-4000-8000-000000000001/.well-known/jwks.json"]
      json({ keys: signing_keys.map { |key, kid| jwk(key, kid) } })
    in [:get, "/v1/apps/7f1c0000-0000-4000-8000-000000000001" | "/v1/apps/app1"]
      json({ id: "app1", name: "Test" })
    in [:get, "/v1/auth/app1/current_user"]
      return json({ error: "Not authorized" }, 401) if session.nil? || revoked.include?(session)

      json({ user: { id: "user1" } })
    in [:delete, "/v1/auth/app1/current_user"]
      json({ message: "ok" })
    in [:post, "/v1/auth/app1/tokens/refresh"]
      json({ access: "new.access", refresh: "new.refresh", seen_refresh: headers["X-Refresh-Token"] })
    in [:get, "/v1/app1/users"]
      json({ users: [{ id: "user1" }], query: query })
    in [:get, "/v1/auth/app1/users"]
      json({ user: query.to_s.include?("ada") ? { id: "user1" } : nil })
    in [:post, "/v1/auth/app1/users"]
      json({ user: { id: "user2", identifier: body["identifier"] } }, 201)
    in [:post, %r{\A/v1/app1/users/[^/]+/(activate|deactivate)\z}] | [:patch, %r{\A/v1/app1/users/}] | [:delete, %r{\A/v1/app1/users/}]
      return json({ error: "Unauthorized" }, 401) unless secret

      json({ ok: true })
    in [:post, "/v1/apps/app1/users/user1/impersonate"]
      return json({ error: "Unauthorized" }, 401) unless secret

      json({ access: "imp.access", session_id: "ses1", impersonation: { reason: body["reason"] } }, 201)
    in [:get, "/v1/apps/app1/users/user1/impersonations"]
      json({ impersonations: [{ session_id: "ses1" }] })
    in [:delete, "/v1/apps/app1/users/user1/impersonate"]
      json({ ended: 1 })
    in [:get, "/v1/app1/users/user1/sessions"]
      json([{ id: "ses1" }])
    in [:post, "/v1/apps/app1/authz/agents/support-bot/tasks"]
      return json({ error: "Unauthorized" }, 401) unless secret

      @tasks += 1
      json({ id: "task#{@tasks}", token: "sct_token#{@tasks}", agent: "support-bot", status: "active",
             acts_for: body["acts_for"], expires_at: (Time.now + ttl).iso8601, chain: ["support-bot"] }, 201)
    in [:post, %r{/tasks/[^/]+/(complete|revoke)\z}]
      json({ status: "done" })
    in [:get, "/v1/apps/app1/authz/agents/support-bot/tasks"]
      json({ tasks: [{ id: "task1", query: query }] })
    in [:get, "/v1/auth/app1/agent/whoami"]
      return json({ error: "Task token missing" }, 401) unless task

      json({ agent: "support-bot", task: "task1", acts_for: "user1", permissions: [], ceiling: ceiling })
    in [:post, "/v1/auth/app1/agent/check"]
      return json({ error: "Task token missing" }, 401) unless task

      d = decide&.call(body, seen) || { decision: "allow" }
      decision = d[:decision] || "allow"
      json({ allowed: decision == "allow", reason: decision == "allow" ? "role_grant" : "no" }.merge(d))
    in [:post, "/v1/auth/app1/agent/sessions"]
      json({ id: "sess1", task_id: "task1", verified: false }, 201)
    in [:post, "/v1/auth/app1/agent/sessions/sess1/verified"]
      return json({ id: "sess1", verified: true }) if body["challenge"] == "ch_ok"

      json({ error: "That challenge doesn't verify this person", error_code: "challenge_invalid" }, 422)
    in [:post, "/v1/auth/app1/agent/sessions/sess1/end"]
      json({ id: "sess1" })
    in [:post, "/v1/auth/app1/agent/verifications"]
      return json({ error: "Task token missing" }, 401) unless task

      json({ token: "ch_ok", status: "pending", method: body["method"], say: "I've emailed a code to a***@example.com. What's the code?" }, 201)
    in [:get, "/v1/auth/app1/agent/verifications/ch_ok"]
      json({ token: "ch_ok", status: verification_status,
             say: verification_status == "completed" ? "Thanks, you're verified." : "Approve it, then tell me." })
    in [:post, "/v1/auth/app1/agent/verifications/ch_ok/code"]
      if body["code"] == "123456"
        self.verification_status = "completed"
        return json({ token: "ch_ok", status: "completed", say: "Thanks, you're verified." })
      end

      json({ token: "ch_ok", status: "pending", remaining_attempts: 2, error: "Invalid code", say: "That code didn't work. Want to try again?" }, 422)
    in [:post, "/v1/auth/app1/agent/approvals"]
      return json({ error: "Task token missing" }, 401) unless task

      json({ id: "req1", status: request_status, say: "I've asked for approval. I'll let you know when there's an answer." }, 201)
    in [:get, "/v1/auth/app1/agent/approvals/req1"]
      json({ id: "req1", status: request_status, say: request_status == "approved" ? "It's approved." : "Still waiting." })
    in [:post, "/v1/auth/app1/challenges"]
      return json({ error: "Unauthorized" }, 401) unless secret

      json({ challenge: { token: "ch_ok", status: "pending", method: body["method"] } }, 201)
    in [:post, "/v1/apps/app1/authz/requests"]
      json({ id: "req1", status: request_status }, 201)
    in [:post, "/v1/auth/app1/authz/check"]
      json({ decision: "allow", allowed: true, reason: "role_grant", permission: "invoice:read", roles: ["clerk"] })
    in [:post, "/v1/auth/app1/authz/check-batch"]
      json({ results: body["checks"].map { |c| { decision: c["action"] == "read" ? "allow" : "deny", reason: "x" } } })
    in [:get, %r{\A/v1/auth/app1/authz/users/[^/]+/permissions\z}]
      json({ user_id: "user1", permissions: ["invoice:read"], query: query })
    in [:post, "/v1/apps/app1/authz/requests/req1/approve"]
      json({ id: "req1", status: "approved" })
    else
      json({ error: "no route #{method} #{path}" }, 404)
    end
  end
end

module ScuteHelpers
  def harness(fake = FakeScute.new, **)
    Scute::Harness.new(agent: "support-bot", app_id: "app1", secret: "sk_test", base_url: "https://scute.test",
                       transport: fake, **)
  end
end
