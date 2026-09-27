# frozen_string_literal: true

require "json"
require "time"

# A small stand-in for the Scute API endpoints the SDK calls, as a transport.
class FakeScute
  Seen = Data.define(:verb, :path, :body, :auth)

  attr_reader :seen
  attr_accessor :request_status, :ttl, :ceiling, :decide, :down

  def initialize(decide: nil, ceiling: %w[invoice:read invoice:refund], request_status: "pending", ttl: 1800)
    @decide = decide
    @ceiling = ceiling
    @request_status = request_status
    @ttl = ttl
    @seen = []
    @tasks = 0
  end

  def paths(path) = seen.select { |s| s.path == path }

  def call(method, url, headers, body)
    raise Errno::ECONNREFUSED, "fake" if down

    path = URI(url).path
    query = URI(url).query
    parsed = body ? JSON.parse(body) : nil
    auth = headers["Authorization"]
    seen << Seen.new(verb: method, path: path, body: parsed, auth: auth)
    route(method, path, query, parsed, auth)
  end

  private

  def json(data, status = 200) = [status, JSON.generate(data)]

  def route(method, path, query, body, auth)
    secret = auth == "Bearer sk_test"
    task = auth.to_s.start_with?("Bearer sct_")

    case [method, path]
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
