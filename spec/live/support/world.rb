# frozen_string_literal: true

require "monitor"
require "securerandom"

module ScuteLive
  # What one run makes: made on first use, shared by the spec files, and
  # removed at the end (after(:suite)), even when examples fail. Names start
  # with live-<run id>; test identities get the code 424242 and are sent nothing.
  class World
    CODE = "424242"

    # The suite's policy, imported at the start (the app's own policy is put
    # back at the end).
    POLICY = {
      "scute_policy" => 1,
      "resources" => {
        "invoice" => { "name" => "Invoice", "actions" => %w[read refund void] },
        "account" => { "name" => "Account", "actions" => %w[read delete] },
        "document" => { "name" => "Document", "actions" => %w[read] }
      },
      "permissions" => {
        "invoice:read" => { "autonomous_allowed" => true },
        "invoice:refund" => { "requires_verification" => true, "verification_method" => "email_otp" },
        "invoice:void" => { "requires_approval" => true },
        "account:delete" => { "blocked_while_impersonating" => true }
      },
      "roles" => {
        "viewer" => { "name" => "Viewer", "permissions" => %w[invoice:read account:read] },
        "billing" => { "name" => "Billing", "permissions" => %w[invoice:read invoice:refund invoice:void account:read account:delete] },
        "doc_owner" => { "name" => "Document owner",
                         "permissions" => [{ "permission" => "document:read",
                                             "when" => { "eq" => [{ "var" => "resource.owner" }, { "var" => "user.id" }] } }] },
        "support_agent" => { "name" => "Support agent", "permissions" => %w[invoice:read invoice:refund invoice:void] }
      }
    }.freeze

    # Log every allow while the suite runs (the decision log spec reads them back).
    AUTHZ_SETTINGS = { "impersonation" => true, "log_allow_rate" => 1 }.freeze

    attr_reader :config, :run_id, :api, :client

    def initialize(config)
      @config = config
      @run_id = ENV.fetch("SCUTE_LIVE_RUN_ID", "")[/\A[a-z0-9]{1,12}\z/] || SecureRandom.hex(3)
      @api = Api.new(config)
      @client = Scute::Client.new(app_id: config.app_id, secret: config.secret, base_url: config.base_url, read_timeout: 30)
      @count = 0
      @memo = {}
      @users = []
      @cleanup = []
      @lock = Monitor.new
    end

    def prefix = "live-#{run_id}"
    def apps(rest = "") = "/v1/apps/#{config.app_id}#{rest}"
    def auth(rest = "") = "/v1/auth/#{config.app_id}#{rest}"

    # live-ruby-<run id>-<n>+scute_test@example.com
    def next_email = @lock.synchronize { "live-ruby-#{run_id}-#{@count += 1}+scute_test@example.com" }

    # +1 312 555 01xx, the suite's fiction range.
    def phone = "+1312555#{format('%04d', 100 + (run_id.to_i(36) % 100))}"

    # Cleanup

    def on_cleanup(label, &block)
      @lock.synchronize { @cleanup << [label, block] }
    end

    # Undoes everything, newest first; answers what couldn't be undone.
    def cleanup!
      jobs = @lock.synchronize { @cleanup.reverse.tap { @cleanup.clear } }
      jobs.filter_map do |label, block|
        block.call
        nil
      rescue StandardError => e
        "#{label}: #{e.class}: #{e.message}"
      end
    end

    # The app's policy and settings

    # scute-ruby has no policy methods: POST /v1/apps/:app_id/authz/policy/import.
    def policy!
      memo(:policy) do
        before = api.get!(apps("/authz/policy/document"))
        plan = api.post!(apps("/authz/policy/import"), body: { document: POLICY, dry_run: true, prune: true })
        applied = api.post!(apps("/authz/policy/import"), body: { document: POLICY, dry_run: false, prune: true })
        on_cleanup("policy") { api.post!(apps("/authz/policy/import"), body: { document: before, dry_run: false, prune: true }) }
        { plan: plan, applied: applied }
      end
    end

    # scute-ruby has no settings method: PATCH /v1/apps/:app_id/authz/settings.
    def authz_settings!
      memo(:authz_settings) do
        before = api.get!(apps("/authz/settings"))
        on_cleanup("authz settings") { api.patch!(apps("/authz/settings"), body: before.slice(*AUTHZ_SETTINGS.keys)) }
        api.patch!(apps("/authz/settings"), body: AUTHZ_SETTINGS)
      end
    end

    # Users

    # An app user made with scute-ruby (users.create), with roles; deleted at the end.
    def user(name, roles: [])
      memo([:user, name]) do
        address = next_email
        created = client.users.create(address)["user"]
        track_user(created["id"])
        roles.each { |role| grant(created["id"], role) }
        { "id" => created["id"], "email" => address }
      end
    end

    def track_user(id)
      @lock.synchronize do
        next if id.nil? || @users.include?(id)

        @users << id
        on_cleanup("user #{id}") { delete_user(id) }
      end
    end

    def delete_user(id)
      client.users.delete(id)
    rescue Scute::APIError => e
      raise unless e.status == 404
    end

    # scute-ruby has no role assignment: POST /v1/apps/:app_id/authz/users/:id/roles.
    def grant(user_id, role)
      policy!
      api.post!(apps("/authz/users/#{user_id}/roles"), body: { role: role })
      track_grant(user_id, role)
    end

    # A role someone holds now (granted here, or by an approved request).
    def track_grant(user_id, role)
      on_cleanup("role #{role}") { revoke(user_id, role, missing_ok: true) }
    end

    # DELETE /v1/apps/:app_id/authz/users/:id/roles/:role
    def revoke(user_id, role, missing_ok: false)
      res = api.delete(apps("/authz/users/#{user_id}/roles/#{role}"))
      return res if res.ok? || (missing_ok && [404, 422].include?(res.status))

      raise Api::Failure, "DELETE role #{role} answered #{res.status}"
    end

    # Signing in (the end user's side)

    # What a browser or app does (scute-ruby is for servers): POST
    # /v1/auth/:app_id/otps/login, then /otps/verify with the test code.
    # Answers the session tokens, or the MFA challenge when one is needed.
    def sign_in(identifier, code: CODE)
      sent = api.post!(auth("/otps/login"), body: { identifier: identifier }, as: :public)
      Redactor.remember(sent["user_id"])
      answer = api.post!(auth("/otps/verify"), body: { user_id: sent["user_id"], otp: code }, as: :public)
      track_user(answer["user_id"] || answer["app_user_id"])
      answer
    end

    # The signed-in user most specs share (email OTP), holding billing.
    def member
      memo(:member) do
        address = next_email
        tokens = sign_in(address)
        grant(tokens["user_id"], "billing")
        { "id" => tokens["user_id"], "email" => address, "tokens" => tokens }
      end
    end

    # Agents

    # An agent registered with scute-ruby (agents.create); deleted at the end.
    def agent(name, roles: ["support_agent"])
      memo([:agent, name]) do
        policy!
        slug = "#{prefix}-#{name}"
        created = client.agents.create(slug: slug, owner_user_id: nil, name: "Live #{name} #{run_id}", roles: roles)
        on_cleanup("agent #{slug}") { delete_agent(slug) }
        created
      end
    end

    def delete_agent(slug)
      client.agents.delete(slug)
    rescue Scute::APIError => e
      raise unless e.status == 404
    end

    def harness(slug, **) = Scute::Harness.new(agent: slug, client: client, **)

    # scute-ruby has no property methods: POST /v1/apps/:app_id/properties.
    def property(name, **attributes)
      created = api.post!(apps("/properties"), body: { name: name, **attributes })
      on_cleanup("property #{name}") do
        res = api.delete(apps("/properties/#{name}"))
        raise Api::Failure, "DELETE property answered #{res.status}" unless res.ok? || res.status == 404
      end
      created
    end

    # Waiting

    # Polls until the block answers something truthy (rows written by a job).
    def eventually(what, timeout: 45, every: 1.5)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      loop do
        found = yield
        return found if found
        raise "Timed out after #{timeout}s waiting for #{what}" if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

        sleep every
      end
    end

    private

    def memo(key)
      @lock.synchronize do
        return @memo[key] if @memo.key?(key)

        @memo[key] = yield
      end
    end
  end
end
