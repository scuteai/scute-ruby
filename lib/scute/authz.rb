# frozen_string_literal: true

module Scute
  module Authz
    # An answer from Scute's engine. `allowed?` is true only for a plain
    # allow: a step-up or approval answer isn't allowed yet.
    Decision = Data.define(:decision, :reason, :permission, :roles, :path, :conditions,
                           :step_up, :approval, :agent, :explanation) do
      def self.from_api(hash)
        h = hash || {}
        new(decision: h["decision"], reason: h["reason"], permission: h["permission"], roles: h["roles"] || [],
            path: h["path"], conditions: h["conditions"], step_up: h["step_up"], approval: h["approval"],
            agent: h["agent"], explanation: h["explanation"])
      end

      def allowed? = decision == "allow"
      def denied? = decision == "deny"
      def step_up? = decision == "allow_with_step_up"
      def needs_approval? = decision == "allow_with_approval"
    end

    # Authorization for your app's users, from your backend.
    class API
      BATCH_LIMIT = 100

      def initialize(client)
        @client = client
      end

      # May this user do this? Pass `challenge` (a completed step-up's token)
      # for allow_with_step_up and `approval` (an approved request's id) for
      # allow_with_approval; an approval is spent by the allow it produces.
      def check(user_id:, action:, resource: nil, context: nil, challenge: nil, approval: nil)
        body = { user_id: user_id, action: action, resource: resource, context: context,
                 challenge: challenge, approval: approval }.compact
        Decision.from_api(@client.request(:post, @client.auth_path("/authz/check"), body: body, idempotent: true))
      end

      # Up to 100 checks (for any users) in one call.
      def check_batch(checks)
        raise ArgumentError, "Send at most #{BATCH_LIMIT} checks" if checks.size > BATCH_LIMIT

        data = @client.request(:post, @client.auth_path("/authz/check-batch"),
                               body: { checks: checks.map { |c| c.to_h.compact } }, idempotent: true)
        Array(data["results"]).map { |r| Decision.from_api(r) }
      end

      # Roles and permissions a user holds, app-wide or on one object ("document:42").
      def permissions(user_id, resource: nil)
        query = resource ? "?resource=#{@client.esc(resource)}" : ""
        @client.request(:get, @client.auth_path("/authz/users/#{@client.esc(user_id)}/permissions#{query}"))
      end

      # Who may do this (paged).
      def authorized_users(action:, resource: nil, limit: nil, offset: nil)
        query = URI.encode_www_form({ action: action, resource: resource, limit: limit, offset: offset }.compact)
        @client.request(:get, @client.auth_path("/authz/authorized-users?#{query}"))
      end

      # A data filter for lists: "all", "none" or a condition over your own fields.
      def filter(user_id:, action:, resource_type:, context: nil)
        body = { user_id: user_id, action: action, resource_type: resource_type, context: context }.compact
        @client.request(:post, @client.auth_path("/authz/filter"), body: body, idempotent: true)
      end

      # Start the verification a step-up asks for, bound to the permission.
      # Check again with `challenge:` once the user completed it.
      def start_step_up(user_id:, decision: nil, permission: nil, method: nil)
        step_up = decision&.step_up || {}
        permission ||= step_up["authorizes_action"] || decision&.permission
        asked = step_up["method"]
        method ||= asked unless asked == "any"
        raise ArgumentError, "start_step_up needs a permission (or decision) and a method" unless permission && method

        body = { purpose: "step_up", method: method, app_user_id: user_id, metadata: { authorizes_action: permission } }
        @client.request(:post, @client.auth_path("/challenges"), body: body)["challenge"]
      end

      # The policy as a signed snapshot (RS256 JWS; keys at /v1/auth/:app_id/jwks).
      def snapshot
        @client.request(:get, @client.apps_path("/authz/snapshot"))
      end

      # Access requests: list (optionally by status or user).
      def requests(status: nil, user_id: nil)
        query = URI.encode_www_form({ status: status, user_id: user_id }.compact)
        data = @client.request(:get, @client.apps_path("/authz/requests#{"?#{query}" unless query.empty?}"))
        Array(data["requests"])
      end

      # File a request for a user: `role:` (optionally on `resource:`, for `duration:` seconds)
      # or `action:` (approval for one operation on `resource:`).
      def create_request(user_id, role: nil, action: nil, resource: nil, duration: nil, reason: nil)
        body = { user_id: user_id, role: role, action: action, resource: resource, duration: duration, reason: reason }.compact
        @client.request(:post, @client.apps_path("/authz/requests"), body: body)
      end

      # Approve or deny. Pass reviewer_id when a user decides through your UI.
      def decide_request(id, verdict, reviewer_id: nil, note: nil)
        raise ArgumentError, "verdict is :approve or :deny" unless %i[approve deny].include?(verdict.to_sym)

        @client.request(:post, @client.apps_path("/authz/requests/#{@client.esc(id)}/#{verdict}"),
                        body: { reviewer_id: reviewer_id, note: note }.compact)
      end
    end
  end
end
