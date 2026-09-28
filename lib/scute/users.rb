# frozen_string_literal: true

require "uri"

module Scute
  module Users
    # The app's users, from your backend (secret key). Answers are the API's
    # JSON as hashes.
    #
    #   scute.users.create("ada@example.com", meta: { plan: "pro" })
    #   scute.users.impersonate(user_id, reason: "Ticket 4411", actor: { email: "support@acme.com" })
    class API
      def initialize(client)
        @client = client
      end

      # page, per_page, and the API's filters (status, search, ...).
      def list(**params)
        query = params.empty? ? "" : "?#{URI.encode_www_form(params.compact)}"
        @client.request(:get, @client.app_path("/users#{query}"))
      end

      def get(id) = @client.request(:get, @client.app_path("/users/#{@client.esc(id)}"))

      FIND_PAGE_SIZE = 100
      FIND_MAX_PAGES = 10

      # The app's user with this email (any case) or phone number (compared as
      # digits, so include the country code), as users.get shows it; nil when
      # nobody by that identifier uses the app. Never creates a user.
      #
      # Searches the app's users with the secret key (list with q:, a loose
      # search over email, phone and name) and keeps only an exact match,
      # looking at up to FIND_MAX_PAGES pages of FIND_PAGE_SIZE.
      def find_by_identifier(identifier)
        query, same = exact_match(identifier.to_s.strip)
        return nil if query.empty?

        (1..FIND_MAX_PAGES).each do |page|
          data = list(q: query, limit: FIND_PAGE_SIZE, page: page) || {}
          found = Array(data["users"]).find(&same)
          return found if found
          break unless data["next_page"]
        end
        nil
      end

      def create(identifier, meta: nil)
        @client.request(:post, @client.auth_path("/users"), body: { identifier: identifier, user_meta: meta }.compact)
      end

      # Sends an invitation (magic link) as well.
      def invite(identifier, meta: nil)
        @client.request(:post, @client.app_path("/users/invite"), body: { identifier: identifier, user_meta: meta }.compact)
      end

      def update(id, **attributes)
        @client.request(:patch, @client.app_path("/users/#{@client.esc(id)}"), body: attributes, idempotent: true)
      end

      def activate(id) = @client.request(:post, @client.app_path("/users/#{@client.esc(id)}/activate"))
      def deactivate(id) = @client.request(:post, @client.app_path("/users/#{@client.esc(id)}/deactivate"))
      def delete(id) = @client.request(:delete, @client.app_path("/users/#{@client.esc(id)}"))

      # ── Signing in as a user (support access) ──
      # Off until the app turns it on (authz settings: impersonation). The
      # session is short, never refreshed, and its token names who is really
      # acting (Session#actor).

      # One of: actor_user_id (an app user holding user:impersonate; pass
      # challenge / approval when that permission asks for them), or actor:
      # the person, named by your backend ({ email:, name:, id: }).
      # Returns the access token as the user, the session id, and the details.
      def impersonate(id, reason:, minutes: nil, actor_user_id: nil, actor: nil, challenge: nil, approval: nil)
        body = { reason: reason, minutes: minutes, actor_user_id: actor_user_id, actor: actor,
                 challenge: challenge, approval: approval }.compact
        @client.request(:post, @client.apps_path("/users/#{@client.esc(id)}/impersonate"), body: body)
      end

      # Sessions as this user that haven't ended.
      def impersonations(id)
        @client.request(:get, @client.apps_path("/users/#{@client.esc(id)}/impersonations"))["impersonations"]
      end

      # End them: one (session_id) or all.
      def stop_impersonating(id, session_id: nil)
        query = session_id ? "?session_id=#{@client.esc(session_id)}" : ""
        @client.request(:delete, @client.apps_path("/users/#{@client.esc(id)}/impersonate#{query}"))
      end

      private

      # [what to search for, whether a listed user is exactly that one]
      def exact_match(wanted)
        if wanted.include?("@")
          email = wanted.downcase
          [email, ->(user) { user["email"].to_s.strip.downcase == email }]
        else
          digits = wanted.delete("^0-9")
          [digits, ->(user) { user["phone"].to_s.delete("^0-9") == digits }]
        end
      end
    end
  end
end
