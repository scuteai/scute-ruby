# frozen_string_literal: true

module Scute
  module Sessions
    # A user's sessions. With the user's own tokens: who they are, refresh,
    # sign out. With the secret key: list and revoke.
    class API
      def initialize(client)
        @client = client
      end

      # The signed-in user (and, in a session someone started as them,
      # "impersonation": who and why). Asks Scute, so a revoked session fails.
      def current_user(access_token)
        @client.user_request(:get, @client.auth_path("/current_user"), access: access_token)
      end

      # New access (and refresh) tokens for a refresh token.
      def refresh(refresh_token)
        @client.user_request(:post, @client.auth_path("/tokens/refresh"), refresh: refresh_token)
      end

      # Ends this session (the other sessions stay).
      def sign_out(access_token)
        @client.user_request(:delete, @client.auth_path("/current_user"), access: access_token)
      end

      def list(user_id) = @client.request(:get, @client.app_path("/users/#{@client.esc(user_id)}/sessions"))

      def revoke(user_id, session_id)
        @client.request(:delete, @client.app_path("/users/#{@client.esc(user_id)}/sessions/#{@client.esc(session_id)}"))
      end
    end
  end
end
