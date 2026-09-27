# frozen_string_literal: true

require "erb"

module Scute
  # Your backend's handle on Scute, with the app's secret key.
  #
  #   scute = Scute::Client.new # SCUTE_APP_ID, SCUTE_SECRET, SCUTE_BASE_URL
  #   scute.authz.check(user_id: user.id, action: "refund", resource: "invoice:42").allowed?
  class Client
    attr_reader :app_id, :http

    def initialize(app_id: ENV.fetch("SCUTE_APP_ID", nil), secret: ENV.fetch("SCUTE_SECRET", nil),
                   base_url: ENV.fetch("SCUTE_BASE_URL", nil), transport: nil, **http_options)
      raise ConfigurationError, "Scute needs an app id: pass app_id or set SCUTE_APP_ID" if app_id.to_s.empty?

      @app_id = app_id.to_s
      @secret = secret
      @http = HTTP.new(base_url: base_url || "https://api.scute.io", transport: transport, **http_options)
    end

    def secret?
      !@secret.to_s.empty?
    end

    def authz
      @authz ||= Authz::API.new(self)
    end

    def agents
      @agents ||= Agents::API.new(self)
    end

    # Verify the access tokens your users send (locally, with the app's
    # signing keys).
    def tokens
      @tokens ||= Tokens.new(self)
    end

    # Manage the app's users (secret key).
    def users
      @users ||= Users::API.new(self)
    end

    # A user's sessions: who they are from their token, refresh, sign out,
    # and (secret key) list and revoke.
    def sessions
      @sessions ||= Sessions::API.new(self)
    end

    # @api private: a call with the secret key.
    def request(method, path, body: nil, idempotent: method == :get)
      raise ConfigurationError, "This call needs the app's secret key: pass secret or set SCUTE_SECRET" unless secret?

      http.request(method, path, bearer: @secret, body: body, idempotent: idempotent)
    end

    # @api private: a call with the user's own session, or a public read.
    def user_request(method, path, access: nil, refresh: nil, body: nil)
      headers = { "X-Authorization" => access, "X-Refresh-Token" => refresh }.compact
      http.request(method, path, headers: headers, public: headers.empty?, body: body, idempotent: method == :get)
    end

    # @api private
    def apps_path(rest = "") = "/v1/apps/#{esc(app_id)}#{rest}"

    # @api private: the API-key user routes (/v1/:app_id/users...).
    def app_path(rest = "") = "/v1/#{esc(app_id)}#{rest}"

    # @api private
    def auth_path(rest = "") = "/v1/auth/#{esc(app_id)}#{rest}"

    # @api private
    def esc(value) = ERB::Util.url_encode(value.to_s)
  end
end
