# frozen_string_literal: true

module Scute
  # For controllers (Rails or any Rack app): who is signed in, from the
  # access token the browser or mobile app sends. Verified locally with the
  # app's keys.
  #
  #   class ApplicationController < ActionController::Base
  #     include Scute::Authentication
  #     before_action :scute_authenticate!
  #     rescue_from Scute::Unauthenticated, with: -> { head :unauthorized }
  #   end
  #
  # The token is read from Authorization: Bearer, X-Authorization, or the
  # cookie the Scute browser SDK sets. Override scute_access_token to read it
  # elsewhere. With Scute::Authorization included too, checks use the signed-in
  # user and pass the impersonation context for you.
  module Authentication
    # Raised by scute_authenticate! when there is no valid session. `reason`
    # is the InvalidToken reason (:missing, :expired, :signature, ...).
    class Unauthenticated < Scute::Error
      attr_reader :reason

      def initialize(message = "Sign in first", reason = :missing)
        super(message)
        @reason = reason
      end
    end

    # A before_action. remote: true also asks Scute that the session is
    # still live (one call per request).
    def scute_authenticate!(remote: false)
      token = scute_access_token
      @scute_session = scute_client.tokens.verify(token, remote: remote)
    rescue InvalidToken => e
      @scute_session = nil
      raise Unauthenticated.new(e.message, e.reason)
    end

    # The verified session, or nil. Verifies on first use when
    # scute_authenticate! didn't run.
    def scute_session
      return @scute_session if defined?(@scute_session)

      token = scute_access_token
      @scute_session = token ? scute_client.tokens.verify(token) : nil
    rescue InvalidToken
      @scute_session = nil
    end

    def scute_signed_in? = !scute_session.nil?

    # X-Authorization (what the Scute SDKs send), then Authorization: Bearer,
    # then the browser SDK's cookie.
    def scute_access_token
      scute_token = scute_header("X-Authorization").to_s.strip
      return scute_token unless scute_token.empty?

      scute_header("Authorization").to_s[/\ABearer\s+(\S+)\z/i, 1] || scute_cookie_token
    end

    def scute_user_id
      scute_session&.user_id
    end

    def scute_client
      @scute_client ||= Client.new
    end

    private

    def scute_header(name)
      if request.respond_to?(:headers)
        request.headers[name]
      else
        request.get_header("HTTP_#{name.upcase.tr('-', '_')}")
      end
    end

    # The browser SDK's cookie: sc-access-token__<app id>.
    def scute_cookie_token
      cookies = request.respond_to?(:cookies) ? request.cookies : {}
      ids = [scute_client.app_id]
      ids << scute_client.tokens.public_app_id if cookies.keys.any? { |k| k.to_s.start_with?("sc-access-token__") }
      ids.uniq.map { |id| cookies["sc-access-token__#{id}"] }.find { |v| !v.to_s.empty? }
    end
  end

  Unauthenticated = Authentication::Unauthenticated
end
