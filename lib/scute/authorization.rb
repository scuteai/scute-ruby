# frozen_string_literal: true

module Scute
  # For controllers (Rails or anything else): include it and define
  # scute_user_id, the Scute app user id of the signed-in person.
  #
  #   class InvoicesController < ApplicationController
  #     include Scute::Authorization
  #     rescue_from Scute::Forbidden, with: :forbidden
  #
  #     def refund
  #       scute_authorize!("refund", "invoice:#{params[:id]}", challenge: params[:challenge])
  #       ...
  #     end
  #   end
  module Authorization
    # Raised by scute_authorize! when the answer isn't a plain allow. The
    # decision says why: step_up? (verify first), needs_approval?, or denied?.
    class Forbidden < Scute::Error
      attr_reader :decision

      def initialize(decision)
        @decision = decision
        super(decision.explanation || "Not allowed (#{decision.reason})")
      end
    end

    # Raises Scute::Unauthenticated, before any call to Scute, when nobody is
    # signed in (scute_user_id is nil): a check never runs without a user.
    def scute_authorize!(action, resource = nil, context: nil, challenge: nil, approval: nil)
      user_id = scute_user_id
      raise Unauthenticated.new("Sign in first", :missing) if user_id.nil?

      decision = scute_client.authz.check(user_id: user_id, action: action, resource: resource,
                                          context: scute_authz_context(context), challenge: challenge, approval: approval)
      raise Forbidden, decision unless decision.allowed?

      decision
    end

    # False, without a call to Scute, when nobody is signed in.
    def scute_can?(action, resource = nil, context: nil)
      user_id = scute_user_id
      return false if user_id.nil?

      scute_client.authz.check(user_id: user_id, action: action, resource: resource,
                               context: scute_authz_context(context)).allowed?
    end

    # A client for this request that passes the person's IP address
    # (scute_client_ip) on calls made with the secret key.
    def scute_client
      @scute_client ||= Client.new(client_ip: scute_client_ip)
    end

    # The person's IP address: request.remote_ip in Rails (honors
    # config.action_dispatch.trusted_proxies), Rack::Request#ip otherwise.
    def scute_client_ip
      ClientIP.from_request(respond_to?(:request) ? request : nil)
    end

    # With Scute::Authentication, the signed-in user (nil when signed out,
    # same as Authentication#scute_user_id); otherwise define it.
    def scute_user_id
      return scute_session&.user_id if respond_to?(:scute_session)

      raise NotImplementedError, "Define scute_user_id (the Scute app user id of the signed-in person), " \
                                 "or include Scute::Authentication"
    end

    private

    # In a session someone started as the user, the check is told so (it
    # wins over what the caller passes).
    def scute_authz_context(context)
      session = respond_to?(:scute_session) ? scute_session : nil
      extra = session ? session.authz_context : {}
      return context if extra.empty?

      (context || {}).to_h.transform_keys(&:to_s).merge(extra)
    end
  end

  Forbidden = Authorization::Forbidden
end
