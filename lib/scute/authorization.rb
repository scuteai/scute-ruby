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

    def scute_authorize!(action, resource = nil, context: nil, challenge: nil, approval: nil)
      decision = scute_client.authz.check(user_id: scute_user_id, action: action, resource: resource,
                                          context: scute_authz_context(context), challenge: challenge, approval: approval)
      raise Forbidden, decision unless decision.allowed?

      decision
    end

    def scute_can?(action, resource = nil, context: nil)
      scute_client.authz.check(user_id: scute_user_id, action: action, resource: resource,
                               context: scute_authz_context(context)).allowed?
    end

    def scute_client
      @scute_client ||= Client.new
    end

    # With Scute::Authentication, the signed-in user; otherwise define it.
    def scute_user_id
      session = respond_to?(:scute_session) ? scute_session : nil
      return session.user_id if session

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
