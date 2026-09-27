# frozen_string_literal: true

module Scute
  class Harness
    # A tool call as guards see it, with helpers to answer.
    class Call
      attr_reader :run, :id, :tool, :spec, :messages
      # args: symbol keys, after any earlier guard's transform. mode: of the guard looking at it now.
      attr_accessor :args, :mode

      def initialize(run:, id:, tool:, args:, spec:, messages: [], approved_by_user: false)
        @run = run
        @id = id
        @tool = tool.to_s
        @args = Harness.symbolize(args)
        @spec = spec
        @messages = messages || []
        @approved_by_user = approved_by_user
        @mode = :enforce
      end

      # The person confirmed this exact call.
      def approved_by_user? = @approved_by_user
      def permission = spec.permission
      def tier = spec.tier
      def resource = spec.resource(args)

      def proceed = Decision.new(kind: :proceed)
      def deny(message, reason = "denied") = Decision.new(kind: :deny, message: message, reason: reason)
      def guide(message, reason = "guided") = Decision.new(kind: :guide, message: message, reason: reason)

      def verify(message = nil, **options)
        Decision.new(kind: :verify, reason: "verification_required", message: message, verify: { permission: permission }.merge(options).compact)
      end

      def approve(message = nil)
        Decision.new(kind: :approve, reason: "confirmation_required", message: message, approve: { by: :user })
      end

      # args: the full argument hash to run with.
      def transform(args, message = nil) = Decision.new(kind: :transform, args: Harness.symbolize(args), message: message)
      def redirect(to, message = nil) = Decision.new(kind: :redirect, redirect: { to: to }, message: message)
    end
  end
end
