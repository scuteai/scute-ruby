# frozen_string_literal: true

module Scute
  class Harness
    # What a guard wants done with a tool call, least to most strict. Verify
    # ranks above approve: an approver should see a request from a verified person.
    RANK = { proceed: 0, transform: 1, approve: 2, verify: 3, guide: 4, redirect: 5, deny: 6 }.freeze

    class Decision
      attr_accessor :kind, :reason, :message, :say, :args, :verify, :approve, :redirect, :engine, :guard
      attr_reader :result

      # result: from an after-guard, what the model sees instead of the tool's result.
      # say: a line for the person (voice or chat), when there's something to tell them.
      def initialize(kind:, reason: nil, message: nil, say: nil, args: nil, verify: nil, approve: nil, redirect: nil, engine: nil, **rest)
        raise ArgumentError, "unknown decision #{kind.inspect}" unless RANK.key?(kind)
        raise ArgumentError, "unknown keywords: #{(rest.keys - [:result]).join(', ')}" unless (rest.keys - [:result]).empty?

        @kind = kind
        @reason = reason
        @message = message
        @say = say
        @args = args
        @verify = verify
        @approve = approve
        @redirect = redirect
        @engine = engine
        @replaces_result = rest.key?(:result)
        @result = rest[:result]
      end

      def replaces_result? = @replaces_result
      def rank = RANK.fetch(kind)

      def to_h
        { kind: kind, reason: reason, message: message, args: args, verify: verify, approve: approve,
          redirect: redirect, guard: guard }.compact
      end
    end

    PROCEED = Decision.new(kind: :proceed).freeze

    GuardResult = Data.define(:guard, :mode, :decision, :error)

    # The harness's answer for one call: the strictest enforced decision and every guard's opinion.
    Verdict = Struct.new(:kind, :decision, :args, :message, :say, :results, :call_id, :tool, keyword_init: true) do
      def runs? = %i[proceed transform].include?(kind)
    end

    module Messages
      module_function

      def describe_call(tool, args)
        parts = args.select { |_, v| v.is_a?(String) || v.is_a?(Numeric) || v == true || v == false }
                    .first(4).map { |k, v| "#{k} #{v.to_s[0, 60]}" }
        parts.empty? ? tool.to_s : "#{tool} (#{parts.join(', ')})"
      end

      # What the model reads when a call doesn't run: what to do next, not only that it failed.
      def for_model(kind, decision, human_tools: false)
        said = (decision.message || decision.engine&.explanation).to_s.strip
        case kind
        when :deny then "Not allowed: #{said.empty? ? 'this action is blocked.' : said} Don't retry it; tell the person."
        when :guide then said.empty? ? "Don't run this as it is." : said
        when :redirect then ["Use #{decision.redirect&.dig(:to) || 'another route'} instead.", said].reject(&:empty?).join(" ")
        when :verify then verify_message(said, human_tools)
        when :approve then approve_message(decision, said)
        else said
        end
      end

      def verify_message(said, human_tools)
        base = said.empty? ? "The person has to verify it's them first." : said
        human_tools ? "#{base} Verify them with scute_verify_person, then try again." : "#{base} Tell them; try again once they have."
      end

      def approve_message(decision, said)
        approve = decision.approve || {}
        return "#{said.empty? ? 'The person has to confirm this first.' : said} Ask them to confirm, then try again." unless approve[:by] == :reviewer

        base = said.empty? ? "A reviewer has to approve this." : said
        return "#{base} Tell the person it needs a reviewer's approval." unless approve[:request_id]

        "#{base} The request is filed (id #{approve[:request_id]}); tell the person it's pending and try again once it's approved."
      end
    end
  end
end
