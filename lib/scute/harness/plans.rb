# frozen_string_literal: true

module Scute
  class Harness
    # Plans and previews of a Run: ask for one review of several calls, and
    # ask what a call would need without using anything up.
    module Plans
      # File a plan: every call the agent means to make, for one review.
      # calls: [{ tool:, args: }]. Once a reviewer approves it, each call that
      # needed approval runs once, with exactly these arguments, through the
      # usual checks. Answers the plan ("id", "status", "say", "steps"); when
      # nothing needs approval, status "not_needed" and no id.
      #
      #   run.request_plan([{ tool: "refund_invoice", args: { invoice_id: 1, amount: 40 } },
      #                     { tool: "refund_invoice", args: { invoice_id: 2, amount: 15 } }], reason: "Ticket 88")
      def request_plan(calls, reason: nil)
        steps = calls.map { |c| plan_call(c) }.select { |call| call.permission && call.spec.action }.map do |call|
          { action: call.spec.action, resource: call.resource, context: @context.merge(args: call.args), details: call.args }.compact
        end
        plan = agent_call(:post, "/agent/plans", body: { steps: steps, reason: reason }.compact)
        if plan["id"]
          @lock.synchronize do
            state["plan_id"] = plan["id"]
            save
          end
        end
        plan
      end

      # Where this run's plan stands, and which steps ran ("used" per step);
      # nil when the run has no plan.
      def plan_status
        id = state["plan_id"] or return nil

        agent_call(:get, "/agent/plans/#{harness.client.esc(id)}")
      end

      # What Scute would answer for this call right now (a dry run), as an
      # Authz::Decision. It doesn't count toward budgets and doesn't use up a
      # verification or an approval.
      def preview(tool, args = {})
        call = plan_call({ tool: tool, args: args })
        return Authz::Decision.from_api("decision" => "allow", "reason" => "no_permission") unless call.permission && call.spec.action

        body = { action: call.spec.action, resource: call.resource, context: @context.merge(args: call.args),
                 details: call.args, dry_run: true }.compact
        Authz::Decision.from_api(agent_call(:post, "/agent/check", body: body, idempotent: true))
      end

      private

      def plan_call(call)
        tool = call[:tool] || call["tool"]
        args = call[:args] || call["args"] || {}
        Call.new(run: self, id: SecureRandom.uuid, tool: tool, args: args, spec: harness.spec(tool))
      end
    end
  end
end
