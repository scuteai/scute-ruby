# frozen_string_literal: true

module Scute
  class Harness
    # The human steps of a Run: verify the person it works for and ask a
    # reviewer to approve, all with the task token.
    module HumanSteps
      # Send the person a verification: a code by email or text, their authenticator
      # app, or a push. Works with the task token alone; the answer has a "say" line.
      def start_verification(verdict: nil, method: nil, permission: nil)
        asked = verdict&.decision&.verify || @last_verify || {}
        permission ||= asked[:permission]
        methods = [method, asked[:method], *Array(asked[:methods])].compact.map(&:to_s).reject { |m| m.empty? || m == "any" }
        raise ArgumentError, "Pick a verification method (email_otp, sms_otp, totp, entra_push...)" if methods.empty?

        verification = agent_call(:post, "/agent/verifications",
                                  body: { method: methods.first, permission: permission, session_id: session }.compact)
        @lock.synchronize do
          state["pending"] = { "token" => verification["token"], "permission" => permission }
          save
        end
        verification
      end

      # The person read out the code. A wrong code comes back with status "pending" and a "say" line.
      def submit_code(code, challenge_token = nil)
        token = challenge_token || state.dig("pending", "token") or raise ArgumentError, "No verification in progress"
        verification = begin
          agent_call(:post, "/agent/verifications/#{harness.client.esc(token)}/code", body: { code: code.to_s })
        rescue APIError => e
          raise unless e.status == 422 && e.body.is_a?(Hash) && e.body["status"]

          e.body
        end
        record_verified(token) if verification["status"] == "completed"
        verification
      end

      # Where a verification stands (poll this for pushes). Recorded once complete.
      def verification_status(challenge_token = nil)
        token = challenge_token || state.dig("pending", "token") or raise ArgumentError, "No verification in progress"
        verification = agent_call(:get, "/agent/verifications/#{harness.client.esc(token)}")
        record_verified(token) if verification["status"] == "completed"
        verification
      end

      # Record a finished verification: one this run started (Scute reports it), or a
      # challenge your backend started (Scute checks it's the person's, completed and fresh).
      def complete_verification(challenge_token = nil)
        challenge_token ||= state.dig("pending", "token")
        raise ArgumentError, "No verification to complete" unless challenge_token

        if state.dig("pending", "token") == challenge_token
          status = verification_status(challenge_token)["status"]
          raise APIError.new("Not verified yet (#{status})", status: 409, code: "not_verified") unless status == "completed"
        else
          agent_call(:post, "/agent/sessions/#{harness.client.esc(session)}/verified", body: { challenge: challenge_token })
          record_verified(challenge_token)
        end
      end

      # @api private: file (or find: Scute returns the open one) the approval for this
      # exact call. Its arguments go with it and reviewers see them; the approval
      # only counts for the same arguments.
      def request_approval(call)
        return nil unless call.permission && call.spec.action

        approval = agent_call(:post, "/agent/approvals", body: {
          action: call.spec.action, resource: call.resource, context: @context,
          reason: Messages.describe_call(call.tool, call.args), details: call.args
        }.compact)
        return nil unless approval["id"]

        @lock.synchronize do
          state["approvals"][approval_key(call)] = { "id" => approval["id"], "call" => fingerprint(call.tool, call.args) }
          save
        end
        approval
      end

      # Where an approval this run filed stands, with a "say" line.
      def approval_status(id) = agent_call(:get, "/agent/approvals/#{harness.client.esc(id)}")

      private

      def record_verified(token)
        @lock.synchronize do
          state["verified_at"] = Time.now.to_f
          if state.dig("pending", "token") == token
            permission = state["pending"]["permission"]
            state["challenges"][permission] = token if permission
            state.delete("pending")
          end
          save
        end
      end
    end
  end
end
