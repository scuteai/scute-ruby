# frozen_string_literal: true

module Scute
  class Harness
    # Tools the model calls to bring the person in: verify them, pass on the
    # code they read out, check a push or an approval, and ask what the task
    # allows. Every answer has a "say" line the agent can speak as is.
    module HumanTools
      METHODS = %w[email_otp sms_otp totp entra_push].freeze
      NAMES = %w[scute_verify_person scute_submit_code scute_check_verification scute_approval_status scute_whoami].freeze

      METHOD_HELP = {
        "email_otp" => "a code by email", "sms_otp" => "a code by text message", "totp" => "the code in their authenticator app",
        "backup_code" => "one of their backup codes", "entra_push" => "a Microsoft Authenticator request", "push" => "a request on their phone"
      }.freeze

      module_function

      def build(run, methods: METHODS)
        run.human_tool_names = NAMES.dup
        {
          "scute_verify_person" => {
            description: "Verify that the person you're helping is who they say they are. Use it when an action needs " \
                         "verification. It sends them a code or a request; tell them the `say` line.",
            parameters: { method: { type: "string", enum: methods, required: false,
                                    desc: "How to verify: #{methods.map { |m| "#{m} = #{METHOD_HELP.fetch(m, m)}" }.join('; ')}." } },
            call: ->(args) { answer { verification(run.start_verification(method: args[:method])) } }
          },
          "scute_submit_code" => {
            description: "Pass on the verification code the person read out to you.",
            parameters: { code: { type: "string", required: true, desc: "The code, digits only." } },
            call: ->(args) { answer { verification(run.submit_code(args[:code].to_s.gsub(/\s+/, ""))) } }
          },
          "scute_check_verification" => {
            description: "Check whether the person finished verifying (for a push or a link). Tell them the `say` line.",
            parameters: {},
            call: ->(_args) { answer { verification(run.verification_status) } }
          },
          "scute_approval_status" => {
            description: "Check whether a reviewer answered an approval request. Tell the person the `say` line.",
            parameters: { id: { type: "string", required: true, desc: "The approval request id." } },
            call: ->(args) { answer { run.approval_status(args[:id]).slice("status", "say") } }
          },
          "scute_whoami" => {
            description: "Who you're working for in this task, what you may do, and how long the task has left.",
            parameters: {},
            call: ->(_args) { answer { whoami(run.whoami) } }
          }
        }
      end

      def answer
        yield
      rescue ArgumentError => e
        if e.message.start_with?("Pick")
          return { "error" => "method_required",
                   "say" => "How would you like to verify: a code by email or text, or your authenticator app?" }
        end
        return { "error" => "no_verification", "say" => "Let me send you a verification first." } if e.message.start_with?("No verification")

        { "error" => e.message }
      rescue Scute::Error => e
        say = e.respond_to?(:body) && e.body.is_a?(Hash) ? e.body["say"] : nil
        { "error" => e.message, "say" => say }.compact
      end

      def verification(answer)
        out = { "status" => answer["status"], "say" => answer["say"] }
        out["remaining_attempts"] = answer["remaining_attempts"] if answer["status"] == "pending" && answer["remaining_attempts"]
        out
      end

      def whoami(answer)
        may = Array(answer["permissions"])
        { "acts_for" => answer["acts_for"], "may" => may, "could_with_more_access" => Array(answer["ceiling"]) - may,
          "needs_verification" => answer["step_up"], "needs_approval" => answer["approval"],
          "expires_in" => answer["expires_in"], "warnings" => answer["warnings"] }.compact
      end
    end
  end
end
