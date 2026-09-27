# frozen_string_literal: true

require "digest"
require "json"
require "monitor"
require "securerandom"
require "time"

module Scute
  class Harness
    # One job an agent does: a Scute task (its token never reaches the model),
    # its session, and what the guards remember. Reuse `id` to resume.
    class Run
      HOUR = 3600
      # Tool names seen through adapters; allowed_tools narrows these.
      attr_accessor :tool_names
      # @api private: the last verification a guard asked for (for the verify_person tool),
      # and the human tool names, always offered to the model.
      attr_accessor :last_verify, :human_tool_names
      attr_reader :harness, :id

      include HumanSteps

      # acts_for: the app user the agent works for (omit for an agent on its own).
      # task: { actions:, resources:, ttl:, ref: } narrows the task.
      # requester: { email:, phone:, app_user_id:, name: }, who asked (a helpdesk caller).
      # parent: the Run that started this one. token: a task token minted by your backend.
      def initialize(harness, id: nil, acts_for: nil, task: {}, requester: nil, parent: nil, token: nil, session: {}, context: {})
        @harness = harness
        @id = (id || SecureRandom.uuid).to_s
        @acts_for = acts_for
        @task = task || {}
        @requester = requester || {}
        @parent = parent
        @given_token = token
        @session_options = session || {}
        @context = context || {}
        @lock = Monitor.new
        @kept = {}
        @grounded = Set.new
        @identified = Set.new
        @tool_names = []
        @human_tool_names = []
      end

      # ── Task ──

      # The task token, starting the task on first use.
      def token
        return @given_token if @given_token

        @lock.synchronize do
          s = state
          raise APIError.new("This run's task is closed; start a new run", status: 409, code: "task_closed") if s["closed"]
          return s["token"] if s["token"] && !expiring?(s)

          mint!
        end
      end

      def task_id
        return whoami["task"] if @given_token

        token
        state["task_id"]
      end

      # Who the agent works for, what the task allows now, and its ceiling. Cached per run.
      def whoami
        @lock.synchronize { @whoami ||= agent_call(:get, "/agent/whoami") }
      end

      # The job is done: close the task (and its session).
      def complete! = close!(:complete)

      # Stop now: the task token stops working everywhere.
      def revoke! = close!(:revoke)

      # ── Session and verification ──

      # The run's session (created on first use). Verification lives on it.
      def session
        @lock.synchronize do
          next state["session_id"] if state["session_id"]

          created = agent_call(:post, "/agent/sessions", body: {
            channel: @session_options[:channel] || "chat",
            external_ref: @session_options[:external_ref] || id,
            caller: @session_options[:caller]
          }.compact)
          state["session_id"] = created["id"]
          save
          created["id"]
        end
      end

      def verified_at = state["verified_at"]

      # The person confirmed this exact call in your UI; guards.approval lets it through once.
      def confirm(tool, args)
        @lock.synchronize do
          state["confirmed"] << fingerprint(tool, args)
          save
        end
      end

      # @api private
      def consume_confirmation(call)
        @lock.synchronize do
          next false unless state["confirmed"].delete(fingerprint(call.tool, call.args))

          save
          true
        end
      end

      # ── Engine ──

      # @api private: Scute's engine on a call (agent roles, the person, the task).
      def engine_check(call, context = nil)
        s = state
        key = approval_key(call)
        approval = s["approvals"][key]
        body = { action: call.spec.action, resource: call.resource, context: @context.merge(context || {}),
                 challenge: s["challenges"][call.permission], approval: approval, session_id: s["session_id"] }.compact
        decision = Authz::Decision.from_api(agent_call(:post, "/agent/check", body: body, idempotent: true))
        @lock.synchronize do
          if decision.reason == "task_closed"
            state["closed"] = true
            save
          elsif approval && decision.allowed?
            state["approvals"].delete(key) # spent
            save
          end
        end
        decision
      end

      # ── Checking calls ──

      def check(tool, args = {}, id: nil, messages: [], approved_by_user: false)
        harness.evaluate(new_call(tool, args, id, messages, approved_by_user))
      end

      # Record a call that ran and run the after-guards. Returns what the model should see.
      def after(tool, args, result, id: nil, messages: [])
        spec = harness.spec(tool)
        @lock.synchronize do
          state["calls"] += 1
          save
        end
        harness.record_execution(budget_key, spec.tier)
        harness.evaluate_after(new_call(tool, args, id, messages, false), result)
      end

      # Guard a block: when a call doesn't run, the lambda returns the message for the model.
      def wrap(tool, &block)
        raise ArgumentError, "wrap needs a block" unless block

        lambda do |args = {}|
          verdict = check(tool, args)
          next verdict.message unless verdict.runs?

          after(tool, verdict.args, block.call(verdict.args))
        end
      end

      # @api private
      def keep(verdict) = @lock.synchronize { @kept[verdict.call_id] = verdict if verdict.runs? }

      # @api private
      def take(call_id) = @lock.synchronize { @kept.delete(call_id) }

      # ── Grounding, identity, usage, budgets ──

      # Values known to be true for this run, for guards.grounding.
      def ground(*values) = values.each { |v| @grounded << v.to_s.downcase unless v.nil? || v.to_s.empty? }

      # Who is asking, once you know (the verified caller's email or phone). For guards.requester_only.
      def identify(*values) = values.each { |v| @identified << v.to_s.downcase unless v.nil? || v.to_s.empty? }

      def identities
        (@requester.values.compact.map { |v| v.to_s.downcase }.reject(&:empty?) + @identified.to_a).uniq
      end

      def grounded_values = (@grounded.to_a + identities).uniq

      def record_usage(usd: 0)
        @lock.synchronize do
          state["usd"] += usd.to_f
          save
        end
      end

      # @api private: hourly budgets count per agent and person, across runs.
      def budget_key = "scute:hour:#{harness.agent}:#{@acts_for || state['acts_for'] || 'none'}"

      def recent_executions = harness.executions(budget_key, HOUR)

      # True when a run budget (calls or spend) is used up.
      def budget_exhausted?
        harness.guards.any? { |g| g.respond_to?(:exhausted?) && g.exhausted?(self) }
      end

      # Tools the task could ever use (its ceiling). Tools without a permission always count.
      def allowed_tools(names = tool_names)
        ceiling = Array(whoami["ceiling"])
        allowed = names.select do |n|
          permission = harness.spec(n).permission
          human_tool_names.include?(n) || permission.nil? || ceiling.include?(permission)
        end
        (allowed + human_tool_names).uniq
      end

      # A copy of what this run remembers.
      def snapshot = JSON.parse(JSON.generate(state))

      # ── Adapters ──

      # RubyLLM: guard a tool (class or instance). Pass chat: so grounding sees the conversation.
      def ruby_llm(tool, chat: nil) = Adapters::RubyLLM.wrap(self, tool, chat: chat)

      # RubyLLM tools the model calls to bring the person in (verify, pass on a code, whoami...).
      def ruby_llm_human_tools(methods: HumanTools::METHODS) = Adapters::RubyLLM.human_tools(self, methods: methods)

      # The same human steps as plain callables: { name => { description:, parameters:, call: ->(args) } }.
      def human_tools(methods: HumanTools::METHODS) = HumanTools.build(self, methods: methods)

      private

      def new_call(tool, args, id, messages, approved_by_user)
        Call.new(run: self, id: id || SecureRandom.uuid, tool: tool, args: args, spec: harness.spec(tool),
                 messages: messages, approved_by_user: approved_by_user)
      end

      def key = "scute:run:#{harness.agent}:#{id}"

      def state
        @lock.synchronize do
          @state ||= begin
            raw = harness.store.get(key)
            raw ? JSON.parse(raw) : {}
          end
          @state["challenges"] ||= {}
          @state["approvals"] ||= {}
          @state["confirmed"] ||= []
          @state["calls"] ||= 0
          @state["usd"] ||= 0.0
          @state
        end
      end

      def save
        s = state
        left = s["expires_at"] ? (Time.parse(s["expires_at"]) - Time.now).ceil : 0
        # Kept a day past the task, so a conversation resumed later still has its counters.
        harness.store.set(key, JSON.generate(s), [left, 0].max + 86_400)
      end

      def expiring?(remembered) = remembered["expires_at"] && Time.parse(remembered["expires_at"]) <= Time.now + 5

      def mint!
        unless harness.client.secret?
          raise ConfigurationError, "A run needs SCUTE_SECRET to start a task, or a task token (run(token:)) minted by your backend"
        end

        minted = harness.client.agents.start_task(
          harness.agent, acts_for: @acts_for, actions: @task[:actions], resources: @task[:resources],
                         ttl: @task[:ttl], ref: @task[:ref], requester: @requester.empty? ? nil : @requester,
                         parent_task_id: @parent&.task_id
        )
        state.merge!("token" => minted["token"], "task_id" => minted["id"], "expires_at" => minted["expires_at"],
                     "acts_for" => minted["acts_for"], "minted" => true)
        state.delete("session_id")
        @whoami = nil
        save
        minted["token"]
      end

      def close!(verb)
        @lock.synchronize do
          s = state
          if s["session_id"] && s["token"]
            begin
              agent_call(:post, "/agent/sessions/#{harness.client.esc(s['session_id'])}/end")
            rescue Error
              nil
            end
          end
          harness.client.agents.public_send(:"#{verb}_task", harness.agent, s["task_id"]) if s["task_id"]
          s["closed"] = true
          save
        end
      end

      def agent_call(method, path, body: nil, idempotent: method == :get)
        harness.client.http.request(method, harness.client.auth_path(path), bearer: token, body: body, idempotent: idempotent)
      end

      def approval_key(call) = "#{call.permission}|#{Harness.resource_ref(call.resource)}"

      def fingerprint(tool, args)
        Digest::SHA256.hexdigest(JSON.generate([tool.to_s, canonical(Harness.symbolize(args))]))
      end

      def canonical(value)
        case value
        when Hash then value.map { |k, v| [k.to_s, canonical(v)] }.sort_by(&:first)
        when Array then value.map { |v| canonical(v) }
        else value
        end
      end
    end
  end
end
