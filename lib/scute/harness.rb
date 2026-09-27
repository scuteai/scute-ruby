# frozen_string_literal: true

module Scute
  # The harness around your agent: guards decide on each tool call, backed
  # by Scute's engine for who may do what.
  #
  #   harness = Scute::Harness.new(agent: "support-bot", guards: [Scute::Guards.permissions])
  #   run = harness.run(acts_for: user.id)
  #   refund = run.wrap("refund_invoice") { |args| Billing.refund(**args) }
  class Harness
    attr_reader :agent, :mode, :guards, :store, :client

    # tools: { refund_invoice: { tier: :high }, get_weather: false }
    # on_decision: ->(event) {} for every decision; on_alert: ->(event) {} when a monitor-mode guard would block.
    def initialize(agent:, guards: nil, tools: {}, mode: :enforce, default_tier: :low, store: nil, client: nil,
                   on_decision: nil, on_alert: nil, **client_options)
      raise ConfigurationError, "Scute::Harness needs agent: the agent's slug in Scute" if agent.to_s.empty?

      @agent = agent.to_s
      @mode = mode.to_sym
      @guards = guards || [Guards.permissions]
      @tools = (tools || {}).transform_keys(&:to_s)
      @default_tier = default_tier
      @store = store || MemoryStore.new
      @client = client || Client.new(**client_options)
      @on_decision = on_decision
      @on_alert = on_alert
      @specs = {}
      @lock = Mutex.new
      @log_lock = Mutex.new
      # Guards that spend single-use proofs go last, in their listed order.
      @ordered = @guards.reject { |g| runs_last?(g) } + @guards.select { |g| runs_last?(g) }
    end

    # Start (or resume, with the same id:) a job for the agent.
    def run(**) = Run.new(self, **)

    def spec(tool)
      @lock.synchronize { @specs[tool.to_s] ||= ToolSpec.new(tool, @tools[tool.to_s], @default_tier) }
    end

    def self.symbolize(hash) = (hash || {}).to_h.transform_keys(&:to_sym)

    # @api private: before-guards; the strictest enforced decision wins.
    def evaluate(call)
      started = clock
      results = []
      winner = PROCEED

      @ordered.each do |guard|
        next unless guard.respond_to?(:before)

        mode = call.mode = (guard.mode || @mode).to_sym
        call.clear = winner.rank <= RANK[:transform]
        decision, error = ask(guard, :before, call)
        results << GuardResult.new(guard: guard.name, mode: mode, decision: decision, error: error)

        if mode != :enforce
          alert(call, :before, guard.name, decision) if mode == :monitor && decision.kind != :proceed
          next
        end
        call.args = decision.args if decision.kind == :transform && decision.args
        winner = named(decision, guard) if decision.rank > winner.rank
        break if decision.kind == :deny
      end

      emit(call, :before, winner, results, started)
      verdict_for(call, winner, results)
    end

    # @api private: after-guards transform or withhold a result.
    def evaluate_after(call, result)
      started = clock
      results = []
      current = result
      winner = PROCEED

      @ordered.each do |guard|
        next unless guard.respond_to?(:after)

        mode = call.mode = (guard.mode || @mode).to_sym
        decision, error = ask(guard, :after, call, current)
        results << GuardResult.new(guard: guard.name, mode: mode, decision: decision, error: error)

        if mode != :enforce
          alert(call, :after, guard.name, decision) if mode == :monitor && decision.kind != :proceed
          next
        end
        next if decision.kind == :proceed

        winner = named(decision, guard) if decision.rank > winner.rank
        if decision.replaces_result?
          current = decision.result
        elsif decision.rank >= RANK[:guide]
          current = { error: decision.message || "This result was withheld." }
        end
        break if decision.kind == :deny
      end

      emit(call, :after, winner, results, started)
      current
    end

    # @api private: serialized in this process; across processes the store
    # decides (use one with atomic writes for hard limits).
    def record_execution(key, tier)
      @log_lock.synchronize do
        recent = executions(key, 3600)
        recent << { "at" => Time.now.to_f, "tier" => tier.to_s }
        store.set(key, JSON.generate(recent), 3600)
      end
    end

    # @api private
    def executions(key, window)
      raw = store.get(key)
      since = Time.now.to_f - window
      raw ? JSON.parse(raw).select { |e| e["at"] > since } : []
    end

    private

    def verdict_for(call, winner, results)
      verdict = Verdict.new(kind: winner.kind, decision: winner, args: call.args, results: results, call_id: call.id,
                            tool: call.tool, say: winner.say || winner.engine&.say)
      verdict.message = Messages.for_model(verdict.kind, winner, human_tools: call.run.human_tool_names.any?) unless verdict.runs?
      call.run.last_verify = winner.verify if verdict.kind == :verify
      verdict
    end

    def ask(guard, phase, *)
      decision = guard.public_send(phase, *)
      decision = PROCEED if decision.nil?
      raise TypeError, "#{guard.name} answered #{decision.class}, not a decision" unless decision.is_a?(Decision)

      [decision, nil]
    rescue StandardError => e
      message = phase == :before ? "This action couldn't be checked safely right now." : "This result couldn't be checked safely, so it was withheld."
      [Decision.new(kind: :deny, reason: "guard_error", message: message), e]
    end

    def runs_last?(guard) = guard.respond_to?(:runs_last?) && guard.runs_last?

    def named(decision, guard)
      decision.dup.tap { |d| d.guard = guard.name }
    end

    def emit(call, phase, winner, results, started)
      return unless @on_decision

      @on_decision.call(run: call.run.id, agent: agent, tool: call.tool, call_id: call.id, phase: phase, kind: winner.kind,
                        guard: winner.guard, reason: winner.reason, message: winner.message, results: results,
                        ms: ((clock - started) * 1000).round(2))
    rescue StandardError
      nil # a logging hook never changes a decision
    end

    def alert(call, phase, guard, decision)
      @on_alert&.call(run: call.run.id, agent: agent, tool: call.tool, call_id: call.id, phase: phase, guard: guard, decision: decision)
    rescue StandardError
      nil
    end

    def clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end
end
