# frozen_string_literal: true

require "digest"
require "json"

module Scute
  class Harness
    # What a Run tells Scute about its tools: their definitions (so a change
    # shows up as drift) and a call to a decoy tool.
    module ToolReports
      # Report the tools this agent has, so Scute notices when one changes
      # later (tool drift, a known prompt injection route). Pass what the
      # model sees: [{ name:, description:, input_schema: }] (inputSchema is
      # fine too). Only a hash of each leaves this process; the first report
      # is the baseline. Answers { "known", "new", "changed" }.
      def report_tools(definitions)
        tools = definitions.map { |d| { name: ToolReports.field(d, :name).to_s, hash: ToolReports.definition_hash(d) } }
        agent_call(:post, "/agent/tools", body: { tools: tools })
      end

      # @api private: guards.decoy. The agent called a decoy tool: Scute pauses
      # it, and this run is over (closed here even if the report can't be sent).
      def report_decoy(tool)
        agent_call(:post, "/agent/decoys", body: { tool: tool.to_s })
      ensure
        @lock.synchronize do
          state["closed"] = true
          save
        end
      end

      # SHA-256 (hex) of a tool definition: name, description ("" when
      # missing) and input schema (null when missing), with object keys
      # sorted at every level, so the order they're written in doesn't
      # matter. The same hash the TypeScript harness sends.
      def self.definition_hash(definition)
        schema = field(definition, :input_schema, :inputSchema)
        canonical = { "description" => field(definition, :description).to_s, "inputSchema" => sorted(schema),
                      "name" => field(definition, :name).to_s }
        Digest::SHA256.hexdigest(JSON.generate(canonical))
      end

      # @api private: a symbol or string key.
      def self.field(hash, *names)
        names.each do |name|
          [name, name.to_s].each { |k| return hash[k] if hash.key?(k) }
        end
        nil
      end

      # @api private: object keys sorted at every level.
      def self.sorted(value)
        case value
        when Hash then value.map { |k, v| [k.to_s, sorted(v)] }.sort_by(&:first).to_h
        when Array then value.map { |v| sorted(v) }
        else value
        end
      end
    end
  end
end
