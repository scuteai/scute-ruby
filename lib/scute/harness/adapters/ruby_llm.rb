# frozen_string_literal: true

module Scute
  class Harness
    module Adapters
      # RubyLLM (https://rubyllm.com): guards a tool's #execute.
      #
      #   chat = RubyLLM.chat
      #   chat.with_tool(run.ruby_llm(RefundInvoice, chat: chat))
      #
      # No runtime dependency on ruby_llm: anything with #execute(**args) works.
      module RubyLLM
        module_function

        def wrap(run, tool, chat: nil)
          instance = tool.is_a?(Class) ? tool.new : tool
          name = tool_name(instance)
          run.tool_names |= [name]
          guard = Module.new do
            define_method(:execute) do |**args|
              messages = chat.respond_to?(:messages) ? chat.messages : []
              verdict = run.check(name, args, messages: messages)
              next({ error: verdict.message }) unless verdict.runs?

              run.after(name, verdict.args, super(**verdict.args), messages: messages)
            end
          end
          instance.singleton_class.prepend(guard)
          instance
        end

        # RubyLLM::Tool subclasses for the human steps (needs the ruby_llm gem loaded).
        def human_tools(run, methods: HumanTools::METHODS)
          raise Scute::ConfigurationError, "ruby_llm isn't loaded" unless defined?(::RubyLLM::Tool)

          HumanTools.build(run, methods: methods).map do |name, spec|
            Class.new(::RubyLLM::Tool) do
              description spec[:description]
              spec[:parameters].each do |param_name, p|
                param param_name, type: p[:type], desc: p[:desc], required: p.fetch(:required, false)
              end
              define_method(:name) { name }
              define_method(:execute) { |**args| spec[:call].call(args) }
            end.new
          end
        end

        def tool_name(instance)
          return instance.name.to_s if instance.respond_to?(:name) && instance.name

          instance.class.name.to_s.split("::").last.gsub(/([a-z0-9])([A-Z])/, '\1_\2').downcase
        end
      end
    end
  end
end
