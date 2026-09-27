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

        def tool_name(instance)
          return instance.name.to_s if instance.respond_to?(:name) && instance.name

          instance.class.name.to_s.split("::").last.gsub(/([a-z0-9])([A-Z])/, '\1_\2').downcase
        end
      end
    end
  end
end
