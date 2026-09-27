# frozen_string_literal: true

RSpec.describe Scute::Harness::Adapters::RubyLLM do
  # Shaped like a RubyLLM::Tool: #name and #execute(**args).
  let(:tool_class) do
    Class.new do
      attr_reader :calls

      def self.name = "Tools::RefundInvoice"

      def initialize = @calls = []

      def execute(invoice_id:, amount:)
        @calls << [invoice_id, amount]
        { refunded: invoice_id, card: "4242 4242 4242 4242" }
      end
    end
  end

  let(:chat) { Struct.new(:messages).new([{ role: :user, content: "refund INV-1 for 90" }]) }

  it "guards #execute and names the tool after the class" do
    run = harness(FakeScute.new, guards: [Scute::Guards.grounding, Scute::Guards.content(pii: [:card])]).run
    tool = run.ruby_llm(tool_class, chat: chat)

    expect(tool.execute(invoice_id: "INV-1", amount: 90)).to eq(refunded: "INV-1", card: "[card removed]")
    expect(tool.execute(invoice_id: "INV-2", amount: 90)[:error]).to match(/Don't guess invoice_id/)
    expect(tool.calls).to eq([["INV-1", 90]])
    expect(run.tool_names).to eq(["refund_invoice"])
  end

  it "asks Scute with the mapped permission" do
    fake = FakeScute.new(decide: ->(*) { { decision: "deny", reason: "outside_task", explanation: "Not in this task." } })
    run = harness(fake).run(acts_for: "user1")
    tool = run.ruby_llm(tool_class.new)

    expect(tool.execute(invoice_id: "INV-1", amount: 90)).to eq(error: "Not allowed: Not in this task. Don't retry it; tell the person.")
    expect(fake.paths("/v1/auth/app1/agent/check").first.body).to include("action" => "refund")
  end
end
