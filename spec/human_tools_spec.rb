# frozen_string_literal: true

RSpec.describe Scute::Harness::HumanTools do
  let(:fake) do
    FakeScute.new(decide: lambda { |body, _|
      next nil if body["challenge"] == "ch_ok"

      { decision: "allow_with_step_up", step_up: { method: "any", authorizes_action: "invoice:refund" },
        explanation: "Refunds need a fresh verification." }
    })
  end
  let(:run) { harness(fake).run(acts_for: "user1") }

  it "lets the model verify the person itself, then do the action" do
    tools = run.human_tools
    refund = run.wrap("refund_invoice") { |args| "refunded #{args[:invoice_id]}" }

    expect(refund.call(invoice_id: "INV-1",
                       amount: 90)).to eq("Refunds need a fresh verification. Verify them with scute_verify_person, then try again.")
    expect(tools["scute_verify_person"][:call].call(method: "email_otp"))
      .to eq("status" => "pending", "say" => "I've emailed a code to a***@example.com. What's the code?")
    expect(fake.paths("/v1/auth/app1/agent/verifications").first.body).to include("permission" => "invoice:refund")
    expect(tools["scute_submit_code"][:call].call(code: "000 000")).to include("status" => "pending", "remaining_attempts" => 2)
    expect(tools["scute_submit_code"][:call].call(code: "123 456")).to eq("status" => "completed", "say" => "Thanks, you're verified.")
    expect(refund.call(invoice_id: "INV-1", amount: 90)).to eq("refunded INV-1")
  end

  it "answers plainly when something is missing" do
    tools = run.human_tools

    expect(tools["scute_submit_code"][:call].call(code: "1")).to eq("error" => "no_verification", "say" => "Let me send you a verification first.")
    expect(tools["scute_verify_person"][:call].call({})["error"]).to eq("method_required")
    expect(tools["scute_whoami"][:call].call({})).to include("acts_for" => "user1", "could_with_more_access" => %w[invoice:read invoice:refund])
    expect(run.allowed_tools(["refund_invoice"])).to include("scute_verify_person", "scute_whoami")
  end

  it "builds RubyLLM tools when ruby_llm is loaded" do
    stub_const("RubyLLM::Tool", Class.new do
      class << self
        attr_reader :params

        def description(text = nil) = text ? @description = text : @description
        def param(name, **opts) = (@params ||= {})[name] = opts
      end
    end)

    tools = run.ruby_llm_human_tools
    verify = tools.find { |t| t.name == "scute_verify_person" }

    expect(tools.map(&:name)).to eq(Scute::Harness::HumanTools::NAMES)
    expect(verify.class.params[:method]).to include(type: "string", required: false)
    expect(verify.execute(method: "email_otp")["status"]).to eq("pending")
  end
end
