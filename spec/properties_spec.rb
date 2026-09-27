# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Properties in the harness" do
  let(:fake) { FakeScute.new }
  let(:run) { harness(fake).run(acts_for: "user1") }

  it "reads a secret and signs with the task token" do
    expect(run.property("stripe")).to eq("sk_live_123")
    expect(run.sign("mandates", claims: { amount: 4200 })).to include("jws" => "h.b.s", "kid" => "prop_1")
    expect(run.sign("mandates", data: "aGVsbG8")).to include("signature" => "c2ln")

    uses = fake.seen.select { |s| s.path.start_with?("/v1/auth/app1/agent/properties/") }
    expect(uses.map(&:auth)).to all(start_with("Bearer sct_"))
    expect(fake.paths("/v1/auth/app1/agent/properties/mandates/sign").first.body).to eq("claims" => { "amount" => 4200 })
  end

  it "raises the refusal" do
    expect { run.property("locked") }.to raise_error(Scute::APIError) { |e| expect(e.code).to eq("agent_not_listed") }
  end

  it "needs something to sign" do
    expect { run.sign("mandates") }.to raise_error(ArgumentError)
  end
end
