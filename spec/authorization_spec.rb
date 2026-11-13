# frozen_string_literal: true

RSpec.describe Scute::Authorization do
  let(:fake) { FakeScute.new }
  let(:controller) do
    client = Scute::Client.new(app_id: "app1", secret: "sk_test", base_url: "https://scute.test", transport: fake)
    Class.new do
      include Scute::Authorization

      define_method(:scute_client) { client }
      def scute_user_id = "user1"
    end.new
  end

  it "passes a plain allow and raises Forbidden with the decision otherwise" do
    expect(controller.scute_authorize!("read", "invoice:1")).to be_allowed
    expect(fake.seen.last.body).to include("user_id" => "user1", "action" => "read", "resource" => "invoice:1")

    expect { controller.scute_authorize!("pay", "invoice:1") }.to raise_error(Scute::Forbidden, "Verify first.") { |e| expect(e.decision).to be_step_up }
    expect { controller.scute_authorize!("approve", "invoice:1") }
      .to raise_error(Scute::Forbidden, "Not allowed (approval_required)") { |e| expect(e.decision).to be_needs_approval }
    expect { controller.scute_authorize!("delete", "invoice:1") }
      .to raise_error(Scute::Forbidden, "Ada can't delete invoices.") { |e| expect(e.decision).to be_denied }
    expect(controller.scute_can?("pay")).to be(false)
    expect(controller.scute_can?("read", "invoice:1")).to be(true)
    expect(fake.paths("/v1/auth/app1/authz/check").map(&:auth).uniq).to eq(["Bearer sk_test"])
  end

  it "needs scute_user_id" do
    bare = Class.new { include Scute::Authorization }.new
    expect { bare.scute_user_id }.to raise_error(NotImplementedError)
  end
end
