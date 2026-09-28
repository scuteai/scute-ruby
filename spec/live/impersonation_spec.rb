# frozen_string_literal: true

require_relative "live_helper"

RSpec.describe "Live: signing in as a user (impersonation)", :live, order: :defined do
  before(:context) do
    world.authz_settings! # impersonation on (scute-ruby has no settings method)
    @imp = { target: world.member, actor: { "email" => "support+scute_test@example.com", "name" => "Live support" } }
  end

  let(:target_id) { @imp[:target]["id"] }

  it "starts a session as the user (users.impersonate); its token names who is really acting" do
    started = client.users.impersonate(target_id, reason: "#{world.prefix}: support ticket", actor: @imp[:actor], minutes: 5)
    @imp[:access] = started["access"]
    @imp[:session_id] = started["session_id"]

    expect(started.keys).not_to include("refresh")
    expect(started["impersonation"]).to include("reason" => "#{world.prefix}: support ticket")
    session = client.tokens.verify(started["access"])
    expect(session).to be_impersonated
    expect(session.user_id).to eq(target_id)
    expect(session.actor).to include("kind" => "backend", "email" => @imp[:actor]["email"])
    expect(session.claims["act"]).to include("sub" => @imp[:actor]["email"])
  end

  it "tells the app about it (sessions.current_user)" do
    me = client.sessions.current_user(@imp[:access])

    expect(me["user"]["id"]).to eq(target_id)
    expect(me["impersonation"]["actor"]).to include("email" => @imp[:actor]["email"])
  end

  it "lists it (users.impersonations)" do
    expect(client.users.impersonations(target_id).map { |i| i["session_id"] }).to include(@imp[:session_id])
  end

  it "denies a 'not while impersonating' permission inside the session" do
    as_user = rack.get("/accounts/1/delete", "HTTP_AUTHORIZATION" => "Bearer #{@imp[:target]['tokens']['access']}")
    as_support = rack.get("/accounts/1/delete", "HTTP_AUTHORIZATION" => "Bearer #{@imp[:access]}")

    expect(as_user).to match([200, a_hash_including("impersonated" => false)])
    expect(as_support).to eq([403, { "error" => "impersonating" }])

    context = client.tokens.verify(@imp[:access]).authz_context
    decision = client.authz.check(user_id: target_id, action: "delete", resource: "account:1", context: context)
    expect(decision).to be_denied
    expect(decision.reason).to eq("impersonating")
    expect(client.authz.check(user_id: target_id, action: "read", resource: "account:1", context: context)).to be_allowed
  end

  it "stops it (users.stop_impersonating); the token stops working" do
    expect(client.users.stop_impersonating(target_id, session_id: @imp[:session_id])).to include("ended" => 1)
    expect(client.users.impersonations(target_id)).to be_empty
    expect { client.tokens.verify(@imp[:access], remote: true) }
      .to raise_error(Scute::InvalidToken) { |e| expect(e.reason).to eq(:revoked) }
  end
end
