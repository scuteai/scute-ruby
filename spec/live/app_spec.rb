# frozen_string_literal: true

require_relative "live_helper"

RSpec.describe "Live: the app", :live, order: :defined do
  # scute-ruby has no method for the app's data (Tokens#public_app_id reads
  # only its id): GET /v1/apps/:app_id, public.
  it "reads the app's data" do
    app = api.get!("/v1/apps/#{app_id}", as: :public)

    expect(app["id"]).to eq(client.tokens.public_app_id)
    expect(app["name"]).to be_a(String)
    expect(app).to include("test_identities" => true, "email_auth_type" => "otp")
  end

  it "publishes the signing keys scute-ruby verifies tokens with" do
    jwks = api.get!(world.auth("/.well-known/jwks.json"), as: :public)

    expect(jwks["keys"]).to include(a_hash_including("kty" => "RSA", "alg" => "RS256", "use" => "sig"))
  end
end
