# frozen_string_literal: true

require_relative "live_helper"

RSpec.describe "Live: access tokens", :live, order: :defined do
  let(:member) { world.member }
  let(:access) { member["tokens"]["access"] }

  def reason_for(token, tokens = client.tokens)
    tokens.verify(token)
    nil
  rescue Scute::InvalidToken => e
    e.reason
  end

  # A byte of the token changed: the claims, or the signature itself.
  def tampered(token, part)
    pieces = token.split(".")
    if part == :claims
      claims = ScuteLive::Crypto.claims(token).merge("uuid" => SecureRandom.uuid)
      pieces[1] = ScuteLive::Crypto.b64(JSON.generate(claims))
    else
      signature = ScuteLive::Crypto.unb64(pieces[2]).bytes
      signature[signature.size / 2] ^= 0x01
      pieces[2] = ScuteLive::Crypto.b64(signature.pack("C*"))
    end
    pieces.join(".")
  end

  describe Scute::Tokens do
    it "verifies a real access token locally with the app's JWKS" do
      session = client.tokens.verify(access)

      expect(session.user_id).to eq(member["id"])
      expect(session.app_id).to eq(client.tokens.public_app_id)
      expect(session.expires_at).to be > Time.now
      expect(session).not_to be_impersonated
      expect(session.authz_context).to eq({})
    end

    it "refuses a tampered token (claims or signature changed, signature stripped)" do
      expect(reason_for(tampered(access, :claims))).to eq(:signature)
      expect(reason_for(tampered(access, :signature))).to eq(:signature)
      expect(reason_for("#{access.split('.').first(2).join('.')}.")).to eq(:malformed)
    end

    it "refuses it once it has expired (a verifier whose clock is past exp)" do
      exp = client.tokens.verify(access).expires_at
      later = Scute::Tokens.new(client, clock: -> { exp + Scute::Tokens::LEEWAY + 1 })

      expect(reason_for(access, later)).to eq(:expired)
    end

    it "refuses a token Scute signed for something else (the policy snapshot: same keys, not a session of this app)" do
      snapshot = client.authz.snapshot["token"]

      expect(ScuteLive::Crypto.claims(snapshot)).to include("typ" => "scute-authz-snapshot")
      expect(reason_for(snapshot)).to eq(:wrong_app)
    end

    it "asks Scute too with remote: true" do
      expect(client.tokens.verify(access, remote: true).user_id).to eq(member["id"])
    end
  end

  describe Scute::Authentication do
    it "reads Authorization: Bearer" do
      expect(rack.get("/me", "HTTP_AUTHORIZATION" => "Bearer #{access}")).to eq([200, { "user_id" => member["id"], "impersonated" => false }])
    end

    it "reads X-Authorization (what the Scute SDKs send)" do
      expect(rack.get("/me", "HTTP_X_AUTHORIZATION" => access).first).to eq(200)
    end

    it "reads the browser SDK's cookie (sc-access-token__<app id>)" do
      expect(rack.get("/me", "HTTP_COOKIE" => "sc-access-token__#{app_id}=#{access}").first).to eq(200)
    end

    it "checks with Scute on scute_authenticate!(remote: true)" do
      expect(rack.get("/me?remote=1", "HTTP_AUTHORIZATION" => "Bearer #{access}").first).to eq(200)
    end

    it "answers 401 without a token, and says why for a bad one" do
      expect(rack.get("/me")).to eq([401, { "error" => "missing" }])
      expect(rack.get("/me", "HTTP_AUTHORIZATION" => "Bearer #{tampered(access, :signature)}")).to eq([401, { "error" => "signature" }])
      expect(rack.get("/me", "HTTP_AUTHORIZATION" => "Bearer not-a-jwt")).to eq([401, { "error" => "malformed" }])
    end

    it "authorizes as the signed-in user with Scute::Authorization" do
      expect(rack.get("/accounts/1/delete", "HTTP_AUTHORIZATION" => "Bearer #{access}")).to match([200, a_hash_including("reason" => "role_grant")])
    end
  end
end
