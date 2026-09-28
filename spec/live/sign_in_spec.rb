# frozen_string_literal: true

require_relative "live_helper"

# The sign-in itself is the end user's (a browser or app; scute-ruby has no
# client for it), so it goes over HTTP with a test identity and 424242.
# Everything after it is scute-ruby: current_user, refresh, sign_out, and
# (secret key) list and revoke.
RSpec.describe "Live: sign-in and sessions", :live, order: :defined do
  def api_status
    yield
    nil
  rescue Scute::APIError => e
    e.status
  end

  describe "email OTP" do
    let(:member) { world.member }

    it "signs in a test email with 424242" do
      tokens = member["tokens"]

      expect(tokens.keys).to include("access", "refresh", "user_id")
      expect(client.tokens.verify(tokens["access"]).user_id).to eq(member["id"])
    end

    it "gets the signed-in user with their token (sessions.current_user)" do
      me = client.sessions.current_user(member["tokens"]["access"])

      expect(me["user"]).to include("id" => member["id"], "email" => member["email"])
      expect(me).not_to have_key("impersonation")
    end
  end

  describe "SMS OTP" do
    before(:context) { @sms = { phone: world.phone } }

    it "signs in a test phone number (+1 312 555 01xx) with 424242" do
      tokens = world.sign_in(@sms[:phone])
      @sms[:tokens] = tokens
      @sms[:user_id] = tokens["user_id"]

      expect(tokens.keys).to include("access", "refresh")
      expect(client.sessions.current_user(tokens["access"])["user"]["phone"].to_s.delete("^0-9")).to eq(@sms[:phone].delete("^0-9"))
    end

    it "lists the user's sessions (sessions.list, the secret key alone)" do
      sessions = client.sessions.list(@sms[:user_id])

      expect(sessions).to be_an(Array)
      expect(sessions).to all(include("id"))
      @sms[:session_id] = sessions.max_by { |s| s["created_at"].to_s }&.dig("id")
      expect(@sms[:session_id]).to be_a(String)
    end

    it "revokes a session (sessions.revoke, the secret key alone); the remote check refuses its token, the local one can't tell" do
      skip "needs the session id from sessions.list" unless @sms[:session_id]

      client.sessions.revoke(@sms[:user_id], @sms[:session_id])

      expect(client.tokens.verify(@sms[:tokens]["access"]).user_id).to eq(@sms[:user_id])
      expect { client.tokens.verify(@sms[:tokens]["access"], remote: true) }
        .to raise_error(Scute::InvalidToken) { |e| expect(e.reason).to eq(:revoked) }
      expect(api_status { client.sessions.refresh(@sms[:tokens]["refresh"]) }).to eq(401)
    end

    it "refreshes a session (sessions.refresh); the new token works with Scute" do
      tokens = world.sign_in(@sms[:phone])
      fresh = client.sessions.refresh(tokens["refresh"])
      @sms[:fresh] = fresh["access"]

      expect(fresh["access"]).to be_a(String)
      expect(fresh["access"] == tokens["access"]).to be(false)
      expect(client.sessions.current_user(fresh["access"])["user"]["id"]).to eq(@sms[:user_id])
    end

    it "the refreshed token verifies locally (tokens.verify)" do
      session = client.tokens.verify(@sms[:fresh])

      expect(session.user_id).to eq(@sms[:user_id])
      expect(session.app_id).to eq(client.tokens.public_app_id)
    end

    it "signs out (sessions.sign_out); the token stops working" do
      client.sessions.sign_out(@sms[:fresh])

      expect(api_status { client.sessions.current_user(@sms[:fresh]) }).to eq(401)
    end
  end
end
