# frozen_string_literal: true

require_relative "live_helper"

# scute-ruby has no MFA API: MFA is the user's own, set up in the browser or
# app with their session. So this drives it over HTTP, as far as proving that
# sign-in with MFA works, and checks the tokens it ends with with scute-ruby.
RSpec.describe "Live: MFA (no scute-ruby API, over HTTP)", :live, order: :defined do
  before(:context) do
    @mfa = { email: world.next_email }
    @mfa[:tokens] = world.sign_in(@mfa[:email])
    @mfa[:user_id] = @mfa[:tokens]["user_id"]
    @mfa[:policy_before] = api.get!("/v1/apps/#{app_id}", as: :public)["mfa_policy"]
  end

  after(:context) do
    api.patch!(world.apps, body: { mfa_policy: @mfa[:policy_before] }) if @mfa&.dig(:policy_changed)
  end

  def as_user = [:session, @mfa[:tokens]["access"]]
  def code_now = ScuteLive::Crypto.totp(@mfa[:secret])

  it "enrolls TOTP and verifies it with a code computed from the secret (RFC 6238)" do
    started = api.post!(world.auth("/mfa/enroll"), body: { method: "totp", name: "live #{world.run_id}" }, as: as_user)
    @mfa[:secret] = started["secret"]
    enrollment = started["enrollment"]["id"]

    expect(started["provisioning_uri"]).to start_with("otpauth://totp/")
    wrong = api.post(world.auth("/mfa/enroll/verify"), body: { enrollment_id: enrollment, code: "000000" }, as: as_user)
    expect([wrong.status, wrong["error_code"]]).to eq([422, "invalid_code"]) unless code_now == "000000"

    verified = api.post!(world.auth("/mfa/enroll/verify"), body: { enrollment_id: enrollment, code: code_now }, as: as_user)
    expect(verified["enrollment"]).to include("method" => "totp", "verified" => true, "is_default" => true)
  end

  it "makes backup codes (inside the re-verify window after signing in)" do
    made = api.post!(world.auth("/mfa/backup-codes"), as: as_user)
    @mfa[:backup_codes] = made["backup_codes"]

    expect(made["backup_codes"].size).to eq(10)
    expect(api.get!(world.auth("/mfa/methods"), as: as_user)).to include("mfa_enabled" => true, "backup_codes_available" => 10)
  end

  it "then signing in needs MFA, and TOTP finishes it" do
    api.patch!(world.apps, body: { mfa_policy: "optional" })
    @mfa[:policy_changed] = true

    answer = world.sign_in(@mfa[:email])
    expect(answer).to include("mfa_required" => true, "app_user_id" => @mfa[:user_id])
    expect(answer.keys).not_to include("access")
    expect(answer["mfa_challenge"]).to include("method" => "totp", "status" => "pending")

    # Answering the challenge (the app's backend relays the code): POST /challenges/:token/verify.
    tokens = api.post!(world.auth("/challenges/#{answer['mfa_challenge']['token']}/verify"), body: { code: code_now })
    expect(client.tokens.verify(tokens["access"]).user_id).to eq(@mfa[:user_id])
    @mfa[:tokens] = tokens
  end

  it "takes a backup code once (a step-up answered with one)" do
    step_up = lambda do
      api.post!(world.auth("/challenges"), body: { purpose: "step_up", method: "backup_code", app_user_id: @mfa[:user_id] })["challenge"]["token"]
    end
    first = step_up.call
    done = api.post!(world.auth("/challenges/#{first}/verify"), body: { code: @mfa[:backup_codes].first })
    @mfa[:reverified] = first

    expect(done).to include("status" => "completed", "remaining_backup_codes" => 9)
    expect(api.post(world.auth("/challenges/#{step_up.call}/verify"), body: { code: @mfa[:backup_codes].first }).status).to eq(422)
  end

  # Removing a method needs a sign-in within the app's mfa_reverify_minutes
  # (5 at least) or a fresh verification (challenge). A test can't age its
  # session past the window, so the fresh sign-in is what passes here; the
  # completed backup-code step-up goes along as the verification.
  it "removes the TOTP method" do
    methods = api.get!(world.auth("/mfa/methods"), as: as_user)["methods"]
    totp = methods.find { |m| m["method"] == "totp" }

    removed = api.delete(world.auth("/mfa/methods/#{totp['id']}"), body: { challenge: @mfa[:reverified] }.compact, as: as_user)
    expect(removed.status).to eq(204)
    expect(api.get!(world.auth("/mfa/methods"), as: as_user)).to include("methods" => [], "mfa_enabled" => false)
  end
end
