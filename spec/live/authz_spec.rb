# frozen_string_literal: true

require_relative "live_helper"

RSpec.describe "Live: authorization", :live, order: :defined do
  before(:context) { world.policy! }

  let(:authz) { client.authz }
  let(:biller) { world.user(:biller, roles: ["billing"]) }

  def check(user, action, resource = nil, **options)
    authz.check(user_id: user["id"], action: action, resource: resource, **options)
  end

  # scute-ruby has no policy methods: POST /v1/apps/:app_id/authz/policy/import.
  describe "policy import (over HTTP)" do
    it "plans it (dry run), applies it, and a second import changes nothing" do
      result = world.policy!

      expect(result[:plan]).to include("dry_run" => true, "applied" => false, "prune" => true)
      expect(result[:applied]).to include("dry_run" => false)
      again = api.post!(world.apps("/authz/policy/import"), body: { document: ScuteLive::World::POLICY, dry_run: false, prune: true })
      expect(again).to include("changes" => [], "applied" => false)
    end
  end

  # scute-ruby has no role assignment: POST and DELETE /v1/apps/:app_id/authz/users/:id/roles.
  describe "roles (assigned over HTTP)" do
    it "assigns viewer (read yes, refund no) and removes it (read no)" do
      reader = world.user(:reader)
      world.grant(reader["id"], "viewer")

      expect(check(reader, "read", "invoice:INV-1")).to be_allowed
      refund = check(reader, "refund", "invoice:INV-1")
      expect(refund).to be_denied
      expect(refund.reason).to eq("no_role_grants_permission")

      world.revoke(reader["id"], "viewer")
      expect(check(reader, "read", "invoice:INV-1")).to be_denied
    end
  end

  describe "checks" do
    it "allows with the role that grants it, and explains" do
      decision = check(biller, "read", "invoice:INV-1")

      expect(decision).to be_allowed
      expect(decision).to have_attributes(reason: "role_grant", permission: "invoice:read", roles: ["billing"])
      expect(decision.explanation).to include(biller["email"])
    end

    it "asks for a step-up, completed with a test identity (424242)" do
      decision = check(biller, "refund", "invoice:INV-2")
      expect(decision).to be_step_up
      expect(decision.step_up).to include("method" => "email_otp", "authorizes_action" => "invoice:refund")

      challenge = authz.start_step_up(user_id: biller["id"], decision: decision)
      # The person types the code; scute-ruby has no method to pass it on: POST /challenges/:token/verify.
      api.post!(world.auth("/challenges/#{challenge['token']}/verify"), body: { code: ScuteLive::World::CODE })

      done = check(biller, "refund", "invoice:INV-2", challenge: challenge["token"])
      expect(done).to be_allowed
      expect(done.reason).to eq("verified")
    end

    it "check_batch answers like single checks over a small matrix" do
      nobody = world.user(:nobody)
      matrix = [[biller, "read", "invoice:INV-1"], [biller, "delete", "account:1"], [biller, "refund", "invoice:INV-3"],
                [biller, "void", "invoice:INV-3"], [nobody, "read", "invoice:INV-1"], [biller, "export", "invoice:INV-1"]]

      batch = authz.check_batch(matrix.map { |user, action, resource| { user_id: user["id"], action: action, resource: resource } })
      singles = matrix.map { |user, action, resource| check(user, action, resource) }

      expect(batch.map { |d| [d.decision, d.reason] }).to eq(singles.map { |d| [d.decision, d.reason] })
      expect(batch.map(&:decision)).to eq(%w[allow allow allow_with_step_up allow_with_approval deny deny])
      expect(batch.last(2).map(&:reason)).to eq(%w[no_role_grants_permission unknown_permission])
    end

    it "lists a user's permissions" do
      permissions = authz.permissions(biller["id"])

      expect(permissions["roles"]).to eq(["billing"])
      expect(permissions["permissions"]).to include("invoice:read", "invoice:refund", "invoice:void", "account:delete")
      expect(permissions).to include("step_up" => ["invoice:refund"], "approval" => ["invoice:void"])
    end

    it "lists who may do something" do
      who = authz.authorized_users(action: "void", resource: "invoice")

      expect(who).to include("permission" => "invoice:void", "everyone" => false)
      expect(who["users"].map { |u| u["id"] }).to include(biller["id"])
    end

    it "builds data filters: all, none, or a condition with the user filled in" do
      owner = world.user(:doc_owner, roles: ["doc_owner"])

      expect(authz.filter(user_id: biller["id"], action: "read", resource_type: "invoice")["filter"]).to eq("all")
      expect(authz.filter(user_id: world.user(:nobody)["id"], action: "read", resource_type: "invoice")["filter"]).to eq("none")
      tree = authz.filter(user_id: owner["id"], action: "read", resource_type: "document")["filter"]
      expect(tree).to be_a(Hash)
      expect(JSON.generate(tree)).to include(owner["id"], "resource.owner")

      mine = { type: "document", key: "D-1", attributes: { owner: owner["id"] } }
      theirs = { type: "document", key: "D-2", attributes: { owner: biller["id"] } }
      expect(check(owner, "read", mine)).to be_allowed
      expect(check(owner, "read", theirs).reason).to eq("condition_failed")
    end
  end

  describe "the policy snapshot" do
    it "is signed with the app's keys (checked here against the JWKS it names)" do
      snapshot = authz.snapshot
      claims = ScuteLive::Crypto.verify_rs256(snapshot["token"], api.get!(snapshot["jwks"], as: :public))

      expect(claims).to include("typ" => "scute-authz-snapshot", "version" => snapshot["version"])
      expect(claims.dig("policy", "roles").keys).to include("viewer", "billing", "doc_owner", "support_agent")
      expect(claims.dig("policy", "permissions", "invoice:void")).to include("requires_approval" => true)
    end

    it "gives the same decisions locally as the server over a small matrix" do
      skip "scute-ruby has no local decision engine: it fetches the signed snapshot (authz.snapshot) but doesn't evaluate it"
    end
  end

  describe "access requests" do
    it "a role request, approved, grants the role" do
      asker = world.user(:asker)
      request = authz.create_request(asker["id"], role: "viewer", reason: "#{world.prefix}: reads invoices")

      expect(request).to include("kind" => "role", "status" => "pending", "role" => "viewer")
      expect(authz.requests(status: "pending", user_id: asker["id"]).map { |r| r["id"] }).to eq([request["id"]])
      expect(check(asker, "read", "invoice:INV-1")).to be_denied

      decided = authz.decide_request(request["id"], :approve, note: "live #{world.run_id}")
      world.track_grant(asker["id"], "viewer")
      expect(decided).to include("status" => "approved", "decision_note" => "live #{world.run_id}")
      expect(check(asker, "read", "invoice:INV-1")).to be_allowed
    end

    it "an approved operation is spent by one check" do
      expect(check(biller, "void", "invoice:INV-7")).to be_needs_approval

      request = authz.create_request(biller["id"], action: "void", resource: "invoice:INV-7", reason: "#{world.prefix}: duplicate")
      expect(request).to include("kind" => "operation", "permission" => "invoice:void", "resource" => "invoice:INV-7")
      authz.decide_request(request["id"], :approve)

      used = check(biller, "void", "invoice:INV-7", approval: request["id"])
      expect(used).to be_allowed
      expect(used.reason).to eq("approved")
      again = check(biller, "void", "invoice:INV-7", approval: request["id"])
      expect(again).to be_needs_approval
      expect(again.approval).to include("error" => "approval_not_usable")
    end

    it "a denied request doesn't help" do
      request = authz.create_request(biller["id"], action: "void", resource: "invoice:INV-8")

      expect(authz.decide_request(request["id"], :deny, note: "no")).to include("status" => "denied")
      expect(check(biller, "void", "invoice:INV-8", approval: request["id"])).to be_needs_approval
    end
  end
end
