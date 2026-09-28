# scute (Ruby)

Scute for Ruby: sign-in verification and user management, authorization
checks for your app's users, and a harness of guards around the agents you
build.

```ruby
gem "scute"
```

Set `SCUTE_APP_ID` and `SCUTE_SECRET` (server side only). Ruby 3.2+, no
runtime dependencies.

## Authentication

Your frontend signs people in with a Scute SDK; your Ruby backend verifies
the access token it sends. Verification is local (RS256, the app's published
keys, cached and re-read on rotation) and checks the expiry and that the token
is this app's.

```ruby
scute = Scute::Client.new

session = scute.tokens.verify(token)   # raises Scute::InvalidToken (e.reason: :expired, :signature, ...)
session.user_id                        # the Scute app user id
session.impersonated?                  # someone (support) is signed in as this user
session.actor                          # who: { "kind" => "backend", "email" => "support@acme.com" }

scute.tokens.verify(token, remote: true) # also asks Scute, so a session revoked a moment ago fails
```

In a controller:

```ruby
class ApplicationController < ActionController::Base
  include Scute::Authentication
  include Scute::Authorization
  before_action :scute_authenticate!
  rescue_from Scute::Unauthenticated, with: -> { head :unauthorized }
end

# scute_session, scute_user_id, scute_signed_in?
# scute_authorize! now checks as the signed-in user, and tells Scute when
# someone is signed in as them (permissions marked "not while
# impersonating" are refused).
```

The token is read from `X-Authorization`, `Authorization: Bearer`, or the
cookie the browser SDK sets; override `scute_access_token` to read it
elsewhere.

### Users and sessions (secret key)

```ruby
scute.users.create("ada@example.com", meta: { plan: "pro" })
scute.users.invite("bob@example.com")
scute.users.find_by_identifier("ada@example.com") # or "+14155550123"; nil when nobody uses it
scute.users.list(page: 1)
scute.users.update(id, user_meta: { plan: "team" })
scute.users.deactivate(id) / activate(id) / delete(id)
scute.users.previous_accounts(id)          # their earlier, deleted accounts
scute.users.merge(id, from: previous_id)   # move one of those into this live account

scute.sessions.list(user_id)
scute.sessions.revoke(user_id, session_id)
scute.sessions.current_user(access_token)
scute.sessions.refresh(refresh_token)
scute.sessions.sign_out(access_token)
```

`find_by_identifier` matches the email in any case, or the phone number
as digits (include the country code), and never creates a user.
`sessions.list` and `sessions.revoke` need only the secret key, no user
session. Meta keys have to be user meta fields the app declares.

Someone deleted who signs in again gets a fresh account with a new id.
`previous_accounts` lists their earlier, deleted accounts, and `merge`
brings one into the live account: roles, object roles, passkeys, MFA
methods and unused backup codes move over, meta and attributes merge (the
live account wins), and history stays on the old account. An account can
be merged once (`already_merged` after that). Someone deactivated and then
deleted can't sign in again this way (`account_deactivated`).

### Signing in as a user (support access)

Off until the app turns it on. The session is short and never refreshed;
its token names who is really acting.

```ruby
tokens = scute.users.impersonate(user_id, reason: "Ticket 4411", actor: { email: "support@acme.com" }, minutes: 15)
# or actor_user_id: an app user who holds user:impersonate
scute.users.impersonations(user_id)
scute.users.stop_impersonating(user_id)
```

Hand `tokens` to the browser (`scute.beginImpersonation(tokens)` in
@scute/js-core); `stopImpersonating()` there brings the support person's own
session back.

## Authorization

```ruby
scute = Scute::Client.new

decision = scute.authz.check(user_id: user.scute_id, action: "refund", resource: "invoice:42")
decision.allowed?        # true only for a plain allow
decision.step_up?        # verify first: scute.authz.start_step_up(user_id:, decision:, method: "email_otp")
decision.needs_approval? # a reviewer approves: scute.authz.create_request(user_id, action:, resource:)
decision.explanation     # "Ada can refund invoice 42: ..."

scute.authz.check_batch([{ user_id: "u1", action: "read", resource: "invoice:1" }, ...])
scute.authz.permissions(user_id, resource: "document:42")
scute.authz.filter(user_id:, action: "read", resource_type: "invoice") # for list queries
```

In a controller:

```ruby
class InvoicesController < ApplicationController
  include Scute::Authorization
  rescue_from Scute::Forbidden, with: -> (e) { render json: { error: e.message }, status: :forbidden }

  def refund
    scute_authorize!("refund", "invoice:#{params[:id]}", challenge: params[:challenge])
    # ...
  end

  private

  def scute_user_id = current_user.scute_id
end
```

## Agents

Register the agent in Scute with an owner and roles (its ceiling). Each job
runs as a short-lived task; every tool call is checked against the agent's
roles, the person it works for and the task, all three.

```ruby
harness = Scute::Harness.new(
  agent: "support-bot",
  guards: [
    Scute::Guards.permissions,
    Scute::Guards.approval(when: { tier: :high }),
    Scute::Guards.grounding,
    Scute::Guards.args(refund_invoice: { amount: { max: 500 } }),
    Scute::Guards.budget(calls: 20, per_hour: { high: 5 }),
    Scute::Guards.content(pii: %i[card ssn])
  ],
  tools: { refund_invoice: { tier: :high } },
  store: Scute::Harness::CacheStore.new(Rails.cache) # runs resume across requests and processes
)

run = harness.run(id: conversation.id, acts_for: user.scute_id, task: { actions: %w[invoice:read invoice:refund] })

refund = run.wrap("refund_invoice") { |args| Billing.refund(**args) }
refund.call(invoice_id: "INV-1", amount: 90) # the result, or a message for the model
```

With [RubyLLM](https://rubyllm.com):

```ruby
chat = RubyLLM.chat
chat.with_tool(run.ruby_llm(RefundInvoice, chat: chat))
```

Guards answer `:proceed`, `:transform`, `:approve`, `:verify`, `:guide`,
`:redirect` or `:deny`; the strictest enforced answer wins and a guard that
raises counts as deny. Each guard runs in `:enforce`, `:monitor` (alerts via
`on_alert`, never blocks) or `:observe` mode; `on_decision` sees everything.

Tool names map to permissions: `refund_invoice` needs `invoice:refund` on
the invoice named by `invoice_id` (or `invoiceId`, or `id`). The call's
arguments reach the engine as `context.args` (`context.args.amount < 500`);
the object's attributes come from what Scute stores, which the model can't
override. Override per tool with
`tools: { send_money: { permission: "payment:create", key: :to }, get_weather: false }`.

Reviewer approvals cover one exact call (its arguments go with the request),
and approvals and verifications are spent only on a call no other guard
stops. Checks within a run go one at a time, so budgets hold under parallel
tool calls. A task revoked in Scute ends the run for good, and so does an
agent Scute paused for going over its budget (the run never starts a new
task for it).

People in the loop, all with the task token:

- Verify: `run.start_verification(method: "email_otp")` sends a code (or
  `sms_otp`, `totp`, `entra_push`), `run.submit_code(code)` passes on what the
  person read out, `run.verification_status` checks a push.
- Let the model do it: `chat.with_tools(*run.ruby_llm_human_tools)` gives it
  `scute_verify_person`, `scute_submit_code`, `scute_check_verification`,
  `scute_approval_status` and `scute_whoami` (`run.human_tools` returns plain
  callables for other frameworks). Every answer has a `say` line the agent
  can speak as is.
- Confirm: `run.confirm(tool, args)` when the person confirmed a call in your UI.
- Reviewer approval: filed as a Scute access request for the exact
  operation; `verdict.say` tells the person, `run.approval_status(id)` checks.

Your own guard:

```ruby
Scute::Guards.define("no-weekend-refunds") do |call|
  call.guide("Refunds wait until Monday.") if call.tool == "refund_invoice" && [0, 6].include?(Time.now.utc.wday)
end
```

### Plans and previews

When the agent knows every call it means to make, it can ask for one review
of all of them:

```ruby
plan = run.request_plan([{ tool: "refund_invoice", args: { invoice_id: 1, amount: 40 } },
                         { tool: "refund_invoice", args: { invoice_id: 2, amount: 15 } }], reason: "Ticket 88")
plan["say"]      # tell the person it's waiting for a reviewer
run.plan_status  # where it stands, and which steps ran
```

Once a reviewer approves it, each step that needed approval runs once, with
exactly those arguments, through the usual checks. When nothing needs
approval, the answer's status is `not_needed`.

`run.preview(tool, args)` asks what a call would need right now (a dry run,
an `Authz::Decision`): it doesn't count toward budgets and doesn't use up a
verification or an approval.

### Tool drift and decoys

Report the tools the model sees, and Scute notices if one changes later (a
changed description is a known prompt injection route):

```ruby
run.report_tools(tools.map { |t| { name: t.name, description: t.description, input_schema: t.params_schema } })
```

Only a hash of each definition leaves your process (the same hash the
TypeScript harness sends). The first report is the baseline.

Decoy tools are tools no legitimate task calls. Offer them to the model like
any other, and list them in `Scute::Guards.decoy`. A call is refused, Scute
pauses the agent and alerts your team, and the run is over:

```ruby
Scute::Harness.new(agent: "support-bot", guards: [Scute::Guards.decoy(%w[export_all_customers]), Scute::Guards.permissions])
```

## Live suite

`bundle exec rspec` runs against a fake API. `spec/live` runs scute-ruby
against a real Scute API instead, with no fakes:

```sh
bundle exec rake live
```

Without credentials it prints one line saying so and exits 0, so it's safe
anywhere. `bundle exec rspec` and CI never run it.

What it covers (the parts scute-ruby has no method for go over plain HTTP,
and each spec says so):

- The app: its data and the signing keys.
- Sign-in: email OTP and SMS OTP with test identities (over HTTP: that's
  the end user's side), then `sessions.current_user`, `refresh`,
  `sign_out`, `list` and `revoke`.
- Tokens: `tokens.verify` with the app's JWKS (tampered, expired and
  not-this-app tokens refused), `remote: true`, and `Scute::Authentication`
  / `Scute::Authorization` in a small Rack app (Rack::MockRequest).
- MFA (no scute-ruby API, over HTTP): TOTP enrollment with codes computed
  per RFC 6238, sign-in that needs MFA, backup codes, removing the method.
- Users: create, get, find by identifier, list, update, deactivate,
  activate, delete; a deleted user signing in again (a fresh account,
  `previous_accounts`, `merge`), and someone deactivated and deleted
  refused at sign-in.
- Signing in as a user: `impersonate` (the `act` claim), `impersonations`,
  a "not while impersonating" permission denied, `stop_impersonating`.
- Authorization: policy import, role assignment, `check`, `check_batch`,
  `permissions`, `authorized_users`, `filter`, step-ups, the signed
  snapshot, access requests.
- Agents: `agents.create`, tasks, `Scute::Harness` checks (allowed,
  outside the task, beyond the agent's roles), human steps with a test
  identity, reviewer approvals, `run.property` and `run.sign` (verified
  with the property's JWKS), suspend and resume, a budget of 2 that pauses
  the agent on its 3rd action (and closes the run). Plans, previews, tool
  drift and decoys are written and skipped until the API has them.
- Auth MCP: JSON-RPC over HTTP with an agent key (`scute_identify`,
  `scute_submit_code`, `scute_check`), then the backend's conversation
  lookup and check.
- The decision log: rows for the checks above.

It signs in only test identities (`live-ruby-<run>-<n>+scute_test@example.com`
and +1 312 555 01xx), which always get the code 424242 and are sent nothing.
Everything it makes is named `live-<run>` and removed at the end, failures
or not; the app's policy and settings are put back as they were. (Access
requests and decision log rows stay: the API has no way to delete them.)
Tokens, secrets and codes other than 424242 never reach the output.

A known SDK bug can be marked with `pending("<what it does instead>")`:
RSpec fails a pending example once it passes, so a fix shows up as a
failure until the `pending` line goes.

### Credentials

The suite needs its own app on a non-production API with test identities
allowed. Make one (and a fresh secret) with:

```sh
heroku run -a scute-api-v2 rake "sdk_live:setup[ruby]"
```

It prints three lines. Put them in `.sdk-live/ruby.env` in the folder that
holds this checkout (outside the repo, never committed):

```sh
SCUTE_LIVE_BASE_URL=https://...
SCUTE_LIVE_APP_ID=app_...
SCUTE_LIVE_SECRET=...
```

or export them, or point `SCUTE_LIVE_ENV_FILE` at another file.

## License

MIT
