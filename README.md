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
scute.users.find_by_identifier("ada@example.com")
scute.users.list(page: 1)
scute.users.update(id, user_meta: { plan: "team" })
scute.users.deactivate(id) / activate(id) / delete(id)

scute.sessions.list(user_id)
scute.sessions.revoke(user_id, session_id)
scute.sessions.current_user(access_token)
scute.sessions.refresh(refresh_token)
scute.sessions.sign_out(access_token)
```

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
tool calls. A task revoked in Scute ends the run for good.

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

## License

MIT
