# scute (Ruby)

Scute for Ruby: authorization checks for your app's users, and a harness of
guards around the agents you build.

```ruby
gem "scute"
```

Set `SCUTE_APP_ID` and `SCUTE_SECRET` (server side only). Ruby 3.2+, no
runtime dependencies.

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
the invoice named by `invoice_id` (or `invoiceId`, or `id`), with plain
arguments as attributes for policy conditions. Override per tool with
`tools: { send_money: { permission: "payment:create", key: :to }, get_weather: false }`.

People in the loop: `run.start_verification(verdict:)` and
`run.complete_verification` (Scute confirms the challenge is theirs),
`run.confirm(tool, args)` when the person confirmed a call in your UI, and
reviewer approvals filed as Scute access requests.

Your own guard:

```ruby
Scute::Guards.define("no-weekend-refunds") do |call|
  call.guide("Refunds wait until Monday.") if call.tool == "refund_invoice" && [0, 6].include?(Time.now.utc.wday)
end
```

## License

MIT
