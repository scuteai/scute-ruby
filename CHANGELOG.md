# Changelog

## Unreleased

- `users.previous_accounts(id)` lists a user's earlier, deleted accounts (someone deleted who signs in again gets a fresh account), and `users.merge(id, from:)` merges one into the live account: roles, passkeys, MFA methods and data move over, history stays on the old account.
- `users.find_by_identifier` searches the app's users with the secret key and keeps only an exact match: the email in any case, or the phone number as digits. It returns nil when nobody by that identifier uses the app, never creates a user, makes no call for a blank identifier, and looks at up to 10 pages of 100.
- `sessions.list` and `sessions.revoke` are documented as working with the secret key alone.
- Properties: `run.property(name)` reads one of the app's secrets inside a tool with the task token; `run.sign(name, claims:)` / `sign(name, data:)` signs with one of the app's key pairs (the private key never leaves Scute).

## 0.2.0

- Authentication: `scute.tokens.verify` checks your users' access tokens locally (RS256 with the app's JWKS, cached, re-read on key rotation at most once a minute, expiry with 30s leeway, the token must be this app's, user sessions only). `remote: true` also asks Scute that the session is live.
- `Scute::Authentication` for controllers: `scute_authenticate!`, `scute_session`, `scute_user_id`, `scute_signed_in?`; reads X-Authorization, a bearer header or the browser SDK's cookie. With `Scute::Authorization`, checks run as the signed-in user and carry the impersonation context.
- `scute.users`: list, get, find by identifier, create, invite, update, activate, deactivate, delete; impersonate, impersonations, stop_impersonating.
- `scute.sessions`: current_user, refresh, sign_out (with the user's tokens); list and revoke (secret key).

## 0.1.0

- `Scute::Client`: authorization checks (single and batch), permissions, authorized users, data filters, step-up challenges, the signed policy snapshot, access requests, and agent management (register, suspend, tasks, delegation assertions).
- `Scute::Authorization`: `scute_authorize!` and `scute_can?` for controllers.
- Hardening (same as @scute/harness): approvals bound to the exact call, proofs spent last, arguments as `context.args`, per-person run state, revoked tasks close the run, budgets reserved under a lock, linear-time content patterns that scan serialized objects and redact when flagging, token-boundary grounding over nested arguments.
- Human steps with the task token (verify, submit a code, push status, reviewer approvals) and `say` lines; human tools for the model (`run.human_tools`, `run.ruby_llm_human_tools`).
- `Scute::Harness`: guards around the agents you build (permissions, verify_person, approval, requester_only, grounding, args, budget, content, define), runs with task tokens, verification and approvals, memory and Rails.cache stores, and a RubyLLM adapter.
