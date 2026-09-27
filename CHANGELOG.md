# Changelog

## 0.1.0

- `Scute::Client`: authorization checks (single and batch), permissions, authorized users, data filters, step-up challenges, the signed policy snapshot, access requests, and agent management (register, suspend, tasks, delegation assertions).
- `Scute::Authorization`: `scute_authorize!` and `scute_can?` for controllers.
- `Scute::Harness`: guards around the agents you build (permissions, verify_person, approval, requester_only, grounding, args, budget, content, define), runs with task tokens, verification and approvals, memory and Rails.cache stores, and a RubyLLM adapter.
