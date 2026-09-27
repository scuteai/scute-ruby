# Changelog

## 0.1.0

- `Scute::Client`: authorization checks (single and batch), permissions, authorized users, data filters, step-up challenges, the signed policy snapshot, access requests, and agent management (register, suspend, tasks, delegation assertions).
- `Scute::Authorization`: `scute_authorize!` and `scute_can?` for controllers.
- Human steps with the task token (verify, submit a code, push status, reviewer approvals) and `say` lines; human tools for the model (`run.human_tools`, `run.ruby_llm_human_tools`).
- `Scute::Harness`: guards around the agents you build (permissions, verify_person, approval, requester_only, grounding, args, budget, content, define), runs with task tokens, verification and approvals, memory and Rails.cache stores, and a RubyLLM adapter.
