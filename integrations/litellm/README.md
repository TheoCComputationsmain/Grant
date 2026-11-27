# Grant guardrail for LiteLLM · upstream PR package

**Target repo:** `BerriAI/litellm`
**Proposed path:** `litellm/proxy/guardrails/guardrail_hooks/grant/grant_guardrail.py`
**Tests:** `litellm/proxy/guardrails/guardrail_hooks/grant/test_grant_guardrail.py`

Grant pauses a tool call returned by any LLM until a human approves it. No wrapper, no new dependency, no custody of credentials or arguments.

## Behavior

| Grant response | Guardrail behavior |
| --- | --- |
| `status: approved` (rule / Always allow) | Response passes through untouched after one `POST /v1/approvals`; target <150ms. |
| `status: pending`, `approval_mode: checkpoint` | Raises `GrantApprovalRequired` with `request_id`, `approval_url`, `receipt_url`, `expires_at`. The caller shows the Grant popup immediately. |
| `status: pending`, `approval_mode: blocking` | Polls `GET /v1/approvals/{request_id}` until decided, approved, rejected, or expired. |
| Grant unreachable / 5xx | Fails closed unless `fail_open: true`. |

Only tool name, call ID, argument *key names*, and a SHA-256 hash of canonical arguments are sent to Grant. Values, credentials, payment details, and raw PII never leave the process.

## Copy-paste `config.yaml`

```yaml
model_list:
  - model_name: gpt-4o
    litellm_params:
      model: openai/gpt-4o
      api_key: os.environ/OPENAI_API_KEY

guardrails:
  - guardrail_name: grant-approval
    litellm_params:
      guardrail: litellm.proxy.guardrails.guardrail_hooks.grant.grant_guardrail.GrantGuardrail
      mode: post_call
      protected_tools:
        - send_email
        - issue_refund
        - create_charge
        - transfer_funds
        - publish_content
      grant_base_url: https://grant-consent.vercel.app
      api_key: os.environ/GRANT_API_KEY
      workspace: production
      approval_mode: checkpoint   # or: blocking
      timeout: 2.0
      poll_interval: 1.0
      poll_timeout: 300.0
      fail_open: false
```

Start with:

```bash
litellm --config config.yaml
```

Request-level opt-in (when `default_on` is false):

```json
{
  "model": "gpt-4o",
  "messages": [{"role": "user", "content": "Draft and send a refund note"}],
  "guardrails": ["grant-approval"]
}
```

`approval_mode: blocking` waits for the human; `checkpoint` returns the approval URL so the product can render the popup and retry the call after approval.

## Running the tests

```bash
python -m pytest integrations/litellm/test_grant_guardrail.py -q
```

Nine tests cover: no tool calls, unprotected tools, approved fast path under 150ms with no raw argument leakage, structured checkpoint, blocking approve, blocking reject, wildcard + fail-closed/fail-open, and invalid configuration. `httpx` is already bundled with LiteLLM, so the test suite adds no dependency.

## PR checklist for BerriAI/litellm

1. Fork and branch from `main`: `git checkout -b feat/grant-approval-guardrail`.
2. Copy `grant_guardrail.py` and `test_grant_guardrail.py` into the proposed directory above; add an empty `__init__.py`.
3. Register the guardrail in `litellm/proxy/guardrails/guardrail_hooks/__init__.py` and, if the repo uses a registry map, add `grant_guardrail` there. Do not add a dependency to `pyproject.toml` or `requirements.txt`.
4. Add a docs page under `docs/my-website/docs/proxy/guardrails/` using the `config.yaml` snippet above, and link it from the guardrails index.
5. Run `python -m pytest litellm/proxy/guardrails/guardrail_hooks/grant/test_grant_guardrail.py -q` and the repo's lint target.
6. Open the PR at **https://github.com/BerriAI/litellm/pulls** titled *Add Grant zero-custody human approval post-call guardrail*. State clearly that the network target is `https://grant-consent.vercel.app`, that the gate is optional/default-off, and that no credentials or raw arguments are transmitted.
7. Do not post fabricated benchmarks, paid reviewers, or fake upvotes. The included <150ms assertion is a local mock-transport test, not a network benchmark.
