# Grant workflow templates · n8n + Dify

Both templates call the live Grant deployment at `https://grant-consent.vercel.app`. Nothing to install locally, no credentials in the files, and no raw scope values in Grant requests.

## n8n · 3-step import

1. In n8n, open **Workflows → Import from File** and select `n8n-grant-approval-workflow.json` (or paste its contents into **Import from JSON**).
2. Add environment variables in the n8n instance: `GRANT_API_KEY` (optional `gr_live_...`; omit for 20 calls/hour demo) and `PROTECTED_ACTION_URL` (the HTTPS endpoint of the action you are gating).
3. Activate the workflow, POST a test payload to `/webhook/grant-gate`, open the returned `approval_url`, approve, then POST again to see the protected action run with a verified receipt.

Example test payload:

```bash
curl -X POST https://YOUR-N8N-HOST/webhook/grant-gate \
  -H 'Content-Type: application/json' \
  -d '{"agent":"support-agent","tool":"send_email","summary":"Send one follow-up email","reference":"ORD-4821"}'
```

Flow: trigger → `POST /v1/approvals` → approve? → `POST /v1/receipts/verify` → valid? → protected action. Pending and invalid paths return a checkpoint / 403 without executing anything.

Community gallery submission: attach the JSON to a post in the n8n community workflows category titled **Grant · Human approval gate**, with the tagline *One quiet approval before an agent sends, spends, refunds, or publishes.* No votes or outreach are requested.

## Dify · 3-step import

1. In Dify, open **Tools → Create Tool → Import from OpenAPI** and upload `dify-grant-tool.yaml`. Alternatively paste `https://grant-consent.vercel.app/openapi.json` as the import URL.
2. In the tool's credential form, leave the API key blank for demo mode or paste a `gr_live_...` key (Dify sends `Authorization: Bearer <key>`). Confirm three tools appear: `createApproval`, `getApproval`, `verifyReceipt`.
3. Add the tools to an agent with this instruction: *Before any sending, refund, charge, publish, or spend tool, call `createApproval`. If status is pending, show the approval_url and stop. On approval, call `verifyReceipt` and only then run the protected tool.*

Publisher metadata (inside the YAML under `info.x-dify`): provider `grant_consent`, label **Grant Consent**, tags `security`, `human-in-the-loop`, `approvals`, `guardrails`, `payments`.

## Safety notes

- Grant receives only `agent_name`, `tool_name`, a short summary, and redacted scope keys. Never put tokens, card numbers, emails, or raw payloads in `scope`.
- Signed receipts contain no scope values. Always verify with `POST /v1/receipts/verify` before executing the protected action.
- Public endpoints accept 20 calls/hour without a key. Production users should add `Get Your Free API Key →` from `https://grant-consent.vercel.app/start`.
