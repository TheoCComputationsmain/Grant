# Grant approval proxy Worker · Cloudflare templates submission

**Template name:** Grant · Human-in-the-loop AI tool approval
**Category:** AI / Security
**Description:** A zero-dependency Cloudflare Worker that gates mutating AI/tool calls behind a Grant human checkpoint and verifies signed receipts before forwarding upstream.

## What it does

1. Parses an OpenAI-style tool call (`tool_calls`, `tools`, `tool`, or `tool_name`).
2. For protected tools, calls `POST https://grant-consent.vercel.app/v1/approvals` with only the tool name, call id, argument key names, and a correlation hash.
3. If approved, verifies the signed receipt with `POST /v1/receipts/verify` and forwards the request to `UPSTREAM_URL` with `X-Grant-Receipt` and `X-Grant-Request-Id`.
4. If pending, returns `202` with `approval_url` and `request_id` (checkpoint mode). `GRANT_MODE=blocking` polls `GET /v1/approvals/{request_id}` instead.
5. If a caller supplies `X-Grant-Receipt`, the Worker verifies it first and rejects invalid receipts with `403` before any upstream call.

No credentials, payment details, raw arguments, or PII are sent to Grant. Grant never holds the upstream payload.

## Deploy

```bash
cd integrations/cloudflare-gateway
npx wrangler secret put UPSTREAM_URL
# optional, for production traffic beyond 20 calls/hour:
npx wrangler secret put GRANT_API_KEY
npx wrangler deploy
```

Derived base URL: `https://grant-consent.vercel.app` from `.vercel/project.json` → `projectName`. Override with `GRANT_BASE_URL` in `wrangler.toml` or a secret.

Test the gate:

```bash
curl -X POST https://GRANT-AI-GATEWAY.WORKERS.dev \
  -H 'Content-Type: application/json' \
  -d '{"tool_calls":[{"id":"call_1","function":{"name":"issue_refund","arguments":"{\"order_ref\":\"ORD-4821\"}"}}]}'
```

Expected while pending:

```json
{"status":"approval_required","request_id":"req_...","approval_url":"https://grant-consent.vercel.app/a/req_...","message":"Open the Grant pop-up, approve, then retry with X-Grant-Receipt."}
```

After approval, retry with the returned header:

```bash
curl -X POST https://GRANT-AI-GATEWAY.WORKERS.dev \
  -H 'Content-Type: application/json' \
  -H 'X-Grant-Receipt: <signed_receipt>' \
  -H 'X-Grant-Request-Id: <request_id>' \
  -d '{"tool_calls":[{"function":{"name":"issue_refund","arguments":{}}}]}'
```

`GET /health` returns the configured Grant base URL and the brand watermark.

## PR checklist for cloudflare/templates

1. Fork **https://github.com/cloudflare/templates** and branch `feat/grant-approval-worker`.
2. Add `worker.ts`, `wrangler.toml`, and this README under a new `grant-ai-gateway/` directory.
3. Keep the template dependency-free: no `package.json`, no `node_modules`, no `nodejs_compat` flag.
4. Run `npx wrangler deploy --dry-run` (or `npx wrangler dev` locally) with a placeholder `UPSTREAM_URL`; confirm no secrets are committed.
5. Open the PR at **https://github.com/cloudflare/templates/pulls** titled *Add Grant human approval AI gateway template*. Describe the checkpoint flow, the two Grant endpoints used, and the zero-custody boundary.
6. Do not include fabricated traffic numbers, paid reviewers, or fake endorsements.
