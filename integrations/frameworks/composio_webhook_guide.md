# Grant webhook gate · Composio / Pipedream tool routers

Drop-in gate for any tool router that can call an HTTPS endpoint before executing a tool. It uses the same zero-wrapper surfaces as every other Grant integration.

**Grant base URL:** `https://grant-consent.vercel.app` (derived from `.vercel/project.json` → `projectName: grant-consent`; override with `GRANT_BASE_URL`)
**Checkpoint:** `POST /v1/approvals` (alias: `POST /v1/gate/webhook`)
**Poll:** `GET /v1/approvals/{request_id}`
**Verify:** `POST /v1/receipts/verify`
**MCP tools:** `request_human_approval`, `check_approval_status` via `POST /api/mcp`
**Privacy:** `https://grant-consent.vercel.app/privacy`
**Watermark:** `● Protected by Grant · Zero-custody consent infrastructure`

## Zero-custody contract

Send only `agent_name`, `tool_name`, a short `summary`, and redacted `scope` metadata (IDs, counts, key names, or hashes). Never send credentials, API keys, card numbers, raw arguments, message bodies, or raw PII. Grant stores a hash of the redacted scope; signed receipts contain no scope values.

## 1. Create the checkpoint

```bash
curl -X POST https://grant-consent.vercel.app/v1/approvals \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer gr_live_...' \
  -d '{
    "agent_name": "composio-router",
    "tool_name": "issue_refund",
    "summary": "Refund order ORD-4821 for 48 USD",
    "scope": {"order_ref": "ORD-4821", "amount": 48, "currency": "USD"},
    "workspace": "store"
  }'
```

Response:

```json
{
  "id": "req_8Kx2mQ1pL",
  "request_id": "req_8Kx2mQ1pL",
  "status": "pending",
  "approval_url": "https://grant-consent.vercel.app/a/req_8Kx2mQ1pL",
  "receipt_url": "/receipt/req_8Kx2mQ1pL",
  "signed_receipt": "",
  "expires_at": "2026-11-27T10:21:00Z"
}
```

Omit `Authorization` for the 20 calls/hour demo tier. Create keys at `https://grant-consent.vercel.app/start` (`Get Your Free API Key →`).

## 2. Handle the decision

- `status: approved` with a non-empty `signed_receipt`: a standing rule or Always-allow policy already decided. Go to step 3.
- `status: pending`: return `approval_url` to the user and stop. Do not execute the tool. Either poll `GET /v1/approvals/{request_id}` in a background job or wait for Grant's callback to your router.
- Reject / expired: do not execute the tool.

Poll example:

```bash
curl https://grant-consent.vercel.app/v1/approvals/req_8Kx2mQ1pL
```

The response includes `status`, `decision`, `decision_type`, `signed_receipt`, `receipt_verified`, and `receipt_url`.

## 3. Verify the receipt, then execute

```bash
curl -X POST https://grant-consent.vercel.app/v1/receipts/verify \
  -H 'Content-Type: application/json' \
  -d '{"signed_receipt": "<signed_receipt>", "request_id": "req_8Kx2mQ1pL"}'
```

Proceed only when `valid` is `true` (and `request_id_matches` is `true` when supplied). Forward the receipt to the downstream tool as `X-Grant-Receipt: <signed_receipt>` and `X-Grant-Request-Id: <request_id>`; the downstream service can re-verify independently.

## Pipedream / Composio step pseudo-code

```js
export default async function grantGate({ steps }) {
  const event = steps.trigger.event.body;
  const base = process.env.GRANT_BASE_URL || 'https://grant-consent.vercel.app';

  const checkpoint = await fetch(`${base}/v1/approvals`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(process.env.GRANT_API_KEY
        ? { Authorization: `Bearer ${process.env.GRANT_API_KEY}` }
        : {}),
    },
    body: JSON.stringify({
      agent_name: 'tool-router',
      tool_name: String(event.tool_name || '').slice(0, 120),
      summary: String(event.summary || `Allow ${event.tool_name}?`).slice(0, 500),
      scope: {
        tool_call_id: String(event.call_id || '').slice(0, 120),
        argument_keys: Object.keys(event.arguments || {}).sort().slice(0, 50),
      },
      workspace: 'public',
    }),
  }).then((response) => response.json());

  if (checkpoint.status === 'pending') {
    return { execute: false, approval_url: checkpoint.approval_url, request_id: checkpoint.request_id };
  }

  const verification = await fetch(`${base}/v1/receipts/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      signed_receipt: checkpoint.signed_receipt || '',
      request_id: checkpoint.request_id,
    }),
  }).then((response) => response.json());

  return {
    execute: verification.valid === true,
    request_id: checkpoint.request_id,
    headers: {
      'X-Grant-Receipt': checkpoint.signed_receipt || '',
      'X-Grant-Request-Id': checkpoint.request_id,
    },
  };
}
```

Configure the router to skip the downstream step when `execute` is `false`, and surface `approval_url` as a clickable link.

## Cline / Cursor / Windsurf MCP setup

Copy `cline_mcp_config.json` into the client's MCP configuration (Cline: MCP Settings → Remote Servers; Cursor: `.cursor/mcp.json`; Windsurf: `~/.codeium/windsurf/mcp_config.json`). It points at:

```
https://grant-consent.vercel.app/api/mcp
```

Demo mode works with an empty `headers` object. For production, add a key:

```json
"headers": { "Authorization": "Bearer gr_live_..." }
```

Available tools: `request_human_approval` and `check_approval_status` (aliases: `grant.request_approval`, `grant.get_request`). Public contract: `https://grant-consent.vercel.app/openapi.json`.

## Rollout checklist

1. Keep the gate enabled for mutating tools only (`send_*`, `refund_*`, `charge_*`, `publish_*`, `write_*`, `delete_*`).
2. Confirm no router log records raw arguments or Grant receipt values.
3. Confirm every downstream action checks `valid: true` before execution.
4. Point users to `https://grant-consent.vercel.app/privacy` in the router's tool description.
