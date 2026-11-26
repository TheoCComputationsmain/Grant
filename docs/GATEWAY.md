# Grant Gateway

The gateway is the real product surface. Agent builders do not add Grant to their code; they point their tool client at Grant instead.

```text
Agent / MCP client / HTTP client
        ↓
Grant Gateway URL
        ↓
MCP server / REST API / internal tool
```

When a call matches policy, Grant pauses it, opens an approval page, and releases the call only after a human decides.

---

## The four interception choke points

| Layer | Status | What it protects |
| --- | --- | --- |
| **1. MCP / API tool gateway** | Implemented | MCP `tools/call`, OpenAPI wrappers, internal APIs |
| **2. Outbound HTTP / local proxy** | Implemented | Computer-use agents, local frameworks, desktop tools |
| **3. Browser injected script** | Implemented (`/grant-inject.js`) | Web agents making `fetch`/XHR calls or high-risk DOM clicks |
| **4. Agent-to-agent message bus** | Implemented (`POST /v1/a2a/gate`) | Multi-agent task handoffs and delegation payloads |

All four surfaces pause the action and deliver the same hosted approval card. The injected script needs no browser extension packaging; load it directly in the agent's page. OAuth scope templates are not a fifth choke point: they are machine-readable rules that map connected-account scopes to gateway reviews, served at `GET /v1/policies/oauth-scopes`. Grant is not an OAuth broker and never sits in a provider token path.

---

## A better idea than wrapping OAuth directly

Instead of becoming an OAuth provider, Grant uses a **capability retry gate**:

1. The gateway sees a sensitive call.
2. It returns `202` with `grant_id`, `approval_url`, and a retry header.
3. The human approves in the browser.
4. The client retries with `X-Grant-Request-Id: req_...` **and** `X-Grant-Receipt: <signature>` from the signed permission returned by `GET /v1/requests/{grant_id}`.
5. Grant verifies the HMAC receipt, its scope hash, workspace, expiry, and gateway binding, then forwards the call using the **fresh** request headers.

This means Grant does not need to store OAuth tokens, refresh tokens, or provider credentials. It turns any existing tool boundary into per-action consent without negotiating provider integrations.

The hosted gateway also holds the connection for up to `GRANT_GATEWAY_WAIT_SECONDS` (default 20, max 45 on Vercel) so many clients never see the 202 at all — they simply wait and then receive the normal upstream result.

---

## Layer 1: register a gateway

```bash
grantctl gateway \
  --name "Payments API" \
  --upstream https://api.example.com \
  --workspace support \
  --paths "/transfer,/payment,/refund,/database" \
  --body-keys "amount,recipient,card" \
  --url https://grant-approve.vercel.app
```

Response:

```json
{
  "id": "gw_ab12cd34",
  "token": "gw_••••••••••••••••••••••••",
  "http_url": "https://grant-approve.vercel.app/g/http/gw_.../",
  "mcp_url": "https://grant-approve.vercel.app/g/mcp/gw_...",
  "policy": {
    "default_action": "review",
    "sensitive_methods": ["POST", "PUT", "PATCH", "DELETE"]
  }
}
```

The token is a capability. Anyone with the gateway URL can use it. Store it privately.

### Point an HTTP client at it

Replace:

```text
https://api.example.com/transfer
```

with:

```text
https://grant-approve.vercel.app/g/http/gw_.../transfer
```

Method, query, body, and headers are forwarded unchanged after approval.

### Point an MCP client at it

Replace the MCP server URL with:

```text
https://grant-approve.vercel.app/g/mcp/gw_...
```

For `tools/call` requests, Grant checks `params.name`. Tool names containing `transfer`, `payment`, `refund`, `delete`, `send`, `publish`, `purchase`, or `execute` trigger review by default.

If the approval does not arrive before the wait window ends, Grant returns a JSON-RPC result containing the approval link instead of blocking forever:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "grant": {
      "status": "pending",
      "approval_url": "https://grant-approve.vercel.app/a/...",
      "message": "Grant · ... Approve once · Always allow · Reject.",
      "retry_header": "X-Grant-Request-Id"
    }
  }
}
```

---

## Layer 2: local proxy daemon

For local frameworks and computer-use agents, run a loopback proxy in front of the upstream tool:

```bash
grantctl proxy \
  --upstream https://api.example.com \
  --name "Local tool firewall" \
  --workspace support \
  --port 8787 \
  --open \
  --url https://grant-approve.vercel.app
```

Then point your local agent at:

```text
http://127.0.0.1:8787/
```

The daemon:

1. registers a Grant gateway automatically;
2. forwards every local call to the hosted gateway;
3. opens the approval link in a browser when `--open` is set;
4. polls the Grant request;
5. retries automatically with `X-Grant-Request-Id` after approval;
6. returns the upstream response to the local agent.

From the agent’s point of view, the call simply took longer. No SDK call is required.

With `--open`, the daemon launches the system default browser at the hosted 460×640 approval pop-up and holds the outbound packet until a signed decision arrives. The browser inject script and the A2A gate use the same hosted service; none of them is a separate consent system.

---

## Layer 3: browser injected script

Load the script on the page where a web/computer-use agent operates:

```html
<script src="https://grant-approve.vercel.app/grant-inject.js"
  data-grant-url="https://grant-approve.vercel.app"
  data-agent="web-agent"
  data-workspace="public"
  data-sensitive-paths="stripe.com,googleapis.com"
  data-risky-clicks="send,pay,delete,transfer,publish"
  data-max-wait-ms="300000"></script>
```

The script:

1. wraps `window.fetch` and `XMLHttpRequest` and pauses calls to the configured sensitive hosts;
2. intercepts risky button/link clicks (`Send`, `Pay`, `Delete`, `Transfer`, `Publish`) in the capture phase, including controls inside Shadow DOM that bubble to the document;
3. posts a redacted `who/what/why/scope` request to `POST /v1/requests` with `channel: browser_inject`, then opens the 460×640 hosted card with `window.open`;
4. resolves on a validated `grant:decision` `postMessage` or by polling `GET /v1/requests/{id}` for the signed decision, and dispatches `grant:inject-decision` on `window`;
5. never reads host-page cookies, tokens, or request bodies — only the destination host, method, and a truncated control label are sent.

Public request and A2A endpoints return `Access-Control-Allow-Origin: *` and answer `OPTIONS` preflight. They accept no credentials, so a wildcard is safe. Popup `postMessage` still validates the parent origin and `event.source`; the polling path covers cases where the popup cannot message back.

---

## Layer 4: agent-to-agent message bus

Place the gate in front of the handoff from Agent A to Agent B:

```python
from grant import Grant

grant = Grant("https://grant-approve.vercel.app", workspace="team")
hold = grant.a2a_gate(
    sender="planner",
    receiver="billing-agent",
    task="pay the outstanding invoice",
    payload={"amount": 120},
    ttl_minutes=30,
)
if hold.status == "pending":
    show_to_human(hold.approval_url)   # dashboard, Slack, or browser tab
    # do not deliver the task to Agent B until the receipt is signed
```

`POST /v1/a2a/gate` returns `202` with `grant_id`, `approval_url`, and a retry header when the task mentions payment, refunds, spend, transfer, deletion, sending, publishing, signing, external actions, or purchases — or when `require_approval` is true. Routine handoffs return `200 passed`. Amount-like payload keys (`amount`, `spend`, `cost`, `value`, `budget`) with a positive number always trigger review. The approval card renders in the supervising human's browser; delivery waits for the same signed receipt as every other choke point.

---

## SaaS OAuth scope templates

Grant does not store provider tokens. Machine-readable templates map standard OAuth scopes to Grant gateway rules, and are served from the API so a client can load them at runtime:

- `GET /v1/policies/oauth-scopes` — full template document
- `GET /v1/policies/oauth-scopes/{scope}` — one scope, e.g. `stripe.charges`

The source of truth is `grant/policies/oauth_scopes.json`. Included scopes: `gmail.send`, `gmail.readonly`, `gmail.modify`, `drive.file`, `calendar.events`, `stripe.charges`, `stripe.refunds`, `slack.chat.write`, `slack.files.write`.

Each template declares the provider, risk, tool names, trigger body keys, and a redacted scope payload. The OAuth provider still performs sign-in and token issuance; Grant never receives an access token, refresh token, authorization code, or provider secret.

### Google Workspace template

```bash
grantctl gateway \
  --name "Google Workspace tools" \
  --upstream https://tools.internal/google \
  --workspace personal \
  --tools "send_email,delete_file,share_file,create_event" \
  --body-keys "recipient,file_id,attendees" \
  --url https://grant-approve.vercel.app
```

### Slack template

```bash
grantctl gateway \
  --name "Slack tools" \
  --upstream https://tools.internal/slack \
  --workspace team \
  --tools "post_message,upload_file,delete_message,invite_user" \
  --paths "/chat.postMessage,/files.upload,/conversations.invite" \
  --url https://grant-approve.vercel.app
```

This converts static “connected once” access into per-action human approval at the tool boundary. It is not an official OAuth broker and should not be described as one.

---

## Policy reference

| Field | Meaning |
| --- | --- |
| `default_action` | `review` pauses everything; `allow` only pauses matches |
| `sensitive_tools` | Substrings matched against MCP tool names |
| `sensitive_paths` | Substrings matched against HTTP paths |
| `sensitive_methods` | Methods that count for path matching |
| `body_keys` | Payload keys that trigger review when present |
| `ttl_minutes` | Approval window, default 15 |

Start with `default_action: "review"` for a new gateway. Switch to `allow` once you know the exact sensitive surfaces.

---

## Credential handling

- Upstream headers are forwarded in memory for the lifetime of a pending call.
- Grant does not write upstream `Authorization`, cookies, or API keys to SQLite or Blob.
- Blob stores only request metadata, redacted scope, and the human decision.
- Grant does not log request headers or raw bodies.
- Scope shown on the approval page is redacted before storage.
- Retry requests use fresh headers from the client, not stored credentials.

This is the minimum trust boundary needed for a transparent gateway. If you require zero credential exposure to Grant, the gateway cannot transparently proxy the upstream call; the client must perform the final request itself.

---

## Approval triggers

Grant keeps the approval card pure and fast. Five triggers can surface the same decision screen:

1. **OAuth-style popup** — open the approval URL in a 460×640 centered window. Pass `parent_origin` through `POST /v1/requests` or gateway registration, add that origin to `GRANT_POPUP_ALLOWED_ORIGINS`, and Grant will send a `postMessage` decision and auto-close.
2. **Shadow-DOM widget** — load `/widget.js` with `data-approval-url`. The launcher and its styles live inside an isolated shadow root, so host-page CSS cannot clash with Grant's paper-and-burgundy system.
3. **Injected script** — load `/grant-inject.js` to pause browser `fetch`/XHR and risky clicks before they leave the page.
4. **A2A handoff** — call `POST /v1/a2a/gate` to pause an agent-to-agent delegation and push the card to a supervising human.
5. **Mobile deep link** — send the approval URL in Slack or email. It renders as a compact card on small screens; `?compact=1` forces the compact layout for testing.

Every card ends with `● Protected by Grant · Zero-custody consent infrastructure`. After a decision, the card does not disappear: it becomes a **Magic Receipt**. The heading reads `Approved. Receipt req_... recorded.` (or the matching title for a refusal / rule), with two paths: `Want to see every AI agent you've authorized—or revoke Always allow anytime?` → `Open Your Free Grant Dashboard →`, and `Building AI agents? Protect your own users' actions in 2 minutes.` → `Get Your Free API Key →`. The dashboard link uses a signed, HttpOnly `grant_dashboard` cookie that silently creates or reuses a workspace on approval. No password form or email capture is required; billing email stays optional for Cashfree matching. The builder CTA starts at `/start?from=receipt`, then the workspace dashboard mints a real `gr_live_…` key after a one-time email sign-in; only the SHA-256 digest is stored.

Upgrade nudges are contextual drawers inside the card, never a full pricing table. Soft limits keep agents running and explain how to upgrade in the console.

---

## Current limits

- Fast-path pending snapshots are in-process; durable cross-instance state is mirrored to a private Vercel Blob store with separate immutable paths for pending and decided states.
- Hosted waiting is capped at 45 seconds because of serverless function limits. The 202 + retry flow handles longer approvals.
- SQLite audit history is instance-local on serverless. Durable Neon/Postgres schema is prepared in `migrations/001_neon_schema.sql` and activates automatically when a `DATABASE_URL` is configured; it is not applied until credentials are provisioned.
- No browser extension package is published; the injectable `/grant-inject.js` route and the local daemon cover the same interception paths.
- The builder CTA on the Magic Receipt starts at `/start?from=receipt` and lands on the workspace dashboard, where `POST /api/keys` mints a real `gr_live_…` key.
- OAuth provider partnerships are not implemented; policy templates are the safe MVP.
