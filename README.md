# Grant

**Consent infrastructure for AI agents.**

When an agent acts on someone’s behalf — sends a message, refunds an order, writes a record, publishes content, spends budget — Grant appears with one quiet question:

> Allow this, or not?

The human gets one link. The agent gets a signed permission. Grant keeps the audit trail.

This is a new product with its own brand, repository, database, and deployment. It is not a feature of AgentGrid or TraceLock.

---

## The idea

People do not install HTTPS. They encounter it exactly when trust matters.

Grant works the same way, but the primary integration is **invisible**:

1. An MCP client or agent sends a tool call.
2. Its URL points at Grant Gateway instead of the upstream tool server.
3. Grant matches the call against policy and pauses it.
4. The human gets one approval page: **Approve once**, **Always allow**, or **Reject**.
5. Grant releases the original call and returns the normal upstream response.

No agent code change is required for gateway users. The Python SDK exists for agents that want explicit control.

Every approval link is an invitation to understand the product. No cold outreach required.

The hosted service lives at **https://grant-approve.vercel.app**. The approval popup uses plain language ("Who's asking", "Expires — In 29m (9:21 AM international time)") and keeps account creation and sign-in inside the popup itself. Public pages are indexed through `public/robots.txt` and `public/sitemap.xml`; private approval, workspace, and ops paths are not.

---

## Quickstart

```bash
cd Grant
pip install -e .

python -c "import grant; print(grant.__version__)"
grantctl doctor --url https://grant-approve.vercel.app
```

Grant is not published to PyPI; install it from this repository.

```python
from grant import Grant, GrantDenied

grant = Grant("https://grant-approve.vercel.app", workspace="support")

ask = grant.request(
    agent="support-agent",
    action="refund_order",
    summary="Refund order ord_42 for $48.00",
    scope={"order_id": "ord_42", "amount": 48},
    ttl_minutes=30,
)

print(ask.message)  # put this where your agent normally talks to the human

try:
    permission = grant.wait(ask.id, timeout=300)
    print(permission.policy, permission.signature)
except GrantDenied:
    print("The human said no. Do not run the action.")
```

The approval URL is a capability link. No account is required to approve.

---

## What ships in this repository

| Path | What it is |
| --- | --- |
| `main.py` | FastAPI service: approval pages, gateway proxy, HTTP API, stats, health checks |
| `grant/` | Python SDK with no third-party imports, plus local proxy daemon |
| `grant/cli.py` | `grantctl` gateway, proxy, request, status, and verify commands |
| `grant/db.py` | Neon Postgres primary adapter with a dev-only SQLite fallback; production refuses ephemeral storage |
| `grant/telemetry.py` | Privacy-preserving login/pop-up telemetry and live reach metrics |
| `grant/login_library.py` | Read-only login/reach library: users, logins, pop-ups, computers, sanitized history |
| `grant/assets/grant-inject.js` | Injectable browser interceptor for fetch/XHR and risky clicks |
| `grant/policies/oauth_scopes.json` | Zero-custody OAuth scope → gateway rule templates |
| `migrations/001_neon_schema.sql` | Durable Neon schema, applied automatically when `DATABASE_URL` is set |
| `grant/emailer.py` | Resend / SMTP / dev-console magic-link delivery with no third-party SDK |
| `scripts/verify_cashfree.py` | Checkout, simulated webhook, and tier-activation verification CLI |
| `tests/` | Launch tests covering consent, gateway, popup, magic receipt, A2A, browser inject, identity, API keys, gates, billing, telemetry, login library, and policy flows |
| `docs/GATEWAY.md` | MCP gateway, local proxy, and OAuth policy templates |
| `docs/` | Quickstart, framework examples, deployment, brand system |
| `vercel.json` | Vercel function configuration |

Grant covers four interception choke points: (1) the MCP/API tool gateway, (2) the outbound HTTP/local proxy with a 460×640 approval pop-up and validated `postMessage` handshake, (3) the injectable browser script that pauses `fetch`/XHR and risky DOM clicks, and (4) the agent-to-agent message bus gate. OAuth scope templates map provider scopes to per-action rules without token custody, and the approval card itself is the discovery surface: the persistent “● Protected by Grant · Zero-custody consent infrastructure” watermark sits on every card, and the post-approval Magic Receipt offers a passwordless dashboard link alongside the builder CTA.

---

## HTTP API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/requests` | Create an approval request |
| `GET` | `/v1/requests/{id}` | Read status and signed permission |
| `GET` | `/v1/permissions/{agent}` | List active permissions |
| `POST` | `/v1/permissions/verify` | Verify a signed permission |
| `POST` | `/v1/gateways` | Register a zero-code MCP/HTTP gateway |
| `GET` | `/g/http/{token}/{path}` | Approval-gated HTTP reverse proxy |
| `POST` | `/g/mcp/{token}` | Approval-gated MCP JSON-RPC proxy |
| `GET` | `/stats` | Public, readable activity totals (cached 60 seconds) |
| `GET` | `/stats.json` | Aggregate usage + live reach metrics only |
| `GET` | `/login-history` | Token-gated login/pop-up history space |
| `GET` | `/login-history.json` | Token-gated login/reach library report |
| `POST` | `/v1/a2a/gate` | Hold an agent-to-agent handoff until a human signs it |
| `GET` | `/openapi.json`, `/api/openapi.json` | OpenAPI 3.1 contract (public CORS) |
| `POST` / `GET` | `/api/mcp` | MCP JSON-RPC (`initialize`, `tools/list`, `tools/call`); browser GET setup card |
| `POST` | `/v1/gate/webhook` | Webhook approval gate with rules-first decisions and signed callbacks |
| `GET` | `/receipt/{req_id}` | Public signed receipt page |
| `POST` | `/v1/auth/otp`, `/v1/auth/otp/verify` | Email OTP sign-in alongside magic links |
| `POST` | `/api/webhooks/cashfree` | Alias of `/v1/billing/webhook` (same Cashfree signature) |
| `GET` | `/manifest.webmanifest`, `/sw.js`, `/icons/icon-{192,512}.svg` | PWA assets |
| `GET` | `/approve/{req_id}`, `/signup`, `/account` | Checkpoint, sign-up, and standalone account app |
| `GET` | `/v1/policies/oauth-scopes` | Zero-custody OAuth scope templates |
| `GET` | `/grant-popup.js` | Single-source pop-up `postMessage` handshake |
| `GET` | `/grant-inject.js` | Injectable browser interceptor (`fetch`, XHR, risky clicks) |
| `GET` | `/health/live` | Process check |
| `GET` | `/health/ready` | Database and signing check |

Example request:

```bash
curl -X POST https://grant-approve.vercel.app/v1/requests \
  -H "Content-Type: application/json" \
  -d '{
    "agent": "support-agent",
    "action": "refund_order",
    "summary": "Refund order ord_42 for $48.00",
    "scope": {"order_id": "ord_42", "amount": 48},
    "workspace": "support",
    "ttl_minutes": 30
  }'
```

The response includes `approval_url` and a ready-to-send `message`.

---

## Zero-wrapper integrations

No SDK is required for these surfaces, and they send permissive CORS headers:

- `GET /openapi.json` and `GET /api/openapi.json` publish the OpenAPI 3.1 contract.
- `POST /api/mcp` accepts JSON-RPC `initialize`, `tools/list`, and `tools/call`; `GET /api/mcp` shows a browser setup card with the same URLs.
- `POST /v1/gate/webhook` evaluates matching auto-approve rules first, then falls back to a human checkpoint. Decisions are delivered as signed HMAC callbacks with at most 2 retries (`GRANT_CALLBACK_MAX_RETRIES`).
- `GET /receipt/{req_id}` is a public signed receipt page; no sign-in required.

Without an `Authorization` header these integration endpoints run in demo mode: **20 requests/hour per hashed IP** (`GRANT_DEMO_LIMIT_PER_HOUR`). A valid `Authorization: Bearer gr_live_…` key is exempt from the demo limiter. Raw IPs and callback secrets are never exposed in public docs or logs.

---

## CLI

```bash
grantctl request \
  --agent support-agent \
  --action refund_order \
  --summary "Refund ord_42" \
  --scope '{"order_id":"ord_42"}' \
  --url https://grant-approve.vercel.app

grantctl status req_abc123 --url https://grant-approve.vercel.app
grantctl permissions support-agent --url https://grant-approve.vercel.app
grantctl doctor --url https://grant-approve.vercel.app
```

---

## Zero-code gateway

```bash
grantctl gateway \
  --name "Payments API" \
  --upstream https://api.example.com \
  --workspace support \
  --paths "/transfer,/payment,/refund" \
  --body-keys "amount,recipient" \
  --url https://grant-approve.vercel.app
```

Point the agent at the returned `http_url` or `mcp_url`. Sensitive calls pause for approval; routine calls pass through.

For local or computer-use agents:

```bash
grantctl proxy \
  --upstream https://api.example.com \
  --port 8787 \
  --open \
  --url https://grant-approve.vercel.app
```

Then point the local agent at `http://127.0.0.1:8787/`.

For browser/web agents, load the injectable script on the page the agent operates in:

```html
<script src="https://grant-approve.vercel.app/grant-inject.js"
  data-grant-url="https://grant-approve.vercel.app"
  data-agent="web-agent"
  data-workspace="public"
  data-sensitive-paths="stripe.com,googleapis.com"
  data-risky-clicks="send,pay,delete,transfer,publish"></script>
```

It pauses matching `fetch`/XHR calls and high-risk clicks, opens the 460×640 hosted card, and resolves on a validated `postMessage` or a signed status poll. It never reads host-page credentials. For multi-agent systems, `grant.a2a_gate(sender=..., receiver=..., task=..., payload=...)` or `POST /v1/a2a/gate` holds the handoff until a human decides. The public request and A2A endpoints allow cross-origin calls with `Access-Control-Allow-Origin: *`; no credentials are accepted. See `docs/GATEWAY.md`.

---

## Magic Receipt

Every approval card carries the persistent watermark `● Protected by Grant · Zero-custody consent infrastructure`, and every UI screen shows “Grant never sees your credentials or payment details. It only records what you allowed.” Once a human chooses Continue (approve once), Always allow, or an auto-approve rule, the card becomes a receipt:

- `Approved. Receipt req_... recorded.` — a signed receipt, never a blank close screen.
- Path A: `Want to see every AI agent you've authorized—or revoke Always allow anytime?` → `Open Your Free Grant Dashboard →`.
- Path B: `Building AI agents? Protect your own users' actions in 2 minutes.` → `Get Your Free API Key →` (starts at `/start?from=receipt`, then the workspace dashboard mints a real `gr_live_…` key after a one-time email sign-in).

A signed, HttpOnly `grant_dashboard` cookie silently creates or reuses a workspace on approval, so the dashboard link is one click with no password form and no email capture. Billing email stays optional and is only used to match Cashfree payments. The receipt remains visible until the person chooses a path. The standalone public receipt lives at `/receipt/{req_id}`.

---

## Checkpoint, signup, and the installed account

- `/approve/{req_id}` is the checkpoint: **Continue**, **Always allow**, and a subtle **Cancel**. A decision writes a signed receipt and, if registered, fires the signed callback.
- `/signup` is the sign-up flow. **Add Shortcut** installs the PWA and is mandatory before continuing to `/account`.
- PWA assets: `/manifest.webmanifest`, `/sw.js`, `/icons/icon-192.svg`, `/icons/icon-512.svg`. The manifest uses `start_url: /account`, `display: standalone`, and colors `#FAF8F5` / `#6d2038`.
- `/account` is the standalone app: profile and plan, usage meter, Cashfree links, claim payment, rule kill switches and spend/scope cap editor, audit trail, login/device history, API-key minting, and the OpenAPI/MCP URLs.

Exact copy, pricing, and palette live in `docs/BRAND.md`; production configuration is in `docs/DEPLOYMENT.md`.

---

## Trust model

- Scope values that look like keys, tokens, passwords, or email addresses are redacted before storage and display.
- Permissions are HMAC-signed. A permission can be verified through `POST /v1/permissions/verify`.
- Approval links are unguessable capability URLs. They are private pages and excluded from search indexing.
- Public `/stats` and `/stats.json` are aggregate-only. They never return IDs, emails, scope values, or URLs; both public HTML pages (`/docs`, `/stats`) are cached for 60 seconds.
- Private `/ops` shows aggregate user and live-reach counts behind a token; no IDs, emails, or raw stats are public.
- Private `/login-history` is a dedicated token-gated space for login and pop-up history; `grant/login_library.py` is its read-only library (users, logins, pop-ups, computers). Both are excluded from search indexing.
- Telemetry stores salted SHA-256 hashes and coarse device labels only — never raw IPs, device IDs, or approval tokens.
- The Magic Receipt cookie (`grant_dashboard`) is an HttpOnly, SameSite=Lax signed workspace capability — no email, password, or OAuth token — and the signed receipt does not depend on it.
- Gateway retries require a signed `X-Grant-Receipt` bound to the exact scope, workspace, gateway, and expiry.
- Grant does not handle money, wallets, escrow, or in-app checkout. Payment links are hosted externally.
- Workspaces are bookmarks. Optional renewal reminders are delivered only to the billing email saved for that workspace.

---

## Product-led growth loop

- **Invite by action:** the approval link is delivered inside the agent’s normal flow.
- **One-tap policy:** “Always allow” turns a single decision into a reusable permission.
- **Workspace bookmark:** the decision page leads to a quiet workspace with the install snippet.
- **Embeddable message:** `ask.message` is designed to be pasted into agent output, Slack, or a tool result.
- **Popup triggers:** OAuth-style window with `postMessage` auto-close, Shadow-DOM widget, injectable browser script, and mobile deep-link card.
- **Magic Receipt:** the approval card is the landing page; the watermark builds builder trust, and the signed receipt turns a one-time approver into a passwordless workspace owner in one click.
- **Contextual guardrails:** conditional auto-approve rules, Slack/webhook delivery, team routing, and audit retention are offered at the moment of risk. SMS/WhatsApp alerts are Pro-tier and coming soon — no provider is connected yet.
- **Public proof:** aggregate stats show adoption without exposing private data.

No fake engagement, voting, upvotes, mass outreach, or purchased traffic is part of this system. There is no PyPI publish claim and no raw PII or secret in public docs.

---

## Brand

Paper `#FAF8F5`, burgundy `#6d2038`, translucent glass surfaces, serif headlines, and faint circuit traces inspired by transparent hardware design. No neon, no cyberpunk glow, no “AI purple”. Every screen shows “Grant never sees your credentials or payment details. It only records what you allowed.” and the `● Protected by Grant · Zero-custody consent infrastructure` watermark.

See `docs/BRAND.md` for the exact palette, motion rules, and non-negotiable copy.

---

## Pricing

Four tiers at `/pricing`, with a monthly/annual toggle (20% off annual). Exact displayed prices: Free $0, Plus **$20/mo / ₹2,400**, Pro **$150/mo**, Enterprise **$4,000/mo**. Annual prices are display-only; hosted checkout is monthly-only. Cashfree phone uses the server-only placeholder `9999999999` — the UI never asks for a phone or card detail.

- **Free** ($0) — Basic Approve once / Always allow pop-up, Email & Web links (1,000/mo), 7-day audit trail. Includes a 14-day Pro Guardrails reverse trial.
- **Plus** ($20/mo or ₹2,400/mo) — For solo builders putting an agent into production with real users or money. Locks: auto-approve rules (spend/scope caps), Slack & Webhook instant approvals (15,000/mo), 30-day audit log retention.
- **Pro** ($150/mo or ₹12,600/mo) — For teams running agents across departments with compliance needs. Locks: multi-approver routing & role rules, 1-year audit trail + CSV/JSON exports, and SMS / WhatsApp approval alerts (100,000/mo, **coming soon** — no provider connected).
- **Enterprise** ($4,000/mo or ₹340,000/mo) — For large organizations and platforms embedding Grant at scale under strict security and legal procurement. Contact CTA with custom terms. Locks: white-label domain & custom branding, SSO / SAML & org directory sync, 99.99% SLA + real-time SIEM log streaming (with custom retention of 7+ years).

Plan positioning, feature bullets, and lock flags live in `grant/plans.py`; `/pricing` renders those exact bullets, and approval drawers surface the relevant Plus/Pro lock at the moment of risk. Gates are enforced server-side in every request-creating handler: an exhausted Free quota returns `402`, and Plus/Pro-only features return `403` with tier upgrade metadata.

Cashfree-hosted monthly forms only. The signed webhook at `POST /v1/billing/webhook` (alias `POST /api/webhooks/cashfree`, same secret and signature) resolves the tier by permanent form/link ID or paid amount, matches the normalized billing email, sets a 32-day expiry, and resets the monthly quota. A different checkout email is stored as a verified row in `unclaimed_payments`; claim it by checkout email or Cashfree Payment ID from `/account`. Day-27 renewal reminders point back to the same static form and are sent only through an explicitly configured email webhook. Grant itself never takes payment or handles cards. Monthly quotas and plan-only features are enforced server-side: an exhausted Free quota returns `402`, and Plus/Pro-only rules return `403`, both with upgrade metadata.

---

## Identity, keys, and launch gates

- **Passwordless identity:** `POST /v1/auth/magic-link` sends a one-time link via Resend or SMTP (dev prints it to console), and `GET /auth/verify` creates or loads a durable `users` row, attaches anonymous `claim_token` rules, records `login_history`, and sets an HttpOnly `grant_session` cookie. Email OTP is also available through `POST /v1/auth/otp` and `POST /v1/auth/otp/verify`; only a code hash is stored (`magic_links.otp_hash`).
- **Real API keys:** the workspace dashboard mints `gr_live_…` keys through `POST /api/keys`. Only the SHA-256 digest is stored in Neon; the raw key is displayed once. Send it as `Authorization: Bearer gr_live_…` to protected endpoints. `GET`/`DELETE /api/keys` manage live keys, and invalid or revoked keys return `401`.
- **Hard gates:** every request-creating handler shares `enforce_request_gates()`. Free quotas return `402`; conditional rules (Plus) and multi-approver routing / mobile channels (Pro) return `403` with `current_tier`, `required_tier`, and `upgrade_url`.
- **Cashfree verification:** `python scripts/verify_cashfree.py --org ws_live --mode checkout` prints the hosted monthly form. After paying, `--mode verify` polls ops-gated `GET /api/billing/status` until the Neon plan tier activates. `--mode simulate` posts to `POST /api/webhooks/cashfree/test` to exercise the same activation path without moving money.

### Status that is still honest

SMS and WhatsApp approval alerts are Pro-tier features marked **coming soon** because Grant has no SMS provider integration. Annual pricing is display-only; hosted checkout is monthly-only. Enterprise is a contact CTA, not a payment link. The Chrome Web Store extension and custom LangGraph/CrewAI SDKs are deliberately out of scope — the inject script and `/v1/a2a/gate` HTTP endpoint are the supported browser and agent integrations. The zero-wrapper endpoints, checkpoint/signup, PWA account app, email OTP, and Cashfree webhook alias described above are part of the current uncommitted work; verify on the deployed preview before treating them as live.

---

## Local development

```bash
python -m venv .venv
. .venv/Scripts/activate      # Windows
pip install -r requirements.txt
pip install -e .
uvicorn main:app --reload
python -m pytest tests -q
```

Current status: **101 passed**.

Before public launch, set `GRANT_PUBLIC_BASE_URL` and `GRANT_SIGNING_SECRET`, and provision a Neon DSN (`DATABASE_URL` / `NEON_DATABASE_URL` / `GRANT_NEON_DATABASE_URL`) for durable storage — the schema in `migrations/001_neon_schema.sql` then applies automatically on boot. None of these deployments or schema applications happen without explicit authorization. See `docs/DEPLOYMENT.md`.
