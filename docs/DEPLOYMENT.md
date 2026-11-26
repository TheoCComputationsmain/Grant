# Deployment

Grant is a separate product and should be deployed as its own Vercel project. Do not point AgentGrid or TraceLock aliases at this service.

## Environment variables

Set these in Vercel Production:

| Variable | Required | Purpose |
| --- | --- | --- |
| `GRANT_PUBLIC_BASE_URL` | Yes | Canonical URL used in approval links, sitemap, docs snippets |
| `GRANT_SIGNING_SECRET` | Yes | HMAC key for signed permissions |
| `GRANT_DB` | Dev only | Local SQLite path (`/tmp/grant.db` on serverless). Never use as the production store. |
| `BLOB_STORE_ID` | Yes on Vercel | Private Vercel Blob store for cross-instance gateway decisions |
| `GRANT_BLOB_PREFIX` | No | Object prefix inside Blob, default `grant-state` |
| `GRANT_RATE_LIMIT_PER_MIN` | No | Requests per IP per minute, default `60` |
| `GRANT_GATEWAY_WAIT_SECONDS` | No | Seconds gateway waits for approval, default `20`, max `45` |
| `GRANT_ALLOW_HTTP_UPSTREAMS` | No | Set `true` only if production must allow `http://` upstreams |
| `GRANT_APP_ENV` | Recommended | `development` or `production`. Vercel sets `VERCEL=1`, which is always treated as production; production requires `DATABASE_URL` and a configured email provider |
| `GRANT_ALLOW_SQLITE_IN_PROD` | No | Escape hatch only; set `true` to explicitly allow ephemeral SQLite in production |
| `GRANT_EMAIL_PROVIDER` | No | `resend`, `smtp`, or `console`. Auto-detected from the credentials below |
| `RESEND_API_KEY` | For magic links | Resend API key for one-time sign-in email |
| `GRANT_EMAIL_FROM` | For magic links | Verified From address for Resend or SMTP |
| `SMTP_HOST` / `SMTP_PORT` | For magic links | SMTP server and port (default `587`) |
| `SMTP_USER` / `SMTP_PASSWORD` | No | SMTP credentials when the server requires authentication |
| `SMTP_TLS` | No | STARTTLS toggle, default `true` (`465` uses implicit TLS) |
| `GRANT_MAGIC_LINK_TTL_MINUTES` | No | Magic-link lifetime, default `30` |
| `GRANT_SESSION_DAYS` | No | Session cookie lifetime in days, default `30` |
| `GRANT_ALLOW_TEST_WEBHOOK` | For live verification | Set `true` to permit ops-only `POST /api/webhooks/cashfree/test` in production |
| `GRANT_CASHFREE_APP_ID` | For paid plans | Cashfree App ID |
| `GRANT_CASHFREE_SECRET_KEY` | For paid plans | Cashfree Secret Key |
| `GRANT_CASHFREE_API_VERSION` | No | Cashfree API version, default `2026-01-01` |
| `GRANT_CASHFREE_MODE` | For paid plans | `sandbox` or `production` |
| `GRANT_CASHFREE_WEBHOOK_SECRET` | For automation | Cashfree webhook secret; may be the Secret Key |
| `GRANT_CASHFREE_RETURN_URL` | No | HTTPS return URL after payment |
| `GRANT_CASHFREE_CURRENCY` | No | `INR` default, or enabled currency such as `USD` |
| `GRANT_CASHFREE_PLACEHOLDER_PHONE` | Production | Server-only phone value required by Cashfree `/links` |
| `GRANT_ENTERPRISE_CONTACT_URL` | No | Booking/contact URL for Enterprise CTA |
| `GRANT_BILLING_WEBHOOK_SECRET` | Legacy fallback | Grant-format HMAC secret for manual plan-flip events |
| `GRANT_CASHFREE_PLUS_MONTHLY_URL` | No | Optional Plus monthly form override; must be an allowlisted Cashfree host |
| `GRANT_CASHFREE_PRO_MONTHLY_URL` | No | Optional Pro monthly form override; must be an allowlisted Cashfree host |
| `GRANT_CRON_SECRET` | For renewal cron | Bearer secret sent by Vercel Cron to `/v1/billing/renewal-reminders` |
| `GRANT_RENEWAL_EMAIL_WEBHOOK_URL` | For renewal email | HTTPS webhook that delivers `{to, subject, text, tier, renewal_url}` |
| `GRANT_RENEWAL_EMAIL_WEBHOOK_TOKEN` | No | Bearer token for the renewal email webhook |
| `GRANT_OPS_TOKEN` | Yes for `/ops` | Token for the token-gated user-count page |
| `GRANT_POPUP_ALLOWED_ORIGINS` | For OAuth-style popups | Comma-separated origins allowed for `postMessage` |
| `GRANT_TELEMETRY_SALT` | No | Salt for privacy-preserving hashed login/pop-up telemetry; defaults to the signing secret |
| `DATABASE_URL` (or `NEON_DATABASE_URL` / `GRANT_NEON_DATABASE_URL`) | **Yes in production** | Neon Postgres DSN. `grant/db.py` auto-applies `migrations/001_neon_schema.sql` on boot and routes all reads/writes to Postgres. Without it, production refuses to boot. |

Generate a signing secret locally and store it as a Vercel Secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Never paste the secret into docs, chat, screenshots, or public stats.

Register this Cashfree webhook URL in the Cashfree dashboard for **both** Payment Link and Payment Form events:

```text
https://grant-approve.vercel.app/v1/billing/webhook
```

Grant requires `x-webhook-timestamp` and `x-webhook-signature`, verifies Base64 HMAC-SHA256 over `timestamp + raw_body`, and rejects stale or unsigned events. It resolves the tier from the permanent `link_id`/`form_id` or the paid amount, normalizes `customer_email` with `LOWER(TRIM(...))`, and matches it to a workspace billing email. A paid event sets `plan_expires_at` to 32 days out, resets the current month's usage, and queues a day-27 reminder. Unmatched paid receipts are stored only as verified unclaimed receipts; no phone, card, raw webhook payload, or payer email is logged or returned publicly.

## Cashfree live verification

Grant uses hosted monthly forms only; annual prices are display-only and Enterprise is a contact CTA. To verify an end-to-end payment and automatic Neon tier activation:

```bash
$env:GRANT_VERIFY_BASE_URL="https://grant-approve.vercel.app"   # PowerShell
$env:GRANT_OPS_TOKEN="<ops token>"
python scripts/verify_cashfree.py --org ws_live --plan plus --mode checkout
# Pay manually on the printed Cashfree hosted form, then:
python scripts/verify_cashfree.py --org ws_live --plan plus --mode verify --timeout 900
python scripts/verify_cashfree.py --org ws_live --mode status
```

`verify` polls the ops-gated `GET /api/billing/status` until the durable `organizations.plan_tier` and effective plan tier match the paid plan. If the payment completes but the tier never activates, check that the Cashfree webhook URL is registered for both Payment Link and Payment Form events and that `GRANT_CASHFREE_WEBHOOK_SECRET` is set.

`--mode simulate` calls ops-only `POST /api/webhooks/cashfree/test`, which runs the same `apply_billing_event` path as the signed webhook without moving money. It is disabled in production unless `GRANT_ALLOW_TEST_WEBHOOK=true`. Simulation is a control test, not proof of a real payment; only the hosted-form payment plus `verify` proves the end-to-end flow.

## Deploy

```bash
cd Grant
vercel storage create grant-consent-state --type blob --access private
vercel storage connect grant-consent-state --yes
vercel deploy --prod --yes --verify
```

Then verify:

```bash
curl https://grant-approve.vercel.app/health/live
curl https://grant-approve.vercel.app/health/ready
curl https://grant-approve.vercel.app/stats.json
curl https://grant-approve.vercel.app/grant-inject.js
curl -X POST https://grant-approve.vercel.app/v1/a2a/gate \
  -H "Content-Type: application/json" \
  -d '{"sender":"planner","receiver":"worker","task":"pay vendor"}'
python -m grant.cli doctor --url https://grant-approve.vercel.app
```

Configure `DATABASE_URL` and one email provider before production boot; otherwise the app fails fast instead of serving ephemeral data. Go-live is blocked until that DSN is provisioned.

## Storage model

Neon Postgres is the primary production store. When `DATABASE_URL` is set, every read and write goes through Postgres, and `grant/db.py` applies `migrations/001_neon_schema.sql` idempotently on boot. In production, boot fails fast with `DATABASE_URL is required in production` rather than silently falling back to instance-local SQLite. The only escape hatch is an explicit `GRANT_ALLOW_SQLITE_IN_PROD=true` for local verification.

SQLite (`GRANT_DB`, `/tmp/grant.db` on Vercel) remains the zero-config local development store. It is ephemeral and instance-local and must not be used to claim durable history.

Canonical durable tables include `users`, `organizations`, `api_keys`, `approval_requests`, `auto_approve_rules`, `login_history`, and `popup_impressions`. `workspaces` and `requests` are kept as hot compatibility tables and are dual-written with `organizations` and `approval_requests` so gateways and signed-receipt retries keep working. `magic_links` and `auth_sessions` store only token digests and expiries; no raw key or magic-link token is persisted.

Gateway registrations, pending requests, and decisions are additionally mirrored to a private Vercel Blob store. Pending and decided states use separate immutable object paths, so a retry that lands on a different function instance still sees the human's decision instead of a stale pending copy. Blob stays the hot decision cache; Neon is the source of truth.

Plan tier, trial, and usage metering tables (`plans`, `usage_events`, `billing_events`) live in Neon when configured. `plans` carries `plan_expires_at` and `quota_reset_at`; `unclaimed_payments` holds verified-but-unmatched receipts; `renewal_reminders` holds the day-27 static-form reminder queue. A billing webhook only flips plan flags; it never handles money. It also updates `organizations.plan_tier`, which the server-side gates read directly.

Do not claim durable audit history until a Neon DSN is provisioned and verified.

## Privacy-preserving reach telemetry

Grant records silent workspace sessions and approval-card renders without raw IPs, device IDs, or token values. Only salted SHA-256 hashes plus a coarse browser/OS label are stored, in `login_history` and `popup_impressions`.

The Magic Receipt sets a capability cookie (`grant_dashboard`, HttpOnly, SameSite=Lax, secure on HTTPS) containing a workspace code plus an HMAC of that code. It holds no email, password, or OAuth token and only makes the dashboard link one click; the signed receipt and audit entry are created independently of any account. Billing email remains optional and is used only to match Cashfree receipts.

- `GET /stats` — public, readable activity page with aggregate counters only.
- `GET /stats.json` — public aggregate counters only: `total_users`, `unique_humans_reached`, `popup_impressions`, `unique_devices`, `active_sessions`, plus existing request/permission counts.
- `/docs` and `/stats` return `Cache-Control: public, s-maxage=60` so traffic spikes do not burn function or Neon compute; private pages stay `no-store`.
- `GET /ops.json` and `GET /ops` — token-gated, add recent-login and device-breakdown summaries; still no emails, IDs, keys, or raw stats.
- `GET /login-history` — dedicated token-gated space with a live snapshot (users, logins, pop-ups, computers) plus sanitized login and pop-up event tables.
- `GET /login-history.json` — token-gated JSON report from `grant/login_library.py`, the read-only library answering “how many users / logins / pop-ups / computers”.

Open the private views with `?token=<GRANT_OPS_TOKEN>`, a `X-Grant-Ops-Token` header, or HTTP Basic auth. The page strips the token from the address bar on load. Telemetry records hashed workspace/session subjects; optional magic-link sign-in creates a durable `users` row, but no raw email is ever exposed on a public page. Telemetry is local-only until a Neon DSN is configured.

## Search and discovery

- Public, indexable: `/`, `/docs`, `/pricing`, `/stats`, `/start`.
- Private, `noindex`: `/a/{token}`, `/r/`, `/w/{code}`, `/console`, `/ops`, `/login-history`, `/protected/{code}`.
- Disallowed in `robots.txt`: `/a/`, `/r/`, `/v1/`, `/w/`, `/console`, `/ops`, `/login-history`, `/protected/`.
- Source files: `public/robots.txt` and `public/sitemap.xml` use `https://grant-approve.vercel.app`; the same routes also render dynamically from `GRANT_PUBLIC_BASE_URL`.
- Submit `/sitemap.xml` in Google Search Console.
- Add Bing Webmaster verification when available.

## Reliability checklist

- [x] Health endpoints
- [x] Request IDs on every response
- [x] Security headers and CSP
- [x] Rate limiting
- [x] Idempotency keys
- [x] WAL SQLite mode and busy timeout
- [x] Duplicate-decision protection
- [x] Signed permissions with verification endpoint
- [x] Expired-request handling
- [x] Aggregate-only stats
- [x] MCP/HTTP approval gateway
- [x] Capability retry header for long approvals
- [x] Local proxy daemon
- [x] Shared Blob-backed gateway and decision state
- [x] Four-tier pricing page with annual toggle
- [x] Latest tier positioning and exact three-feature lock matrix ($20 Plus / $150 Pro / $4,000 Enterprise)
- [x] Contextual upgrade drawers and usage meter
- [x] Hard server-side gates (Free quota `402`; Plus/Pro-only rules `403` with upgrade metadata)
- [x] Cashfree hosted monthly-form redirects and signed plan-flip webhook
- [x] Tier by permanent form/link ID or paid amount
- [x] 32-day plan expiry with monthly quota reset
- [x] Unclaimed-payment claim flow under workspace Billing
- [x] Day-27 renewal reminder queue with static form link
- [x] Token-gated aggregate `/ops` page
- [x] Privacy-preserving login + pop-up telemetry and live reach metrics
- [x] Dedicated token-gated `/login-history` space and read-only login/reach library
- [x] Signed gateway retry receipt (`X-Grant-Receipt`) with scope/gateway/expiry binding
- [x] Machine-readable zero-custody OAuth scope templates (`/v1/policies/oauth-scopes`)
- [x] Hardened 460×640 pop-up handshake with `event.source` validation
- [x] Browser inject route (`/grant-inject.js`) with fetch/XHR/risky-click interception and signed status polling
- [x] A2A gate (`POST /v1/a2a/gate`) with 202 pending / 200 passed and SDK `grant.a2a_gate()`
- [x] CORS preflight and wildcard on public request/status/A2A endpoints (no credentials accepted)
- [x] Persistent protocol watermark on every approval, expiry, and receipt card
- [x] Magic Receipt with exact end-user/builder copy and signed `grant_dashboard` cookie for silent, passwordless workspace creation
- [x] Jargon-free menu and plain-English expiry ("In 29m (9:21 AM international time)")
- [x] Inline create-workspace / sign-in options inside the approval popup with safe return links
- [x] Google discovery files (`public/robots.txt`, `public/sitemap.xml`) with private routes excluded
- [x] 60-second shared cache on public `/docs` and `/stats`
- [x] Custom domain + canonical URL confirmed live
- [x] Neon-primary persistence with durable identity/ledger tables and production fail-fast guard
- [x] Passwordless magic-link identity with one-time tokens and durable `login_history`
- [x] Real `gr_live_…` API keys with SHA-256-only storage and Bearer validation
- [x] Ops-gated Cashfree tier verification script and test-webhook endpoint
- [x] Honest "coming soon" copy for unconnected SMS / WhatsApp channels
- [ ] Browser extension package (injectable script and Shadow-DOM widget routes are live)
- [ ] Neon DSN provisioned in Vercel (schema applies automatically once set)
- [ ] Live paid Cashfree transaction verified end to end

## No outbound dependency

Grant does not require an email provider to work. Approval links travel inside the agent’s own message, tool output, chat client, or UI. Optional renewal reminders are queued without an email provider and are only delivered when `GRANT_RENEWAL_EMAIL_WEBHOOK_URL` points to an external sender; otherwise they remain pending and nothing is sent. No fake outreach or engagement is generated.
