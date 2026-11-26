# Deployment

Grant is a separate product and should be deployed as its own Vercel project. Do not point AgentGrid or TraceLock aliases at this service.

## Environment variables

Set these in Vercel Production:

| Variable | Required | Purpose |
| --- | --- | --- |
| `GRANT_PUBLIC_BASE_URL` | Yes | Canonical URL used in approval links, sitemap, docs snippets |
| `GRANT_SIGNING_SECRET` | Yes | HMAC key for signed permissions |
| `GRANT_DB` | Recommended | Local SQLite path; use `/tmp/grant.db` on serverless |
| `BLOB_STORE_ID` | Yes on Vercel | Private Vercel Blob store for cross-instance gateway decisions |
| `GRANT_BLOB_PREFIX` | No | Object prefix inside Blob, default `grant-state` |
| `GRANT_RATE_LIMIT_PER_MIN` | No | Requests per IP per minute, default `60` |
| `GRANT_GATEWAY_WAIT_SECONDS` | No | Seconds gateway waits for approval, default `20`, max `45` |
| `GRANT_ALLOW_HTTP_UPSTREAMS` | No | Set `true` only if production must allow `http://` upstreams |
| `GRANT_APP_ENV` | No | `development` or `production` |
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
| `DATABASE_URL` / `NEON_DATABASE_URL` / `GRANT_NEON_DATABASE_URL` | For durable storage | Any one Neon/Postgres DSN. When set, `grant/db.py` auto-applies `migrations/001_neon_schema.sql` on boot and routes all reads/writes to Postgres. Not configured yet. |

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
grantctl doctor --url https://grant-approve.vercel.app
```

## Storage model

SQLite is the local compact store. On Vercel it lives at `/tmp/grant.db`, which is writable but ephemeral and instance-local.

Gateway registrations, pending requests, and decisions are additionally mirrored to a private Vercel Blob store. Pending and decided states use separate immutable object paths, so a retry that lands on a different function instance still sees the human's decision instead of a stale pending copy.

Plan tier, trial, and usage metering tables (`plans`, `usage_events`, `billing_events`) are also SQLite-first. `plans` carries `plan_expires_at` and `quota_reset_at`; `unclaimed_payments` holds verified-but-unmatched receipts; `renewal_reminders` holds the day-27 static-form reminder queue. A billing webhook only flips plan flags; it never handles money. Neon is the intended durable store for those flags, but no Neon credentials are configured yet.

The complete durable schema is prepared in `migrations/001_neon_schema.sql` (including telemetry tables and `requests.channel` / `requests.gateway_hash`). It is **not applied** until a Neon DSN is provisioned. Once `DATABASE_URL`, `NEON_DATABASE_URL`, or `GRANT_NEON_DATABASE_URL` is set, `grant/db.py` applies it idempotently on boot and switches the whole app to Postgres without code changes.

Before claiming durable audit history:

- provision a Neon database and set one of the DSN variables above, which creates `settings`, `workspaces`, `gateways`, `requests`, `permissions`, `billing_contacts`, `plans`, `usage_events`, `billing_events`, `unclaimed_payments`, `renewal_reminders`, `login_history`, and `popup_impressions` with the same column names, and
- keep Blob as the hot decision cache.

Do not claim durable audit history until persistent storage is configured.

## Privacy-preserving reach telemetry

Grant records silent workspace sessions and approval-card renders without raw IPs, device IDs, or token values. Only salted SHA-256 hashes plus a coarse browser/OS label are stored, in `login_history` and `popup_impressions`.

The Magic Receipt sets a capability cookie (`grant_dashboard`, HttpOnly, SameSite=Lax, secure on HTTPS) containing a workspace code plus an HMAC of that code. It holds no email, password, or OAuth token and only makes the dashboard link one click; the signed receipt and audit entry are created independently of any account. Billing email remains optional and is used only to match Cashfree receipts.

- `GET /stats` — public, readable activity page with aggregate counters only.
- `GET /stats.json` — public aggregate counters only: `total_users`, `unique_humans_reached`, `popup_impressions`, `unique_devices`, `active_sessions`, plus existing request/permission counts.
- `/docs` and `/stats` return `Cache-Control: public, s-maxage=60` so traffic spikes do not burn function or Neon compute; private pages stay `no-store`.
- `GET /ops.json` and `GET /ops` — token-gated, add recent-login and device-breakdown summaries; still no emails, IDs, keys, or raw stats.
- `GET /login-history` — dedicated token-gated space with a live snapshot (users, logins, pop-ups, computers) plus sanitized login and pop-up event tables.
- `GET /login-history.json` — token-gated JSON report from `grant/login_library.py`, the read-only library answering “how many users / logins / pop-ups / computers”.

Open the private views with `?token=<GRANT_OPS_TOKEN>`, a `X-Grant-Ops-Token` header, or HTTP Basic auth. The page strips the token from the address bar on load. “Users” means workspaces/orgs and hashed session subjects; Grant has no account system or true login. Telemetry is local-only until a Neon DSN is configured.

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
- [x] Soft-limit grace periods (never block live agents)
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
- [ ] Browser extension package (injectable script and Shadow-DOM widget routes are live)
- [ ] Persistent production database / Neon plan flags (schema prepared, DSN not configured)

## No outbound dependency

Grant does not require an email provider to work. Approval links travel inside the agent’s own message, tool output, chat client, or UI. Optional renewal reminders are queued without an email provider and are only delivered when `GRANT_RENEWAL_EMAIL_WEBHOOK_URL` points to an external sender; otherwise they remain pending and nothing is sent. No fake outreach or engagement is generated.
