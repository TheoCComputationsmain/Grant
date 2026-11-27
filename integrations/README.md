# Grant · Hybrid Distribution & Upstream Integration Suite

Zero-dependency, zero-custody adapters that point at Grant's live hosted HTTP surfaces. No wrapper service, no local runtime, and no credentials or payment details ever reach Grant.

## Base URL (auto-detected / documented default)

Every manifest, template, and plugin in this directory uses:

```
https://grant-approve.vercel.app
```

This is the verified production alias of the `grant-consent` Vercel project (`.vercel/project.json` → `projectName: "grant-consent"`). The alias is pinned so every adapter resolves to the live domain instead of the project's default `*.vercel.app` URL:

- `https://grant-approve.vercel.app` — **canonical; the only domain used by every file in this directory**
- `https://grant-pied.vercel.app` — secondary alias, not used in manifests

To re-derive from a checkout (auto-detect the project, pin the verified alias):

```bash
python -c "import json,pathlib; p=json.loads(pathlib.Path('.vercel/project.json').read_text()); print('https://grant-approve.vercel.app' if p['projectName'] == 'grant-consent' else 'https://' + p['projectName'] + '.vercel.app')"
```

Optional override in adapters: `GRANT_BASE_URL` (or `GRANT_PUBLIC_BASE_URL` on the service).

## Surfaces used

| Surface | Purpose |
| --- | --- |
| `GET /openapi.json` (`/api/openapi.json`) | Public OpenAPI 3.1 contract for GPT Actions and Dify |
| `POST /api/mcp` | Streamable HTTP Remote MCP JSON-RPC endpoint |
| `POST /v1/approvals` | Create a human checkpoint; `GET /v1/approvals/{request_id}` polls it |
| `POST /v1/gate/webhook` | Alias of the checkpoint call for webhook routers |
| `POST /v1/receipts/verify` | Verify a signed, minimal Grant receipt |

## Zero-custody rule

Adapters send only: agent name, tool name, a short human-readable summary, and redacted scope metadata (key names or hashes). They never send credential values, payment details, raw arguments, or raw PII. Signed receipts contain no scope values.

## Packages

| Path | Destination |
| --- | --- |
| `mcp-registry/` | Smithery.ai + Glama.ai remote MCP listings |
| `chatgpt-gpt-store/` | Two public Custom GPT blueprints with Grant Actions |
| `workflows/` | n8n workflow + Dify tool schema |
| `litellm/` | PR package for `BerriAI/litellm` |
| `portkey/` | PR package for `Portkey-AI/gateway` |
| `cloudflare-gateway/` | PR package for `cloudflare/templates` |
| `frameworks/` | CrewAI hook, Cline/Cursor/Windsurf config, Composio/Pipedream spec |
