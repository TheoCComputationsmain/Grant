# Grant · MCP registry submission guide

All listings point at the same hosted Streamable HTTP MCP endpoint. No installation step, no Dockerfile, and no local process.

## Official MCP Registry — published

Grant is already published and active at `io.github.TheoCComputationsmain/grant-consent`:

```text
https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.TheoCComputationsmain%2Fgrant-consent
```

`server.json` at the repository root declares the remote endpoint, and `.github/workflows/publish-mcp.yml` republishes it on `v*` tags using GitHub OIDC. To update the listing, edit `server.json`, bump the version, and push a new tag.

**Remote MCP URL:** `https://grant-approve.vercel.app/api/mcp`
**Public contract:** `https://grant-approve.vercel.app/openapi.json`
**Privacy policy:** `https://grant-approve.vercel.app/privacy`

The canonical domain is the verified production alias of the `grant-consent` Vercel project. If the live alias changes, update `https://grant-approve.vercel.app` in `server.json`, `glama.json`, `smithery.yaml` (historical only), and this guide.

## Shared copy (paste exactly)

**Title**

```
Grant · Human-in-the-loop approvals
```

**Short tagline**

```
One quiet approval before an AI agent sends, spends, refunds, or publishes. Zero custody.
```

**Full description**

```
Grant is consent infrastructure for AI agents. When an assistant is about to send an email, issue a refund, move money, publish content, or spend budget, Grant pauses the action and gives the human one private approval link. The human chooses Approve once, Always allow, or Reject. The agent receives a signed, verifiable receipt.

Grant is zero-custody: it never receives credentials, payment details, raw scope values, or raw PII. It stores a one-way hash of redacted scope metadata and a minimal signed receipt containing the request ID, decision, agent, tool name, and timestamp.

This is a hosted Remote MCP server over Streamable HTTP. There is nothing to install and no local runtime: point your MCP client at https://grant-approve.vercel.app/api/mcp and call request_human_approval or check_approval_status. A free demo tier allows 20 calls per hour without a key; add a gr_live_ Bearer key for production.
```

**Tags**

```
security, human-in-the-loop, approvals, guardrails, payments
```

**Tool summary**

| Tool | What it does |
| --- | --- |
| `request_human_approval` | Creates a scoped checkpoint and returns `request_id`, `approval_url`, `receipt_url`, and `expires_at`. |
| `check_approval_status` | Returns status, decision, `decision_type`, `signed_receipt`, and `receipt_verified`. |

Legacy aliases `grant.request_approval` and `grant.get_request` are also available.

## Smithery.ai — retired

Smithery shut down its MCP proxy, managed identity, accounts, API keys, API, Connect, Toolbox, CLI, and SDKs on **October 31, 2026**. `https://smithery.ai/new` now returns a not-found page and the remaining site is a read-only directory powered by Arcade. `smithery.yaml` is kept only as a historical submission record; do not attempt the old CLI command. Use the official MCP Registry above instead.

## Glama.ai

1. Open **https://glama.ai/mcp/servers** and choose **Submit a server** (or claim an existing listing).
2. Server URL:

   ```
   https://grant-approve.vercel.app/api/mcp
   ```

3. Repository URL:

   ```
   https://github.com/TheoCComputationsmain/Grant
   ```

4. Paste the shared title, tagline, description, and tags. Set maintainer to the GitHub username in `glama.json` (`TheoCComputationsmain`); change both if the listing is claimed from a different account.
5. Add `glama.json` to the **repository root** when the upstream PR lands (Glama reads it from the root to verify ownership). Until then, paste its values into the submission form.
6. Submit and confirm the listing shows a remote HTTP server, not a local stdio command. Glama requires a signed-in account; the browser flow redirects to GitHub OAuth before **Add Server** can be used. `glama.json` is also copied to the repository root for ownership verification.

No outreach, votes, or traffic generation is part of this checklist.
