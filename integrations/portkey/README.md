# Grant plugin for Portkey AI Gateway · upstream PR package

**Target repo:** `Portkey-AI/gateway`
**Proposed path:** `plugins/grant/` containing `index.ts`, `manifest.json`, and (optional) `index.test.ts`
**Function id:** `index` — Portkey's `plugins/build.ts` imports `./<plugin>/<functionId>`, so the id must match the TypeScript filename.

`verdict: true` means the request may continue. A pending Grant checkpoint returns `verdict: false` with `data.approval_url`, `data.request_id`, and `data.signed_receipt`, so the caller can render the Grant popup and retry. No new dependency: global `fetch` and `AbortController` only. Zero custody: no argument values, credentials, or payment details are sent to Grant.

## Gateway config after merge

```json
{
  "guardrails": [
    {
      "id": "grant-approval",
      "type": "guardrail",
      "checks": [
        {
          "id": "grant.index",
          "parameters": {
            "grantBaseUrl": "https://grant-approve.vercel.app",
            "protectedTools": ["*"],
            "agentName": "portkey-gateway",
            "workspace": "production",
            "timeoutMs": 2000
          }
        }
      ],
      "config": {
        "default:on": true,
        "on_fail": "block"
      }
    }
  ]
}
```

Use both hooks:

```yaml
beforeRequestHook: [grant-approval]
afterRequestHook: [grant-approval]
```

Optional API key: set `credentials.grantApiKey` (or `GRANT_API_KEY` in the gateway environment). Without it, Grant allows 20 calls/hour in demo mode.

## Local development

```bash
git clone https://github.com/Portkey-AI/gateway.git
cd gateway
mkdir -p plugins/grant
cp integrations/portkey/index.ts plugins/grant/index.ts
cp integrations/portkey/manifest.json plugins/grant/manifest.json
# add {"grant": ["plugins/grant"]} entry to conf.json plugins_enabled if required by your fork
npm run build-plugins
npm run test:plugins
npx vitest run plugins/grant
```

## PR checklist for Portkey-AI/gateway

1. Branch from `main`: `git checkout -b feat/grant-approval-plugin`.
2. Add `plugins/grant/index.ts` and `plugins/grant/manifest.json` from this package. Keep the function id equal to the filename (`index`).
3. Register `grant` in `conf.json` → `plugins_enabled` so `plugins/build.ts` generates the `grant.index` import. Do not add an npm dependency.
4. Add a short section to `plugins/README.md` listing the new plugin and the config snippet above.
5. Run `npm run build-plugins && npm run test:plugins`; include the output in the PR description.
6. Open **https://github.com/Portkey-AI/gateway/pulls** with title *Add Grant zero-custody human approval guardrail plugin*. State that the endpoint is `https://grant-approve.vercel.app/v1/approvals`, that the gate is opt-in via `guardrails`, and that verdict semantics are unchanged.
7. Include a note that pending approvals do not execute the protected tool and that signed receipts are verified by Grant's `/v1/receipts/verify` endpoint downstream.

No fabricated test results, paid reviewers, or fake traffic.
