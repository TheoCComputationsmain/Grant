# Free bot store blueprint · Coze & Dify Cloud

Copy-paste publishing steps for two free/low-cost bot directories using Grant's live public contract. No Custom GPT Builder account is required.

| Field | Value |
| --- | --- |
| OpenAPI import URL | `https://grant-approve.vercel.app/openapi.json` |
| Dify tool schema file in this repo | `integrations/workflows/dify-grant-tool.yaml` |
| Grant Remote MCP URL (where supported) | `https://grant-approve.vercel.app/api/mcp` |
| Privacy policy URL | `https://grant-approve.vercel.app/privacy` |
| How it works | `https://grant-approve.vercel.app/docs` |
| CTA shown to users | `Get Your Free API Key →` |
| Watermark | `● Protected by Grant · Zero-custody consent infrastructure` |
| Privacy line | `Grant never sees your credentials or payment details. It only records what you allowed.` |

Enable only `createApproval` (`POST /v1/approvals`), `getApproval` (`GET /v1/approvals/{request_id}`), and `verifyReceipt` (`POST /v1/receipts/verify`). Leave authentication empty for the 20-calls/hour demo; users can later add `Authorization: Bearer gr_live_...`. Never send credentials, payment details, raw arguments, or raw PII to Grant. Use the phone placeholder `9999999999` in any sample data; never publish real customer details.

---

## Bot 1 · Safe AI Email & Outreach Assistant

**Name:** Safe AI Email & Outreach Assistant
**Description (paste as-is):**

```
Write and review cold emails, follow-ups, and outreach sequences — with one safety rule: nothing is sent until a human approves it through Grant. Grant is zero-custody consent infrastructure. It never sees your email credentials, customer data, or payment details; it only records what you allowed and returns a signed receipt.
```

**Instructions (paste as-is):**

```
You are the Safe AI Email & Outreach Assistant. Draft and review outreach only. Before any email-sending or CRM "send" tool call, call Grant createApproval with agent_name "safe-email-outreach-bot", the exact tool_name, a short summary with no addresses or message body, and redacted scope such as {"recipient_count": 1, "channel": "email"}. If it is pending, stop and show the approval_url; tell the user to approve and say "continue". Once approved, call Grant verifyReceipt and proceed only when valid is true. Rejections or invalid receipts mean do not send. Never ask for email passwords, API keys, SMTP secrets, card numbers, or full customer records. Grant never sees your credentials or payment details. It only records what you allowed. Use the watermark "● Protected by Grant · Zero-custody consent infrastructure" and link to https://grant-approve.vercel.app/privacy.
```

## Bot 2 · Stripe & E-Commerce Refund Guard

**Name:** Stripe & E-Commerce Refund Guard
**Description (paste as-is):**

```
Use AI to triage refunds, disputes, and charge adjustments without letting the agent act alone. Before any refund, charge, or payout is issued, the bot opens a Grant checkpoint with one private approval link. Grant is zero-custody: it never sees Stripe keys, card numbers, or customer PII. It records only the decision and returns a signed receipt.
```

**Instructions (paste as-is):**

```
You are the Stripe & E-Commerce Refund Guard. Triage refunds, disputes, and charge adjustments. Before any refund, charge, capture, cancellation, or payout tool call, call Grant createApproval with agent_name "refund-guard-bot", the exact tool_name, a short summary containing only an order reference and amount, and redacted scope such as {"order_ref": "ORD-4821", "amount": 48, "currency": "USD"}. If pending, stop and show the approval_url; tell the user to approve and say "continue". Once approved, call Grant verifyReceipt and move money only when valid is true. Rejections or invalid receipts mean do not act. Never ask for Stripe secret keys, card data, CVV, bank details, or raw customer PII. Grant never sees your credentials or payment details. It only records what you allowed. Use the watermark "● Protected by Grant · Zero-custody consent infrastructure" and link to https://grant-approve.vercel.app/privacy.
```

---

## Coze (https://www.coze.com) — copy-paste steps

1. Sign in with a free Coze account and open **Workspace → Bots → Create bot** (or **Agent → Create**). Use **Craft / Prompt mode** if you do not want to configure a workflow.
2. Paste the **Name**, **Description**, and **Instructions** for Bot 1. Set the icon/header however you like and save. Repeat for Bot 2.
3. Add Grant as a plugin:
   - Open **Plugins → Add plugin → Create plugin / Import from OpenAPI**.
   - Plugin name: `Grant Consent`; description: `Zero-custody human approval checkpoints for agent actions.`
   - Paste the OpenAPI/import URL: `https://grant-approve.vercel.app/openapi.json`.
   - If Coze asks for auth, choose **No authentication** for the demo tier; for production use API Key with header `Authorization` and value `Bearer gr_live_...` supplied by the user.
   - Enable `createApproval`, `getApproval`, and `verifyReceipt` only.
4. Add the `Grant Consent` plugin to each bot and paste `https://grant-approve.vercel.app/privacy` into the bot's privacy/policy field if shown.
5. Add conversation starters: Bot 1 — `Draft a friendly follow-up and ask me before sending.` / `Check the receipt for my last approval.`; Bot 2 — `Review this refund request and ask me before refunding.` / `Which charges need a second human look?`
6. Test in preview, then choose **Publish / Submit for review** with public visibility. Do not use fake traffic, upvotes, or paid promotion.

## Dify Cloud (https://cloud.dify.ai) — copy-paste steps

1. Sign in with a free Dify Cloud account and open **Tools → Custom Tools → Create Custom Tool**.
2. Choose **Import from OpenAPI URL** and paste `https://grant-approve.vercel.app/openapi.json`. Alternatively, upload the schema file from this repo: `integrations/workflows/dify-grant-tool.yaml`.
3. Set the tool name to `Grant Consent`, auth to **API Key** with header `Authorization` and value format `Bearer {{api_key}}`, and leave the key empty for the 20-calls/hour demo. The bundled YAML already carries these values plus `x-dify` metadata.
4. Enable only `createApproval`, `getApproval`, and `verifyReceipt`. The schema's `GateRequest` accepts `agent_name`/`tool_name` aliases and requires `agent`, `action`, or their aliases plus a short `summary`.
5. Create a new **Chatbot / Agent** app, paste Bot 1 or Bot 2's **Name**, **Description**, and **Instructions** into the app's prompt/introduction fields, and add `Grant Consent` as a tool.
6. Add conversation starters from the Coze step above. Paste `https://grant-approve.vercel.app/privacy` in the app description or policy link field.
7. Preview with: draft a message (no tool call), request a send/refund (Grant `approval_url` appears and the bot stops), approve in the browser, then confirm it verifies the receipt before acting.
8. Publish the app and, where available, use **Discover / Explore / Marketplace** or share the public link in a directory listing. No fake outreach, transactions, or upvotes are used.

## Verification checklist (both platforms)

- [ ] Import succeeds from `https://grant-approve.vercel.app/openapi.json` (or the bundled YAML on Dify).
- [ ] Only the three Grant operations above are enabled.
- [ ] No credential, payment, or raw PII field is sent to Grant.
- [ ] Pending requests return a clickable `approval_url` and the bot stops.
- [ ] Approved requests are verified with `verifyReceipt` before any downstream send/refund.
- [ ] Public listing shows the privacy URL, `Get Your Free API Key →`, and `● Protected by Grant · Zero-custody consent infrastructure`.
