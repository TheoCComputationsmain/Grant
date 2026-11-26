# Grant quickstart

Grant has two surfaces:

- the **service**, which creates approval links and signed permissions;
- the **SDK**, which lets an agent ask for permission in one call.

## 1. Install the client

```bash
pip install grant-consent
```

The SDK uses only the Python standard library.

## 2. Check the service

```bash
grantctl doctor --url https://grant-approve.vercel.app
```

Expected shape:

```json
{
  "status": "ready",
  "database": "connected",
  "signing": "environment",
  "api_version": "0.1.0"
}
```

## 3. Create an approval from Python

```python
from grant import Grant, GrantDenied, GrantTimeout

grant = Grant("https://grant-approve.vercel.app", workspace="support")

ask = grant.request(
    agent="support-agent",
    action="send_email",
    summary="Send the weekly summary to the customer",
    scope={"template": "weekly_summary", "recipient_count": 1},
)

print(ask.message)
```

`ask.message` is intentionally plain enough to place inside the agent’s normal output:

```text
Grant · support-agent wants to send_email. Review the exact scope and decide here:
https://grant-approve.vercel.app/a/...

Approve once · Always allow · Reject. No account needed.
```

## 4. Wait for the human

```python
try:
    permission = grant.wait(ask.id, timeout=300)
    print(permission.policy)     # once or always
    print(permission.signature)  # signed by Grant
except GrantDenied:
    print("Do not perform the action.")
except GrantTimeout:
    print("No decision arrived. Do not perform the action.")
```

## 5. Verify the permission server-side

```python
result = grant.verify(permission.id, permission.signature)
assert result["valid"] is True
```

## 6. Use plain HTTP instead

```bash
curl -X POST https://grant-approve.vercel.app/v1/requests \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: order-ord_42-refund" \
  -d '{
    "agent": "support-agent",
    "action": "refund_order",
    "summary": "Refund order ord_42 for $48.00",
    "scope": {"order_id": "ord_42", "amount": 48},
    "workspace": "support",
    "ttl_minutes": 30
  }'
```

Use the same `Idempotency-Key` when retrying a network failure. Grant returns the original request instead of creating a duplicate.

## 7. Skip SDK changes with the gateway

Register a gateway in front of an existing MCP server or API:

```bash
grantctl gateway \
  --name "Payments API" \
  --upstream https://api.example.com \
  --paths "/transfer,/refund" \
  --body-keys "amount,recipient" \
  --url https://grant-approve.vercel.app
```

Point the client at the returned `http_url` or `mcp_url`. No agent code change is needed. See `GATEWAY.md` for the local proxy daemon and OAuth policy templates.

## 8. Open a workspace

Visit `/start` on the Grant host, name a workspace, and bookmark the link. Pass the workspace code to `Grant(..., workspace="ws_...")` so approvals appear in that quiet audit view.
