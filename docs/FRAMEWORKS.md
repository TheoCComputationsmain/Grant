# Framework examples

Grant sits at the action boundary. It does not care which agent framework you use.

## Plain tool function

```python
from grant import Grant, GrantDenied

grant = Grant("https://grant-approve.vercel.app", workspace="support")


def refund_order(order_id: str, amount: float) -> dict:
    ask = grant.request(
        agent="support-agent",
        action="refund_order",
        summary=f"Refund order {order_id} for ${amount:.2f}",
        scope={"order_id": order_id, "amount": amount},
        ttl_minutes=30,
    )

    # Put this in the tool output so the human sees Grant at the moment of action.
    print(ask.message)

    try:
        permission = grant.wait(ask.id, timeout=300)
    except GrantDenied:
        return {"ok": False, "reason": "human_rejected"}

    if grant.verify(permission.id, permission.signature)["valid"] is not True:
        return {"ok": False, "reason": "invalid_permission"}

    return perform_refund(order_id, amount, permission)
```

## LangGraph node

```python
from langgraph.graph import StateGraph
from grant import Grant, GrantDenied

grant = Grant("https://grant-approve.vercel.app", workspace="support")


def refund_node(state):
    ask = grant.request(
        agent="support-agent",
        action="refund_order",
        summary=state["summary"],
        scope={"order_id": state["order_id"]},
    )
    # Emit ask.message as part of the node's normal status output.
    state["grant_message"] = ask.message
    try:
        permission = grant.wait(ask.id, timeout=300)
    except GrantDenied:
        return {**state, "status": "cancelled"}
    return {**state, "status": "approved", "permission": permission.signature}


graph = StateGraph(dict).add_node("refund", refund_node).compile()
```

## CrewAI tool

```python
from crewai_tools import tool
from grant import Grant, GrantDenied

grant = Grant("https://grant-approve.vercel.app", workspace="ops")


@tool("Publish release note")
def publish_release_note(title: str, body: str) -> str:
    ask = grant.request(
        agent="release-agent",
        action="publish_post",
        summary=f"Publish release note: {title}",
        scope={"title": title, "body_preview": body[:240]},
    )
    try:
        permission = grant.wait(ask.id, timeout=300)
    except GrantDenied:
        return "Publication cancelled by human."
    return publish(title, body, permission)
```

## MCP tool

```python
from mcp.server.fastmcp import FastMCP
from grant import Grant, GrantDenied

mcp = FastMCP("support-tools")
grant = Grant("https://grant-approve.vercel.app", workspace="support")


@mcp.tool()
def send_summary(topic: str) -> str:
    ask = grant.request(
        agent="mcp-support-agent",
        action="send_a_summary",
        summary=f"Send a summary about {topic}",
        scope={"topic": topic},
    )
    try:
        permission = grant.wait(ask.id, timeout=300)
    except GrantDenied:
        return "No permission granted. Nothing was sent."
    return send(topic, permission)
```

## Slack or chat delivery

Grant intentionally does not require a work email address or own an inbox. Send `ask.message` through the channel your agent already uses. The link carries the consent surface.

## Rules for good scope

- Include the smallest identifiers needed: order ID, file path, channel name.
- Never put API keys, tokens, passwords, or raw credentials in `scope`.
- Grant redacts obvious secret-like values, but the caller should still avoid sending them.
- Use a stable `Idempotency-Key` for retries so a human never sees duplicate approvals.
