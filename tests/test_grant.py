import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import re
import tempfile
import time
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

TEST_DB = Path(tempfile.gettempdir()) / "grant_test.db"
if TEST_DB.exists():
    TEST_DB.unlink()

os.environ["GRANT_DB"] = str(TEST_DB)
os.environ["GRANT_RATE_LIMIT_PER_MIN"] = "0"
os.environ["GRANT_SIGNING_SECRET"] = "test-signing-secret-not-for-production"
os.environ["GRANT_PUBLIC_BASE_URL"] = "https://grant.test"
os.environ["GRANT_GATEWAY_WAIT_SECONDS"] = "0"
os.environ["GRANT_OPS_TOKEN"] = "ops-test-token-not-for-production"
os.environ["GRANT_BILLING_WEBHOOK_SECRET"] = "webhook-test-secret-not-for-production"
os.environ["GRANT_CASHFREE_APP_ID"] = "app_test_not_real"
os.environ["GRANT_CASHFREE_SECRET_KEY"] = "secret_test_not_real"
os.environ["GRANT_CASHFREE_WEBHOOK_SECRET"] = "cf-webhook-test-secret-not-real"
os.environ["GRANT_CASHFREE_MODE"] = "sandbox"
os.environ["GRANT_CASHFREE_RETURN_URL"] = "https://grant.test/console"
os.environ["GRANT_CASHFREE_PLACEHOLDER_PHONE"] = "9999999999"
os.environ["GRANT_POPUP_ALLOWED_ORIGINS"] = "https://app.example.test,https://console.example.test"

import pytest
from fastapi.testclient import TestClient

import main


@pytest.fixture(scope="module")
def api():
    with TestClient(main.app) as client:
        yield client


def ensure_workspace(code: str) -> None:
    with main.transaction() as conn:
        main.create_org_record(conn, code, f"{code} test")


def payload(agent="support-agent", action="refund_order", **overrides):
    body = {
        "agent": agent,
        "action": action,
        "summary": "Refund order ord_42 for $48.00",
        "scope": {"order_id": "ord_42", "amount": 48},
        "workspace": "support",
        "ttl_minutes": 30,
    }
    body.update(overrides)
    return body


def create(api, **overrides):
    response = api.post("/v1/requests", json=payload(**overrides))
    assert response.status_code == 201
    return response.json()


def test_health_home_and_docs(api):
    assert api.get("/health/live").json() == {"status": "alive"}
    ready = api.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json()["database"] == "connected"
    assert ready.json()["signing"] == "environment"

    home = api.get("/")
    assert home.status_code == 200
    assert "Permission for everything" in home.text
    assert "backdrop-filter" in home.text
    assert "grant-trace" in home.text
    assert "#6d2038" in home.text

    docs = api.get("/docs")
    assert docs.status_code == 200
    assert "One request." in docs.text
    assert "https://grant.test/v1/requests" not in docs.text
    assert "/v1/permissions/verify" in docs.text


def test_create_request_returns_approval_message(api):
    body = create(api, agent="message-agent", action="send_a_summary")
    assert body["status"] == "pending"
    assert body["approval_url"].startswith("https://grant.test/a/")
    assert "message-agent" in body["message"]
    assert "send_a_summary" in body["message"]
    assert body["approval_url"] in body["message"]
    assert "No account needed" in body["message"]

    status = api.get(f"/v1/requests/{body['id']}")
    assert status.status_code == 200
    assert status.json()["status"] == "pending"


def test_approval_page_is_polished_and_redacts_scope(api):
    body = create(
        api,
        agent="redact-agent",
        action="send_summary",
        scope={
            "order_id": "ord_42",
            "api_key": "sk-abcdefghijklmnop",
            "owner": "someone@example.com",
            "nested": {"token": "grt_abcdefghijklmnop"},
        },
    )
    page = api.get(body["url"])
    assert page.status_code == 200
    assert "Exact scope" in page.text
    assert "send_summary" in page.text
    assert "noindex" in page.text
    assert "redact-agent" in page.text
    assert "sk-abcdefghijklmnop" not in page.text
    assert "grt_abcdefghijklmnop" not in page.text
    assert "someone@example.com" not in page.text
    assert "[redacted-key]" in page.text
    assert "[email]" in page.text

    room_json = api.get(f"/r/{body['id']}")
    assert room_json.status_code == 404


def test_approve_once_creates_signed_permission(api):
    body = create(api, agent="approve-once-agent", action="refund_order")
    decision = api.post(f"{body['url']}/decide", data={"decision": "approve"}, follow_redirects=False)
    assert decision.status_code == 303
    assert decision.headers["location"].startswith("/a/")
    assert "done=" not in decision.headers["location"]

    status = api.get(f"/v1/requests/{body['id']}").json()
    assert status["status"] == "decided"
    assert status["decision"] == "approve"
    assert status["permission"]["policy"] == "once"
    assert status["permission"]["signature"]

    verified = api.post(
        "/v1/permissions/verify",
        json={"id": status["permission"]["id"], "signature": status["permission"]["signature"]},
    )
    assert verified.json()["valid"] is True
    assert verified.json()["agent"] == "approve-once-agent"

    bad = api.post(
        "/v1/permissions/verify",
        json={"id": status["permission"]["id"], "signature": "bad"},
    )
    assert bad.json() == {"valid": False, "reason": "bad_signature"}


def test_duplicate_decision_does_not_duplicate_permission(api):
    body = create(api, agent="duplicate-agent", action="send_report")
    api.post(f"{body['url']}/decide", data={"decision": "approve"}, follow_redirects=False)
    api.post(f"{body['url']}/decide", data={"decision": "approve"}, follow_redirects=False)
    perms = api.get("/v1/permissions/duplicate-agent").json()
    assert perms["count"] == 1
    assert [item["source_request"] for item in perms["permissions"]] == [body["id"]]


def test_reject_creates_no_permission(api):
    body = create(api, agent="reject-agent", action="delete_file")
    api.post(f"{body['url']}/decide", data={"decision": "reject"}, follow_redirects=False)
    done = api.get(f"{body['url']}?done=reject")
    assert "Nothing was allowed" in done.text
    assert api.get("/v1/permissions/reject-agent").json()["count"] == 0


def test_always_allow_creates_long_policy(api):
    body = create(api, agent="always-agent", action="publish_post")
    api.post(f"{body['url']}/decide", data={"decision": "always"}, follow_redirects=False)
    perms = api.get("/v1/permissions/always-agent").json()
    assert perms["count"] == 1
    assert perms["permissions"][0]["policy"] == "always"


def test_expired_request_cannot_be_decided(api):
    body = create(api, agent="expired-agent", action="send_a_summary")
    past = "2000-01-01T00:00:00Z"
    with main.transaction() as conn:
        conn.execute("UPDATE requests SET expires_at = ? WHERE id = ?", (past, body["id"]))

    page = api.get(body["url"])
    assert "This request expired" in page.text
    decision = api.post(f"{body['url']}/decide", data={"decision": "approve"})
    assert decision.status_code == 410


def test_idempotency_key_returns_same_request(api):
    headers = {"Idempotency-Key": "idem-test-1"}
    first = api.post("/v1/requests", json=payload(agent="idem-agent"), headers=headers)
    second = api.post("/v1/requests", json=payload(agent="idem-agent"), headers=headers)
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]


def test_workspace_flow_persists_name_and_snippet(api):
    response = api.post("/v1/workspaces", data={"name": "Studio"}, follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("/w/ws_")

    page = api.get(location)
    assert page.status_code == 200
    assert "Studio" in page.text
    assert location.rsplit("/", 1)[-1] in page.text
    assert "Copy snippet" in page.text
    assert "No requests yet" in page.text


def test_public_stats_are_aggregate_only(api):
    before = api.get("/stats.json").json()
    create(api, agent="stats-agent", action="send_note")
    response = api.get("/stats.json")
    body = response.json()
    assert response.headers["cache-control"] == "no-store"
    assert body["requests"] == before["requests"] + 1
    assert set(body) == {
        "generated_at",
        "requests",
        "pending",
        "decided",
        "permissions",
        "total_users",
        "unique_humans_reached",
        "popup_impressions",
        "unique_devices",
        "active_sessions",
    }
    assert "api_key" not in response.text
    assert "@" not in response.text
    assert "stats-agent" not in response.text


def test_discovery_endpoints(api):
    robots = api.get("/robots.txt")
    assert "Disallow: /a/" in robots.text
    sitemap = api.get("/sitemap.xml")
    assert "<loc>https://grant.test/</loc>" in sitemap.text
    assert "/docs" in sitemap.text
    assert "/start" in sitemap.text


@pytest.fixture
def fake_upstream(monkeypatch):
    calls = []

    async def fake(policy, *, method, path, query, body, headers):
        calls.append({"policy": policy, "method": method, "path": path, "query": query, "body": body})
        return 200, {"content-type": "application/json"}, b'{"ok":true}'

    monkeypatch.setattr(main, "forward_upstream", fake)
    return calls


def receipt_for(api, grant_id):
    status = api.get(f"/v1/requests/{grant_id}").json()
    permission = status.get("permission") or {}
    return permission.get("signature", "")


def register_gateway(api, **overrides):
    body = {
        "name": "Payments API",
        "upstream_url": "https://api.example.com",
        "workspace": "gateway-team",
        "default_action": "review",
    }
    body.update(overrides)
    response = api.post("/v1/gateways", json=body)
    assert response.status_code == 201
    return response.json()


def test_gateway_registration_uses_capability_token(api):
    body = register_gateway(api, name="Billing")
    assert body["token"].startswith("gw_")
    assert f"/g/http/{body['token']}/" in body["http_url"]
    assert f"/g/mcp/{body['token']}" in body["mcp_url"]
    assert body["policy"]["default_action"] == "review"

    inspect = api.get(f"/v1/gateways/{body['token']}")
    assert inspect.status_code == 200
    assert inspect.json()["name"] == "Billing"
    assert inspect.json()["upstream_url"] == "https://api.example.com"

    missing = api.get("/v1/gateways/gw_doesnotexist")
    assert missing.status_code == 404


def test_http_gateway_pauses_sensitive_call_then_releases_after_approval(api, fake_upstream):
    gateway = register_gateway(api)
    token = gateway["token"]
    path = f"/g/http/{token}/transfer"

    paused = api.post(path, json={"amount": 48, "to": "acct_42"})
    assert paused.status_code == 202
    body = paused.json()
    assert body["status"] == "pending"
    assert body["grant_id"].startswith("req_")
    assert body["retry_header"] == "X-Grant-Request-Id"

    approval_token = body["approval_url"].rsplit("/", 1)[-1]
    approval = api.get(f"/a/{approval_token}")
    assert "POST /transfer" in approval.text
    assert "acct_42" in approval.text
    assert "48" in approval.text

    assert fake_upstream == []
    api.post(f"/a/{approval_token}/decide", data={"decision": "approve"}, follow_redirects=False)

    released = api.post(
        path,
        json={"amount": 48, "to": "acct_42"},
        headers={
            "X-Grant-Request-Id": body["grant_id"],
            "X-Grant-Receipt": receipt_for(api, body["grant_id"]),
        },
    )
    assert released.status_code == 200
    assert released.json() == {"ok": True}
    assert len(fake_upstream) == 1
    assert fake_upstream[0]["method"] == "POST"
    assert fake_upstream[0]["path"] == "/transfer"


def test_http_gateway_forwards_routine_call_when_policy_allows(api, fake_upstream):
    gateway = register_gateway(api, default_action="allow", name="Read API")
    response = api.get(f"/g/http/{gateway['token']}/health")
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert len(fake_upstream) == 1
    assert fake_upstream[0]["path"] == "/health"


def test_mcp_gateway_pauses_sensitive_tool_call(api, fake_upstream):
    gateway = register_gateway(api)
    payload = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "transfer_funds", "arguments": {"amount": 12}},
    }
    response = api.post(f"/g/mcp/{gateway['token']}", json=payload)
    assert response.status_code == 202
    body = response.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 7
    assert body["result"]["grant"]["status"] == "pending"

    approval_token = body["result"]["grant"]["approval_url"].rsplit("/", 1)[-1]
    approval = api.get(f"/a/{approval_token}")
    assert "mcp:transfer_funds" in approval.text
    assert "MCP tool transfer_funds" in approval.text


def test_gateway_rejects_without_forwarding(api, fake_upstream):
    gateway = register_gateway(api)
    path = f"/g/http/{gateway['token']}/transfer"
    paused = api.post(path, json={"amount": 1})
    approval_token = paused.json()["approval_url"].rsplit("/", 1)[-1]
    api.post(f"/a/{approval_token}/decide", data={"decision": "reject"}, follow_redirects=False)

    retry = api.post(path, json={"amount": 1}, headers={"X-Grant-Request-Id": paused.json()["grant_id"]})
    assert retry.status_code == 403
    assert fake_upstream == []


def test_gateway_requires_signed_receipt_on_retry(api, fake_upstream):
    gateway = register_gateway(api, name="Receipt API")
    path = f"/g/http/{gateway['token']}/transfer"
    paused = api.post(path, json={"amount": 48, "to": "acct_42"})
    approval_token = paused.json()["approval_url"].rsplit("/", 1)[-1]
    api.post(f"/a/{approval_token}/decide", data={"decision": "approve"}, follow_redirects=False)

    missing = api.post(
        path, json={"amount": 48, "to": "acct_42"},
        headers={"X-Grant-Request-Id": paused.json()["grant_id"]},
    )
    assert missing.status_code == 403
    assert "X-Grant-Receipt" in missing.json()["detail"]

    forged = api.post(
        path, json={"amount": 48, "to": "acct_42"},
        headers={"X-Grant-Request-Id": paused.json()["grant_id"], "X-Grant-Receipt": "deadbeef"},
    )
    assert forged.status_code == 403
    assert fake_upstream == []


def test_gateway_receipt_is_scope_and_gateway_bound(api, fake_upstream):
    gateway = register_gateway(api, name="Bound API")
    path = f"/g/http/{gateway['token']}/transfer"
    paused = api.post(path, json={"amount": 48, "to": "acct_42"})
    approval_token = paused.json()["approval_url"].rsplit("/", 1)[-1]
    api.post(f"/a/{approval_token}/decide", data={"decision": "approve"}, follow_redirects=False)
    grant_id = paused.json()["grant_id"]
    receipt = receipt_for(api, grant_id)

    changed_body = api.post(
        path, json={"amount": 9999, "to": "acct_42"},
        headers={"X-Grant-Request-Id": grant_id, "X-Grant-Receipt": receipt},
    )
    assert changed_body.status_code == 403
    assert "scope" in changed_body.json()["detail"].lower()

    other = register_gateway(api, name="Other API")
    other_path = f"/g/http/{other['token']}/transfer"
    other_call = api.post(
        other_path, json={"amount": 48, "to": "acct_42"},
        headers={"X-Grant-Request-Id": grant_id, "X-Grant-Receipt": receipt},
    )
    assert other_call.status_code == 403
    assert any(
        word in other_call.json()["detail"].lower() for word in ("gateway", "scope")
    )
    assert fake_upstream == []


def test_sdk_imports_without_third_party_dependencies():
    import grant

    assert grant.__version__ == "0.1.0"
    assert callable(grant.Grant)
    assert callable(grant.Grant().request)


def test_pricing_page_has_four_tiers_annual_toggle_and_contact_cta(api):
    ensure_workspace("ws_pricing")
    response = api.get("/pricing?org_id=ws_pricing")
    assert response.status_code == 200
    text = response.text
    for name in ("Free", "Plus", "Pro", "Enterprise"):
        assert f"<h3>{name}</h3>" in text
    assert "Most popular for production" in text
    assert "Save 20%" in text
    assert 'data-grant-cycle-button="annual"' in text
    assert "$20/mo" in text
    assert "₹2,400/mo" in text
    assert "$192.00/yr" in text
    assert "₹23,040.00/yr" in text
    assert "$150/mo" in text
    assert "₹12,600/mo" in text
    assert "$1,440.00/yr" in text
    assert "$4,000/mo" in text
    assert "₹340,000/mo" in text
    assert "Book a call" in text
    assert "Manual concierge upgrade" in text
    for bullet in (
        "Basic Approve once / Always allow pop-up",
        "Email &amp; Web links (1,000/mo)",
        "Auto-approve rules (spend/scope caps)",
        "Slack &amp; Webhook instant approvals (15,000/mo)",
        "30-day audit log retention",
        "Multi-approver routing &amp; role rules",
        "SMS / WhatsApp approval alerts (100,000/mo) — coming soon",
        "1-year audit trail + CSV/JSON exports",
        "White-label domain &amp; custom branding",
        "SSO / SAML &amp; org directory sync",
        "99.99% SLA + real-time SIEM log streaming",
    ):
        assert f"<li>{bullet}</li>" in text
    assert "hosted checkout is monthly-only today" in text
    assert "/v1/checkout/plus?org_id=ws_pricing" in text
    assert (
        "Use your Grant account email (user@email.com) at checkout for instant activation."
        in text
    )
    anonymous = api.get("/pricing")
    assert "/signin?" in anonymous.text
    assert 'href="/v1/checkout/plus?' not in anonymous.text


def test_console_shows_trial_usage_meter_and_channel_prompt(api):
    created = api.post("/v1/workspaces", data={"name": "Console team"}, follow_redirects=False)
    code = created.headers["location"].rsplit("/", 1)[-1]
    response = api.get(f"/console?code={code}")
    assert response.status_code == 200
    assert "Pro Guardrails trial active" in response.text
    assert "approvals used" in response.text
    assert "Slack approvals" in response.text
    assert "Upgrade" in response.text


def test_hard_quota_blocks_with_upgrade_metadata(api, monkeypatch):
    created = api.post("/v1/workspaces", data={"name": "Grace team"}, follow_redirects=False)
    code = created.headers["location"].rsplit("/", 1)[-1]
    main.get_plan(code)
    body = create(api, agent="grace-agent", action="refund_order", workspace=code)
    with main.transaction() as conn:
        conn.execute(
            "UPDATE plans SET tier='free', status='active', trial_ends_at='' WHERE org_id=?",
            (code,),
        )
        conn.execute(
            "UPDATE requests SET created_at=? WHERE id=?",
            ("2026-01-01T00:00:00Z", body["id"]),
        )
    monkeypatch.setattr(main, "monthly_usage", lambda org_id: 1_050)

    blocked = api.post("/v1/requests", json=payload(agent="grace-agent-2", workspace=code))
    assert blocked.status_code == 402
    detail = blocked.json()["detail"]
    assert detail["code"] == "approval_quota_exceeded"
    assert detail["current_tier"] == "free" and detail["required_tier"] == "plus"
    assert detail["used"] == 1_050 and detail["limit"] == 1_000
    assert f"org_id={code}" in detail["upgrade_url"]

    page = api.get(f"/w/{code}")
    assert "New approval requests are paused" in page.text
    assert "expire in 48 hours" in page.text
    assert "SMS / WhatsApp alerts are coming soon" in page.text


def test_approval_card_has_drawers_popup_metadata_and_compact_view(api):
    body = create(
        api,
        agent="drawer-agent",
        action="refund_order",
        parent_origin="https://app.example.test",
    )
    path = urlsplit(body["url"]).path
    response = api.get(body["url"])
    assert response.status_code == 200
    assert 'data-grant-nudge-trigger="always"' in response.text
    assert 'data-grant-nudge-trigger="always">Always allow</button>' in response.text
    assert "grant-drawer-auto" in response.text
    assert "grant-drawer-delivery" in response.text
    assert "grant-drawer-approver" in response.text
    assert "Auto-approve with caps" in response.text
    assert "Instant Slack &amp; webhook delivery" in response.text
    assert "Multi-approver routing" in response.text
    assert "Auto-approve rule" in response.text
    assert "Slack / webhook" in response.text
    assert "Route to approver" in response.text
    assert "Start the 14-day free trial" in response.text
    assert 'data-grant-allowed-origins="https://app.example.test,https://console.example.test"' in response.text
    assert 'data-grant-parent-origin="https://app.example.test"' in response.text
    assert '/grant-popup.js' in response.text
    assert "Protected by Grant" in response.text

    compact = api.get(f"{path}?compact=1")
    assert 'data-grant-compact="true"' in compact.text

    api.post(f"{path}/decide", data={"decision": "approve"}, follow_redirects=False)
    done = api.get(f"{path}?done=approve&parent_origin=https://app.example.test")
    assert 'data-grant-complete="true"' in done.text
    assert 'data-grant-decision="approve"' in done.text


def test_unlisted_popup_origin_is_never_trusted(api):
    body = create(api, agent="origin-agent", action="send_note", parent_origin="https://evil.example")
    response = api.get(body["url"])
    assert response.status_code == 200
    head = response.text.split("<body>", 1)[0]
    assert "data-grant-parent-origin" not in head
    assert "data-grant-allowed-origins" in head


def test_widget_js_route_serves_isolated_shadow_dom_script(api):
    response = api.get("/widget.js")
    assert response.status_code == 200
    assert "application/javascript" in response.headers["content-type"]
    assert "attachShadow" in response.text
    assert "grant:decision" in response.text
    assert "window.open" in response.text
    assert "noopener=yes" not in response.text
    assert "event.source !== popup" in response.text


def test_popup_script_route_is_the_single_source_of_the_handshake(api):
    response = api.get("/grant-popup.js")
    assert response.status_code == 200
    assert "application/javascript" in response.headers["content-type"]
    assert "grant:decision" in response.text
    assert "grant:ready" in response.text
    assert "auto_rule" in response.text
    assert "event.source !== window.opener" in response.text


def test_protected_dashboard_shows_agents_without_ids_or_emails(api):
    created = api.post("/v1/workspaces", data={"name": "Trust page"}, follow_redirects=False)
    code = created.headers["location"].rsplit("/", 1)[-1]
    body = create(api, agent="protected-agent", action="refund_order", workspace=code)
    path = urlsplit(body["url"]).path
    api.post(f"{path}/decide", data={"decision": "approve"}, follow_redirects=False)

    response = api.get(f"/protected/{code}")
    assert response.status_code == 200
    assert "Protected by Grant" in response.text
    assert "protected-agent" in response.text
    assert "Deploying your own agents?" in response.text
    visible = response.text.split("</style>", 1)[-1].split("<script>", 1)[0]
    assert "signature" not in visible.lower()
    assert "@" not in visible

    missing = api.get("/protected/ws_missing")
    assert missing.status_code == 404


def test_checkout_routes_redirect_to_fixed_monthly_forms(api, monkeypatch):
    monkeypatch.setenv("GRANT_CASHFREE_PLUS_MONTHLY_URL", "https://payments-test.cashfree.com/forms/grant-plus-monthly-inr")
    monkeypatch.setenv("GRANT_CASHFREE_PRO_MONTHLY_URL", "https://payments-test.cashfree.com/forms/grant-pro-monthly-inr")
    ensure_workspace("ws_checkout")

    plus = api.get("/v1/checkout/plus?org_id=ws_checkout", follow_redirects=False)
    assert plus.status_code == 302
    assert plus.headers["location"].endswith("/forms/grant-plus-monthly-inr")

    annual = api.get(
        "/v1/checkout/plus?cycle=annual&org_id=ws_checkout", follow_redirects=False
    )
    assert annual.status_code == 302
    assert annual.headers["location"].endswith("/forms/grant-plus-monthly-inr")

    pro = api.get("/v1/checkout/pro?org_id=ws_checkout", follow_redirects=False)
    assert pro.headers["location"].endswith("/forms/grant-pro-monthly-inr")

    enterprise = api.get("/v1/checkout/enterprise?org_id=ws_checkout", follow_redirects=False)
    assert enterprise.status_code == 302
    assert "/pricing#enterprise" in enterprise.headers["location"]

    concierge = api.get("/v1/checkout/concierge?org_id=ws_checkout", follow_redirects=False)
    assert concierge.headers["location"].endswith("/forms/grant-plus-monthly-inr")

    bad = api.get("/v1/checkout/plus?org_id=bad%20org", follow_redirects=False)
    assert bad.status_code == 400

    signed_out = api.get("/v1/checkout/plus?org_id=ws_unknown", follow_redirects=False)
    assert signed_out.status_code == 303
    assert signed_out.headers["location"].startswith("/signin?")

    signed_in = api.post(
        "/signin",
        data={"code": "ws_checkout", "next": "/pricing?plan=plus&cycle=monthly"},
        follow_redirects=False,
    )
    assert signed_in.status_code == 303
    assert "org_id=ws_checkout" in signed_in.headers["location"]


def test_billing_email_links_workspace_and_static_form_webhook_flips_tier(api):
    with main.transaction() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO workspaces (code, name, created_at) VALUES (?, ?, ?)",
            ("ws_form", "Form test", main.iso()),
        )
    saved = api.post(
        "/w/ws_form/billing-email",
        data={"email": "Owner@Example.com"},
        follow_redirects=False,
    )
    assert saved.status_code == 303
    assert main.get_billing_email("ws_form") == "owner@example.com"
    assert main.org_for_billing_email(" OWNER@example.com ") == "ws_form"
    with main.transaction() as conn:
        conn.execute(
            "INSERT INTO usage_events (org_id, request_id, created_at) VALUES (?, ?, ?)",
            ("ws_form", "req_before_upgrade", main.iso()),
        )
    assert main.monthly_usage("ws_form") == 1

    form_event = {
        "type": "PAYMENT_FORM_ORDER_WEBHOOK",
        "data": {
            "form": {"form_id": "grant_pro_monthly_inr", "cf_form_id": 385405894},
            "order": {
                "order_status": "PAID",
                "transaction_id": "txn_form_1",
                "customer_details": {"customer_email": "owner@example.com"},
            },
        },
    }
    raw, headers = signed_webhook(form_event)
    response = api.post("/v1/billing/webhook", content=raw, headers=headers)
    assert response.status_code == 200
    assert response.json()["applied"] is True
    plan = main.get_plan("ws_form")
    assert plan["tier"] == "pro"
    assert plan["status"] == "active"
    assert plan["quota_reset_at"]
    expiry = main.plans.parse(plan["plan_expires_at"])
    assert expiry is not None
    assert expiry > main.plans.utcnow() + timedelta(days=31)
    assert main.monthly_usage("ws_form") == 0
    assert "owner@example.com" not in response.text
    with main.closing(main.db()) as conn:
        reminder = conn.execute(
            "SELECT * FROM renewal_reminders WHERE org_id = 'ws_form'"
        ).fetchone()
    assert reminder is not None
    assert reminder["tier"] == "pro"
    assert reminder["status"] == "pending"
    assert reminder["form_url"].endswith("/forms/grant-pro-monthly-inr")

    duplicate = api.post("/v1/billing/webhook", content=raw, headers=headers)
    assert duplicate.json()["applied"] is False


def test_unclaimed_payment_claim_and_amount_mapping(api):
    ensure_workspace("ws_claim")

    def form_receipt(form_id: str, amount: int, email: str, transaction: str) -> dict:
        return {
            "type": "PAYMENT_FORM_ORDER_WEBHOOK",
            "data": {
                "form": {"form_id": form_id, "cf_form_id": 111},
                "order": {
                    "order_status": "PAID",
                    "order_amount": amount,
                    "order_currency": "INR",
                    "transaction_id": transaction,
                    "customer_details": {"customer_email": email},
                },
            },
        }

    first, first_headers = signed_webhook(
        form_receipt("grant_plus_monthly_inr", 2400, "payer.one@example.com", "txn_claim_1")
    )
    first_response = api.post("/v1/billing/webhook", content=first, headers=first_headers)
    assert first_response.json()["stored_unclaimed"] is True
    assert "payer.one@example.com" not in first_response.text
    assert main.get_plan("ws_claim")["tier"] != "plus"

    claimed = api.post(
        "/w/ws_claim/claim-payment",
        data={"claim": " PAYER.ONE@EXAMPLE.COM "},
        follow_redirects=False,
    )
    assert claimed.status_code == 303
    assert "payer.one@example.com" not in claimed.text
    assert main.get_plan("ws_claim")["tier"] == "plus"
    assert main.get_billing_email("ws_claim") == "payer.one@example.com"

    second, second_headers = signed_webhook(
        form_receipt("unmapped-form", 12600, "payer.two@example.com", "txn_amount_2")
    )
    second_response = api.post("/v1/billing/webhook", content=second, headers=second_headers)
    assert second_response.json()["stored_unclaimed"] is True
    claimed_by_id = api.post(
        "/w/ws_claim/claim-payment",
        data={"claim": "txn_amount_2"},
        follow_redirects=False,
    )
    assert claimed_by_id.status_code == 303
    assert main.get_plan("ws_claim")["tier"] == "pro"
    assert main.get_billing_email("ws_claim") == "payer.two@example.com"

    forged, forged_headers = signed_webhook(
        form_receipt("grant_pro_monthly_inr", 12600, "spoof@example.com", "txn_spoof")
    )
    forged_headers["x-grant-signature"] = "sha256=" + "00" * 32
    rejected = api.post("/v1/billing/webhook", content=forged, headers=forged_headers)
    assert rejected.status_code == 401
    with main.closing(main.db()) as conn:
        assert conn.execute(
            "SELECT 1 FROM unclaimed_payments WHERE payment_ref = 'txn_spoof'"
        ).fetchone() is None


def signed_webhook(payload: dict, secret: str | None = None) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    stamp = str(int(time.time()))
    key = secret or main.BILLING_WEBHOOK_SECRET
    digest = hmac.new(key.encode("utf-8"), stamp.encode("ascii") + b"." + raw, hashlib.sha256).hexdigest()
    return raw, {"x-grant-signature": "sha256=" + digest, "x-grant-timestamp": stamp}


def test_billing_webhook_flips_plan_once_and_handles_cancellation(api):
    completed = {
        "id": "evt_billing_1",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_billing_1",
                "customer": "cus_billing_1",
                "metadata": {"org_id": "ws_billing", "plan": "plus"},
            }
        },
    }
    raw, headers = signed_webhook(completed)
    response = api.post("/v1/billing/webhook", content=raw, headers=headers)
    assert response.status_code == 200
    assert response.json()["applied"] is True
    plan = main.get_plan("ws_billing")
    assert plan["tier"] == "plus"
    assert plan["status"] == "active"

    duplicate = api.post("/v1/billing/webhook", content=raw, headers=headers)
    assert duplicate.json()["applied"] is False

    cancelled = {
        "id": "evt_billing_2",
        "type": "customer.subscription.deleted",
        "client_reference_id": "ws_billing",
    }
    cancel_raw, cancel_headers = signed_webhook(cancelled)
    cancelled_response = api.post("/v1/billing/webhook", content=cancel_raw, headers=cancel_headers)
    assert cancelled_response.json()["applied"] is True
    assert main.get_plan("ws_billing")["tier"] == "free"

    tampered = api.post(
        "/v1/billing/webhook",
        content=raw,
        headers={
            "x-grant-signature": "sha256=" + "00" * 32,
            "x-grant-timestamp": headers["x-grant-timestamp"],
        },
    )
    assert tampered.status_code == 401


def test_day_27_renewal_reminders_are_scheduled_and_ops_gated(api):
    with main.transaction() as conn:
        due = main.iso_plus(-24 * 60)
        conn.execute(
            "UPDATE renewal_reminders SET due_at = ? WHERE status = 'pending' AND org_id = 'ws_form'",
            (due,),
        )
    unauthorized = api.get("/v1/billing/renewal-reminders")
    assert unauthorized.status_code == 401
    response = api.get(
        f"/v1/billing/renewal-reminders?token={main.OPS_TOKEN}&send=0"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["due"] >= 1
    assert body["sent"] == 0
    assert body["delivery_configured"] is False


def signed_cashfree_webhook(payload: dict) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    stamp = str(int(time.time() * 1000))
    key = main.CASHFREE_WEBHOOK_SECRET
    digest = hmac.new(key.encode("utf-8"), stamp.encode("ascii") + raw, hashlib.sha256).digest()
    signature = base64.b64encode(digest).decode("ascii")
    return raw, {"x-webhook-signature": signature, "x-webhook-timestamp": stamp}


def test_cashfree_webhook_flips_tier_once_and_rejects_tampering(api):
    paid = {
        "type": "PAYMENT_LINK_EVENT",
        "data": {
            "cf_link_id": "cf_ws_cashfree",
            "link_id": "grant_ws_cashfree_pro_monthly_abc",
            "link_status": "PAID",
            "link_notes": {"org_id": "ws_cashfree", "plan": "pro", "cycle": "monthly"},
            "order": {"transaction_id": "txn_cashfree_1", "transaction_status": "SUCCESS"},
        },
    }
    raw, headers = signed_cashfree_webhook(paid)
    response = api.post("/v1/billing/webhook", content=raw, headers=headers)
    assert response.status_code == 200
    assert response.json()["applied"] is True
    plan = main.get_plan("ws_cashfree")
    assert plan["tier"] == "pro"
    assert plan["status"] == "active"

    duplicate = api.post("/v1/billing/webhook", content=raw, headers=headers)
    assert duplicate.json()["applied"] is False

    bad_headers = dict(headers, **{"x-webhook-signature": base64.b64encode(b"bad").decode("ascii")})
    tampered = api.post("/v1/billing/webhook", content=raw, headers=bad_headers)
    assert tampered.status_code == 401


def test_cashfree_signed_amount_only_receipt_is_claimable(api):
    ensure_workspace("ws_amount_claim")
    amount_event = {
        "type": "PAYMENT_LINK_EVENT",
        "data": {
            "link_id": "grant_unmapped_link",
            "link_status": "PAID",
            "link_amount": 12600,
            "link_currency": "INR",
            "order": {"transaction_id": "txn_cashfree_amount"},
            "customer_details": {"customer_email": "amount.payer@example.com"},
        },
    }
    raw, headers = signed_cashfree_webhook(amount_event)
    response = api.post("/v1/billing/webhook", content=raw, headers=headers)
    assert response.status_code == 200
    assert response.json()["stored_unclaimed"] is True
    assert "amount.payer@example.com" not in response.text

    claimed = api.post(
        "/w/ws_amount_claim/claim-payment",
        data={"claim": "txn_cashfree_amount"},
        follow_redirects=False,
    )
    assert claimed.status_code == 303
    assert main.get_plan("ws_amount_claim")["tier"] == "pro"
    assert main.get_billing_email("ws_amount_claim") == "amount.payer@example.com"


def test_unsigned_webhook_events_are_ignored_only_when_not_actionable(api):
    ignored = {
        "type": "PAYMENT_LINK_EVENT",
        "data": {"link_status": "PARTIALLY_PAID"},
    }
    response = api.post("/v1/billing/webhook", json=ignored)
    assert response.status_code == 200
    assert response.json() == {"ok": True, "applied": False, "reason": "ignored"}

    actionable = {
        "type": "PAYMENT_LINK_EVENT",
        "data": {
            "link_status": "PAID",
            "link_notes": {"org_id": "ws_unsigned", "plan": "pro"},
        },
    }
    denied = api.post("/v1/billing/webhook", json=actionable)
    assert denied.status_code == 401


def test_ops_view_is_token_gated_fast_and_aggregate_only(api):
    denied = api.get("/ops.json")
    assert denied.status_code == 401
    assert "WWW-Authenticate" in denied.headers

    token = "ops-test-token-not-for-production"
    page = api.get(f"/ops?token={token}")
    assert page.status_code == 200
    assert "User count, live" in page.text
    assert "ops-organizations" in page.text
    assert "setInterval" in page.text

    response = api.get("/ops.json", headers={"x-grant-ops-token": token})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) >= {
        "generated_at",
        "workspaces",
        "organizations",
        "requests",
        "approved",
        "paid",
        "trials",
        "total_users",
        "unique_humans_reached",
        "popup_impressions",
        "unique_devices",
        "active_sessions",
        "recent_logins",
        "device_breakdown",
    }
    assert "@" not in response.text
    assert "api_key" not in response.text

    basic = base64.b64encode(f"ops:{token}".encode("utf-8")).decode("ascii")
    basic_response = api.get("/ops.json", headers={"Authorization": f"Basic {basic}"})
    assert basic_response.status_code == 200


def test_concurrent_decisions_create_exactly_one_permission(api):
    body = create(api, agent="concurrent-agent", action="refund_order")
    token = urlsplit(body["url"]).path.rsplit("/", 1)[-1]
    row = main.get_request_by_token(token)
    assert row is not None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: main.decide_request(row, "approve"), range(8)))
    assert sum(1 for result in results if result) == 1
    permissions = api.get("/v1/permissions/concurrent-agent").json()
    assert permissions["count"] == 1


def test_burst_idempotency_returns_one_request(api):
    key = "burst-idempotency-key"
    body = payload(agent="burst-agent", action="send_note")
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(
            pool.map(
                lambda _: api.post(
                    "/v1/requests", json=body, headers={"Idempotency-Key": key}
                ),
                range(8),
            )
        )
    assert {response.status_code for response in responses} == {201}
    assert len({response.json()["id"] for response in responses}) == 1


def test_blob_decided_state_wins_over_stale_local_copy(api, monkeypatch):
    body = create(api, agent="blob-agent", action="refund_order")
    token = urlsplit(body["url"]).path.rsplit("/", 1)[-1]
    row = main.get_request_by_id(body["id"])
    stale = main.request_snapshot(row)
    decided = dict(stale)
    decided["status"] = "decided"
    decided["decision"] = "approve"

    async def fake_get(path: str):
        if "decision-tokens/" in path or "decisions/" in path:
            return decided
        return None

    monkeypatch.setattr(main, "blob_enabled", lambda: True)
    monkeypatch.setattr(main, "_blob_get", fake_get)
    resolved = asyncio.run(main.resolve_request_by_token(token))
    assert resolved is not None
    assert resolved["status"] == "decided"
    assert resolved["decision"] == "approve"


def test_protocol_aliases_map_who_what_why_expiry(api):
    response = api.post(
        "/v1/requests",
        json={
            "who": "alias-agent",
            "what": "send_note",
            "why": "Alias rationale",
            "scope": {"amount": 1},
            "workspace": "support",
            "expiry": "2h",
        },
    )
    assert response.status_code == 201
    body = response.json()
    row = main.get_request_by_id(body["id"])
    assert row["agent"] == "alias-agent"
    assert row["action"] == "send_note"
    assert row["summary"] == "Alias rationale"
    assert "Auto-approve rule" in body["message"]


def test_auto_rule_creates_a_signed_scoped_permission(api):
    body = create(api, agent="rule-agent", action="refund_order")
    path = urlsplit(body["url"]).path
    api.post(f"{path}/decide", data={"decision": "auto_rule"}, follow_redirects=False)
    status = api.get(f"/v1/requests/{body['id']}").json()
    assert status["decision"] == "auto_rule"
    assert status["permission"]["policy"] == "auto_rule"
    assert status["permission"]["scope_hash"] == body["scope_hash"]
    verified = api.post(
        "/v1/permissions/verify",
        json={
            "id": status["permission"]["id"],
            "signature": status["permission"]["signature"],
        },
    )
    assert verified.json()["valid"] is True
    assert "30-day scoped rule" in api.get(path).text


def test_done_query_cannot_spoof_a_decision(api):
    body = create(api, agent="spoof-agent", action="send_note")
    path = urlsplit(body["url"]).path
    spoofed = api.get(f"{path}?done=approve")
    assert 'data-grant-complete="true"' not in spoofed.text
    assert "Approve once" in spoofed.text
    assert api.get(f"/v1/requests/{body['id']}").json()["status"] == "pending"

    api.post(f"{path}/decide", data={"decision": "approve"}, follow_redirects=False)
    location = api.post(
        f"{path}/decide",
        data={
            "decision": "reject",
            "parent_origin": "https://app.example.test",
            "compact": "1",
        },
        follow_redirects=False,
    ).headers["location"]
    assert "parent_origin=https%3A%2F%2Fapp.example.test" in location
    assert "compact=1" in location
    assert "done=" not in location
    assert api.get(f"/v1/requests/{body['id']}").json()["decision"] == "approve"


def test_oauth_scope_templates_are_machine_readable_and_zero_custody(api):
    response = api.get("/v1/policies/oauth-scopes")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == 1
    for scope in ("gmail.send", "stripe.charges", "slack.chat.write"):
        assert scope in body["templates"]
    assert "zero-custody" in body["custody"].lower()
    assert "access_token" not in json.dumps(body).lower()
    assert "refresh_token" not in json.dumps(body).lower()

    one = api.get("/v1/policies/oauth-scopes/stripe.charges")
    assert one.status_code == 200
    assert one.json()["template"]["risk"] == "high"
    assert one.json()["template"]["decision_hint"] == "require_human"
    assert api.get("/v1/policies/oauth-scopes/not.a.scope").status_code == 404

    from grant import policies

    gateway = policies.gateway_policy_for("gmail.send", workspace="support")
    assert gateway["sensitive_tools"] == ["send_email", "gmail.send"]
    assert gateway["custody"] == "zero"


def test_telemetry_records_login_popup_and_decision(api):
    with main.transaction() as conn:
        before_logins = conn.execute("SELECT COUNT(*) FROM login_history").fetchone()[0]
        before_popups = conn.execute("SELECT COUNT(*) FROM popup_impressions").fetchone()[0]

    ws = api.post("/v1/workspaces", data={"name": "Telemetry"}, follow_redirects=False)
    code = ws.headers["location"].rsplit("/", 1)[-1]
    api.get(f"/w/{code}")
    body = create(api, agent="telemetry-agent", action="send_note", workspace=code, channel="email")
    path = urlsplit(body["url"]).path
    api.get(path)
    api.post(f"{path}/decide", data={"decision": "approve"}, follow_redirects=False)

    with main.transaction() as conn:
        logins = conn.execute("SELECT COUNT(*) FROM login_history").fetchone()[0]
        impressions = conn.execute("SELECT COUNT(*) FROM popup_impressions").fetchone()[0]
        latest = conn.execute(
            "SELECT channel, decision, device_hash FROM popup_impressions "
            "ORDER BY opened_at DESC LIMIT 1"
        ).fetchone()
    assert logins >= before_logins + 2
    assert impressions >= before_popups + 1
    assert latest["channel"] == "email"
    assert latest["decision"] == "approve"
    assert len(latest["device_hash"]) == 64

    overview = main.telemetry.overview()
    assert overview["popup_impressions"] >= 1
    assert overview["total_users"] >= 1
    assert overview["unique_devices"] >= 1
    assert "@" not in json.dumps(overview)


def test_login_library_counts_users_logins_popups_and_computers(api):
    from grant import login_library

    before = login_library.summary()
    ws = api.post("/v1/workspaces", data={"name": "Library"}, follow_redirects=False)
    code = ws.headers["location"].rsplit("/", 1)[-1]
    api.get(f"/w/{code}")
    body = create(
        api, agent="library-agent", action="send_note", workspace=code,
        channel="browser_popup",
    )
    path = urlsplit(body["url"]).path
    api.get(path)
    api.post(f"{path}/decide", data={"decision": "approve"}, follow_redirects=False)

    report = login_library.report()
    assert set(report) >= {
        "generated_at", "total_users", "unique_humans_reached", "total_logins",
        "popup_impressions", "decided_popups", "unique_computers", "active_sessions",
        "login_history", "popup_history", "devices",
    }
    assert report["total_logins"] >= before["total_logins"] + 2
    assert report["popup_impressions"] >= before["popup_impressions"] + 1
    assert report["decided_popups"] >= before["decided_popups"] + 1
    assert report["total_users"] >= before["total_users"] + 1
    assert report["unique_computers"] >= 1
    assert report["login_history"][0]["source"] in {"workspace", "console", "signin"}
    assert any(
        row["channel"] == "browser_popup" and row["decision"] == "approve"
        for row in report["popup_history"]
    )
    assert report["devices"]
    assert all(set(item) == {"device", "count"} for item in report["devices"])
    payload = json.dumps(report)
    assert "@" not in payload
    assert code not in payload


def test_login_history_views_are_token_gated_and_private(api):
    denied = api.get("/login-history")
    assert denied.status_code == 401
    assert "WWW-Authenticate" in denied.headers
    assert api.get("/login-history.json").status_code == 401

    token = "ops-test-token-not-for-production"
    page = api.get(f"/login-history?token={token}")
    assert page.status_code == 200
    assert "Who reached Grant, live." in page.text
    assert "Login events" in page.text
    assert "Pop-up events" in page.text
    assert "Computers" in page.text
    assert "/login-history" in api.get(f"/ops?token={token}").text
    assert "Disallow: /login-history" in api.get("/robots.txt").text

    response = api.get("/login-history.json", headers={"x-grant-ops-token": token})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["total_users"] >= 1
    assert body["popup_impressions"] >= 1
    assert "@" not in response.text
    assert token not in response.text
    assert "api_key" not in response.text

    basic = base64.b64encode(f"ops:{token}".encode("utf-8")).decode("ascii")
    assert (
        api.get("/login-history.json", headers={"Authorization": f"Basic {basic}"}).status_code
        == 200
    )


def test_friendly_expiry_is_readable_countdown():
    past = "2026-01-02T09:21:00Z"
    assert main.friendly_expiry(past) == "Expired (9:21 AM international time)"
    upcoming = main.friendly_expiry(main.iso_plus(29))
    assert re.fullmatch(
        r"In \d+m \(\d{1,2}:\d{2} (AM|PM) international time\)", upcoming
    ), upcoming
    assert main.friendly_expiry("") == "Soon"


def test_approval_card_is_uncluttered_with_inline_account_options(api):
    body = create(
        api,
        agent="popup-agent",
        action="send_note",
        parent_origin="https://app.example.test",
    )
    path = urlsplit(body["url"]).path
    response = api.get(f"{path}?compact=1&parent_origin=https://app.example.test")
    text = response.text
    assert response.status_code == 200
    assert re.search(r"In \d+m \(\d{1,2}:\d{2} (AM|PM) international time\)", text)
    assert body["id"] not in text
    assert "Exact scope" in text
    assert "New here? Create a workspace · Already have one? Sign in" in text
    assert 'action="/v1/workspaces"' in text
    assert 'action="/signin"' in text
    expected_next = f"{path}?parent_origin=https%3A%2F%2Fapp.example.test&compact=1"
    assert html.escape(expected_next, quote=True) in text
    assert "Grant does not use passwords" in text


def test_workspace_and_signin_return_to_popup_approval(api):
    ensure_workspace("ws_popup_return")
    body = create(api, agent="return-agent", action="send_note")
    path = urlsplit(body["url"]).path

    created = api.post(
        "/v1/workspaces",
        data={"name": "Popup team", "next": path + "?compact=1"},
        follow_redirects=False,
    )
    assert created.status_code == 303
    assert created.headers["location"] == path + "?compact=1"

    signed = api.post(
        "/signin",
        data={"code": "ws_popup_return", "next": path + "?compact=1"},
        follow_redirects=False,
    )
    assert signed.status_code == 303
    assert signed.headers["location"] == path + "?compact=1"

    signin_html = api.get("/signin").text
    assert "/start?next=" in signin_html
    assert "capability" not in signin_html.lower()


def test_navigation_uses_plain_language(api):
    home = api.get("/").text
    for label in ("How it works", "Plans", "My workspace", "Sign in", "Activity"):
        assert label in home
    assert '<a href="/stats.json">Stats</a>' not in home
    assert ">Docs</a>" not in home


def test_public_discovery_files_and_cached_pages(api):
    project_root = Path(__file__).resolve().parents[1]
    robots_file = (project_root / "public" / "robots.txt").read_text(encoding="utf-8")
    sitemap_file = (project_root / "public" / "sitemap.xml").read_text(encoding="utf-8")
    assert "grant-approve.vercel.app" in robots_file
    assert "Disallow: /a/" in robots_file
    assert "Disallow: /r/" in robots_file
    for route in ("/", "/docs", "/pricing", "/stats"):
        assert f"https://grant-approve.vercel.app{route}" in sitemap_file
    assert "/a/" not in sitemap_file

    docs = api.get("/docs")
    assert docs.headers["cache-control"] == "public, s-maxage=60"
    stats = api.get("/stats")
    assert stats.status_code == 200
    assert stats.headers["cache-control"] == "public, s-maxage=60"
    assert "Quiet numbers." in stats.text
    visible = stats.text.split("</style>", 1)[-1].split("<script>", 1)[0]
    assert "@" not in visible


def test_approval_cards_carry_protocol_watermark(api):
    watermark = "● Protected by Grant · Zero-custody consent infrastructure"

    pending = create(api, agent="watermark-agent", action="send_note")
    assert watermark in api.get(pending["url"]).text

    with main.transaction() as conn:
        conn.execute(
            "UPDATE requests SET expires_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00Z", pending["id"]),
        )
    assert watermark in api.get(pending["url"]).text

    body = create(api, agent="receipt-agent", action="refund_order")
    path = urlsplit(body["url"]).path
    api.post(f"{path}/decide", data={"decision": "approve"}, follow_redirects=False)
    assert watermark in api.get(body["url"]).text


def test_magic_receipt_creates_workspace_and_signed_dashboard_link(api):
    api.cookies.clear()
    body = create(api, agent="receipt-agent", action="refund_order")
    path = urlsplit(body["url"]).path

    pending = api.get(body["url"])
    assert f"Approved. Receipt {body['id']} recorded." not in pending.text

    decided = api.post(f"{path}/decide", data={"decision": "approve"}, follow_redirects=False)
    assert decided.status_code == 303
    cookie_header = decided.headers.get("set-cookie", "")
    assert main.DASHBOARD_COOKIE + "=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header

    value = api.cookies.get(main.DASHBOARD_COOKIE)
    code = main.dashboard_code_from_cookie(value)
    assert code and code.startswith("ws_")
    assert main.get_workspace(code)
    assert main.dashboard_code_from_cookie(code + ".tampered") == ""
    assert main.dashboard_code_from_cookie("") == ""

    receipt = api.get(body["url"])
    assert f"Approved. Receipt {body['id']} recorded." in receipt.text
    assert "Want to see every AI agent you've authorized—or revoke Always allow anytime?" in receipt.text
    assert "Open Your Free Grant Dashboard →" in receipt.text
    assert f'href="/w/{code}"' in receipt.text
    assert "Building AI agents? Protect your own users' actions in 2 minutes." in receipt.text
    assert 'href="/start?from=receipt">Get Your Free API Key →' in receipt.text
    assert body["id"] not in pending.text

    reused = create(api, agent="receipt-agent-2", action="send_note")
    api.post(f"{urlsplit(reused['url']).path}/decide", data={"decision": "always"}, follow_redirects=False)
    assert api.cookies.get(main.DASHBOARD_COOKIE) == value


def test_a2a_gate_halts_risky_handoffs_and_passes_routine_ones(api):
    routine = api.post(
        "/v1/a2a/gate",
        json={
            "sender": "planner",
            "receiver": "researcher",
            "task": "Summarize public release notes",
            "payload": {"topic": "release notes"},
            "workspace": "a2a",
        },
    )
    assert routine.status_code == 200
    assert routine.json()["status"] == "passed"
    assert routine.json()["grant_id"] == ""

    risky = api.post(
        "/v1/a2a/gate",
        json={
            "sender": "planner",
            "receiver": "billing-agent",
            "task": "pay the outstanding invoice",
            "payload": {"amount": 120},
            "workspace": "a2a",
            "parent_origin": "https://app.example.test",
        },
    )
    assert risky.status_code == 202
    result = risky.json()
    assert result["status"] == "pending"
    assert result["grant_id"].startswith("req_")
    assert result["approval_url"].startswith("https://grant.test/a/")
    assert "X-Grant-Request-Id" == result["retry_header"]

    status = api.get(f"/v1/requests/{result['grant_id']}").json()
    assert status["status"] == "pending"
    assert status["scope_hash"]

    forced = api.post(
        "/v1/a2a/gate",
        json={
            "sender": "planner",
            "receiver": "writer",
            "task": "Draft a short summary",
            "require_approval": True,
        },
    )
    assert forced.status_code == 202
    assert main.a2a_needs_approval("pay vendor", {}) is True
    assert main.a2a_needs_approval("read notes", {"topic": "notes"}) is False


def test_inject_script_route_serves_browser_interceptor(api):
    response = api.get("/grant-inject.js")
    assert response.status_code == 200
    assert "application/javascript" in response.headers["content-type"]
    assert "XMLHttpRequest.prototype.open" in response.text
    assert "window.open" in response.text
    assert "attachShadow" not in response.text
    assert "grant:inject-decision" in response.text
    assert "pendingResolvers[grantId]" in response.text
    assert "__grantInjectFinish" not in response.text
    assert "channel: \"browser_inject\"" in response.text


def test_public_api_allows_cross_origin_inject_and_a2a_calls(api):
    origin = "https://another-app.example"
    preflight = api.options(
        "/v1/requests",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert preflight.status_code == 204
    assert preflight.headers["access-control-allow-origin"] == "*"
    assert "POST" in preflight.headers["access-control-allow-methods"]

    body = api.post(
        "/v1/requests",
        json=payload(agent="cors-agent", action="send_note"),
        headers={"Origin": origin},
    )
    assert body.headers["access-control-allow-origin"] == "*"
    assert api.get(f"/v1/requests/{body.json()['id']}", headers={"Origin": origin}).headers[
        "access-control-allow-origin"
    ] == "*"
    assert api.post(
        "/v1/a2a/gate",
        json={"sender": "a", "receiver": "b", "task": "read notes"},
        headers={"Origin": origin},
    ).headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-origin" not in api.get("/docs").headers


def test_neon_schema_declares_durable_launch_tables():
    schema = (Path(__file__).resolve().parents[1] / "migrations" / "001_neon_schema.sql").read_text(
        encoding="utf-8"
    )
    for table in (
        "users",
        "organizations",
        "api_keys",
        "approval_requests",
        "auto_approve_rules",
        "login_history",
        "popup_impressions",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in schema
    assert "idx_rules_claim" in schema
    assert "idx_api_keys_org" in schema


def test_workspace_and_request_are_mirrored_into_durable_tables(api):
    ensure_workspace("ws_durable")
    body = create(api, agent="durable-agent", action="send_note", workspace="ws_durable")
    with main.transaction() as conn:
        org = conn.execute("SELECT * FROM organizations WHERE id = ?", ("ws_durable",)).fetchone()
        approval = conn.execute(
            "SELECT * FROM approval_requests WHERE id = ?", (body["id"],)
        ).fetchone()
    assert org["name"] == "ws_durable test"
    assert org["plan_tier"] in {"free", "pro"}
    assert approval["org_id"] == "ws_durable"
    assert approval["token"] and approval["status"] == "pending"


def test_production_refuses_ephemeral_sqlite_without_postgres(monkeypatch):
    from grant import db as dbmod

    monkeypatch.setattr(dbmod, "_APP_ENV", "production")
    monkeypatch.setattr(dbmod, "_DSN", "")
    monkeypatch.setattr(dbmod, "_ALLOW_SQLITE_IN_PROD", False)
    with pytest.raises(RuntimeError, match="DATABASE_URL is required in production"):
        dbmod.require_production_store()
    monkeypatch.setattr(dbmod, "_ALLOW_SQLITE_IN_PROD", True)
    dbmod.require_production_store()


def force_tier(code: str, tier: str) -> None:
    main.get_plan(code)
    with main.transaction() as conn:
        conn.execute(
            "UPDATE plans SET tier=?, status='active', trial_ends_at='', plan_expires_at='' "
            "WHERE org_id=?",
            (tier, code),
        )
        conn.execute("UPDATE organizations SET plan_tier=? WHERE id=?", (tier, code))


def _magic_token(link: str) -> str:
    query = dict(parse_qsl(urlsplit(link).query))
    return query["token"]


def test_magic_link_send_stores_only_digest_and_exposes_dev_link(api):
    email = "magic-send@example.test"
    response = api.post("/v1/auth/magic-link", json={"email": email})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["delivery"] == "console"
    link = body["dev_link"]
    assert link.startswith("https://grant.test/auth/verify?")
    raw = _magic_token(link)

    with main.transaction() as conn:
        row = conn.execute(
            "SELECT * FROM magic_links WHERE email = ? ORDER BY created_at DESC LIMIT 1", (email,)
        ).fetchone()
    assert row is not None
    assert row["token_hash"] == main.hash_token(raw)
    assert raw not in str(dict(row))


def test_magic_link_verify_creates_user_session_and_login_history(api):
    email = "magic-verify@example.test"
    link = api.post("/v1/auth/magic-link", json={"email": email}).json()["dev_link"]
    with main.transaction() as conn:
        before = conn.execute(
            "SELECT COUNT(*) FROM login_history WHERE source = 'magic_link'"
        ).fetchone()[0]

    verified = api.get(link, follow_redirects=False)
    assert verified.status_code == 303
    assert verified.headers["location"].startswith("/w/")
    assert main.SESSION_COOKIE in verified.cookies

    with main.transaction() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        session = conn.execute(
            "SELECT * FROM auth_sessions WHERE id = ?",
            (verified.cookies[main.SESSION_COOKIE],),
        ).fetchone()
        after = conn.execute(
            "SELECT COUNT(*) FROM login_history WHERE source = 'magic_link'"
        ).fetchone()[0]
    assert user is not None and user["last_login_at"]
    assert session is not None and session["user_id"] == user["id"]
    assert session["org_id"] and session["expires_at"]
    assert after == before + 1


def test_magic_link_is_one_time_only(api):
    email = "magic-once@example.test"
    link = api.post("/v1/auth/magic-link", json={"email": email}).json()["dev_link"]
    assert api.get(link, follow_redirects=False).status_code == 303
    replay = api.get(link, follow_redirects=False)
    assert replay.status_code == 400
    assert "invalid or expired" in replay.json()["detail"]


def test_magic_link_links_anonymous_claim_rules(api):
    email = "magic-claim@example.test"
    claim = "claim_" + main.new_code(8)
    with main.transaction() as conn:
        conn.execute(
            "INSERT INTO auto_approve_rules (id, org_id, user_id, agent, action, scope_json, "
            "claim_token, status, created_at) VALUES (?, ?, '', 'a', 'b', '{}', ?, 'active', ?)",
            ("rule_" + main.new_code(8), "ws_claim", claim, main.iso()),
        )
    link = api.post(
        "/v1/auth/magic-link", json={"email": email, "claim_token": claim}
    ).json()["dev_link"]
    assert api.get(link, follow_redirects=False).status_code == 303

    with main.transaction() as conn:
        rule = conn.execute(
            "SELECT * FROM auto_approve_rules WHERE claim_token = ?", (claim,)
        ).fetchone()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    assert rule["user_id"] == user["id"]
    assert rule["linked_at"]


@contextmanager
def _signed_in(api, email: str):
    """Temporarily attach a magic-link session to the shared test client."""
    previous = dict(api.cookies)
    link = api.post("/v1/auth/magic-link", json={"email": email}).json()["dev_link"]
    verified = api.get(link, follow_redirects=False)
    api.cookies.set(main.SESSION_COOKIE, verified.cookies[main.SESSION_COOKIE])
    try:
        yield
    finally:
        api.cookies.clear()
        api.cookies.update(previous)


def test_api_key_mint_stores_only_digest_and_lists_metadata(api):
    with _signed_in(api, "key-mint@example.test"):
        created = api.post("/api/keys", json={"name": "ci agent"})
        assert created.status_code == 201
        body = created.json()
        raw = body["key"]
        assert raw.startswith("gr_live_") and len(raw) > 24
        assert body["key_prefix"] in raw

        with main.transaction() as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (body["id"],)).fetchone()
        assert row["key_hash"] == main.hash_token(raw)
        assert raw not in str(dict(row))
        assert row["user_id"] and row["org_id"] == body["org_id"]

        listed = api.get("/api/keys")
        assert listed.status_code == 200
        keys = listed.json()["keys"]
        assert any(item["id"] == body["id"] for item in keys)
        assert all("key" not in item and "key_hash" not in item for item in keys)


def test_api_key_authenticates_protected_endpoints_and_rejects_invalid(api):
    with _signed_in(api, "key-auth@example.test"):
        body = api.post("/api/keys", json={"name": "agent"}).json()
    raw = body["key"]
    auth = {"Authorization": f"Bearer {raw}"}

    assert api.get("/api/keys", headers=auth).status_code == 200
    created = api.post(
        "/v1/requests",
        json=payload(agent="bearer-agent", action="send_note", workspace=body["org_id"]),
        headers=auth,
    )
    assert created.status_code == 201
    assert api.post("/v1/a2a/gate", json={"sender": "a", "receiver": "b", "task": "pay"}, headers=auth).status_code in {200, 202}

    bad = {"Authorization": "Bearer gr_live_not_a_real_key_000000"}
    assert api.get("/api/keys", headers=bad).status_code == 401
    assert api.post("/v1/requests", json=payload(), headers=bad).status_code == 401

    revoked = api.delete(f"/api/keys/{body['id']}", headers=auth)
    assert revoked.status_code == 200 and revoked.json()["revoked"] is True
    assert api.get("/api/keys", headers=auth).status_code == 401

    with main.transaction() as conn:
        row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (body["id"],)).fetchone()
    assert row["revoked_at"]


def test_rule_feature_gates_enforce_plus_and_pro(api):
    ensure_workspace("ws_gates")
    force_tier("ws_gates", "free")

    blocked = api.post(
        "/v1/rules",
        json={"workspace": "ws_gates", "agent": "a", "action": "b", "max_amount": 10},
    )
    assert blocked.status_code == 403
    detail = blocked.json()["detail"]
    assert detail["code"] == "plan_upgrade_required"
    assert detail["current_tier"] == "free" and detail["required_tier"] == "plus"
    assert detail["feature"] == "conditional_auto_approve"

    plain = api.post(
        "/v1/rules", json={"workspace": "ws_gates", "agent": "a", "action": "b"}
    )
    assert plain.status_code == 201

    force_tier("ws_gates", "plus")
    allowed = api.post(
        "/v1/rules",
        json={"workspace": "ws_gates", "agent": "a", "action": "b", "max_amount": 10},
    )
    assert allowed.status_code == 201
    routing = api.post(
        "/v1/rules",
        json={"workspace": "ws_gates", "agent": "a", "action": "b", "multi_approver": True},
    )
    assert routing.status_code == 403
    assert routing.json()["detail"]["required_tier"] == "pro"

    force_tier("ws_gates", "pro")
    routed = api.post(
        "/v1/rules",
        json={"workspace": "ws_gates", "agent": "a", "action": "b", "multi_approver": True},
    )
    assert routed.status_code == 201 and routed.json()["multi_approver"] is True
    listed = api.get("/v1/rules", params={"workspace": "ws_gates"})
    assert listed.status_code == 200
    assert all("claim_token" not in item for item in listed.json()["rules"])


def test_channel_and_auto_rule_gates_enforce_tiers(api):
    ensure_workspace("ws_channels")
    force_tier("ws_channels", "free")
    sms = api.post(
        "/v1/requests", json=payload(agent="sms-agent", workspace="ws_channels", channel="sms")
    )
    assert sms.status_code == 403
    assert sms.json()["detail"]["feature"] == "mobile_channels"
    assert sms.json()["detail"]["required_tier"] == "pro"

    force_tier("ws_channels", "plus")
    slack = api.post(
        "/v1/requests", json=payload(agent="slack-agent", workspace="ws_channels", channel="slack")
    )
    assert slack.status_code == 201

    force_tier("ws_channels", "free")
    body = create(api, agent="rule-agent", action="send_note", workspace="ws_channels")
    with main.transaction() as conn:
        row = conn.execute("SELECT token FROM requests WHERE id = ?", (body["id"],)).fetchone()
    decision = api.post(
        f"/a/{row['token']}/decide", data={"decision": "auto_rule"}, follow_redirects=False
    )
    assert decision.status_code == 403
    assert decision.json()["detail"]["required_tier"] == "plus"


def test_pricing_marks_unconnected_mobile_channels_as_coming_soon(api):
    page = api.get("/pricing?org_id=ws_pricing")
    assert page.status_code == 200
    assert "SMS / WhatsApp approval alerts (100,000/mo) — coming soon" in page.text
    assert "marked “coming soon” until a provider is configured" in page.text
    assert "hosted checkout is monthly-only today" in page.text


def test_billing_status_is_ops_gated_and_reports_tier(api):
    ensure_workspace("ws_billing_status")
    force_tier("ws_billing_status", "plus")
    unauthorized = api.get("/api/billing/status", params={"org_id": "ws_billing_status"})
    assert unauthorized.status_code == 401

    basic = base64.b64encode(f"ops:{os.environ['GRANT_OPS_TOKEN']}".encode("utf-8")).decode("ascii")
    response = api.get(
        "/api/billing/status",
        params={"org_id": "ws_billing_status"},
        headers={"Authorization": f"Basic {basic}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["org_id"] == "ws_billing_status"
    assert body["tier"] == "plus" and body["stored_tier"] == "plus"
    assert body["cashfree_webhook_configured"] is True


def test_cashfree_test_webhook_activates_tier_and_is_idempotent(api, monkeypatch):
    ensure_workspace("ws_cf_test")
    force_tier("ws_cf_test", "free")
    monkeypatch.setattr(main, "APP_ENV", "development")
    monkeypatch.setattr(main, "ALLOW_TEST_WEBHOOK", True)
    token = os.environ["GRANT_OPS_TOKEN"]

    unauthenticated = api.post(
        "/api/webhooks/cashfree/test", json={"org_id": "ws_cf_test", "plan": "plus"}
    )
    assert unauthenticated.status_code == 401
    bad_request = api.post(
        "/api/webhooks/cashfree/test", params={"token": token}, json={}
    )
    assert bad_request.status_code == 400

    event = api.post(
        "/api/webhooks/cashfree/test",
        params={"token": token},
        json={"org_id": "ws_cf_test", "plan": "plus", "event_id": "test_gap6_1"},
    )
    assert event.status_code == 200
    body = event.json()
    assert body["simulation"] is True and body["applied"] is True
    assert body["before_tier"] == "free" and body["after_tier"] == "plus"

    replay = api.post(
        "/api/webhooks/cashfree/test",
        params={"token": token},
        json={"org_id": "ws_cf_test", "plan": "plus", "event_id": "test_gap6_1"},
    )
    assert replay.status_code == 200 and replay.json()["applied"] is False

    with main.transaction() as conn:
        stored = conn.execute(
            "SELECT plan_tier FROM organizations WHERE id = ?", ("ws_cf_test",)
        ).fetchone()
    assert stored["plan_tier"] == "plus"

