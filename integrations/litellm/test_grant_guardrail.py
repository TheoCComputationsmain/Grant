"""Run from the Grant repository root:

    python -m pytest integrations/litellm/test_grant_guardrail.py -q

No LiteLLM install is required: the module falls back to a tiny local shim while
still inheriting the real CustomGuardrail when installed upstream.
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest

from grant_guardrail import (
    CHECKPOINT,
    DEFAULT_GRANT_BASE_URL,
    GrantApprovalRequired,
    GrantDenied,
    GrantGuardrail,
    resolve_grant_base_url,
)

APPROVED = {
    "id": "req_approve1",
    "request_id": "req_approve1",
    "status": "approved",
    "decision_type": "continue_once",
    "signed_receipt": "eyJyZXF1ZXN0X2lkIjoicmVxX2FwcHJvdmUxIn0",
    "receipt_url": "/receipt/req_approve1",
}
PENDING = {
    "id": "req_pending1",
    "request_id": "req_pending1",
    "status": "pending",
    "approval_url": "https://grant-consent.vercel.app/a/req_pending1",
    "receipt_url": "/receipt/req_pending1",
    "expires_at": "2026-11-27T10:21:00Z",
}
TOOL_CALL = {
    "choices": [
        {
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "send_email",
                            "arguments": json.dumps(
                                {"to": "private@example.test", "api_key": "sk-secret-123", "body": "hello"}
                            ),
                        },
                    }
                ],
            }
        }
    ]
}
NO_TOOL_CALL = {"choices": [{"message": {"role": "assistant", "content": "Just a note."}}]}


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_default_base_url_is_live_production():
    assert resolve_grant_base_url() == DEFAULT_GRANT_BASE_URL
    assert resolve_grant_base_url("https://custom.example/") == "https://custom.example"


def test_no_tool_calls_make_no_grant_request():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    async def run() -> None:
        async with _client(handler) as client:
            guard = GrantGuardrail(client=client)
            assert await guard.async_post_call_success_hook(data={}, response=NO_TOOL_CALL) is None

    asyncio.run(run())
    assert seen == []


def test_unprotected_tool_is_ignored():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json=APPROVED)

    async def run() -> None:
        async with _client(handler) as client:
            guard = GrantGuardrail(client=client, protected_tools={"issue_refund"})
            response = {"choices": [{"message": {"tool_calls": [{"function": {"name": "get_weather", "arguments": {}}}]}}]}
            assert await guard.async_post_call_success_hook(data={}, response=response) is None

    asyncio.run(run())
    assert seen == []


def test_approved_call_passes_through_once_without_raw_arguments():
    seen: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, json.loads(request.content)))
        return httpx.Response(201, json=APPROVED)

    async def run() -> None:
        async with _client(handler) as client:
            guard = GrantGuardrail(client=client, approval_mode=CHECKPOINT)
            start = time.perf_counter()
            result = await guard.async_post_call_success_hook(data={}, response=TOOL_CALL)
            assert result is None
            assert guard.last_latency_ms is not None and guard.last_latency_ms < 150

    asyncio.run(run())
    assert [path for path, _ in seen] == ["/v1/approvals"]
    request_json = json.dumps(seen)
    assert "send_email" in request_json
    assert "sk-secret-123" not in request_json
    assert "private@example.test" not in request_json
    assert seen[0][1]["scope"]["argument_keys"] == ["api_key", "body", "to"]


def test_checkpoint_mode_raises_structured_approval_required():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(202, json=PENDING)

    async def run() -> None:
        async with _client(handler) as client:
            guard = GrantGuardrail(client=client, approval_mode=CHECKPOINT)
            with pytest.raises(GrantApprovalRequired) as exc:
                await guard.async_post_call_success_hook(data={}, response=TOOL_CALL)
            payload = exc.value.as_dict()
            assert payload["grant_approval_required"] is True
            assert payload["request_id"] == "req_pending1"
            assert payload["approval_url"] == PENDING["approval_url"]
            assert "Open the Grant checkpoint" in payload["message"]

    asyncio.run(run())
    assert seen == ["/v1/approvals"]


def test_blocking_mode_polls_until_approved():
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.method == "POST":
            return httpx.Response(202, json=PENDING)
        return httpx.Response(
            200,
            json={
                "request_id": "req_pending1",
                "status": "decided",
                "decision": "approve",
                "signed_receipt": "eyJyZXF1ZXN0X2lkIjoicmVxX3BlbmRpbmcxIn0",
            },
        )

    async def run() -> None:
        async with _client(handler) as client:
            guard = GrantGuardrail(client=client, approval_mode="blocking", poll_interval=0.01)
            assert await guard.async_post_call_success_hook(data={}, response=TOOL_CALL) is None

    asyncio.run(run())
    assert seen == [("POST", "/v1/approvals"), ("GET", "/v1/approvals/req_pending1")]


def test_blocking_mode_denies_on_reject():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(202, json=PENDING)
        return httpx.Response(200, json={"request_id": "req_pending1", "status": "decided", "decision": "reject"})

    async def run() -> None:
        async with _client(handler) as client:
            guard = GrantGuardrail(client=client, approval_mode="blocking", poll_interval=0.01)
            with pytest.raises(GrantDenied, match="did not approve"):
                await guard.async_post_call_success_hook(data={}, response=TOOL_CALL)

    asyncio.run(run())


def test_wildcard_protects_every_tool_and_fail_closed_on_http_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"detail": "unavailable"})

    async def run() -> None:
        async with _client(handler) as client:
            guard = GrantGuardrail(client=client, protected_tools={"*"}, fail_open=False)
            with pytest.raises(GrantDenied, match="http_503"):
                await guard.async_post_call_success_hook(data={}, response=TOOL_CALL)
            permissive = GrantGuardrail(client=client, protected_tools={"*"}, fail_open=True)
            no_calls = {"choices": [{"message": {"tool_calls": [{"function": {"name": "anything", "arguments": {}}}]}}]}
            assert await permissive.async_post_call_success_hook(data={}, response=no_calls) is None

    asyncio.run(run())


def test_invalid_approval_mode_is_rejected():
    with pytest.raises(ValueError, match="approval_mode"):
        GrantGuardrail(approval_mode="maybe")
