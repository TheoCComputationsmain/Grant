"""Grant post-call guardrail for LiteLLM.

Upstream target (PR package):
  litellm/proxy/guardrails/guardrail_hooks/grant/grant_guardrail.py

Zero new dependencies: this module uses ``httpx``, which LiteLLM already ships,
plus the Python standard library. Zero custody: only tool names, a short summary,
and redacted scope metadata (argument key names plus a hash) are sent to Grant.
Credential values, payment details, raw arguments, and raw PII are never sent.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Iterable

import httpx

try:  # pragma: no cover - the fallback only applies outside a LiteLLM install
    from litellm.integrations.custom_guardrail import CustomGuardrail
except ImportError:  # pragma: no cover
    class CustomGuardrail:  # minimal local shim so upstream tests run anywhere
        def __init__(self, guardrail_name: str | None = None, **kwargs: Any) -> None:
            self.guardrail_name = guardrail_name


DEFAULT_GRANT_BASE_URL = "https://grant-consent.vercel.app"
ALLOWING_DECISIONS = frozenset({"approve", "always", "auto_rule", "approved"})
BLOCKING = "blocking"
CHECKPOINT = "checkpoint"
DEFAULT_PROTECTED_TOOLS = frozenset(
    {
        "send_email",
        "send_message",
        "issue_refund",
        "create_charge",
        "transfer_funds",
        "publish_content",
        "write_record",
        "delete_record",
        "execute_payment",
    }
)


def resolve_grant_base_url(explicit: str | None = None) -> str:
    """Env → local Vercel project config → documented hosted default."""
    candidate = (
        explicit
        or os.environ.get("GRANT_BASE_URL")
        or os.environ.get("GRANT_PUBLIC_BASE_URL")
        or ""
    ).strip()
    if candidate:
        return candidate.rstrip("/")
    here = Path(__file__).resolve()
    for root in (Path.cwd(), *here.parents):
        config = root / ".vercel" / "project.json"
        if config.is_file():
            try:
                name = str(json.loads(config.read_text(encoding="utf-8")).get("projectName") or "").strip()
            except (OSError, ValueError):
                name = ""
            if name:
                return f"https://{name}.vercel.app"
    return DEFAULT_GRANT_BASE_URL


class GrantApprovalRequired(Exception):
    """Checkpoint-mode signal carrying the structured Grant popup payload."""

    def __init__(self, *, request_id: str, approval_url: str, receipt_url: str = "", expires_at: str = "", signed_receipt: str = "") -> None:
        self.metadata = {
            "grant_approval_required": True,
            "request_id": request_id,
            "approval_url": approval_url,
            "receipt_url": receipt_url,
            "expires_at": expires_at,
            "signed_receipt": signed_receipt,
            "message": "Open the Grant checkpoint, approve, then retry the tool call.",
        }
        super().__init__(json.dumps(self.metadata, sort_keys=True))

    def as_dict(self) -> dict[str, Any]:
        return dict(self.metadata)


class GrantDenied(Exception):
    """The human rejected, cancelled, or the receipt could not be verified."""


class GrantApprovalTimeout(Exception):
    """Blocking mode ran out of time before a human decided."""


def _tool_function(call: Any) -> tuple[str, Any, str]:
    if isinstance(call, dict):
        function = call.get("function") if isinstance(call.get("function"), dict) else {}
        name = str(function.get("name") or call.get("name") or "")
        arguments = function.get("arguments", call.get("arguments", {}))
        call_id = str(call.get("id") or "")
    else:
        function = getattr(call, "function", None)
        name = str(getattr(function, "name", None) or getattr(call, "name", "") or "")
        arguments = getattr(function, "arguments", None)
        if arguments is None:
            arguments = getattr(call, "arguments", {}) or {}
        call_id = str(getattr(call, "id", "") or "")
    return name, arguments, call_id


def _iter_tool_calls(response: Any) -> Iterable[Any]:
    if response is None:
        return
    data: Any = response
    if hasattr(response, "model_dump"):
        try:
            data = response.model_dump(mode="json")
        except TypeError:  # pragma: no cover - older pydantic
            data = response.model_dump()
    if not isinstance(data, dict):
        return
    choices = data.get("choices")
    if isinstance(choices, list):
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message") or choice.get("delta") or {}
            if isinstance(message, dict) and isinstance(message.get("tool_calls"), list):
                yield from message["tool_calls"]
    output = data.get("output")
    if isinstance(output, list):
        for item in output:
            if isinstance(item, dict) and item.get("type") == "function_call":
                yield {
                    "id": item.get("call_id") or item.get("id") or "",
                    "type": "function",
                    "function": {"name": item.get("name") or "", "arguments": item.get("arguments") or {}},
                }


def _redacted_scope(arguments: Any, call_id: str) -> dict[str, Any]:
    """Derive non-sensitive metadata only; values never leave the process."""
    parsed: Any = arguments
    if isinstance(arguments, str):
        try:
            parsed = json.loads(arguments)
        except (TypeError, ValueError):
            parsed = {"unparsed": True}
    if not isinstance(parsed, dict):
        parsed = {"value": parsed}
    try:
        canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        canonical = repr(sorted(str(key) for key in parsed))
    return {
        "tool_call_id": call_id[:120],
        "argument_keys": sorted(str(key) for key in parsed)[:50],
        "arguments_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


class GrantGuardrail(CustomGuardrail):
    """Gate returned tool calls through a Grant human checkpoint.

    ``approval_mode="checkpoint"`` raises :class:`GrantApprovalRequired` with the
    approval URL so the caller can surface the Grant popup immediately.
    ``approval_mode="blocking"`` polls ``/v1/approvals/{request_id}`` until a
    human decides. An already-approved call adds one HTTP round trip only.
    """

    use_native_lifecycle_hooks = True

    def __init__(
        self,
        guardrail_name: str = "grant-approval",
        *,
        protected_tools: Iterable[str] | None = None,
        grant_base_url: str | None = None,
        api_key: str | None = None,
        workspace: str = "public",
        approval_mode: str = CHECKPOINT,
        timeout: float = 2.0,
        poll_interval: float = 1.0,
        poll_timeout: float = 300.0,
        fail_open: bool = False,
        client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("event_hook", "post_call")
        super().__init__(guardrail_name=guardrail_name, **kwargs)
        if approval_mode not in {BLOCKING, CHECKPOINT}:
            raise ValueError("approval_mode must be 'blocking' or 'checkpoint'")
        self.protected_tools = frozenset(
            str(tool).strip() for tool in (protected_tools if protected_tools is not None else DEFAULT_PROTECTED_TOOLS)
        )
        self.base_url = resolve_grant_base_url(grant_base_url)
        self.api_key = api_key or os.environ.get("GRANT_API_KEY") or ""
        self.workspace = workspace[:60] or "public"
        self.approval_mode = approval_mode
        self.timeout = timeout
        self.poll_interval = max(0.05, poll_interval)
        self.poll_timeout = max(1.0, poll_timeout)
        self.fail_open = fail_open
        self.last_latency_ms: float | None = None
        self._client = client
        self._owns_client = client is None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=0.5))
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _matches(self, tool_name: str) -> bool:
        if "*" in self.protected_tools:
            return True
        needle = tool_name.strip().casefold()
        return any(needle == tool.casefold() for tool in self.protected_tools)

    async def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        client = self._get_client()
        response = await client.request(
            method,
            f"{self.base_url}{path}",
            headers=self._headers(),
            json=payload if payload is not None else None,
        )
        try:
            body = response.json()
        except ValueError:
            body = {}
        return response.status_code, body if isinstance(body, dict) else {}

    async def _post_checkpoint(self, tool_name: str, arguments: Any, call_id: str) -> dict[str, Any]:
        try:
            status, body = await self._request(
                "POST",
                "/v1/approvals",
                {
                    "agent_name": "litellm-guardrail",
                    "tool_name": tool_name[:120],
                    "summary": f"Allow the assistant to call {tool_name[:100]}?",
                    "scope": _redacted_scope(arguments, call_id),
                    "workspace": self.workspace,
                    "channel": "litellm_guardrail",
                },
            )
        except httpx.HTTPError:
            if self.fail_open:
                return {"status": "approved", "signed_receipt": "", "failure": "grant_unavailable"}
            return {"status": "denied", "signed_receipt": "", "failure": "grant_unavailable"}
        if status >= 400:
            if self.fail_open:
                return {"status": "approved", "signed_receipt": "", "failure": f"http_{status}"}
            return {"status": "denied", "signed_receipt": "", "failure": f"http_{status}"}
        return body

    async def _poll(self, request_id: str) -> dict[str, Any]:
        deadline = time.monotonic() + self.poll_timeout
        while time.monotonic() < deadline:
            await asyncio.sleep(self.poll_interval)
            try:
                status, body = await self._request("GET", f"/v1/approvals/{request_id}")
            except httpx.HTTPError:
                continue
            if status >= 400:
                continue
            decision = str(body.get("decision") or "").strip().casefold()
            state = str(body.get("status") or "").strip().casefold()
            if decision in ALLOWING_DECISIONS or state == "approved":
                return body
            if decision in {"reject", "cancelled", "cancel", "denied"} or state in {"cancelled", "expired"}:
                return {**body, "status": "denied"}
        return {"status": "timeout", "request_id": request_id}

    @staticmethod
    def _approved(checkpoint: dict[str, Any]) -> bool:
        status = str(checkpoint.get("status") or "").strip().casefold()
        decision = str(checkpoint.get("decision_type") or checkpoint.get("decision") or "").strip().casefold()
        return status == "approved" or decision in {"continue_once", "always_allow", *ALLOWING_DECISIONS}

    async def async_post_call_success_hook(
        self,
        data: dict[str, Any] | None = None,
        user_api_key_dict: Any = None,
        response: Any = None,
        **kwargs: Any,
    ) -> Any:
        """Inspect tool calls returned by the model and gate protected ones.

        Approved calls pass through untouched (one POST, no polling). Pending
        calls either raise a structured checkpoint signal or block while polling.
        """
        data = kwargs.pop("data", data)
        response = kwargs.pop("response", response)
        started = time.perf_counter()
        try:
            calls = list(_iter_tool_calls(response))
            for call in calls:
                tool_name, arguments, call_id = _tool_function(call)
                if not tool_name or not self._matches(tool_name):
                    continue
                checkpoint = await self._post_checkpoint(tool_name, arguments, call_id)
                if self._approved(checkpoint):
                    continue
                request_id = str(checkpoint.get("request_id") or checkpoint.get("id") or "")
                if str(checkpoint.get("status") or "").casefold() == "pending" or checkpoint.get("approval_url"):
                    if self.approval_mode == CHECKPOINT:
                        raise GrantApprovalRequired(
                            request_id=request_id,
                            approval_url=str(checkpoint.get("approval_url") or ""),
                            receipt_url=str(checkpoint.get("receipt_url") or ""),
                            expires_at=str(checkpoint.get("expires_at") or ""),
                            signed_receipt=str(checkpoint.get("signed_receipt") or ""),
                        )
                    checkpoint = await self._poll(request_id)
                    if self._approved(checkpoint):
                        continue
                    if str(checkpoint.get("status") or "").casefold() == "timeout":
                        raise GrantApprovalTimeout(f"Grant approval timed out for {request_id}")
                    raise GrantDenied(f"Grant did not approve {tool_name} ({request_id})")
                failure = str(checkpoint.get("failure") or checkpoint.get("status") or "unknown")
                raise GrantDenied(f"Grant blocked {tool_name}: {failure}")
            return None
        finally:
            self.last_latency_ms = (time.perf_counter() - started) * 1000
