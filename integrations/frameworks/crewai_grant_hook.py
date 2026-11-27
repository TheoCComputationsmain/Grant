"""Grant before-tool-call hook for CrewAI agents.

Zero dependencies (urllib + stdlib). Zero custody: only the tool name, argument
key names, and a SHA-256 correlation hash are sent to Grant. Values, credentials,
payment details, and raw PII stay inside the agent process.

Usage:

    from crewai_grant_hook import grant_tool, GrantApprovalRequired

    @tool("Issue refund")
    @grant_tool(agent_name="support-crew", protected=True)
    def issue_refund(order_ref: str, amount: float) -> str:
        ...

On a pending checkpoint, ``GrantApprovalRequired.metadata["approval_url"]`` is
the private Grant pop-up link. Show it to the human, then retry the call once
the human approves. ``mode="blocking"`` waits for the decision instead.
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

DEFAULT_GRANT_BASE_URL = "https://grant-approve.vercel.app"
ALLOWING_DECISIONS = {"approve", "always", "auto_rule", "approved"}


class GrantApprovalRequired(Exception):
    """Checkpoint-mode signal with the Grant popup URL."""

    def __init__(self, metadata: dict[str, Any]) -> None:
        self.metadata = metadata
        super().__init__(json.dumps(metadata, sort_keys=True, default=str))


class GrantDenied(Exception):
    """The human rejected the action or the receipt could not be verified."""


def resolve_grant_base_url(explicit: str | None = None) -> str:
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
                # `grant-consent` is the Vercel project name; the verified
                # production alias is `grant-approve.vercel.app`.
                return DEFAULT_GRANT_BASE_URL if name == "grant-consent" else f"https://{name}.vercel.app"
    return DEFAULT_GRANT_BASE_URL


def _redacted_scope(arguments: Any) -> dict[str, Any]:
    values = dict(arguments) if isinstance(arguments, dict) else {"args": arguments}
    try:
        canonical = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        canonical = repr(values)
    return {
        "argument_keys": sorted(str(key) for key in values)[:50],
        "arguments_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def _request(
    method: str,
    path: str,
    payload: dict[str, Any] | None,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    timeout: float = 5.0,
    **_: Any,
) -> dict[str, Any]:
    url = f"{resolve_grant_base_url(base_url)}{path}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    key = api_key or os.environ.get("GRANT_API_KEY") or ""
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
    try:
        parsed = json.loads(body) if body else {}
    except ValueError:
        parsed = {}
    return parsed if isinstance(parsed, dict) else {}


def check_approval_status(request_id: str, **options: Any) -> dict[str, Any]:
    """Read status, decision, and signed receipt for one Grant request."""
    return _request("GET", f"/v1/approvals/{request_id[:120]}", None, **options)


def verify_receipt(signed_receipt: str, request_id: str = "", **options: Any) -> bool:
    """Verify a signed receipt before executing a protected action."""
    result = _request(
        "POST",
        "/v1/receipts/verify",
        {"signed_receipt": signed_receipt, "request_id": request_id},
        **options,
    )
    return bool(result.get("valid"))


def request_human_approval(
    *,
    tool_name: str,
    summary: str,
    agent_name: str = "crewai-agent",
    arguments: Any = None,
    workspace: str = "public",
    mode: str = "checkpoint",
    poll_interval: float = 1.0,
    poll_timeout: float = 300.0,
    fail_open: bool = False,
    **options: Any,
) -> dict[str, Any]:
    """Create a Grant checkpoint and return its decision payload.

    ``mode="checkpoint"`` raises :class:`GrantApprovalRequired` while pending.
    ``mode="blocking"`` polls until the human decides.
    """
    if mode not in {"checkpoint", "blocking"}:
        raise ValueError("mode must be 'checkpoint' or 'blocking'")
    result = _request(
        "POST",
        "/v1/approvals",
        {
            "agent_name": agent_name[:120],
            "tool_name": tool_name[:120],
            "summary": summary[:500],
            "scope": _redacted_scope(arguments),
            "workspace": workspace[:60] or "public",
            "channel": "crewai_hook",
        },
        **options,
    )
    decision_type = str(result.get("decision_type") or "")
    if str(result.get("status") or "").lower() == "approved" or decision_type in {"continue_once", "always_allow"}:
        receipt = str(result.get("signed_receipt") or "")
        request_id = str(result.get("request_id") or result.get("id") or "")
        if receipt and not verify_receipt(receipt, request_id, **options):
            raise GrantDenied("Grant receipt could not be verified.")
        return result

    metadata = {
        "grant_approval_required": True,
        "request_id": str(result.get("request_id") or result.get("id") or ""),
        "approval_url": str(result.get("approval_url") or ""),
        "receipt_url": str(result.get("receipt_url") or ""),
        "expires_at": str(result.get("expires_at") or ""),
        "signed_receipt": str(result.get("signed_receipt") or ""),
        "tool_name": tool_name[:120],
        "message": "Open the Grant pop-up and approve, then retry this tool call.",
    }
    if str(result.get("status") or "").lower() != "pending" and not metadata["approval_url"]:
        if fail_open:
            return {"status": "approved", "failure": "grant_unavailable"}
        raise GrantDenied(f"Grant checkpoint failed: {result.get('failure') or result.get('status') or 'unknown'}")

    if mode == "checkpoint":
        raise GrantApprovalRequired(metadata)

    deadline = time.monotonic() + poll_timeout
    while time.monotonic() < deadline:
        time.sleep(max(0.05, poll_interval))
        status = check_approval_status(metadata["request_id"], **options)
        decision = str(status.get("decision") or "").lower()
        state = str(status.get("status") or "").lower()
        if decision in ALLOWING_DECISIONS or state == "approved":
            receipt = str(status.get("signed_receipt") or "")
            if receipt and not verify_receipt(receipt, metadata["request_id"], **options):
                raise GrantDenied("Grant receipt could not be verified.")
            return status
        if decision in {"reject", "cancel", "cancelled"} or state in {"cancelled", "expired"}:
            raise GrantDenied(f"Grant rejected {tool_name}.")
    raise GrantDenied(f"Grant approval timed out for {tool_name}.")


def before_tool_call(tool_name: str, arguments: Any = None, **options: Any) -> dict[str, Any]:
    """CrewAI-friendly hook. Returns an approval payload or raises a checkpoint."""
    summary = options.pop("summary", f"Allow the crew to call {tool_name[:100]}?")
    return request_human_approval(tool_name=tool_name, summary=summary, arguments=arguments, **options)


def grant_tool(
    func: Callable[..., Any] | None = None,
    *,
    tool_name: str | None = None,
    protected: bool = True,
    **options: Any,
) -> Callable[..., Any]:
    """Wrap a CrewAI tool callable so sensitive executions need human approval."""

    def decorate(target: Callable[..., Any]) -> Callable[..., Any]:
        name = tool_name or getattr(target, "__name__", "tool")

        if inspect.iscoroutinefunction(target):

            @functools.wraps(target)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                if protected:
                    before_tool_call(name, kwargs or args, **options)
                return await target(*args, **kwargs)

            return async_wrapper

        @functools.wraps(target)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if protected:
                before_tool_call(name, kwargs or args, **options)
            return target(*args, **kwargs)

        return wrapper

    return decorate(func) if func is not None else decorate
