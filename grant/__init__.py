"""Grant Python SDK — consent infrastructure for AI agents.

The SDK has no third-party dependencies. It speaks plain HTTP to a Grant
service and returns small immutable objects your agent can act on.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any
from urllib import error, request

__version__ = "0.1.0"
DEFAULT_BASE_URL = os.environ.get("GRANT_BASE_URL", "https://grant-approve.vercel.app").rstrip("/")


class GrantError(RuntimeError):
    """Base error for Grant client failures."""


class GrantDenied(GrantError):
    """The human rejected the request."""

    def __init__(self, request_id: str):
        super().__init__(f"Grant request {request_id} was rejected.")
        self.request_id = request_id


class GrantTimeout(GrantError):
    """No decision arrived before the deadline."""

    def __init__(self, request_id: str, timeout: float):
        super().__init__(f"Grant request {request_id} was not decided within {timeout:g}s.")
        self.request_id = request_id
        self.timeout = timeout


@dataclass(frozen=True)
class Approval:
    id: str
    url: str
    approval_url: str
    expires_at: str
    scope_hash: str
    status: str
    message: str


@dataclass(frozen=True)
class Permission:
    id: str
    workspace: str
    agent: str
    action: str
    scope_hash: str
    policy: str
    created_at: str
    expires_at: str
    source_request: str
    signature: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Permission":
        return cls(
            id=str(data["id"]),
            workspace=str(data.get("workspace", "")),
            agent=str(data.get("agent", "")),
            action=str(data.get("action", "")),
            scope_hash=str(data.get("scope_hash", "")),
            policy=str(data.get("policy", "")),
            created_at=str(data.get("created_at", "")),
            expires_at=str(data.get("expires_at", "")),
            source_request=str(data.get("source_request", "")),
            signature=str(data.get("signature", "")),
        )


@dataclass(frozen=True)
class RequestStatus:
    id: str
    status: str
    decision: str | None
    decision_at: str | None
    expires_at: str
    scope_hash: str
    permission: Permission | None


@dataclass(frozen=True)
class Gateway:
    id: str
    token: str
    name: str
    http_url: str
    mcp_url: str
    policy: dict[str, Any]


class Grant:
    """Small client for the Grant consent service."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        workspace: str = "public",
        timeout: float = 10.0,
    ) -> None:
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.workspace = workspace
        self.timeout = timeout

    def _call(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        all_headers = {"Accept": "application/json", "User-Agent": f"grant-python/{__version__}"}
        if data is not None:
            all_headers["Content-Type"] = "application/json"
        if headers:
            all_headers.update(headers)
        req = request.Request(self.base_url + path, data=data, method=method, headers=all_headers)
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read()
        except error.HTTPError as exc:
            raw = exc.read()
            detail = ""
            try:
                body = json.loads(raw.decode("utf-8"))
                detail = str(body.get("detail") or body.get("message") or "")
            except (ValueError, UnicodeDecodeError):
                detail = raw.decode("utf-8", errors="replace")[:300]
            raise GrantError(f"Grant {method} {path} failed ({exc.code}): {detail}") from exc
        except error.URLError as exc:
            raise GrantError(f"Grant {method} {path} could not reach {self.base_url}: {exc.reason}") from exc
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise GrantError(f"Grant {method} {path} returned invalid JSON.") from exc

    def request(
        self,
        *,
        agent: str,
        action: str,
        summary: str,
        scope: dict[str, Any] | None = None,
        requester: str = "agent",
        workspace: str | None = None,
        ttl_minutes: int = 30,
        callback_url: str = "",
        parent_origin: str = "",
        channel: str = "browser_popup",
        idempotency_key: str | None = None,
    ) -> Approval:
        body: dict[str, Any] = {
            "agent": agent,
            "action": action,
            "summary": summary,
            "scope": scope or {},
            "requester": requester,
            "workspace": workspace or self.workspace,
            "ttl_minutes": ttl_minutes,
            "callback_url": callback_url,
            "parent_origin": parent_origin,
            "channel": channel,
        }
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        data = self._call("POST", "/v1/requests", payload=body, headers=headers)
        return Approval(
            id=str(data["id"]),
            url=str(data["url"]),
            approval_url=str(data["approval_url"]),
            expires_at=str(data["expires_at"]),
            scope_hash=str(data.get("scope_hash", "")),
            status=str(data.get("status", "pending")),
            message=str(data.get("message", "")),
        )

    def status(self, request_id: str) -> RequestStatus:
        data = self._call("GET", f"/v1/requests/{request_id}")
        permission_data = data.get("permission")
        permission = Permission.from_dict(permission_data) if isinstance(permission_data, dict) else None
        return RequestStatus(
            id=str(data["id"]),
            status=str(data["status"]),
            decision=data.get("decision"),
            decision_at=data.get("decision_at"),
            expires_at=str(data["expires_at"]),
            scope_hash=str(data.get("scope_hash", "")),
            permission=permission,
        )

    def wait(self, request_id: str, *, timeout: float = 300, poll_interval: float = 2) -> Permission:
        deadline = time.monotonic() + max(0, timeout)
        while True:
            status = self.status(request_id)
            if status.status == "decided":
                if status.decision == "reject":
                    raise GrantDenied(request_id)
                if status.permission is None:
                    raise GrantError(f"Grant request {request_id} has no signed permission.")
                return status.permission
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GrantTimeout(request_id, timeout)
            time.sleep(min(max(0.1, poll_interval), remaining))

    def permissions(self, agent: str) -> list[Permission]:
        data = self._call("GET", f"/v1/permissions/{agent}")
        return [Permission.from_dict(item) for item in data.get("permissions", [])]

    def verify(self, permission_id: str, signature: str) -> dict[str, Any]:
        return self._call(
            "POST",
            "/v1/permissions/verify",
            payload={"id": permission_id, "signature": signature},
        )

    def gateway(
        self,
        *,
        name: str,
        upstream_url: str,
        workspace: str = "public",
        sensitive_tools: list[str] | None = None,
        sensitive_paths: list[str] | None = None,
        sensitive_methods: list[str] | None = None,
        body_keys: list[str] | None = None,
        default_action: str = "review",
        ttl_minutes: int = 15,
    ) -> Gateway:
        body: dict[str, Any] = {
            "name": name,
            "upstream_url": upstream_url,
            "workspace": workspace,
            "sensitive_tools": sensitive_tools or [],
            "sensitive_paths": sensitive_paths or [],
            "body_keys": body_keys or [],
            "default_action": default_action,
            "ttl_minutes": ttl_minutes,
        }
        if sensitive_methods is not None:
            body["sensitive_methods"] = sensitive_methods
        data = self._call("POST", "/v1/gateways", payload=body)
        return Gateway(
            id=str(data["id"]),
            token=str(data["token"]),
            name=str(data["name"]),
            http_url=str(data["http_url"]),
            mcp_url=str(data["mcp_url"]),
            policy=data.get("policy", {}),
        )

    def a2a_gate(
        self,
        *,
        sender: str,
        receiver: str,
        task: str,
        payload: dict[str, Any] | None = None,
        workspace: str | None = None,
        ttl_minutes: int = 30,
        require_approval: bool = False,
    ) -> Approval:
        """Hold an agent-to-agent handoff until a human approves it."""
        data = self._call(
            "POST",
            "/v1/a2a/gate",
            payload={
                "sender": sender,
                "receiver": receiver,
                "task": task,
                "payload": payload or {},
                "workspace": workspace or self.workspace,
                "ttl_minutes": ttl_minutes,
                "require_approval": require_approval,
            },
        )
        approval_url = str(data.get("approval_url") or "")
        return Approval(
            id=str(data.get("grant_id") or ""),
            url=approval_url,
            approval_url=approval_url,
            expires_at=str(data.get("expires_at") or ""),
            scope_hash="",
            status=str(data.get("status") or ""),
            message=str(data.get("message") or ""),
        )

    def request_status(self, request_id: str) -> RequestStatus:
        """Alias for status(), named for gateway retry loops."""
        return self.status(request_id)


__all__ = [
    "Approval",
    "Grant",
    "GrantDenied",
    "GrantError",
    "GrantTimeout",
    "Gateway",
    "Permission",
    "RequestStatus",
    "__version__",
]
