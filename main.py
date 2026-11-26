"""Grant — consent infrastructure for AI agents.

An agent asks. A human sees one quiet approval link. Grant returns a signed
permission and keeps an audit trail. No email accounts, no wallet, no secrets.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager, closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlencode, urlparse, urlsplit

from fastapi import FastAPI, Form, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import AliasChoices, BaseModel, Field, model_validator

from grant import (
    billing,
    cashfree,
    db as dbmod,
    emailer,
    login_library,
    plans,
    policies,
    telemetry,
)

APP_ENV = os.environ.get("GRANT_APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production" or os.environ.get("VERCEL", "").strip() == "1"
DB_PATH = Path(os.environ.get("GRANT_DB", Path(__file__).resolve().parent / "grant.db"))
PUBLIC_BASE_URL = os.environ.get("GRANT_PUBLIC_BASE_URL", "").rstrip("/")
RATE_LIMIT_PER_MIN = int(os.environ.get("GRANT_RATE_LIMIT_PER_MIN", "60"))
GATEWAY_WAIT_SECONDS = max(0, min(45, int(os.environ.get("GRANT_GATEWAY_WAIT_SECONDS", "20"))))
ALLOW_HTTP_UPSTREAMS = os.environ.get("GRANT_ALLOW_HTTP_UPSTREAMS", "").strip().lower() in {"1", "true", "yes"}
SMS_PROVIDER_CONFIGURED = bool(
    os.environ.get("GRANT_SMS_PROVIDER", "").strip()
    or os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
    or os.environ.get("GRANT_WHATSAPP_PROVIDER", "").strip()
)
DEMO_LIMIT_PER_HOUR = max(1, min(1000, int(os.environ.get("GRANT_DEMO_LIMIT_PER_HOUR", "20"))))
CALLBACK_MAX_RETRIES = max(0, min(5, int(os.environ.get("GRANT_CALLBACK_MAX_RETRIES", "2"))))
ALLOW_TEST_WEBHOOK = os.environ.get("GRANT_ALLOW_TEST_WEBHOOK", "").strip().lower() in {
    "1", "true", "yes"
}
BLOB_PREFIX = os.environ.get("GRANT_BLOB_PREFIX", "grant-state").strip("/") or "grant-state"
_SIGNING_SECRET = os.environ.get("GRANT_SIGNING_SECRET", "").strip()
MAGIC_LINK_TTL_MINUTES = max(1, min(1440, int(os.environ.get("GRANT_MAGIC_LINK_TTL_MINUTES", "30"))))
SESSION_DAYS = max(1, min(365, int(os.environ.get("GRANT_SESSION_DAYS", "30"))))
SESSION_COOKIE = "grant_session"
BILLING_WEBHOOK_SECRET = os.environ.get(billing.WEBHOOK_SECRET_ENV_KEY, "").strip()
CASHFREE_WEBHOOK_SECRET = (
    os.environ.get(cashfree.WEBHOOK_SECRET_ENV_KEY, "").strip()
    or os.environ.get(cashfree.SECRET_KEY_ENV_KEY, "").strip()
)
OPS_TOKEN = os.environ.get("GRANT_OPS_TOKEN", "").strip()
CRON_SECRET = (
    os.environ.get("GRANT_CRON_SECRET", "").strip()
    or os.environ.get("CRON_SECRET", "").strip()
)
RENEWAL_EMAIL_WEBHOOK_URL = os.environ.get("GRANT_RENEWAL_EMAIL_WEBHOOK_URL", "").strip()
RENEWAL_EMAIL_WEBHOOK_TOKEN = os.environ.get("GRANT_RENEWAL_EMAIL_WEBHOOK_TOKEN", "").strip()
PAID_PLAN_GRACE_DAYS = 32
RENEWAL_REMINDER_DAY = 27
POPUP_ALLOWED_ORIGINS = tuple(
    dict.fromkeys(
        origin.strip().rstrip("/")
        for origin in os.environ.get("GRANT_POPUP_ALLOWED_ORIGINS", "").split(",")
        if origin.strip().startswith(("http://", "https://"))
    )
)

_LOCK = threading.Lock()
_BUCKETS: dict[str, list[float]] = {}
_IDEMPOTENCY: dict[str, tuple[str, str]] = {}
_IDEMPOTENCY_LOCK = threading.Lock()
_IDEMPOTENCY_EVENTS: dict[str, threading.Event] = {}
_PENDING: dict[str, dict[str, Any]] = {}

HOP_BY_HOP_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "connection",
        "transfer-encoding",
        "accept-encoding",
        "x-grant-request-id",
        "x-grant-gateway-token",
    }
)
DEFAULT_SENSITIVE_TOOLS = (
    "transfer",
    "payment",
    "pay",
    "refund",
    "purchase",
    "buy",
    "delete",
    "send",
    "publish",
    "execute",
)
DEFAULT_SENSITIVE_PATH_PARTS = ("/transfer", "/payment", "/pay", "/refund", "/delete", "/send", "/publish")

ALLOWED_DECISIONS = frozenset({"approve", "auto_rule", "always", "reject"})
SENSITIVE_KEY_RE = re.compile(
    r"(api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|"
    r"passwd|authorization|credential|private[_-]?key|session|email|phone|ssn|card|key)",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SK_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
GRANT_KEY_RE = re.compile(r"\b(?:agk|tlk|grt)_[A-Za-z0-9_-]{8,}\b", re.IGNORECASE)
BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._-]{8,}", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


def iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def iso_plus(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def friendly_expiry(value: Any) -> str:
    """Turn a raw ISO timestamp into a plain-English countdown.

    People should see ``In 29m (9:21 AM international time)`` instead of a
    machine timestamp. "International time" is UTC, without the jargon.
    """
    try:
        stamp = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return "Soon"
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    clock = stamp.astimezone(timezone.utc).strftime("%I:%M %p").lstrip("0")
    suffix = f"({clock} international time)"
    seconds = int((stamp - datetime.now(timezone.utc)).total_seconds())
    if seconds <= 0:
        return f"Expired {suffix}"
    if seconds < 60:
        return f"In a moment {suffix}"
    minutes = seconds // 60
    if minutes < 60:
        return f"In {minutes}m {suffix}"
    hours = minutes // 60
    if hours < 24:
        return f"In {hours}h {suffix}"
    return f"In {hours // 24}d {suffix}"


def db():
    """SQLite for local dev; Neon Postgres when a DSN is configured."""
    return dbmod.connection()


@contextmanager
def transaction() -> Iterator[Any]:
    with dbmod.transaction() as conn:
        yield conn


def _ensure_column(conn: Any, table: str, column: str, declaration: str) -> None:
    """Add a column to an older database without touching other data."""
    dbmod.ensure_column(conn, table, column, declaration)


def _ensure_signing_secret(conn: Any) -> None:
    global _SIGNING_SECRET
    if _SIGNING_SECRET:
        return
    stored = conn.execute("SELECT value FROM settings WHERE key = 'signing_secret'").fetchone()
    if stored:
        _SIGNING_SECRET = stored["value"]
        return
    _SIGNING_SECRET = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('signing_secret', ?) "
        "ON CONFLICT(key) DO NOTHING",
        (_SIGNING_SECRET,),
    )


def init_db() -> None:
    if dbmod.postgres_enabled():
        with transaction() as conn:
            conn.execute(dbmod.schema_sql())
            conn.execute(
                "INSERT INTO organizations (id, name, plan_tier, created_at) "
                "SELECT code, name, 'free', created_at FROM workspaces "
                "ON CONFLICT (id) DO NOTHING"
            )
            conn.execute(
                "INSERT INTO approval_requests (id, org_id, token, agent, action, summary, "
                "scope_json, scope_hash, requester, channel, gateway_hash, created_at, expires_at, "
                "status, decision, decision_at, policy) SELECT id, workspace, token, agent, action, "
                "summary, scope_json, scope_hash, requester, channel, gateway_hash, created_at, "
                "expires_at, status, decision, decision_at, policy FROM requests "
                "ON CONFLICT (id) DO NOTHING"
            )
            _ensure_signing_secret(conn)
        return
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with transaction() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS organizations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner_user_id TEXT,
                plan_tier TEXT NOT NULL DEFAULT 'free',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                key_hash TEXT UNIQUE NOT NULL,
                key_prefix TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS workspaces (
                code TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT OR IGNORE INTO organizations (id, name, plan_tier, created_at) "
            "SELECT code, name, 'free', created_at FROM workspaces"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS gateways (
                token_hash TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                upstream_url TEXT NOT NULL,
                policy_json TEXT NOT NULL,
                workspace TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                token TEXT UNIQUE NOT NULL,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                summary TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                scope_hash TEXT NOT NULL,
                requester TEXT NOT NULL,
                workspace TEXT NOT NULL,
                callback_url TEXT NOT NULL,
                channel TEXT NOT NULL DEFAULT 'browser_popup',
                gateway_hash TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                decision TEXT,
                decision_at TEXT,
                policy TEXT
            )
            """
        )
        _ensure_column(conn, "requests", "channel", "TEXT NOT NULL DEFAULT 'browser_popup'")
        _ensure_column(conn, "requests", "gateway_hash", "TEXT NOT NULL DEFAULT ''")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_requests (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                summary TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                scope_hash TEXT NOT NULL,
                requester TEXT NOT NULL,
                channel TEXT NOT NULL DEFAULT 'browser_popup',
                gateway_hash TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                decision TEXT,
                decision_at TEXT,
                policy TEXT
            )
            """
        )
        conn.execute(
            "INSERT OR IGNORE INTO approval_requests (id, org_id, token, agent, action, summary, "
            "scope_json, scope_hash, requester, channel, gateway_hash, created_at, expires_at, "
            "status, decision, decision_at, policy) SELECT id, workspace, token, agent, action, "
            "summary, scope_json, scope_hash, requester, channel, gateway_hash, created_at, "
            "expires_at, status, decision, decision_at, policy FROM requests"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auto_approve_rules (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                user_id TEXT,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                scope_json TEXT NOT NULL,
                max_amount REAL,
                multi_approver INTEGER NOT NULL DEFAULT 0,
                claim_token TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                linked_at TEXT
            )
            """
        )
        _ensure_column(conn, "auto_approve_rules", "multi_approver", "INTEGER NOT NULL DEFAULT 0")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS magic_links (
                token_hash TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                org_id TEXT,
                claim_token TEXT,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                email TEXT,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS permissions (
                id TEXT PRIMARY KEY,
                workspace TEXT NOT NULL,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                scope_hash TEXT NOT NULL,
                policy TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                source_request TEXT NOT NULL,
                signature TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS billing_contacts (
                org_id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_billing_contacts_email ON billing_contacts(email)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS plans (
                org_id TEXT PRIMARY KEY,
                tier TEXT NOT NULL,
                status TEXT NOT NULL,
                trial_tier TEXT,
                trial_ends_at TEXT,
                plan_expires_at TEXT,
                quota_reset_at TEXT,
                checkout_id TEXT NOT NULL,
                customer_ref TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        _ensure_column(conn, "plans", "plan_expires_at", "TEXT")
        _ensure_column(conn, "plans", "quota_reset_at", "TEXT")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS usage_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS billing_events (
                event_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                tier TEXT NOT NULL,
                status TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS unclaimed_payments (
                event_id TEXT PRIMARY KEY,
                payment_ref TEXT NOT NULL,
                email TEXT NOT NULL,
                tier TEXT NOT NULL,
                paid_at TEXT NOT NULL,
                status TEXT NOT NULL,
                workspace TEXT NOT NULL,
                created_at TEXT NOT NULL,
                claimed_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS renewal_reminders (
                reminder_key TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                tier TEXT NOT NULL,
                due_at TEXT NOT NULL,
                plan_expires_at TEXT NOT NULL,
                form_url TEXT NOT NULL,
                status TEXT NOT NULL,
                sent_at TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_unclaimed_email ON unclaimed_payments(email, status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_unclaimed_ref ON unclaimed_payments(payment_ref, status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_renewal_due ON renewal_reminders(status, due_at)"
        )
        for table, column, declaration in (
            ("users", "plan_tier", "TEXT NOT NULL DEFAULT 'free'"),
            ("users", "monthly_quota", "INT NOT NULL DEFAULT 1000"),
            ("users", "approvals_used", "INT NOT NULL DEFAULT 0"),
            ("users", "plan_expires_at", "TEXT"),
            ("approval_requests", "owner_user_id", "TEXT"),
            ("approval_requests", "agent_name", "TEXT"),
            ("approval_requests", "tool_name", "TEXT"),
            ("approval_requests", "callback_url", "TEXT"),
            ("approval_requests", "callback_secret", "TEXT"),
            ("approval_requests", "decision_type", "TEXT"),
            ("approval_requests", "signed_receipt", "TEXT"),
            ("approval_requests", "decided_at", "TEXT"),
            ("auto_approve_rules", "device_hash", "TEXT"),
            ("auto_approve_rules", "agent_name", "TEXT"),
            ("auto_approve_rules", "tool_name", "TEXT"),
            ("auto_approve_rules", "condition_json", "TEXT"),
            ("auto_approve_rules", "expires_at", "TEXT"),
            ("auto_approve_rules", "revoked_at", "TEXT"),
            ("magic_links", "otp_hash", "TEXT"),
            ("unclaimed_payments", "id", "TEXT"),
            ("unclaimed_payments", "cf_payment_id", "TEXT"),
            ("unclaimed_payments", "customer_email", "TEXT NOT NULL DEFAULT ''"),
            ("unclaimed_payments", "plan_tier", "TEXT NOT NULL DEFAULT ''"),
            ("unclaimed_payments", "amount", "NUMERIC"),
            ("unclaimed_payments", "claimed_by_user_id", "TEXT"),
        ):
            _ensure_column(conn, table, column, declaration)
        conn.execute("UPDATE approval_requests SET agent_name = agent WHERE agent_name IS NULL OR agent_name = ''")
        conn.execute("UPDATE approval_requests SET tool_name = action WHERE tool_name IS NULL OR tool_name = ''")
        conn.execute("UPDATE auto_approve_rules SET agent_name = agent WHERE agent_name IS NULL OR agent_name = ''")
        conn.execute("UPDATE auto_approve_rules SET tool_name = action WHERE tool_name IS NULL OR tool_name = ''")
        conn.execute("UPDATE unclaimed_payments SET customer_email = email WHERE customer_email IS NULL OR customer_email = ''")
        conn.execute("UPDATE unclaimed_payments SET plan_tier = tier WHERE plan_tier IS NULL OR plan_tier = ''")
        conn.execute("UPDATE unclaimed_payments SET id = event_id WHERE id IS NULL OR id = ''")
        conn.execute("UPDATE unclaimed_payments SET cf_payment_id = payment_ref WHERE cf_payment_id IS NULL OR cf_payment_id = ''")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS demo_rate_limits (
                ip_hash TEXT NOT NULL,
                bucket TEXT NOT NULL,
                used INT NOT NULL DEFAULT 0,
                PRIMARY KEY (ip_hash, bucket)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_requests_workspace ON requests(workspace, created_at DESC)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_permissions_agent ON permissions(agent, expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_permissions_source ON permissions(source_request)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_org_created ON usage_events(org_id, created_at)")
        for statement in (
            "CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id, revoked_at)",
            "CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_rules_org ON auto_approve_rules(org_id, status)",
            "CREATE INDEX IF NOT EXISTS idx_rules_claim ON auto_approve_rules(claim_token)",
            "CREATE INDEX IF NOT EXISTS idx_approval_org ON approval_requests(org_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_user ON auth_sessions(user_id, expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_magic_email ON magic_links(email, created_at DESC)",
        ):
            conn.execute(statement)
        _ensure_signing_secret(conn)
        telemetry.ensure_sqlite_tables(conn)


@asynccontextmanager
async def lifespan(app: FastAPI):
    dbmod.require_production_store()
    init_db()
    yield


app = FastAPI(
    title="Grant",
    version="0.1.0",
    description="Consent infrastructure for AI agents. One link. One decision. Full audit.",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


CORS_PUBLIC_PATHS = (
    "/v1/requests",
    "/v1/a2a/gate",
    "/openapi.json",
    "/api/openapi.json",
    "/api/mcp",
    "/v1/gate/webhook",
    "/v1/auth/otp",
    "/v1/auth/otp/verify",
    "/manifest.webmanifest",
    "/sw.js",
)


CORS_PUBLIC_PREFIXES = ("/v1/requests/", "/receipt/", "/approve/", "/icons/")


def cors_public_path(path: str) -> bool:
    return (
        path in CORS_PUBLIC_PATHS
        or path.startswith(CORS_PUBLIC_PREFIXES)
    )


@app.middleware("http")
async def polish_headers(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    public_cors = cors_public_path(request.url.path)
    if public_cors and request.method == "OPTIONS":
        response = Response(status_code=204)
    else:
        response = await call_next(request)
    response.headers["x-grant-request-id"] = request_id
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["referrer-policy"] = "no-referrer"
    if public_cors:
        response.headers["access-control-allow-origin"] = "*"
        response.headers["access-control-allow-methods"] = "GET, POST, OPTIONS"
        response.headers["access-control-allow-headers"] = (
            "Content-Type, Authorization, Idempotency-Key, X-Grant-Request-Id"
        )
        response.headers["access-control-max-age"] = "600"
    if "cache-control" not in response.headers:
        response.headers["cache-control"] = "no-store"
    response.headers["content-security-policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    return response


def expiry_to_minutes(value: Any) -> int | None:
    """Accept ``30m``/``2h``/``1d`` or an ISO timestamp as an expiry hint."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    match = re.fullmatch(r"(\d+)\s*([smhd])", text)
    if match:
        amount = int(match.group(1))
        factor = {"s": 1 / 60, "m": 1, "h": 60, "d": 1440}[match.group(2)]
        return max(1, min(10_080, int(amount * factor)))
    try:
        stamp = datetime.fromisoformat(text.replace("z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        delta = stamp - datetime.now(timezone.utc)
        return max(1, min(10_080, int(delta.total_seconds() / 60)))
    except ValueError:
        return None


class RequestIn(BaseModel):
    agent: str = Field(
        min_length=1, max_length=120, validation_alias=AliasChoices("agent", "who", "agent_name")
    )
    action: str = Field(
        min_length=1, max_length=120, validation_alias=AliasChoices("action", "what", "tool_name")
    )
    summary: str = Field(
        min_length=1, max_length=500, validation_alias=AliasChoices("summary", "why", "reason")
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    requester: str = Field(default="agent", max_length=120)
    workspace: str = Field(default="public", max_length=60)
    callback_url: str = Field(default="", max_length=500)
    callback_secret: str = Field(default="", max_length=200)
    owner_user_id: str = Field(default="", max_length=120)
    ttl_minutes: int = Field(default=30, ge=1, le=10_080)
    parent_origin: str = Field(default="", max_length=200)
    channel: str = Field(default="browser_popup", max_length=40)

    @model_validator(mode="before")
    @classmethod
    def _accept_protocol_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        values = dict(data)
        for target, aliases in (
            ("agent", ("who", "agent_name")),
            ("action", ("what", "tool_name")),
            ("summary", ("why", "reason")),
        ):
            if target not in values:
                for alias in aliases:
                    if alias in values:
                        values[target] = values[alias]
                        break
        if "ttl_minutes" not in values and "expires_in_seconds" in values:
            try:
                seconds = int(values.get("expires_in_seconds"))
                values["ttl_minutes"] = max(1, min(10_080, (seconds + 59) // 60))
            except (TypeError, ValueError):
                pass
        if "ttl_minutes" not in values and "expiry" in values:
            minutes = expiry_to_minutes(values.get("expiry"))
            if minutes is not None:
                values["ttl_minutes"] = minutes
        return values


class VerifyIn(BaseModel):
    id: str = Field(min_length=1, max_length=120)
    signature: str = Field(min_length=1, max_length=160)


class A2AGateIn(BaseModel):
    """A task handoff between agents that may need a human decision."""

    sender: str = Field(min_length=1, max_length=120)
    receiver: str = Field(min_length=1, max_length=120)
    task: str = Field(min_length=1, max_length=500)
    payload: dict[str, Any] = Field(default_factory=dict)
    workspace: str = Field(default="public", max_length=60)
    ttl_minutes: int = Field(default=30, ge=1, le=10_080)
    parent_origin: str = Field(default="", max_length=200)
    require_approval: bool = False


class GatewayIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    upstream_url: str = Field(min_length=1, max_length=1000)
    workspace: str = Field(default="public", max_length=60)
    sensitive_tools: list[str] = Field(default_factory=list, max_length=100)
    sensitive_paths: list[str] = Field(default_factory=list, max_length=100)
    sensitive_methods: list[str] = Field(default_factory=lambda: ["POST", "PUT", "PATCH", "DELETE"])
    body_keys: list[str] = Field(default_factory=list, max_length=100)
    default_action: str = Field(default="review", pattern="^(allow|review)$")
    ttl_minutes: int = Field(default=15, ge=1, le=720)
    parent_origin: str = Field(default="", max_length=200)


class RuleIn(BaseModel):
    """A standing auto-approval rule; conditional and routing locks are server-side."""

    workspace: str = Field(default="public", max_length=60)
    agent: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=1, max_length=120)
    scope: dict[str, Any] = Field(default_factory=dict)
    max_amount: float | None = Field(default=None, ge=0)
    multi_approver: bool = False
    claim_token: str = Field(default="", max_length=120)
    condition: dict[str, Any] | None = Field(default=None, max_length=200)
    expires_in_seconds: int | None = Field(default=None, ge=60, le=31_536_000)
    owner_user_id: str = Field(default="", max_length=120)


class GateWebhookIn(BaseModel):
    """Zero-wrapper gate call; aliases match the public API and MCP tool schema."""

    agent: str = Field(
        min_length=1, max_length=120, validation_alias=AliasChoices("agent", "agent_name", "who")
    )
    action: str = Field(
        min_length=1, max_length=120, validation_alias=AliasChoices("action", "tool_name", "what")
    )
    summary: str = Field(
        min_length=1, max_length=500, validation_alias=AliasChoices("summary", "why", "reason")
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    workspace: str = Field(default="public", max_length=60)
    callback_url: str = Field(default="", max_length=500)
    callback_secret: str = Field(default="", max_length=200)
    owner_user_id: str = Field(default="", max_length=120)
    ttl_minutes: int = Field(default=30, ge=1, le=10_080)
    expires_in_seconds: int | None = Field(default=None, ge=60, le=604_800)
    channel: str = Field(default="webhook", max_length=40)

    @model_validator(mode="before")
    @classmethod
    def _accept_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        values = dict(data)
        for target, aliases in (
            ("agent", ("who", "agent_name")),
            ("action", ("what", "tool_name")),
            ("summary", ("why", "reason")),
        ):
            if target not in values:
                for alias in aliases:
                    if alias in values:
                        values[target] = values[alias]
                        break
        if "ttl_minutes" not in values and "expires_in_seconds" in values:
            try:
                seconds = int(values.get("expires_in_seconds"))
                values["ttl_minutes"] = max(1, min(10_080, (seconds + 59) // 60))
            except (TypeError, ValueError):
                pass
        return values


class OtpIn(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    next: str = Field(default="", max_length=200)
    org_id: str = Field(default="", max_length=120)


class OtpVerifyIn(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    code: str = Field(min_length=4, max_length=12)
    next: str = Field(default="", max_length=200)


def clean(value: Any, limit: int = 200) -> str:
    return html.escape(str(value or "")[:limit], quote=True)


def js_literal(value: str) -> str:
    return json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def redact_text(value: Any) -> str:
    text = str(value)
    text = SK_RE.sub("[redacted-key]", text)
    text = GRANT_KEY_RE.sub("[redacted-key]", text)
    text = BEARER_RE.sub("Bearer [redacted]", text)
    text = JWT_RE.sub("[redacted-jwt]", text)
    text = EMAIL_RE.sub("[email]", text)
    return text[:2000]


def redact_scope(value: Any, key: str = "") -> Any:
    if SENSITIVE_KEY_RE.search(key):
        return "[redacted-key]"
    if isinstance(value, dict):
        return {str(k)[:80]: redact_scope(v, str(k)) for k, v in list(value.items())[:80]}
    if isinstance(value, (list, tuple)):
        return [redact_scope(item, key) for item in list(value)[:80]]
    if isinstance(value, (str, float, int, bool)) or value is None:
        return redact_text(value) if isinstance(value, str) else value
    return "[redacted]"


def canonical_scope(scope: dict[str, Any]) -> tuple[str, str]:
    redacted = redact_scope(scope)
    encoded = canonical_json(redacted)
    if len(encoded) > 4000:
        redacted = {"redacted": "scope exceeded 4000 characters"}
        encoded = canonical_json(redacted)
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def signing_mode() -> str:
    return "environment" if os.environ.get("GRANT_SIGNING_SECRET", "").strip() else "local-generated"


def permission_payload(row: sqlite3.Row | dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(row["id"]),
        "workspace": str(row["workspace"]),
        "agent": str(row["agent"]),
        "action": str(row["action"]),
        "scope_hash": str(row["scope_hash"]),
        "policy": str(row["policy"]),
        "created_at": str(row["created_at"]),
        "expires_at": str(row["expires_at"]),
        "source_request": str(row["source_request"]),
    }


def sign_permission(payload: dict[str, str]) -> str:
    secret = (_SIGNING_SECRET or "grant-local-development").encode("utf-8")
    return hmac.new(secret, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def permission_dict(row: sqlite3.Row) -> dict[str, str]:
    payload = permission_payload(row)
    return {**payload, "signature": sign_permission(payload)}


def receipt_payload(
    row: Any, decision: str, permission: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Minimal, shareable receipt payload. No scope values are ever included."""
    approved = decision in {"approve", "auto_rule", "always"}
    status = "approved" if approved else "cancelled"
    return {
        "request_id": str(row["id"]),
        "status": status,
        "decision_type": {
            "approve": "continue_once",
            "auto_rule": "always_allow",
            "always": "always_allow",
            "reject": "cancelled",
        }.get(decision, decision),
        "agent_name": str(row["agent"]),
        "tool_name": str(row["action"]),
        "scope_hash": str(row["scope_hash"]),
        "algorithm": "HMAC-SHA256",
        "permission_id": str(permission["id"]) if permission else "",
        "decided_at": iso(),
    }


def make_signed_receipt(payload: dict[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(canonical_json(payload).encode("utf-8")).decode("ascii").rstrip("=")
    secret = (_SIGNING_SECRET or "grant-local-development").encode("utf-8")
    digest = hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{encoded}.{digest}"


def verify_signed_receipt(value: str) -> tuple[bool, dict[str, Any] | None]:
    encoded, separator, digest = str(value or "").strip().partition(".")
    if not separator or not encoded or not digest:
        return False, None
    secret = (_SIGNING_SECRET or "grant-local-development").encode("utf-8")
    expected = hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, digest):
        return False, None
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False, None
    return (isinstance(payload, dict), payload if isinstance(payload, dict) else None)


def new_code(bytes_count: int = 12) -> str:
    return secrets.token_urlsafe(bytes_count)


def rate_limited(request: Request) -> bool:
    if RATE_LIMIT_PER_MIN <= 0:
        return False
    host = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _LOCK:
        bucket = [stamp for stamp in _BUCKETS.get(host, []) if now - stamp < 60]
        if len(bucket) >= RATE_LIMIT_PER_MIN:
            _BUCKETS[host] = bucket
            return True
        bucket.append(now)
        _BUCKETS[host] = bucket
        return False


def demo_rate_allowed(http_request: Request, bucket: str = "public") -> bool:
    """Durable, privacy-preserving 20/hour gate for credential-less demo calls."""
    hour_bucket = f"{bucket}:{int(time.time() // 3600)}"
    identity = telemetry.ip_hash(http_request)
    with transaction() as conn:
        row = conn.execute(
            "SELECT used FROM demo_rate_limits WHERE ip_hash = ? AND bucket = ?",
            (identity, hour_bucket),
        ).fetchone()
        used = int(row["used"]) if row else 0
        if used >= DEMO_LIMIT_PER_HOUR:
            return False
        if row:
            conn.execute(
                "UPDATE demo_rate_limits SET used = used + 1 WHERE ip_hash = ? AND bucket = ?",
                (identity, hour_bucket),
            )
        else:
            conn.execute(
                "INSERT INTO demo_rate_limits (ip_hash, bucket, used) VALUES (?, ?, 1)",
                (identity, hour_bucket),
            )
        conn.execute("DELETE FROM demo_rate_limits WHERE bucket < ?", (f"{bucket}:{int(time.time() // 3600) - 2}",))
    return True


def public_call_allowed(http_request: Request, *, bucket: str, authorized: bool) -> bool:
    """A live API key bypasses the demo limiter; anonymous calls do not."""
    return True if authorized else demo_rate_allowed(http_request, bucket)


def scope_amount(scope: dict[str, Any]) -> float | None:
    for key in ("amount", "total", "value", "price", "spend", "max_amount"):
        value = scope.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(re.sub(r"[^0-9.\-]", "", value))
            except ValueError:
                continue
    return None


def find_matching_rule(
    org: str, agent: str, action: str, scope_json: str
) -> sqlite3.Row | None:
    """First active conditional rule that covers this exact agent/tool/scope."""
    try:
        scope = json.loads(scope_json or "{}")
    except json.JSONDecodeError:
        scope = {}
    if not isinstance(scope, dict):
        scope = {}
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT * FROM auto_approve_rules "
            "WHERE org_id = ? AND status = 'active' AND "
            "(revoked_at IS NULL OR revoked_at = '') AND "
            "(expires_at IS NULL OR expires_at = '' OR expires_at >= ?) "
            "ORDER BY created_at DESC",
            (safe_org_id(org), iso()),
        ).fetchall()
    for row in rows:
        rule_agent = str(row["agent_name"] or row["agent"] or "")
        rule_action = str(row["tool_name"] or row["action"] or "")
        if rule_agent and rule_agent != agent:
            continue
        if rule_action and rule_action != action:
            continue
        condition: dict[str, Any] = {}
        raw_condition = str(row["condition_json"] or "")
        if raw_condition:
            try:
                parsed = json.loads(raw_condition)
                if isinstance(parsed, dict):
                    condition = parsed
            except json.JSONDecodeError:
                continue
        cap = row["max_amount"]
        if cap is None:
            cap = condition.get("max_amount")
        if cap is not None:
            amount = scope_amount(scope)
            if amount is None or amount > float(cap):
                continue
        matched = True
        for key, expected in condition.items():
            if key == "max_amount":
                continue
            actual = scope.get(key)
            if isinstance(expected, list):
                if actual not in expected:
                    matched = False
                    break
            elif actual != expected:
                matched = False
                break
        if matched:
            return row
    return None


def callback_payload(row: Any, decision: str) -> dict[str, Any]:
    """Signed, minimal callback body. No raw scope values are included."""
    permission_row = get_permission_by_request(str(row["id"]))
    permission = permission_dict(permission_row) if permission_row else None
    payload = receipt_payload(row, decision, permission)
    keys = row.keys() if hasattr(row, "keys") else row
    payload["signed_receipt"] = str(row["signed_receipt"] or "") if "signed_receipt" in keys else ""
    payload["callback_url"] = ""
    return payload


def callback_signature(body: dict[str, Any], secret: str, timestamp: str) -> str:
    material = f"{timestamp}.{canonical_json(body)}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()


def _post_callback(url: str, body: dict[str, Any], headers: dict[str, str]) -> int:
    request = urlrequest.Request(
        url,
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlrequest.build_opener().open(request, timeout=5) as response:
            return int(getattr(response, "status", 0) or response.getcode())
    except (urlerror.URLError, TimeoutError, OSError, ValueError):
        return 0


async def dispatch_callback(row: Any, decision: str) -> bool:
    """POST a signed decision receipt, retrying up to twice on failure."""
    keys = row.keys() if hasattr(row, "keys") else row
    callback_url = str(row["callback_url"] or "") if "callback_url" in keys else ""
    secret = str(row["callback_secret"] or "") if "callback_secret" in keys else ""
    receipt = str(row["signed_receipt"] or "") if "signed_receipt" in keys else ""
    with closing(db()) as conn:
        stored = conn.execute(
            "SELECT callback_url, callback_secret, signed_receipt FROM approval_requests WHERE id = ?",
            (str(row["id"]),),
        ).fetchone()
    if stored:
        callback_url = str(stored["callback_url"] or callback_url)
        secret = str(stored["callback_secret"] or secret)
        receipt = str(stored["signed_receipt"] or receipt)
    if not callback_url:
        return False
    secret = secret or (_SIGNING_SECRET or "grant-local-development")
    parts = urlsplit(callback_url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return False
    if IS_PRODUCTION and parts.scheme != "https":
        return False
    body = callback_payload(row, decision)
    body["signed_receipt"] = receipt or body["signed_receipt"]
    timestamp = iso()
    headers = {
        "content-type": "application/json",
        "x-grant-timestamp": timestamp,
        "x-grant-signature": "sha256=" + callback_signature(body, secret, timestamp),
        "x-grant-request-id": str(row["id"])[:120],
    }
    for attempt in range(CALLBACK_MAX_RETRIES + 1):
        if attempt:
            await asyncio.sleep(0.1 * attempt)
        status = await asyncio.to_thread(_post_callback, callback_url, body, headers)
        if 200 <= status < 300:
            return True
    return False


def get_request_by_token(token: str) -> sqlite3.Row | None:
    with closing(db()) as conn:
        return conn.execute("SELECT * FROM requests WHERE token = ?", (token,)).fetchone()


def get_request_by_id(request_id: str) -> sqlite3.Row | None:
    with closing(db()) as conn:
        return conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()


def get_permission_by_request(request_id: str) -> sqlite3.Row | None:
    with closing(db()) as conn:
        return conn.execute(
            "SELECT * FROM permissions WHERE source_request = ? ORDER BY created_at DESC LIMIT 1",
            (request_id,),
        ).fetchone()


def get_permission_by_id(permission_id: str) -> sqlite3.Row | None:
    with closing(db()) as conn:
        return conn.execute("SELECT * FROM permissions WHERE id = ?", (permission_id,)).fetchone()


def get_workspace(code: str) -> sqlite3.Row | None:
    with closing(db()) as conn:
        return conn.execute("SELECT * FROM workspaces WHERE code = ?", (code,)).fetchone()


def get_organization(code: str) -> sqlite3.Row | None:
    with closing(db()) as conn:
        return conn.execute("SELECT * FROM organizations WHERE id = ?", (code,)).fetchone()


def create_org_record(conn: Any, code: str, name: str, owner_user_id: str = "") -> None:
    """Dual-write the capability workspace and durable organization records."""
    now = iso()
    conn.execute(
        "INSERT OR IGNORE INTO workspaces (code, name, created_at) VALUES (?, ?, ?)",
        (code, name[:80] or "My agents", now),
    )
    conn.execute(
        "INSERT OR IGNORE INTO organizations (id, name, owner_user_id, plan_tier, created_at) "
        "VALUES (?, ?, ?, 'free', ?)",
        (code, name[:80] or "My agents", str(owner_user_id or "")[:120] or None, now),
    )


def sync_org_tier(conn: Any, org: str, tier: str) -> None:
    conn.execute("UPDATE organizations SET plan_tier = ? WHERE id = ?", (tier, org))


def safe_org_id(value: str | None) -> str:
    return billing.safe_org_id(value) or "public"


def clean_parent_origin(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parts = urlsplit(raw)
    origin = f"{parts.scheme}://{parts.netloc}" if parts.scheme in {"http", "https"} and parts.netloc else ""
    return origin if origin in POPUP_ALLOWED_ORIGINS else ""


def approval_path(
    token: str, *, parent_origin: str = "", compact: bool = False, channel: str = ""
) -> str:
    params: dict[str, str] = {}
    origin = clean_parent_origin(parent_origin)
    if origin:
        params["parent_origin"] = origin
    if compact:
        params["compact"] = "1"
    if channel:
        params["channel"] = telemetry.normalize_channel(channel)
    suffix = "?" + urlencode(params) if params else ""
    return f"/a/{token}{suffix}"


PLAN_FIELDS = (
    "org_id",
    "tier",
    "status",
    "trial_tier",
    "trial_ends_at",
    "plan_expires_at",
    "quota_reset_at",
    "checkout_id",
    "customer_ref",
    "created_at",
    "updated_at",
)


def plan_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {field: row[field] for field in PLAN_FIELDS}


def insert_plan(conn: sqlite3.Connection, plan: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO plans (
            org_id, tier, status, trial_tier, trial_ends_at,
            plan_expires_at, quota_reset_at,
            checkout_id, customer_ref, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        tuple(str(plan.get(field) or "") for field in PLAN_FIELDS),
    )


def update_plan(conn: sqlite3.Connection, plan: dict[str, Any]) -> None:
    conn.execute(
        """
        UPDATE plans SET tier = ?, status = ?, trial_tier = ?, trial_ends_at = ?,
            plan_expires_at = ?, quota_reset_at = ?,
            checkout_id = ?, customer_ref = ?, updated_at = ?
        WHERE org_id = ?
        """,
        (
            str(plan.get("tier") or "free"),
            str(plan.get("status") or "inactive"),
            str(plan.get("trial_tier") or ""),
            str(plan.get("trial_ends_at") or ""),
            str(plan.get("plan_expires_at") or ""),
            str(plan.get("quota_reset_at") or ""),
            str(plan.get("checkout_id") or ""),
            str(plan.get("customer_ref") or ""),
            str(plan.get("updated_at") or plans.iso()),
            str(plan.get("org_id") or ""),
        ),
    )


def get_plan(org_id: str | None) -> dict[str, Any]:
    org = safe_org_id(org_id)
    with transaction() as conn:
        row = conn.execute("SELECT * FROM plans WHERE org_id = ?", (org,)).fetchone()
        if row:
            return plan_from_row(row)
        plan = plans.default_plan(org)
        insert_plan(conn, plan)
        sync_org_tier(conn, org, plans.effective_tier(plan))
        return plan


def normalize_billing_email(value: str) -> str:
    """Normalize a billing email for matching. Never logged or returned raw."""
    return billing.normalize_email(value)


def set_billing_email(org_id: str, email: str) -> bool:
    org = safe_org_id(org_id)
    normalized = normalize_billing_email(email)
    if not org or not normalized:
        return False
    with transaction() as conn:
        conn.execute(
            "INSERT INTO billing_contacts (org_id, email, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(org_id) DO UPDATE SET email = excluded.email, updated_at = excluded.updated_at",
            (org, normalized, iso()),
        )
    return True


def get_billing_email(org_id: str) -> str:
    with closing(db()) as conn:
        row = conn.execute(
            "SELECT email FROM billing_contacts WHERE org_id = ?", (safe_org_id(org_id),)
        ).fetchone()
    return str(row["email"]) if row else ""


def org_for_billing_email(email: str) -> str:
    normalized = normalize_billing_email(email)
    if not normalized:
        return ""
    with closing(db()) as conn:
        row = conn.execute(
            "SELECT org_id FROM billing_contacts WHERE email = ? ORDER BY updated_at DESC LIMIT 1",
            (normalized,),
        ).fetchone()
    return str(row["org_id"]) if row else ""


def org_for_checkout_email(email: str) -> str:
    """Resolve a Cashfree payer email to a workspace or user-owned org.

    The email is normalized in memory and never returned in an API response.
    """
    normalized = normalize_billing_email(email)
    if not normalized:
        return ""
    existing = org_for_billing_email(normalized)
    if existing:
        return existing
    with closing(db()) as conn:
        user = conn.execute("SELECT id FROM users WHERE email = ?", (normalized,)).fetchone()
        if user:
            org = conn.execute(
                "SELECT id FROM organizations WHERE owner_user_id = ? ORDER BY created_at LIMIT 1",
                (user["id"],),
            ).fetchone()
            if org:
                return str(org["id"])
    return ""


def sync_user_plan(
    conn: Any, org: str, tier: str, status: str, action: dict[str, str] | None = None
) -> None:
    """Mirror a paid plan flip onto the durable user record for /account."""
    action = action or {}
    normalized = normalize_billing_email(str(action.get("email") or ""))
    user_row = None
    if normalized:
        user_row = conn.execute("SELECT * FROM users WHERE email = ?", (normalized,)).fetchone()
    if not user_row:
        org_row = conn.execute(
            "SELECT owner_user_id FROM organizations WHERE id = ?", (safe_org_id(org),)
        ).fetchone()
        owner = str(org_row["owner_user_id"] or "") if org_row else ""
        if owner:
            user_row = conn.execute("SELECT * FROM users WHERE id = ?", (owner,)).fetchone()
    if not user_row and normalized:
        user = find_or_create_user(conn, normalized)
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    if not user_row:
        return
    selected = plans.tier(tier)
    active_paid = status == "active" and tier in billing.PAID_TIERS
    quota = selected.approvals_per_month if selected.approvals_per_month is not None else 0
    expiry = str(action.get("plan_expires_at") or "")
    if not expiry and active_paid:
        expiry = plans.iso(plans.utcnow() + timedelta(days=PAID_PLAN_GRACE_DAYS))
    conn.execute(
        "UPDATE users SET plan_tier = ?, monthly_quota = ?, approvals_used = ?, "
        "plan_expires_at = ? WHERE id = ?",
        (
            tier if active_paid else "free",
            quota if active_paid else int(row_value(user_row, "monthly_quota", 1000)),
            0 if active_paid else int(row_value(user_row, "approvals_used", 0)),
            expiry if active_paid else "",
            user_row["id"],
        ),
    )
    if normalized:
        conn.execute(
            "INSERT INTO billing_contacts (org_id, email, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(org_id) DO UPDATE SET email = excluded.email, updated_at = excluded.updated_at",
            (safe_org_id(org), normalized, iso()),
        )


def row_value(row: Any, key: str, default: Any) -> Any:
    keys = row.keys() if hasattr(row, "keys") else row
    if key not in keys:
        return default
    value = row[key]
    return default if value is None else value


def sanitize_payment_ref(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "", str(value or ""))[:120]


def record_unclaimed_payment(receipt: dict[str, str]) -> bool:
    """Store a verified paid receipt whose email has no Grant workspace."""
    event_id = str(receipt.get("event_id") or "").strip()[:120]
    email = normalize_billing_email(receipt.get("email"))
    tier = str(receipt.get("tier") or "").strip().lower()
    if not event_id or not email or tier not in billing.PAID_TIERS:
        return False
    payment_ref = sanitize_payment_ref(receipt.get("payment_ref"))
    with transaction() as conn:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO unclaimed_payments "
            "(event_id, id, payment_ref, cf_payment_id, customer_email, email, tier, plan_tier, "
            "amount, paid_at, status, workspace, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unclaimed', '', ?)",
            (
                event_id,
                event_id,
                payment_ref,
                payment_ref or None,
                email,
                email,
                tier,
                tier,
                str(receipt.get("amount") or "")[:40] or None,
                str(receipt.get("paid_at") or "")[:40],
                iso(),
            ),
        )
    return bool(cursor.rowcount)


def reset_current_quota(conn: sqlite3.Connection, org: str) -> None:
    conn.execute(
        "DELETE FROM usage_events WHERE org_id = ? AND created_at >= ?",
        (org, month_start_iso()),
    )


def schedule_renewal_reminder(
    conn: sqlite3.Connection, action: dict[str, str], org: str, now: datetime
) -> None:
    """Queue a day-27 reminder pointing at the same static monthly form."""
    tier = str(action.get("tier") or "").strip().lower()
    form_url = cashfree.MONTHLY_FORM_URLS.get(tier)
    if not form_url:
        return
    reminder_key = sanitize_payment_ref(
        action.get("event_id") or action.get("payment_ref") or f"{org}:{tier}:{iso()}"
    )[:120]
    conn.execute(
        "INSERT OR IGNORE INTO renewal_reminders "
        "(reminder_key, org_id, tier, due_at, plan_expires_at, form_url, status, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)",
        (
            reminder_key,
            org,
            tier,
            plans.iso(now + timedelta(days=RENEWAL_REMINDER_DAY)),
            plans.iso(now + timedelta(days=PAID_PLAN_GRACE_DAYS)),
            form_url,
            plans.iso(now),
        ),
    )


def claim_unclaimed_payment(org_id: str, claim: str) -> bool:
    """Claim one verified receipt by checkout email or Cashfree payment ID."""
    org = safe_org_id(org_id)
    value = str(claim or "").strip()
    email = normalize_billing_email(value)
    payment_ref = "" if email else sanitize_payment_ref(value)
    if not org or not get_workspace(org) or (not email and not payment_ref):
        return False
    with transaction() as conn:
        if email:
            row = conn.execute(
                "SELECT * FROM unclaimed_payments "
                "WHERE status = 'unclaimed' AND "
                "(customer_email = ? OR email = ?) ORDER BY created_at DESC LIMIT 1",
                (email, email),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM unclaimed_payments "
                "WHERE status = 'unclaimed' AND "
                "(cf_payment_id = ? OR payment_ref = ?) ORDER BY created_at DESC LIMIT 1",
                (payment_ref, payment_ref),
            ).fetchone()
        if not row:
            return False
        owner = conn.execute(
            "SELECT owner_user_id FROM organizations WHERE id = ?", (org,)
        ).fetchone()
        claimed_by = str(owner["owner_user_id"] or "") if owner else ""
        cursor = conn.execute(
            "UPDATE unclaimed_payments SET status = 'claimed', workspace = ?, claimed_at = ?, "
            "claimed_by_user_id = ? WHERE event_id = ? AND status = 'unclaimed'",
            (org, iso(), claimed_by or None, row["event_id"]),
        )
        if cursor.rowcount != 1:
            return False
        contact = email or normalize_billing_email(row["email"])
        if contact:
            conn.execute(
                "INSERT INTO billing_contacts (org_id, email, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(org_id) DO UPDATE SET email = excluded.email, updated_at = excluded.updated_at",
                (org, contact, iso()),
            )
    apply_billing_event(
        {
            "org_id": org,
            "tier": str(row["tier"]),
            "status": "active",
            "event_type": "unclaimed_payment_claim",
            "event_id": str(row["event_id"]),
            "customer_ref": str(row["payment_ref"]),
            "checkout_id": str(row["payment_ref"]),
            "payment_ref": str(row["payment_ref"]),
            "paid_at": str(row["paid_at"]),
        }
    )
    return True


def month_start_iso() -> str:
    now = plans.utcnow()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def monthly_usage(org_id: str | None) -> int:
    with closing(db()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS used FROM usage_events WHERE org_id = ? AND created_at >= ?",
            (safe_org_id(org_id), month_start_iso()),
        ).fetchone()
    return int(row["used"]) if row else 0


def record_usage(org_id: str | None, request_id: str) -> None:
    with transaction() as conn:
        conn.execute(
            "INSERT INTO usage_events (org_id, request_id, created_at) VALUES (?, ?, ?)",
            (safe_org_id(org_id), str(request_id)[:120], iso()),
        )


def plan_context(org_id: str | None, *, used: int | None = None) -> dict[str, Any]:
    org = safe_org_id(org_id)
    plan = get_plan(org)
    count = monthly_usage(org) if used is None else max(0, int(used))
    current = plans.effective_tier(plan)
    return {
        "org_id": org,
        "plan": plan,
        "used": count,
        "usage": plans.usage_state(plan, count),
        "limits": plans.limits(current),
    }


FEATURE_MIN_TIER = {
    "conditional_auto_approve": "plus",
    "instant_delivery": "plus",
    "multi_approver_routing": "pro",
    "mobile_channels": "pro",
    "compliance_exports": "pro",
    "white_label": "enterprise",
    "sso_saml": "enterprise",
    "siem_streaming": "enterprise",
}
CHANNEL_FEATURES = {
    "slack": "instant_delivery",
    "webhook": "instant_delivery",
    "sms": "mobile_channels",
    "whatsapp": "mobile_channels",
}


def upgrade_url(org: str, feature: str) -> str:
    return "/pricing?" + urlencode({"org_id": org, "from": feature})


def upgrade_detail(
    feature: str,
    current: str,
    required: str,
    org: str,
    message: str,
    status: int,
) -> dict[str, Any]:
    return {
        "code": "plan_upgrade_required" if status == 403 else "approval_quota_exceeded",
        "error": "upgrade_required" if status == 403 else "quota_exceeded",
        "message": message,
        "feature": feature,
        "current_tier": current,
        "required_tier": required,
        "upgrade_url": upgrade_url(org, feature),
    }


def require_feature(org_id: str | None, feature: str) -> str:
    """Hard 403 gate for Plus/Pro/Enterprise-only server features."""
    org = safe_org_id(org_id)
    current = plans.effective_tier(get_plan(org))
    if plans.feature_locks(current).get(feature):
        return current
    required = FEATURE_MIN_TIER.get(feature, "plus")
    raise HTTPException(
        status_code=403,
        detail=upgrade_detail(
            feature,
            current,
            required,
            org,
            f"{feature.replace('_', ' ').title()} requires the {plans.tier(required).name} plan.",
            403,
        ),
    )


def require_request_quota(org_id: str | None) -> None:
    """Hard 402 gate once the current monthly approval quota is spent."""
    org = safe_org_id(org_id)
    usage = plans.usage_state(get_plan(org), monthly_usage(org))
    limit = usage["limit"]
    if limit is None or usage["used"] < limit:
        return
    detail = upgrade_detail(
        "approval_quota",
        usage["tier"],
        "plus",
        org,
        f"Monthly approval quota of {limit} reached. Upgrade to continue.",
        402,
    )
    detail.update({"used": usage["used"], "limit": limit})
    raise HTTPException(status_code=402, detail=detail)


def enforce_request_gates(payload: RequestIn) -> None:
    """Single server-side choke point shared by every request-creating API."""
    org = safe_org_id(payload.workspace)
    channel = str(payload.channel or "").strip().lower()
    feature = CHANNEL_FEATURES.get(channel)
    if feature:
        require_feature(org, feature)
    require_request_quota(org)


def apply_billing_event(action: dict[str, str]) -> bool:
    """Apply one normalized billing event. Returns False when already applied.

    A successful paid event grants a 30-day month plus a 2-day grace buffer,
    resets the current month's usage, and queues the day-27 renewal reminder.
    """
    org = safe_org_id(action.get("org_id"))
    event_id = str(action.get("event_id") or "")[:120]
    tier = str(action.get("tier") or "free").strip().lower()
    status = str(action.get("status") or "inactive").strip().lower()
    now = plans.utcnow()
    active_paid = status == "active" and tier in billing.PAID_TIERS
    with transaction() as conn:
        if event_id and conn.execute(
            "SELECT 1 FROM billing_events WHERE event_id = ?", (event_id,)
        ).fetchone():
            return False
        row = conn.execute("SELECT * FROM plans WHERE org_id = ?", (org,)).fetchone()
        plan = plan_from_row(row) if row else plans.default_plan(org)
        plan.update(
            {
                "tier": tier,
                "status": status,
                "plan_expires_at": (
                    plans.iso(now + timedelta(days=PAID_PLAN_GRACE_DAYS)) if active_paid else ""
                ),
                "quota_reset_at": plans.iso(now) if active_paid else "",
                "checkout_id": str(action.get("checkout_id") or "")[:120],
                "customer_ref": str(action.get("customer_ref") or "")[:120],
                "updated_at": plans.iso(now),
            }
        )
        if status == "active":
            plan["trial_tier"] = ""
            plan["trial_ends_at"] = ""
        insert_plan(conn, plan)
        update_plan(conn, plan)
        sync_org_tier(conn, org, plans.effective_tier(plan))
        sync_user_plan(conn, org, tier, status, action)
        if active_paid:
            reset_current_quota(conn, org)
            schedule_renewal_reminder(conn, action, org, now)
        if event_id:
            conn.execute(
                "INSERT INTO billing_events (event_id, org_id, tier, status, applied_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (event_id, org, plan["tier"], plan["status"], plans.iso(now)),
            )
    return True


def gateway_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_gateway(token: str) -> sqlite3.Row | None:
    with closing(db()) as conn:
        return conn.execute(
            "SELECT * FROM gateways WHERE token_hash = ?", (gateway_token_hash(token[:120]),)
        ).fetchone()


def policy_from_row(row: sqlite3.Row) -> dict[str, Any]:
    policy = json.loads(row["policy_json"])
    policy["name"] = row["name"]
    policy["upstream_url"] = row["upstream_url"]
    policy["workspace"] = row["workspace"]
    return policy


REQUEST_SNAPSHOT_FIELDS = (
    "id",
    "token",
    "agent",
    "action",
    "summary",
    "scope_json",
    "scope_hash",
    "requester",
    "workspace",
    "callback_url",
    "channel",
    "gateway_hash",
    "created_at",
    "expires_at",
    "status",
    "decision",
    "decision_at",
    "policy",
)


def request_snapshot(row: Any) -> dict[str, Any]:
    keys = row.keys() if hasattr(row, "keys") else row
    return {field: row[field] for field in REQUEST_SNAPSHOT_FIELDS if field in keys}


def blob_enabled() -> bool:
    return bool(
        os.environ.get("BLOB_STORE_ID")
        or os.environ.get("BLOB_READ_WRITE_TOKEN")
        or os.environ.get("VERCEL_BLOB_READ_WRITE_TOKEN")
    )


def _blob_module():
    from vercel import blob

    return blob


def _blob_paths(row: dict[str, Any], *, decided: bool = False) -> tuple[str, str]:
    request_id = str(row["id"])[:120]
    token = str(row["token"])[:80]
    if decided:
        return (
            f"{BLOB_PREFIX}/decisions/{request_id}.json",
            f"{BLOB_PREFIX}/decision-tokens/{token}.json",
        )
    return (
        f"{BLOB_PREFIX}/requests/{request_id}.json",
        f"{BLOB_PREFIX}/tokens/{token}.json",
    )


async def blob_put_request(row: Any, *, decided: bool = False) -> bool:
    if not blob_enabled():
        return False
    snapshot = request_snapshot(row)
    payload = canonical_json(snapshot).encode("utf-8")
    try:
        blob = _blob_module()
        for path in _blob_paths(snapshot, decided=decided):
            await blob.put_blob(
                path,
                payload,
                access="private",
                content_type="application/json",
                allow_overwrite=True,
                cache_control_max_age=0,
            )
        return True
    except Exception as exc:
        print("grant blob write failed:", type(exc).__name__)
        return False


async def _blob_get(path: str) -> dict[str, Any] | None:
    try:
        result = await _blob_module().get_blob(path, access="private")
        data = json.loads(result.body.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception as exc:
        if type(exc).__name__ != "BlobNotFoundError":
            print("grant blob read failed:", type(exc).__name__)
        return None


async def blob_get_request(request_id: str) -> dict[str, Any] | None:
    if not blob_enabled():
        return None
    safe_id = str(request_id)[:120]
    decided = await _blob_get(f"{BLOB_PREFIX}/decisions/{safe_id}.json")
    if decided:
        return decided
    return await _blob_get(f"{BLOB_PREFIX}/requests/{safe_id}.json")


async def blob_get_request_by_token(token: str) -> dict[str, Any] | None:
    if not blob_enabled():
        return None
    safe_token = str(token)[:80]
    decided = await _blob_get(f"{BLOB_PREFIX}/decision-tokens/{safe_token}.json")
    if decided:
        return decided
    return await _blob_get(f"{BLOB_PREFIX}/tokens/{safe_token}.json")


def _row_status(row: Any) -> str:
    if not row:
        return ""
    try:
        return str(row["status"] or "")
    except (KeyError, TypeError):
        return ""


async def resolve_request_by_id(request_id: str) -> sqlite3.Row | dict[str, Any] | None:
    remote = await blob_get_request(request_id)
    local = get_request_by_id(request_id[:120])
    if _row_status(remote) == "decided":
        return remote
    if _row_status(local) == "decided":
        return local
    return remote or local


async def resolve_request_by_token(token: str) -> sqlite3.Row | dict[str, Any] | None:
    remote = await blob_get_request_by_token(token)
    local = get_request_by_token(token[:80])
    if _row_status(remote) == "decided":
        return remote
    if _row_status(local) == "decided":
        return local
    return remote or local


GATEWAY_SNAPSHOT_FIELDS = (
    "token_hash",
    "name",
    "upstream_url",
    "policy_json",
    "workspace",
    "created_at",
)


def gateway_snapshot(row: Any) -> dict[str, Any]:
    return {field: row[field] for field in GATEWAY_SNAPSHOT_FIELDS}


async def blob_put_gateway(row: Any) -> bool:
    if not blob_enabled():
        return False
    snapshot = gateway_snapshot(row)
    payload = canonical_json(snapshot).encode("utf-8")
    try:
        await _blob_module().put_blob(
            f"{BLOB_PREFIX}/gateways/{str(snapshot['token_hash'])[:120]}.json",
            payload,
            access="private",
            content_type="application/json",
            allow_overwrite=True,
            cache_control_max_age=0,
        )
        return True
    except Exception as exc:
        print("grant gateway blob write failed:", type(exc).__name__)
        return False


async def blob_get_gateway(token: str) -> dict[str, Any] | None:
    if not blob_enabled():
        return None
    return await _blob_get(f"{BLOB_PREFIX}/gateways/{gateway_token_hash(token[:120])}.json")


async def resolve_gateway(token: str) -> sqlite3.Row | dict[str, Any] | None:
    return await blob_get_gateway(token) or get_gateway(token)


def cleanup_pending() -> None:
    now = time.monotonic()
    for request_id, snapshot in list(_PENDING.items()):
        if snapshot.get("expires_monotonic", 0) < now:
            _PENDING.pop(request_id, None)


def store_pending(request_id: str, snapshot: dict[str, Any]) -> None:
    cleanup_pending()
    with _LOCK:
        _PENDING[request_id] = snapshot


def get_pending(request_id: str) -> dict[str, Any] | None:
    cleanup_pending()
    with _LOCK:
        return _PENDING.get(request_id[:120])


def pop_pending(request_id: str) -> dict[str, Any] | None:
    with _LOCK:
        return _PENDING.pop(request_id[:120], None)


def _policy_values(policy: dict[str, Any], key: str, defaults: tuple[str, ...]) -> list[str]:
    values = policy.get(key) or list(defaults)
    return [str(item).lower() for item in values]


def policy_is_sensitive(
    policy: dict[str, Any],
    *,
    method: str = "",
    path: str = "",
    tool: str = "",
    payload: Any = None,
) -> tuple[bool, str]:
    if str(policy.get("default_action", "review")).lower() == "review":
        return True, "policy default"

    tool_text = tool.lower()
    for word in _policy_values(policy, "sensitive_tools", DEFAULT_SENSITIVE_TOOLS):
        if word and word in tool_text:
            return True, f"tool:{tool}"

    path_text = path.lower()
    method_text = method.upper()
    methods = {value.upper() for value in _policy_values(policy, "sensitive_methods", ())}
    for part in _policy_values(policy, "sensitive_paths", DEFAULT_SENSITIVE_PATH_PARTS):
        if part and part in path_text and method_text in methods:
            return True, f"path:{path}"

    try:
        body_text = canonical_json(payload or {}).lower()
    except (TypeError, ValueError):
        body_text = ""
    for key in _policy_values(policy, "body_keys", ()):
        if key and key in body_text:
            return True, f"body key:{key}"

    return False, "routine"


def gateway_request_info(
    policy_name: str,
    *,
    method: str,
    path: str,
    query: str,
    tool: str,
    payload: Any,
    reason: str,
) -> tuple[str, str, dict[str, Any]]:
    if tool:
        action = f"mcp:{tool}"[:120]
        summary = f"MCP tool {tool} was called through {policy_name}. Trigger: {reason}."
    else:
        action = f"{method} {path}"[:120]
        summary = f"An agent called {method} {path} on {policy_name}. Trigger: {reason}."
    scope = {
        "gateway": policy_name,
        "method": method,
        "path": path[:500],
        "query": query[:500],
        "tool": tool[:120],
        "body": payload if isinstance(payload, (dict, list, str, int, float, bool)) or payload is None else str(payload),
    }
    return action, summary, scope


def forward_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in headers.items() if key.lower() not in HOP_BY_HOP_HEADERS}


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_UPSTREAM_OPENER = urlrequest.build_opener(_NoRedirect)


def _sync_forward(
    url: str, method: str, body: bytes | None, headers: dict[str, str]
) -> tuple[int, dict[str, str], bytes]:
    req = urlrequest.Request(url, data=body, method=method.upper(), headers=headers)
    try:
        with _UPSTREAM_OPENER.open(req, timeout=30) as response:
            status = int(response.status)
            raw = response.read()
            raw_headers = response.headers.items()
    except urlerror.HTTPError as exc:
        status = int(exc.code)
        raw = exc.read()
        raw_headers = exc.headers.items()
    except urlerror.URLError:
        return 502, {"content-type": "application/json"}, b'{"detail":"Upstream request failed."}'
    clean_headers = {
        key: value
        for key, value in raw_headers
        if key.lower() not in HOP_BY_HOP_HEADERS and not key.lower().startswith("x-grant-")
    }
    return status, clean_headers, raw


async def forward_upstream(
    policy: dict[str, Any],
    *,
    method: str,
    path: str,
    query: str,
    body: bytes | None,
    headers: dict[str, str],
) -> tuple[int, dict[str, str], bytes]:
    base = policy["upstream_url"].rstrip("/")
    url = base + "/" + path.lstrip("/")
    if query:
        url += "?" + query
    return await asyncio.to_thread(_sync_forward, url, method, body, forward_headers(headers))


async def wait_for_decision(request_id: str, timeout: int) -> sqlite3.Row | None:
    deadline = time.monotonic() + max(0, timeout)
    while True:
        row = await resolve_request_by_id(request_id)
        if row and (row["status"] == "decided" or expired(row)):
            return row
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        await asyncio.sleep(min(0.8, remaining))


def gateway_pending_payload(result: dict[str, str], *, mcp_id: Any = None) -> dict[str, Any]:
    pending = {
        "grant_id": result["id"],
        "status": "pending",
        "approval_url": result["approval_url"],
        "message": result["message"],
        "retry_header": "X-Grant-Request-Id",
        "expires_at": result["expires_at"],
    }
    if mcp_id is not None:
        return {"jsonrpc": "2.0", "id": mcp_id, "result": {"grant": pending}}
    return pending


def grant_message(agent: str, action: str, approval_url: str) -> str:
    return (
        f"Grant · {agent} wants to {action}. "
        f"Review the exact scope and decide here: {approval_url}\n"
        "Approve once · Auto-approve rule · Always allow · Reject. No account needed."
    )


def a2a_needs_approval(task: str, payload: dict[str, Any]) -> bool:
    """Decide whether an agent-to-agent handoff crosses a consent boundary."""
    for key in ("amount", "spend", "cost", "value", "budget"):
        amount = payload.get(key)
        if isinstance(amount, (int, float)) and not isinstance(amount, bool) and amount > 0:
            return True
    text = f"{task} {canonical_json(payload)}".lower()
    return any(
        word in text
        for word in ("pay", "refund", "spend", "transfer", "delete", "send", "publish", "sign", "external", "purchase")
    )


def create_request(payload: RequestIn, *, gateway_hash: str = "") -> dict[str, str]:
    enforce_request_gates(payload)
    scope_json, scope_hash = canonical_scope(payload.scope)
    request_id = "req_" + new_code(9)
    token = new_code(24)
    now = iso()
    expires = iso_plus(payload.ttl_minutes)
    org = safe_org_id(payload.workspace)
    get_plan(org)
    with transaction() as conn:
        conn.execute(
            """
            INSERT INTO requests (
                id, token, agent, action, summary, scope_json, scope_hash, requester,
                workspace, callback_url, channel, gateway_hash, created_at, expires_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            """,
            (
                request_id,
                token,
                payload.agent.strip(),
                payload.action.strip(),
                payload.summary.strip(),
                scope_json,
                scope_hash,
                payload.requester.strip() or "agent",
                payload.workspace.strip() or "public",
                payload.callback_url.strip(),
                telemetry.normalize_channel(payload.channel),
                str(gateway_hash or "")[:120],
                now,
                expires,
            ),
        )
        conn.execute(
            """
            INSERT INTO approval_requests (
                id, org_id, token, agent, action, summary, scope_json, scope_hash, requester,
                channel, gateway_hash, created_at, expires_at, status,
                owner_user_id, agent_name, tool_name, callback_url, callback_secret
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                org,
                token,
                payload.agent.strip(),
                payload.action.strip(),
                payload.summary.strip(),
                scope_json,
                scope_hash,
                payload.requester.strip() or "agent",
                telemetry.normalize_channel(payload.channel),
                str(gateway_hash or "")[:120],
                now,
                expires,
                str(payload.owner_user_id or "")[:120],
                payload.agent.strip()[:120],
                payload.action.strip()[:120],
                payload.callback_url.strip()[:500],
                payload.callback_secret.strip()[:200],
            ),
        )
    record_usage(org, request_id)
    url = approval_path(token, parent_origin=payload.parent_origin)
    approval_url = f"{PUBLIC_BASE_URL}{url}" if PUBLIC_BASE_URL else url
    return {
        "id": request_id,
        "token": token,
        "url": url,
        "approval_url": approval_url,
        "expires_at": expires,
        "scope_hash": scope_hash,
        "message": grant_message(payload.agent.strip(), payload.action.strip(), approval_url),
    }


def decide_request(row: sqlite3.Row, decision: str) -> bool:
    now = iso()
    if decision == "always":
        expires = iso_plus(365 * 24 * 60)
    elif decision == "auto_rule":
        expires = iso_plus(30 * 24 * 60)
    else:
        expires = iso_plus(60)
    permission: dict[str, Any] | None = None
    with transaction() as conn:
        updated = conn.execute(
            "UPDATE requests SET status = 'decided', decision = ?, decision_at = ?, policy = ? "
            "WHERE id = ? AND status = 'pending'",
            (decision, now, decision, row["id"]),
        )
        if updated.rowcount != 1:
            return False
        if decision in {"approve", "auto_rule", "always"}:
            permission = {
                "id": "perm_" + new_code(9),
                "workspace": row["workspace"],
                "agent": row["agent"],
                "action": row["action"],
                "scope_hash": row["scope_hash"],
                "policy": decision if decision != "approve" else "once",
                "created_at": now,
                "expires_at": expires,
                "source_request": row["id"],
            }
            conn.execute(
                """
                INSERT INTO permissions (
                    id, workspace, agent, action, scope_hash, policy, created_at,
                    expires_at, source_request, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    permission["id"],
                    permission["workspace"],
                    permission["agent"],
                    permission["action"],
                    permission["scope_hash"],
                    permission["policy"],
                    permission["created_at"],
                    permission["expires_at"],
                    permission["source_request"],
                    sign_permission(permission),
                ),
            )
        receipt = make_signed_receipt(receipt_payload(row, decision, permission))
        public_status = "approved" if decision in {"approve", "auto_rule", "always"} else "cancelled"
        conn.execute(
            "UPDATE approval_requests SET status = ?, decision = ?, decision_at = ?, "
            "decided_at = ?, policy = ?, decision_type = ?, signed_receipt = ? WHERE id = ?",
            (
                public_status,
                decision,
                now,
                now,
                decision,
                receipt_payload(row, decision, permission)["decision_type"],
                receipt if permission else "",
                row["id"],
            ),
        )
    return True


def expired(row: sqlite3.Row) -> bool:
    try:
        return datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) < datetime.now(timezone.utc)
    except (TypeError, ValueError):
        return False


def risk_for(action: str, scope_json: str) -> str:
    text = f"{action} {scope_json}".lower()
    risky = ("pay", "refund", "spend", "transfer", "delete", "remove", "send", "publish", "sign", "purchase")
    return "review" if any(word in text for word in risky) else "routine"


CSS = """
:root{color-scheme:light;--paper:#FAF8F5;--paper-deep:#F2EFE8;--ink:#2b1b20;--burgundy:#6d2038;--burgundy-2:#8c3a55;--muted:#7d6b69;--line:#E6E1D6;--glass:rgba(255,255,255,.72);--glass-2:rgba(255,255,255,.48);--shadow:0 18px 44px rgba(79,41,52,.08)}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;min-height:100vh;background:var(--paper);color:var(--ink);font:16px/1.65 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;letter-spacing:-.005em}
.circuit{position:fixed;inset:0;width:100%;height:100%;color:rgba(109,32,56,.085);pointer-events:none;z-index:0}
.trace-flow{stroke-dasharray:7 11;animation:trace 18s linear infinite}
@keyframes trace{to{stroke-dashoffset:-180}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}.trace-flow{animation:none}.btn{transition:none}}
.wrap{position:relative;z-index:1;max-width:1120px;margin:0 auto;padding:22px 20px 90px}
.glass{background:linear-gradient(135deg,var(--glass),var(--glass-2));backdrop-filter:blur(20px) saturate(135%);-webkit-backdrop-filter:blur(20px) saturate(135%);border:1px solid var(--line);border-radius:26px;box-shadow:var(--shadow),inset 0 1px 0 rgba(255,255,255,.92)}
.top{display:flex;align-items:center;justify-content:space-between;gap:18px;flex-wrap:wrap;margin-bottom:54px;padding:12px 16px;border-radius:20px}
.brand{display:flex;align-items:center;gap:11px;font-weight:800;letter-spacing:.16em;font-size:.92rem;text-transform:uppercase;color:var(--ink);text-decoration:none}
.mark{width:32px;height:32px;border-radius:10px;background:linear-gradient(135deg,var(--burgundy),var(--burgundy-2));color:#fff8f2;display:grid;place-items:center;font-family:ui-serif,Georgia,serif;font-size:1rem;font-weight:700;box-shadow:0 8px 22px rgba(109,32,56,.2)}
.nav{display:flex;gap:22px;align-items:center;flex-wrap:wrap}
.nav a{color:var(--muted);font-size:.9rem;text-decoration:none}
.nav a:hover{color:var(--burgundy)}
a:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid var(--burgundy);outline-offset:3px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:0;border-radius:14px;padding:12px 18px;font-weight:700;cursor:pointer;text-decoration:none;transition:transform .18s ease,box-shadow .18s ease,background .18s ease;background:var(--burgundy);color:#fff8f2;box-shadow:0 12px 30px rgba(109,32,56,.18)}
.btn:hover{transform:translateY(-2px);text-decoration:none;box-shadow:0 16px 34px rgba(109,32,56,.24)}
.btn.ghost{background:rgba(255,255,255,.45);color:var(--ink);border:1px solid var(--line);box-shadow:none}
.btn.ghost:hover{background:rgba(255,255,255,.7)}
.btn.mini{padding:9px 13px;border-radius:11px;font-size:.82rem}
.hero{text-align:center;max-width:820px;margin:0 auto 44px;padding:58px 44px}
.eyebrow{display:inline-flex;align-items:center;gap:8px;padding:7px 13px;border-radius:99px;border:1px solid var(--line);background:rgba(255,255,255,.42);color:var(--burgundy);font-size:.74rem;font-weight:800;letter-spacing:.14em;text-transform:uppercase}
.dot{width:6px;height:6px;border-radius:50%;background:var(--burgundy);box-shadow:0 0 0 4px rgba(109,32,56,.1)}
h1,h2,h3{font-family:ui-serif,Georgia,Cambria,serif;letter-spacing:-.03em;font-weight:600}
h1{font-size:clamp(2.5rem,6vw,4.6rem);line-height:1.02;margin:24px 0 18px}
h1 em{font-style:italic;color:var(--burgundy)}
h2{font-size:2rem;margin:0 0 8px}
.lede{font-size:1.12rem;color:var(--muted);max-width:640px;margin:0 auto 28px}
.lede.left{margin-left:0}
.cta{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
.preview{max-width:900px;margin:0 auto 54px;padding:26px}
.preview-head{display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;align-items:center;margin-bottom:18px}
.preview-head span{font-size:.8rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-weight:700}
.mock{display:grid;grid-template-columns:1.6fr 1fr;gap:14px}
.mock-main,.mock-side{border-radius:18px;padding:18px;background:rgba(255,255,255,.42);border:1px solid rgba(255,255,255,.8)}
.mock h3{margin:0 0 8px;font-size:1.4rem}
.mock p{margin:0 0 14px;color:var(--muted)}
.chips{display:flex;gap:8px;flex-wrap:wrap}
.chip{display:inline-block;padding:5px 10px;border-radius:99px;background:rgba(109,32,56,.07);border:1px solid var(--line);font-size:.78rem;color:var(--burgundy)}
.mock-actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:16px}
.section{padding:36px 40px;margin-bottom:18px}
.sub{color:var(--muted);margin:0 0 26px}
.claim{margin-top:16px;padding-top:14px;border-top:1px solid var(--line)}
.claim summary{cursor:pointer;font-weight:700;color:var(--burgundy)}
.claim .sub{margin:10px 0}
.stack-form{margin-top:12px}
.account-panel summary{line-height:1.5}
.watermark{display:block;margin:26px 0 0;text-align:center;font-size:.74rem;letter-spacing:.06em;color:var(--muted)}
.watermark::first-letter{color:var(--burgundy)}
.receipt-paths{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin:22px 0;text-align:left}
.receipt-card{padding:20px;border-radius:18px;background:rgba(255,255,255,.46);border:1px solid rgba(255,255,255,.8)}
.receipt-card h2{font-size:1.25rem;margin:0 0 8px}
.receipt-card p{margin:0 0 16px;color:var(--muted);font-size:.92rem}
.receipt-card .btn{width:100%}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}
.tile{padding:20px;border-radius:18px;background:rgba(255,255,255,.38);border:1px solid rgba(255,255,255,.75)}
.tile .num{font-family:ui-serif,Georgia,serif;font-size:1.7rem;color:var(--burgundy)}
.tile h3{margin:8px 0 6px;font-size:1.1rem}
.tile p{margin:0;color:var(--muted);font-size:.93rem}
.message{max-width:900px;margin:0 auto 18px;padding:22px 26px}
.message .from{font-size:.74rem;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);font-weight:800}
.message p{margin:8px 0 0;font:13px/1.7 ui-monospace,SFMono-Regular,Consolas,monospace;color:#40262e;white-space:pre-wrap;word-break:break-word}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
pre{background:#f7f2ea;border:1px solid var(--line);border-radius:14px;padding:15px 17px;overflow:auto;font-size:13px;line-height:1.6;color:#40262e}
.approval{max-width:760px;margin:0 auto;padding:34px 38px}
.approval h1,.done h1{font-size:2.4rem;margin:18px 0 8px}
.kv{display:grid;grid-template-columns:130px 1fr;gap:8px 14px;margin:20px 0;padding:16px;border-radius:16px;background:rgba(255,255,255,.4);border:1px solid rgba(255,255,255,.7)}
.kv dt{color:var(--muted);font-size:.82rem;text-transform:uppercase;letter-spacing:.08em;font-weight:700}
.kv dd{margin:0;word-break:break-word}
.scope-box{white-space:pre-wrap;word-break:break-word;font:13px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;background:#f7f2ea;border:1px solid var(--line);border-radius:14px;padding:14px;margin:10px 0 0}
.decision,.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:24px}
.actions{margin-top:18px}
.done{text-align:center;padding:48px 40px}
.done .seal{width:74px;height:74px;margin:0 auto 18px;border-radius:24px;background:linear-gradient(135deg,var(--burgundy),var(--burgundy-2));color:#fff8f2;display:grid;place-items:center;font-size:1.8rem;box-shadow:0 16px 40px rgba(109,32,56,.22)}
.footer{text-align:center;color:var(--muted);font-size:.86rem;margin-top:50px}
.footer a{color:var(--burgundy)}
.table{width:100%;border-collapse:collapse;margin-top:16px}
th,td{text-align:left;padding:11px 9px;border-bottom:1px solid var(--line);font-size:.9rem;vertical-align:top}
th{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}
.status{display:inline-block;padding:3px 9px;border-radius:99px;font-size:.74rem;font-weight:800;text-transform:uppercase;letter-spacing:.06em}
.status.pending{background:rgba(140,58,85,.1);color:var(--burgundy)}
.status.decided{background:rgba(45,95,72,.1);color:#2d5f48}
.alert{padding:14px 16px;border-radius:14px;background:rgba(109,32,56,.07);border:1px solid var(--line);color:var(--burgundy);margin:14px 0}
.field{width:100%;border:1px solid var(--line);border-radius:14px;padding:12px 14px;background:rgba(255,255,255,.55);color:var(--ink);font:inherit;outline:none}
.field:focus{border-color:var(--burgundy);box-shadow:0 0 0 3px rgba(109,32,56,.08)}
label{display:block;font-size:.84rem;color:var(--muted);font-weight:700;margin:16px 0 7px}
.tier-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;align-items:stretch}
.tier{display:flex;flex-direction:column;padding:22px;border-radius:20px;background:rgba(255,255,255,.42);border:1px solid rgba(255,255,255,.8);min-height:360px}
.tier.featured{border-color:rgba(109,32,56,.36);background:linear-gradient(160deg,rgba(255,255,255,.78),rgba(250,239,232,.72));box-shadow:0 20px 50px rgba(109,32,56,.14)}
.tier h3{font-size:1.4rem;margin:8px 0 6px}
.tier .position{font-size:.78rem;line-height:1.35;color:var(--muted);margin:0 0 8px}
.tier .price{font-family:ui-serif,Georgia,serif;font-size:2rem;color:var(--burgundy);line-height:1.1}
.tier .alt{font-size:.82rem;color:var(--muted);margin:4px 0 16px}
.tier ul{list-style:none;padding:0;margin:0 0 20px;color:var(--muted);font-size:.9rem}
.tier li{padding:5px 0;border-bottom:1px solid var(--line)}
.tier li:last-child{border-bottom:0}
.tier .btn{margin-top:auto;width:100%}
.checkout-note{font-size:.76rem;line-height:1.35;color:var(--muted);margin:8px 0 0;text-align:center}
.badge{display:inline-flex;padding:5px 10px;border-radius:99px;background:var(--burgundy);color:#fff8f2;font-size:.68rem;font-weight:800;letter-spacing:.1em;text-transform:uppercase}
.toggle{display:inline-flex;padding:4px;border-radius:99px;background:rgba(255,255,255,.5);border:1px solid var(--line);margin:0 auto 26px}
.toggle button{border:0;background:transparent;color:var(--muted);padding:8px 16px;border-radius:99px;font:inherit;font-weight:700;cursor:pointer}
.toggle button[aria-pressed="true"]{background:var(--burgundy);color:#fff8f2}
.meter{display:flex;align-items:center;gap:14px;padding:14px 18px;border-radius:18px;background:rgba(255,255,255,.46);border:1px solid rgba(255,255,255,.8);margin-bottom:18px;flex-wrap:wrap}
.meter-track{height:8px;min-width:150px;flex:1;border-radius:99px;background:rgba(109,32,56,.1);overflow:hidden}
.meter-fill{height:100%;background:linear-gradient(90deg,var(--burgundy),var(--burgundy-2));border-radius:99px}
.meter .label{font-size:.88rem;color:var(--muted);font-weight:700}
.banner{padding:14px 16px;border-radius:14px;border:1px solid var(--line);background:rgba(255,255,255,.48);margin:12px 0;color:var(--ink)}
.banner.warn{background:rgba(140,58,85,.08);color:var(--burgundy)}
.lock{display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border-radius:99px;background:rgba(109,32,56,.1);color:var(--burgundy);font-size:.66rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;margin-left:6px}
.drawer{padding:14px 16px;border-radius:14px;border:1px solid var(--line);background:rgba(255,255,255,.58);margin-top:12px}
.drawer[hidden]{display:none}
.drawer p{margin:0 0 6px;font-size:.9rem;color:var(--muted)}
.drawer p:first-child{color:var(--ink);font-weight:700}
.op-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}
.op-card{padding:20px;border-radius:18px;background:rgba(255,255,255,.46);border:1px solid rgba(255,255,255,.8)}
.op-card .num{font-family:ui-serif,Georgia,serif;font-size:2.6rem;color:var(--burgundy);line-height:1}
.op-card .label{font-size:.8rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);font-weight:800;margin-top:8px}
.live-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#2d5f48;margin-right:8px;box-shadow:0 0 0 4px rgba(45,95,72,.12)}
.live-dot.error{background:var(--burgundy);box-shadow:0 0 0 4px rgba(109,32,56,.12)}
.device-list{margin:10px 0 0;padding-left:18px;color:var(--muted);font-size:.86rem;line-height:1.7}
html[data-grant-compact="true"] .approval{max-width:460px;padding:24px}
html[data-grant-compact="true"] .decision,html[data-grant-compact="true"] .actions{flex-direction:column}
html[data-grant-compact="true"] .btn{width:100%}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--burgundy);color:#fff8f2;padding:10px 16px;border-radius:99px;font-weight:800;font-size:.88rem;opacity:0;pointer-events:none;transition:opacity .2s;z-index:5}
.toast.show{opacity:1}
@media(max-width:900px){.tier-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:700px){.wrap{padding:16px 13px 60px}.top{margin-bottom:28px;padding:10px 12px}.nav{gap:13px}.hero{padding:38px 24px}.preview,.section,.approval,.done{padding:24px 20px}.mock{grid-template-columns:1fr}.kv{grid-template-columns:1fr}.btn{width:100%}.cta .btn{width:auto}.tier-grid{grid-template-columns:1fr}.receipt-paths{grid-template-columns:1fr}.tier{min-height:0}.meter{align-items:flex-start}.meter-track{width:100%;flex:none}.drawer{position:fixed;inset:auto 10px 10px 10px;z-index:6;max-height:70vh;overflow:auto;box-shadow:var(--shadow)}html[data-grant-compact="true"] .approval{padding:20px 16px}}
.checkpoint,.intro,.receipt-cert,.account-app{max-width:860px;margin:0 auto;padding:34px 38px}
.checkpoint h1,.intro h1,.receipt-cert h1{font-size:2.25rem;margin:18px 0 8px}
.checkpoint .lede.left,.intro .lede.left{text-align:left}
.checkpoint-actions{display:flex;gap:10px;flex-wrap:wrap;margin:24px 0 8px}
.checkpoint-actions .btn{min-width:150px}
.subtle-link{display:inline-block;margin:8px 0;font-size:.88rem;color:var(--muted);text-decoration:underline;text-underline-offset:3px}
.cancel-link{border:0;background:none;color:var(--muted);font-size:.82rem;text-decoration:underline;text-underline-offset:3px;cursor:pointer;padding:8px 0}
.countdown{font-weight:700;color:var(--burgundy)}
.zero-note{padding:12px 14px;border:1px solid var(--line);border-radius:14px;background:rgba(255,255,255,.55);color:var(--muted);font-size:.9rem;margin:16px 0}
.confirm-flash{position:fixed;inset:0;display:grid;place-items:center;background:rgba(250,248,245,.92);color:var(--burgundy);font-family:ui-serif,Georgia,serif;font-size:1.6rem;z-index:20;opacity:0;pointer-events:none;transition:opacity .2s}
.confirm-flash.show{opacity:1}
.intro-step{padding:20px 0;border-bottom:1px solid var(--line)}
.intro-step:last-child{border-bottom:0}
.intro-step .step-num{font-family:ui-serif,Georgia,serif;color:var(--burgundy);font-size:1.1rem}
.plan-mini{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:14px}
.plan-mini div{padding:10px;border:1px solid var(--line);border-radius:12px;font-size:.78rem;color:var(--muted)}
.plan-mini strong{display:block;color:var(--ink);font-size:.9rem}
.install-card{padding:18px;border:1px solid var(--line);border-radius:18px;background:rgba(255,255,255,.6);margin-top:14px}
.install-card ol{margin:10px 0 16px;padding-left:20px;color:var(--muted)}
.badge-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 0}
.badge.ok{background:rgba(45,95,72,.1);color:#2d5f48;font-size:.74rem;padding:4px 10px;border-radius:99px;font-weight:800}
.scope-fingerprint{font-size:.8rem;color:var(--muted);word-break:break-all}
.receipt-cta{margin-top:24px;padding:18px;border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.5)}
.account-app{max-width:1080px}
.account-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.account-grid .section,.checkpoint .section{padding:24px}
.form-row{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-top:10px}
.form-row .field{flex:1;min-width:180px}
.kill-row{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid var(--line)}
.kill-row:last-child{border-bottom:0}
.key-once{padding:14px;border:1px solid var(--line);border-radius:14px;background:#fff;word-break:break-all}
@media(max-width:700px){.plan-mini{grid-template-columns:repeat(2,minmax(0,1fr))}.account-grid{grid-template-columns:1fr}.checkpoint,.intro,.receipt-cert,.account-app{padding:22px 18px}}
"""

CIRCUIT = """
<svg class="circuit" viewBox="0 0 1200 800" aria-hidden="true" preserveAspectRatio="xMidYMid slice">
 <defs>
  <pattern id="grant-trace" width="180" height="140" patternUnits="userSpaceOnUse">
   <path class="trace-flow" d="M0 70 H38 L62 46 H112 L138 20 H180" fill="none" stroke="currentColor" stroke-width="1.1"/>
   <path class="trace-flow" d="M0 118 H52 L78 92 H150 L174 68 H180" fill="none" stroke="currentColor" stroke-width=".8"/>
   <circle cx="38" cy="70" r="3.2" fill="currentColor"/><circle cx="112" cy="46" r="2.4" fill="currentColor"/>
   <circle cx="52" cy="118" r="2.6" fill="currentColor"/><circle cx="150" cy="92" r="3" fill="currentColor"/>
   <rect x="136" y="14" width="8" height="8" rx="2" fill="none" stroke="currentColor" stroke-width="1"/>
  </pattern>
 </defs>
 <rect width="100%" height="100%" fill="url(#grant-trace)"/>
</svg>
"""

SCRIPT = """
<script>
function copyText(text){
  if(navigator.clipboard){navigator.clipboard.writeText(text).catch(function(){});}
  var t=document.getElementById('toast');
  if(t){t.classList.add('show');setTimeout(function(){t.classList.remove('show')},1400);}
}
function copyCurrentLink(){copyText(location.href);}
function grantToggleDrawer(id, force){
  var el=document.getElementById(id);
  if(!el){return;}
  el.hidden = typeof force === 'boolean' ? !force : !el.hidden;
}
function grantOpenDrawer(id){
  document.querySelectorAll('.drawer').forEach(function(node){node.hidden = node.id !== id;});
}
function grantSetCycle(cycle){
  document.querySelectorAll('[data-grant-cycle-button]').forEach(function(button){
    button.setAttribute('aria-pressed', button.getAttribute('data-grant-cycle-button') === cycle ? 'true' : 'false');
  });
  document.querySelectorAll('[data-grant-price]').forEach(function(node){
    node.textContent = node.getAttribute(cycle === 'annual' ? 'data-annual' : 'data-monthly');
  });
  document.querySelectorAll('[data-grant-checkout]').forEach(function(link){
    var url = new URL(link.href, location.href);
    url.searchParams.set('cycle', cycle);
    link.href = url.toString();
  });
}
var grantDeferredPrompt = null;
window.addEventListener('beforeinstallprompt', function(event){
  event.preventDefault();
  grantDeferredPrompt = event;
  document.querySelectorAll('[data-grant-install]').forEach(function(button){button.hidden = false;});
});
window.addEventListener('appinstalled', function(){grantDeferredPrompt = null;});
async function grantInstallShortcut(stay){
  if(grantDeferredPrompt){
    grantDeferredPrompt.prompt();
    try{await grantDeferredPrompt.userChoice;}catch(error){}
    grantDeferredPrompt = null;
  }
  try{localStorage.setItem('grant-shortcut-added', '1');}catch(error){}
  if(stay){
    document.querySelectorAll('[data-grant-install-enable]').forEach(function(node){node.disabled = false;});
    var status = document.getElementById('grant-install-status');
    if(status){status.textContent = 'Shortcut added. Continue to your account.';}
    return;
  }
  location.href = '/account';
}
document.addEventListener('DOMContentLoaded', function(){
  if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js').catch(function(){});}
  document.querySelectorAll('[data-grant-install]').forEach(function(button){
    button.addEventListener('click', function(){grantInstallShortcut(this.dataset.grantInstallStay === '1');});
  });
  document.querySelectorAll('[data-grant-nudge-trigger="always"]').forEach(function(node){
    node.addEventListener('mouseenter', function(){grantOpenDrawer('grant-drawer-auto');});
    node.addEventListener('focus', function(){grantOpenDrawer('grant-drawer-auto');});
  });
  document.addEventListener('click', function(event){
    var trigger = event.target.closest('[data-grant-drawer-open]');
    if(trigger){grantOpenDrawer(trigger.getAttribute('data-grant-drawer-open'));return;}
    var close = event.target.closest('[data-grant-drawer-close]');
    if(close){grantToggleDrawer(close.getAttribute('data-grant-drawer-close'), false);}
  });
});
</script>
"""

_POPUP_ASSET = Path(__file__).resolve().parent / "grant" / "assets" / "grant-popup.js"
POPUP_JS = (
    _POPUP_ASSET.read_text(encoding="utf-8")
    if _POPUP_ASSET.exists()
    else "console.warn('Grant popup asset is unavailable.');"
)

_WIDGET_ASSET = Path(__file__).resolve().parent / "grant" / "assets" / "grant-overlay.js"
WIDGET_JS = (
    _WIDGET_ASSET.read_text(encoding="utf-8")
    if _WIDGET_ASSET.exists()
    else "console.warn('Grant overlay asset is unavailable.');"
)

_INJECT_ASSET = Path(__file__).resolve().parent / "grant" / "assets" / "grant-inject.js"
INJECT_JS = (
    _INJECT_ASSET.read_text(encoding="utf-8")
    if _INJECT_ASSET.exists()
    else "console.warn('Grant inject asset is unavailable.');"
)


def page(
    title: str,
    body: str,
    description: str,
    *,
    private: bool = False,
    root_attrs: dict[str, str] | None = None,
) -> str:
    canonical = f'<link rel="canonical" href="{html.escape(PUBLIC_BASE_URL or "")}/">' if PUBLIC_BASE_URL else ""
    robots = '<meta name="robots" content="noindex,nofollow">' if private else ""
    attrs = "".join(
        f' {key}="{html.escape(str(value), quote=True)}"'
        for key, value in (root_attrs or {}).items()
        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", key)
    )
    favicon = (
        "<link rel=\"icon\" href=\"data:image/svg+xml,"
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>"
        "<rect width='64' height='64' rx='16' fill='%236d2038'/>"
        "<text x='32' y='44' font-size='36' text-anchor='middle' fill='%23fff8f2' font-family='Georgia'>G</text>"
        "</svg>\">"
    )
    return f"""<!doctype html><html lang="en"{attrs}><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(description, quote=True)}">
<meta name="theme-color" content="#FAF8F5">
<link rel="manifest" href="/manifest.webmanifest">
<meta property="og:title" content="{html.escape(title, quote=True)}">
<meta property="og:description" content="{html.escape(description, quote=True)}">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
{favicon}{canonical}{robots}<style>{CSS}</style></head>
<body>{CIRCUIT}<div class="wrap">{body}<div class="footer">Grant never sees your credentials or payment details. It only records what you allowed. · <a href="/docs">How it works</a> · <a href="/stats">Activity</a></div></div>
<div class="toast" id="toast">Copied</div>{SCRIPT}<script src="/grant-popup.js"></script></body></html>"""


def header() -> str:
    return """
<div class="top glass">
  <a class="brand" href="/"><span class="mark">G</span> Grant</a>
  <nav class="nav"><a href="/docs">How it works</a><a href="/pricing">Plans</a><a href="/start">My workspace</a><a href="/signin">Sign in</a><a href="/stats">Activity</a></nav>
</div>
"""


def home_page() -> str:
    body = header() + """
<section class="hero glass">
  <span class="eyebrow"><span class="dot"></span> Simple approvals for AI agents</span>
  <h1>Permission for everything<br><em>your agents do.</em></h1>
  <p class="lede">When an agent acts on someone’s behalf, Grant appears with one calm question: allow this, or not? No signup to approve. No secrets to install. No friction to trust.</p>
  <div class="cta"><a class="btn" href="/docs">Read the 30-second guide</a><form method="post" action="/v1/demo"><button class="btn ghost" type="submit">Try an approval</button></form></div>
</section>
<section class="message glass">
  <span class="from">What your agent says</span>
  <p>Grant · support-agent wants to refund_order. Review the exact scope and decide here:
__GRANT_BASE__/a/••••••••••••

Approve once · Always allow · Reject. No account needed.</p>
</section>
<section class="preview glass">
  <div class="preview-head"><span>Example approval</span><span>Refund an order</span></div>
  <div class="mock">
    <div class="mock-main"><h3>Refund an order</h3><p>Support agent is asking to refund order <span class="mono">ord_42</span> for $48.00.</p>
      <div class="chips"><span class="chip">order: ord_42</span><span class="chip">amount: 48 USD</span><span class="chip">expires: 30 min</span></div>
      <div class="mock-actions"><button class="btn mini" type="button">Approve once</button><button class="btn ghost mini" type="button">Always allow</button><button class="btn ghost mini" type="button">Reject</button></div>
    </div>
    <div class="mock-side"><span class="eyebrow">What Grant gives you</span><h3 style="margin-top:14px">A decision, not a dashboard.</h3><p>Approve once, set a standing policy, or refuse. The agent receives a signed permission and your audit stays intact.</p></div>
  </div>
</section>
<section class="section glass">
  <h2>A confirmation people already understand.</h2>
  <p class="sub">People do not install trust. They encounter it exactly when it matters.</p>
  <div class="grid">
    <div class="tile"><div class="num">01</div><h3>The agent asks</h3><p>A one-line call creates an approval request with the action, scope, and expiry.</p></div>
    <div class="tile"><div class="num">02</div><h3>The human decides</h3><p>A single link opens a quiet, readable page. One tap approves, rejects, or sets a policy.</p></div>
    <div class="tile"><div class="num">03</div><h3>The agent continues</h3><p>Grant returns a signed permission. Every decision is recorded for audit and revocation.</p></div>
  </div>
</section>
<section class="section glass">
  <h2>Install it where your agent already runs.</h2>
  <p class="sub">Python package, tiny CLI, plain HTTP. The approval link is the interface.</p>
  <pre><code>pip install grant-consent

from grant import Grant

grant = Grant("__GRANT_BASE__")
ask = grant.request(
    agent="support-agent",
    action="refund_order",
    summary="Refund order ord_42 for $48.00",
    scope={"order_id": "ord_42", "amount": 48},
)

print(ask.message)  # the agent sends this at the moment of action
permission = grant.wait(ask.id, timeout=300)</code></pre>
</section>
"""
    base = PUBLIC_BASE_URL or "https://grant.yourdomain.com"
    body = body.replace("__GRANT_BASE__", base)
    return page("Grant — consent infrastructure for AI agents", body, "Grant gives every AI agent action one clear approval link and a signed permission.")


def guardrail_drawer(kind: str, org_id: str) -> str:
    org = safe_org_id(org_id)
    query = urlencode({"org_id": org, "from": f"approval-{kind}"})
    specs = {
        "auto": {
            "id": "grant-drawer-auto",
            "tier": "Plus",
            "title": "Auto-approve with caps",
            "detail": (
                "Allow refund_order only when amount &lt;= $50. Free keeps manual "
                "Approve once and Always allow; Plus unlocks conditional spend and scope rules."
            ),
            "summary": "conditional rules, Slack/webhook delivery, and 30-day receipts",
            "cta": "See auto-approve rules",
        },
        "delivery": {
            "id": "grant-drawer-delivery",
            "tier": "Plus",
            "title": "Instant Slack & webhook delivery",
            "detail": (
                "Email and web links work on Free. Plus sends approval cards to Slack "
                "and signed webhook callbacks so decisions happen in seconds."
            ),
            "summary": "Slack/webhook delivery, conditional rules, and 30-day receipts",
            "cta": "See instant delivery",
        },
        "approver": {
            "id": "grant-drawer-approver",
            "tier": "Pro",
            "title": "Multi-approver routing",
            "detail": (
                "Send code deploys to engineering and refunds over $500 to finance — "
                "or require 2-of-3 approvals. Pro adds role rules and 1-year exports; "
                "SMS / WhatsApp alerts are coming soon."
            ),
            "summary": "multi-approver routing and 1-year exports",
            "cta": "See team approvals",
        },
    }
    spec = specs.get(kind, specs["auto"])
    selected = plans.tier(str(spec["tier"]).lower())
    element_id = str(spec["id"])
    return f"""
<div class="drawer" id="{element_id}" hidden>
  <p><span class="lock">{clean(spec["tier"])}</span> {clean(spec["title"])}</p>
  <p>{spec["detail"]} Grant {clean(spec["tier"])} adds {spec["summary"]} for ${selected.monthly_usd}/mo. Start the 14-day free trial.</p>
  <div class="actions"><a class="btn mini" href="/pricing?{query}">{clean(spec["cta"])}</a><button class="btn ghost mini" type="button" data-grant-drawer-close="{element_id}">Not now</button></div>
</div>
"""


def approval_page(
    row: sqlite3.Row | dict[str, Any],
    done: str = "",
    *,
    parent_origin: str = "",
    compact: bool = False,
    dashboard_code: str = "",
) -> str:
    scope = json.dumps(json.loads(row["scope_json"]), indent=2, ensure_ascii=False)
    # `done` is only a legacy redirect marker. A pending row must never be
    # rendered as decided because a caller appended ?done=approve.
    decision = row["decision"] or ""
    workspace = clean(row["workspace"], 60)
    protected_url = f"/protected/{workspace}" if workspace else "/start"
    root_attrs = {
        "data-grant-allowed-origins": ",".join(POPUP_ALLOWED_ORIGINS),
    }
    if clean_parent_origin(parent_origin):
        root_attrs["data-grant-parent-origin"] = clean_parent_origin(parent_origin)
    if compact:
        root_attrs["data-grant-compact"] = "true"

    if row["status"] == "decided":
        if decision == "reject":
            outcome = "Nothing was allowed. The agent was told no."
            seal = "×"
        elif decision == "auto_rule":
            outcome = "A 30-day scoped rule was signed. Matching actions reuse it automatically."
            seal = "✓"
        else:
            outcome = "The agent received a signed permission. Your audit stays intact."
            seal = "✓"
        root_attrs.update(
            {
                "data-grant-complete": "true",
                "data-grant-decision": clean(decision, 20),
                "data-grant-id": clean(row["id"], 120),
            }
        )
        receipt_title = {
            "reject": "Refused",
            "always": "Allowed",
            "auto_rule": "Rule saved",
        }.get(decision, "Approved")
        receipt_id = clean(row["id"], 48)
        owned_workspace = dashboard_code or workspace
        dashboard_href = (
            f"/w/{html.escape(owned_workspace, quote=True)}"
            if owned_workspace
            else "/start?from=receipt"
        )
        body = header() + f"""
<section class="done glass">
  <div class="seal">{seal}</div>
  <h1>{receipt_title}. Receipt {receipt_id} recorded.</h1>
  <p class="lede">{clean(decision).title()} for <strong>{clean(row['agent'])}</strong> → {clean(row['action'])}. {outcome}</p>
  <p class="sub">Cryptographic receipt · signed by Grant · no password, no secrets held.</p>
  <div class="receipt-paths">
    <div class="receipt-card">
      <h2>For you</h2>
      <p>Want to see every AI agent you've authorized—or revoke Always allow anytime?</p>
      <a class="btn" href="{dashboard_href}">Open Your Free Grant Dashboard →</a>
    </div>
    <div class="receipt-card">
      <h2>For builders</h2>
      <p>Building AI agents? Protect your own users' actions in 2 minutes.</p>
      <a class="btn ghost" href="/start?from=receipt">Get Your Free API Key →</a>
    </div>
  </div>
  <p class="watermark">● Protected by Grant · Zero-custody consent infrastructure</p>
</section>
"""
        return page(
            "Decision recorded — Grant",
            body,
            "Your decision has been recorded by Grant.",
            private=True,
            root_attrs=root_attrs,
        )

    if expired(row):
        body = header() + """
<section class="done glass"><div class="seal">×</div><h1>This request expired.</h1>
<p class="lede">The approval window closed. Ask the agent to send a fresh request.</p>
<div class="cta"><a class="btn" href="/">Back to Grant</a></div>
<p class="watermark">● Protected by Grant · Zero-custody consent infrastructure</p></section>
"""
        return page(
            "Request expired — Grant",
            body,
            "This Grant approval request has expired.",
            private=True,
            root_attrs=root_attrs,
        )

    # Keep the full approval address when someone creates or opens a workspace
    # from inside the popup. No JavaScript is required for either flow.
    return_query: dict[str, str] = {}
    if clean_parent_origin(parent_origin):
        return_query["parent_origin"] = clean_parent_origin(parent_origin)
    if compact:
        return_query["compact"] = "1"
    approval_path = "/a/" + clean(row["token"], 80)
    return_target = approval_path + ("?" + urlencode(return_query) if return_query else "")
    hidden_return = html.escape(return_target, quote=True)
    account_panel = f"""
  <details class="claim account-panel">
    <summary>New here? Create a workspace · Already have one? Sign in</summary>
    <p class="sub">A workspace keeps your approvals and plan together. You can still approve without one. Grant does not use passwords — save your workspace link.</p>
    <form method="post" action="/v1/workspaces" class="stack-form">
      <input type="hidden" name="next" value="{hidden_return}">
      <label for="popup-new-workspace">Workspace name</label>
      <input class="field" id="popup-new-workspace" name="name" value="My agents" maxlength="80" required>
      <div class="decision"><button class="btn mini" type="submit">Create workspace</button></div>
    </form>
    <form method="post" action="/signin" class="stack-form">
      <input type="hidden" name="next" value="{hidden_return}">
      <label for="popup-existing-workspace">Use an existing workspace</label>
      <input class="field" id="popup-existing-workspace" name="code" placeholder="Your workspace code" maxlength="60" required>
      <div class="decision"><button class="btn ghost mini" type="submit">Sign in</button></div>
    </form>
  </details>
"""
    body = header() + f"""
<section class="approval glass">
  <span class="eyebrow"><span class="dot"></span> Approval request</span>
  <h1>{clean(row['action'])}</h1>
  <p class="lede left">{clean(row['summary'], 500)}</p>
  <dl class="kv">
    <dt>Who's asking</dt><dd>{clean(row['agent'])}</dd>
    <dt>Requested by</dt><dd>{clean(row['requester'])}</dd>
    <dt>Expires</dt><dd>{friendly_expiry(row['expires_at'])}</dd>
  </dl>
  <form method="post" action="/a/{clean(row['token'])}/decide" class="decision">
    <input type="hidden" name="parent_origin" value="{clean(root_attrs.get('data-grant-parent-origin', ''), 200)}">
    <input type="hidden" name="compact" value="{'1' if compact else '0'}">
    <button class="btn" name="decision" value="approve" type="submit">Approve once</button>
    <button class="btn ghost" name="decision" value="auto_rule" type="submit">Auto-approve rule<span class="lock">Plus</span></button>
    <button class="btn ghost" name="decision" value="always" type="submit" data-grant-nudge-trigger="always">Always allow</button>
    <button class="btn ghost" name="decision" value="reject" type="submit">Reject</button>
  </form>
  <details class="claim">
    <summary>Exact scope · see what is allowed</summary>
    <div class="scope-box">{html.escape(scope)}</div>
  </details>
  <details class="claim">
    <summary>More options</summary>
    <div class="actions">
      <button class="btn ghost mini" type="button" onclick="copyCurrentLink()">Copy approval link</button>
      <button class="btn ghost mini" type="button" data-grant-drawer-open="grant-drawer-auto">Auto-approve rule<span class="lock">Plus</span></button>
      <button class="btn ghost mini" type="button" data-grant-drawer-open="grant-drawer-delivery">Slack / webhook<span class="lock">Plus</span></button>
      <button class="btn ghost mini" type="button" data-grant-drawer-open="grant-drawer-approver">Route to approver<span class="lock">Pro</span></button>
    </div>
    {guardrail_drawer("auto", workspace)}
    {guardrail_drawer("delivery", workspace)}
    {guardrail_drawer("approver", workspace)}
  </details>
  {account_panel}
  <p class="alert">Grant never sees your credentials or payment details. It only records what you allowed. <a href="{protected_url}">Protected by Grant</a></p>
  <p class="watermark">● Protected by Grant · Zero-custody consent infrastructure</p>
</section>
"""
    return page(
        f"{row['action']} — Grant approval",
        body,
        "Review and decide on an AI agent action.",
        private=True,
        root_attrs=root_attrs,
    )


def age_days(value: str | None) -> int:
    try:
        stamp = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return 0
    return max(0, (datetime.now(timezone.utc) - stamp).days)


def usage_meter_html(context: dict[str, Any]) -> str:
    usage = context["usage"]
    org = context["org_id"]
    current = plans.tier(usage["tier"])
    used = int(usage["used"])
    limit = usage["limit"]
    if limit is None:
        label = f"{current.name} · {used:,} approvals this month"
        percent = 0
        state = "ok"
    else:
        label = f"{used:,} / {limit:,} {current.name} approvals used"
        percent = min(100, int(used * 100 / max(1, limit)))
        state = str(usage["state"])
    query = urlencode({"org_id": org, "from": "meter"})
    return f"""
<div class="meter">
  <span class="label">{clean(label)}</span>
  <div class="meter-track" role="progressbar" aria-label="Monthly approvals used" aria-valuenow="{used}" aria-valuemax="{limit or used or 1}"><div class="meter-fill" style="width:{percent}%"></div></div>
  <span class="status {clean(state)}">{clean(state)}</span>
  <a class="btn mini ghost" href="/pricing?{query}">Upgrade</a>
</div>
"""


def plan_banners_html(context: dict[str, Any], rows: list[sqlite3.Row]) -> str:
    plan = context["plan"]
    usage = context["usage"]
    current = plans.tier(usage["tier"])
    org = context["org_id"]
    query = urlencode({"org_id": org, "from": "dashboard"})
    banners: list[str] = []

    if usage["trial_days_left"] > 0:
        banners.append(
            f'<div class="banner">Pro Guardrails trial active — <strong>{usage["trial_days_left"]} days left</strong>. '
            f'Conditional rules, Slack approvals, multi-approver routing, and 365-day receipts are on until then.</div>'
        )
    elif plan.get("status") == "trial":
        banners.append(
            f'<div class="banner warn">Your Pro Guardrails trial ended. Your agents keep running; '
            f'<a href="/pricing?{query}">choose a plan</a> to keep the same controls.</div>'
        )

    if usage["state"] == "over":
        banners.append(
            f'<div class="banner warn">Monthly approval limit reached. '
            f'<strong>New approval requests are paused</strong> until you upgrade or the quota resets. '
            f'<a href="/pricing?{query}">Move to Plus</a>.</div>'
        )
    elif usage["state"] == "near":
        banners.append(
            f'<div class="banner">You are close to the monthly approval limit. '
            f'Upgrade before the next spike so receipts stay active: <a href="/pricing?{query}">see plans</a>.</div>'
        )

    if current.log_retention_days is not None and any(age_days(row["created_at"]) >= 5 for row in rows):
        if current.log_retention_days <= 7:
            banners.append(
                f'<div class="banner warn">Approval receipts from last week expire in 48 hours. '
                f'<a href="/pricing?{query}">Upgrade to Plus</a> for 30-day retention or Pro for a 1-year audit trail with CSV/JSON exports.</div>'
            )

    if "slack" not in current.channels:
        banners.append(
            f'<div class="banner">Waiting on email slows down demos. '
            f'<a href="/pricing?{query}">See faster approvals</a> — Plus adds Slack and webhook callbacks; Pro adds multi-approver routing and compliance exports. '
            f'SMS / WhatsApp alerts are coming soon.</div>'
        )
    return "".join(banners)


def safe_next_path(value: str) -> str:
    """Keep post-workspace redirects on this site."""
    candidate = str(value or "").strip()
    if not candidate.startswith("/") or candidate.startswith("//") or "\\" in candidate:
        return "/pricing"
    return candidate[:200]


DASHBOARD_COOKIE = "grant_dashboard"


def dashboard_cookie(code: str) -> str:
    """Signed, capability-only session for the magic-receipt dashboard."""
    safe = str(code or "")[:60]
    secret = (_SIGNING_SECRET or os.environ.get("GRANT_SIGNING_SECRET") or "").encode("utf-8")
    digest = hmac.new(secret, safe.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return f"{safe}.{digest}"


def dashboard_code_from_cookie(value: str) -> str:
    code, separator, signature = str(value or "").partition(".")
    if not separator or not code or not signature:
        return ""
    expected = dashboard_cookie(code).partition(".")[2]
    if not hmac.compare_digest(signature, expected):
        return ""
    return code


def hash_token(value: str) -> str:
    """Deterministic token digest. Only digests are stored."""
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def valid_email(value: str) -> bool:
    candidate = str(value or "").strip()
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", candidate)) and len(candidate) <= 254


def find_or_create_user(conn: Any, email: str) -> dict[str, Any]:
    normalized = normalize_billing_email(email)
    row = conn.execute("SELECT * FROM users WHERE email = ?", (normalized,)).fetchone()
    if row:
        return dict(row)
    user = {
        "id": "usr_" + new_code(12),
        "email": normalized,
        "created_at": iso(),
        "plan_tier": "free",
        "monthly_quota": 1000,
        "approvals_used": 0,
        "plan_expires_at": "",
    }
    conn.execute(
        "INSERT INTO users (id, email, created_at, plan_tier, monthly_quota, approvals_used, "
        "plan_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            user["id"],
            user["email"],
            user["created_at"],
            user["plan_tier"],
            user["monthly_quota"],
            user["approvals_used"],
            user["plan_expires_at"],
        ),
    )
    return user


def create_session(conn: Any, user_id: str, org: str, email: str) -> str:
    session_id = "ses_" + new_code(18)
    conn.execute(
        "INSERT INTO auth_sessions (id, user_id, org_id, email, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            session_id,
            user_id,
            org,
            normalize_billing_email(email) or None,
            iso_plus(SESSION_DAYS * 24 * 60),
            iso(),
        ),
    )
    return session_id


def session_identity(http_request: Request) -> dict[str, Any] | None:
    session_id = str(http_request.cookies.get(SESSION_COOKIE, ""))[:120]
    if not session_id:
        return None
    with closing(db()) as conn:
        row = conn.execute(
            "SELECT s.*, u.email AS account_email FROM auth_sessions s "
            "LEFT JOIN users u ON u.id = s.user_id "
            "WHERE s.id = ? AND s.expires_at >= ?",
            (session_id, iso()),
        ).fetchone()
    if not row:
        return None
    return {
        "id": session_id,
        "user_id": str(row["user_id"]),
        "email": str(row["account_email"] or row["email"] or ""),
        "org_id": str(row["org_id"]),
    }


def link_claim_rules(conn: Any, claim_token: str, user_id: str) -> int:
    """Attach rules created anonymously before the human signed in."""
    token = str(claim_token or "")[:120]
    if not token:
        return 0
    cursor = conn.execute(
        "UPDATE auto_approve_rules SET user_id = ?, linked_at = ? "
        "WHERE claim_token = ? AND (user_id IS NULL OR user_id = '')",
        (user_id, iso(), token),
    )
    return int(cursor.rowcount)


API_KEY_PREFIX = "gr_live_"


def bearer_value(authorization: str) -> str:
    """Extract a bearer credential without accepting arbitrary schemes."""
    match = re.match(r"^Bearer\s+(.+)$", str(authorization or "").strip(), re.IGNORECASE)
    if not match:
        return ""
    token = match.group(1).strip()
    return token[:200] if len(token) <= 200 else ""


def api_key_principal(token: str) -> dict[str, Any] | None:
    """Resolve a live ``gr_live_`` key. Only its SHA-256 digest is persisted."""
    candidate = str(token or "").strip()
    if not candidate.startswith(API_KEY_PREFIX) or len(candidate) < 24:
        return None
    with transaction() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
            (hash_token(candidate),),
        ).fetchone()
        if not row:
            return None
        conn.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (iso(), row["id"]))
    return {
        "org_id": str(row["org_id"]),
        "user_id": str(row["user_id"]),
        "key_id": str(row["id"]),
        "kind": "api_key",
    }


def principal_from_request(http_request: Request) -> dict[str, Any] | None:
    """A signed session, a live API key, or the dashboard capability cookie."""
    token = bearer_value(http_request.headers.get("authorization", ""))
    if token:
        return api_key_principal(token)
    identity = session_identity(http_request)
    if identity:
        return {**identity, "kind": "session"}
    code = dashboard_code_from_cookie(http_request.cookies.get(DASHBOARD_COOKIE, ""))
    if code and get_workspace(code):
        return {"org_id": code, "user_id": "", "kind": "capability"}
    return None


def require_user_principal(http_request: Request) -> dict[str, Any]:
    principal = principal_from_request(http_request)
    if not principal or not principal.get("user_id"):
        raise HTTPException(
            status_code=401,
            detail="Sign in with an email link or provide a valid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def validate_bearer_if_present(http_request: Request) -> dict[str, Any] | None:
    """Zero-install callers may omit credentials; supplied keys must be live."""
    header = str(http_request.headers.get("authorization", "")).strip()
    if not header:
        return None
    principal = api_key_principal(bearer_value(header))
    if not principal:
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def mint_api_key(conn: Any, org: str, user_id: str, name: str) -> tuple[dict[str, Any], str]:
    raw = API_KEY_PREFIX + secrets.token_urlsafe(24)
    key_id = "key_" + new_code(12)
    created = iso()
    label = str(name or "").strip()[:60] or "Grant API key"
    prefix = raw[: len(API_KEY_PREFIX) + 8]
    conn.execute(
        "INSERT INTO api_keys (id, org_id, user_id, name, key_hash, key_prefix, created_at, "
        "last_used_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
        (key_id, org, user_id, label, hash_token(raw), prefix, created),
    )
    return (
        {"id": key_id, "org_id": org, "name": label, "key_prefix": prefix, "created_at": created},
        raw,
    )


def api_key_public(row: Any) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "name": str(row["name"]),
        "key_prefix": str(row["key_prefix"]),
        "created_at": str(row["created_at"]),
        "last_used_at": str(row["last_used_at"] or ""),
        "revoked_at": str(row["revoked_at"] or ""),
    }


def signin_page(next_path: str = "/pricing", error: bool = False) -> str:
    target = html.escape(safe_next_path(next_path), quote=True)
    start_href = html.escape(f"/start?{urlencode({'next': safe_next_path(next_path)})}", quote=True)
    message = (
        '<p class="alert">That workspace link was not found. Check your saved link, or create a workspace.</p>'
        if error
        else ""
    )
    body = header() + f"""
<section class="approval glass">
  <span class="eyebrow"><span class="dot"></span> Welcome back</span>
  <h1>Sign in to your workspace.</h1>
  <p class="lede left">Enter the workspace code from your saved link. We'll take you straight back to what you were doing.</p>
  {message}
  <form method="post" action="/signin">
    <input type="hidden" name="next" value="{target}">
    <label for="signin-code">Workspace code</label>
    <input class="field" id="signin-code" name="code" placeholder="Your workspace code" maxlength="60" required>
    <div class="decision"><button class="btn" type="submit">Sign in</button><a class="btn ghost" href="{start_href}">Create a workspace</a></div>
  </form>
  <details class="claim" style="margin-top:18px">
    <summary>Or sign in with an email link</summary>
    <form method="post" action="/v1/auth/magic-link" class="stack-form">
      <input type="hidden" name="next" value="{target}">
      <label for="signin-email">Email address</label>
      <input class="field" id="signin-email" type="email" name="email" maxlength="254" placeholder="you@example.com" required>
      <div class="decision"><button class="btn mini" type="submit">Email me a sign-in link</button></div>
    </form>
  </details>
  <details class="claim">
    <summary>Or use a one-time code</summary>
    <form method="post" action="/v1/auth/otp" class="stack-form">
      <input type="hidden" name="next" value="{target}">
      <label for="otp-email">Email address</label>
      <input class="field" id="otp-email" type="email" name="email" maxlength="254" placeholder="you@example.com" required>
      <div class="decision"><button class="btn mini" type="submit">Email me a code</button></div>
    </form>
  </details>
  <p class="alert">Grant does not use passwords. Your workspace link stays private; email links and codes work once.</p>
</section>
"""
    return page("Sign in — Grant", body, "Sign in to your Grant workspace.", private=True)


def start_page(next_path: str = "") -> str:
    target = html.escape(safe_next_path(next_path) if next_path else "", quote=True)
    body = header() + f"""
<section class="approval glass">
  <span class="eyebrow"><span class="dot"></span> No email required</span>
  <h1>Create your workspace.</h1>
  <p class="lede left">A quiet place to see approvals and permissions. Save the link we show you — it is your key.</p>
  <form method="post" action="/v1/workspaces">
    <input type="hidden" name="next" value="{target}">
    <label for="name">Workspace name</label>
    <input class="field" id="name" name="name" value="My agents" maxlength="80" required>
    <div class="decision"><button class="btn" type="submit">Create workspace</button><a class="btn ghost" href="/signin">I already have one</a></div>
  </form>
  <p class="alert">Use a bookmark or password manager. Grant does not send account email.</p>
</section>
"""
    return page("Create a workspace — Grant", body, "Create a Grant workspace without an email address.", private=True)


def workspace_page(
    workspace_row: sqlite3.Row | None,
    code: str,
    fallback_name: str,
    rows: list[sqlite3.Row],
    perms: list[sqlite3.Row],
    *,
    context: dict[str, Any] | None = None,
    billing_email: str = "",
    claim_token: str = "",
) -> str:
    label = clean(workspace_row["name"] if workspace_row else fallback_name, 80) or "My agents"
    code = clean(workspace_row["code"] if workspace_row else code, 60)
    context = context or plan_context(code)
    request_rows = "".join(
        f"<tr><td class='mono'>{clean(r['id'])}</td><td>{clean(r['agent'])}</td><td>{clean(r['action'])}</td>"
        f"<td><span class='status {'pending' if r['status']=='pending' else 'decided'}'>{clean(r['status'])}</span></td>"
        f"<td>{clean(r['decision'] or '—')}</td></tr>"
        for r in rows
    ) or "<tr><td colspan='5'>No requests yet. Create one from your agent.</td></tr>"
    perm_rows = "".join(
        f"<tr><td>{clean(p['agent'])}</td><td>{clean(p['action'])}</td><td>{clean(p['policy'])}</td><td>{friendly_expiry(p['expires_at'])}</td></tr>"
        for p in perms
    ) or "<tr><td colspan='4'>No standing permissions yet.</td></tr>"
    base = PUBLIC_BASE_URL or "https://grant.yourdomain.com"
    snippet = f'grant = Grant("{base}", workspace="{code}")'
    query = urlencode({"org_id": code, "from": "workspace"})
    billing_form = f"""
<section class="section glass">
  <h2>Billing email <span class="eyebrow">optional</span></h2>
  <p class="sub">Save the Grant account email you'll use at Cashfree. We only use it to match a paid monthly form to this workspace — nothing is shared.</p>
  <form method="post" action="/w/{html.escape(code, quote=True)}/billing-email" class="form-row">
    <input type="email" name="email" maxlength="254" required placeholder="you@example.com" value="{html.escape(billing_email, quote=True)}">
    <button class="btn mini" type="submit">Save</button>
  </form>
  <details class="claim">
    <summary>Paid with a different email? Claim your upgrade.</summary>
    <p class="sub">Enter the email you used at Cashfree, or your Cashfree Payment ID. A verified unclaimed receipt upgrades this workspace instantly.</p>
    <form method="post" action="/w/{html.escape(code, quote=True)}/claim-payment" class="form-row">
      <input name="claim" maxlength="254" required placeholder="Checkout email or Payment ID">
      <button class="btn mini" type="submit">Claim upgrade</button>
    </form>
  </details>
</section>
"""
    account_section = f"""
<section class="section glass">
  <h2>Your account <span class="eyebrow">passwordless</span></h2>
  <p class="sub">Email yourself a one-time sign-in link. This keeps your approvals tied to a real user, not just a bookmark.</p>
  <form method="post" action="/v1/auth/magic-link" class="form-row">
    <input type="hidden" name="org_id" value="{html.escape(code, quote=True)}">
    <input type="hidden" name="claim_token" value="{html.escape(claim_token, quote=True)}">
    <input type="email" name="email" maxlength="254" required placeholder="you@example.com" value="{html.escape(billing_email, quote=True)}">
    <button class="btn mini" type="submit">Send sign-in link</button>
  </form>
</section>
"""
    with closing(db()) as conn:
        key_rows = conn.execute(
            "SELECT * FROM api_keys WHERE org_id = ? ORDER BY created_at DESC LIMIT 20", (code,)
        ).fetchall()
    live_keys = [row for row in key_rows if not row["revoked_at"]]
    key_items = "".join(
        f'<p class="sub"><code>{html.escape(str(row["key_prefix"]), quote=True)}</code> '
        f'{html.escape(str(row["name"]), quote=True)} '
        f'<form method="post" action="/api/keys/{html.escape(str(row["id"]), quote=True)}/revoke" style="display:inline">'
        f'<button class="btn ghost mini" type="submit">Revoke</button></form></p>'
        for row in live_keys
    ) or '<p class="sub">No live API keys yet.</p>'
    api_keys_section = f"""
<section class="section glass">
  <h2>API keys <span class="eyebrow">gr_live_…</span></h2>
  <p class="sub">Mint a real key for programmatic agents. The raw key is shown once; Grant stores only its SHA-256 hash. An email sign-in is required.</p>
  <form method="post" action="/api/keys" class="form-row">
    <input type="text" name="name" maxlength="60" placeholder="Key name (e.g. production agent)">
    <button class="btn mini" type="submit">Get Your Free API Key →</button>
  </form>
  {key_items}
</section>
"""
    body = header() + f"""
<section class="section glass">
  <span class="eyebrow"><span class="dot"></span> Workspace</span>
  <h1>{label}</h1>
  <p class="sub">Bookmark this page. No login required, no noise.</p>
  {usage_meter_html(context)}
  {plan_banners_html(context, rows)}
  <div class="grid">
    <div class="tile"><div class="num">{len(rows)}</div><h3>Requests</h3><p>Approval links created for this workspace.</p></div>
    <div class="tile"><div class="num">{sum(1 for r in rows if r['status']=='pending')}</div><h3>Pending</h3><p>Waiting for a human decision.</p></div>
    <div class="tile"><div class="num">{len(perms)}</div><h3>Permissions</h3><p>Signed allowances in force.</p></div>
  </div>
</section>
<section class="section glass">
  <h2>Install snippet</h2>
  <pre><code>{html.escape(snippet)}</code></pre>
  <div class="actions"><button class="btn ghost mini" type="button" onclick="copyText({js_literal(snippet)})">Copy snippet</button><a class="btn ghost mini" href="/protected/{code}">Protected by Grant</a><a class="btn ghost mini" href="/pricing?{query}">Guardrails & plans</a></div>
</section>
{account_section}
{api_keys_section}
{billing_form}
<section class="section glass"><h2>Requests</h2><table class="table"><thead><tr><th>ID</th><th>Agent</th><th>Action</th><th>Status</th><th>Decision</th></tr></thead><tbody>{request_rows}</tbody></table></section>
<section class="section glass"><h2>Standing permissions</h2><table class="table"><thead><tr><th>Agent</th><th>Action</th><th>Policy</th><th>Expires</th></tr></thead><tbody>{perm_rows}</tbody></table></section>
"""
    return page(f"{label} — Grant workspace", body, "Your Grant approvals and permissions.", private=True)


DOCS_TEMPLATE = """
<section class="hero glass"><span class="eyebrow"><span class="dot"></span> Documentation</span><h1>One request.<br><em>One decision.</em></h1>
<p class="lede">Grant is a consent layer. Your agent asks, a human taps a link, and your agent receives a signed permission. It appears inside the agent’s normal message — not as a separate app people must remember.</p></section>
<section class="section glass"><h2>Install</h2>
<pre><code>pip install grant-consent
grantctl doctor --url __GRANT_BASE__</code></pre>
<p class="sub">The Python package and CLI use only the standard library. The hosted service provides the approval page and signed permission ledger.</p></section>
<section class="section glass"><h2>Python</h2>
<pre><code>from grant import Grant

grant = Grant("__GRANT_BASE__", workspace="support")
ask = grant.request(
    agent="support-agent",
    action="refund_order",
    summary="Refund order ord_42 for $48.00",
    scope={"order_id": "ord_42", "amount": 48},
    ttl_minutes=30,
)

print(ask.message)              # put this in the agent's normal reply/tool output
permission = grant.wait(ask.id, timeout=300)
print(permission.policy)        # once / always
print(permission.signature)     # signed by Grant</code></pre></section>
<section class="section glass"><h2>HTTP</h2>
<pre><code>POST /v1/requests
{
  "agent": "support-agent",
  "action": "refund_order",
  "summary": "Refund order ord_42",
  "scope": {"order_id": "ord_42", "amount": 48},
  "workspace": "support",
  "ttl_minutes": 30
}</code></pre>
<p class="sub">Response includes <span class="mono">id</span>, <span class="mono">approval_url</span>, <span class="mono">expires_at</span>, and a ready-to-send <span class="mono">message</span>.</p></section>
<section class="section glass"><h2>CLI</h2>
<pre><code>grantctl request --agent support-agent --action refund_order \\
  --summary "Refund ord_42" --scope '{"order_id":"ord_42"}' \\
  --url __GRANT_BASE__
grantctl status req_abc123 --url __GRANT_BASE__
grantctl permissions support-agent --url __GRANT_BASE__</code></pre></section>
<section class="section glass"><h2>Verify a permission</h2>
<pre><code>POST /v1/permissions/verify
{"id": "perm_abc123", "signature": "..."}</code></pre>
<p class="sub">Grant returns whether the signature is valid plus the allowed action, policy, scope hash, and expiry.</p></section>
<section class="section glass"><h2>Zero-code gateway</h2>
<pre><code>grantctl gateway \\
  --name "Payments API" \\
  --upstream https://api.example.com \\
  --paths "/transfer,/payment,/refund" \\
  --body-keys "amount,recipient" \\
  --url __GRANT_BASE__</code></pre>
<p class="sub">Point an HTTP or MCP client at the returned gateway URL. Sensitive calls pause for approval; routine calls pass through. Local agents can use <span class="mono">grantctl proxy --upstream ... --open</span>.</p></section>
<section class="section glass"><h2>Pop-up triggers</h2>
<p class="sub">The approval card stays pure and fast. Choose the trigger that matches where your agent runs.</p>
<div class="grid">
<div class="tile"><h3>OAuth-style window</h3><p>Open the approval URL in a 460×640 window. Grant sends a <span class="mono">postMessage</span> decision and closes itself on approve or reject.</p></div>
<div class="tile"><h3>Shadow-DOM widget</h3><p>Load <span class="mono">/widget.js</span> with <span class="mono">data-approval-url</span>. Styling is isolated from the host page.</p></div>
<div class="tile"><h3>Mobile deep link</h3><p>Send the same URL in Slack or email. On phones it renders as a compact card; add <span class="mono">?compact=1</span> for a forced compact view.</p></div>
</div>
<pre><code>&lt;script async src="__GRANT_BASE__/widget.js"
  data-approval-url="__GRANT_BASE__/a/••••••••••••"
  data-label="Review approval"&gt;&lt;/script&gt;</code></pre>
</section>
<section class="section glass"><h2>Design principles</h2><div class="grid">
<div class="tile"><h3>No email required</h3><p>Approval links are capabilities. Workspaces are bookmarks.</p></div>
<div class="tile"><h3>No secrets stored</h3><p>Secret-like scope values are redacted before the approval page is rendered.</p></div>
<div class="tile"><h3>No money inside</h3><p>Payments happen externally. Grant only manages permission.</p></div>
</div></section>
<section class="section glass"><h2>Endpoints</h2>
<pre><code>POST /v1/requests              create an approval request
GET  /v1/requests/{id}         read status and signed permission
GET  /v1/permissions/{agent}   list active permissions
POST /v1/permissions/verify    verify a signed permission
POST /v1/gateways              register an MCP/HTTP gateway
POST /g/mcp/{token}            approval-gated MCP JSON-RPC proxy
ANY  /g/http/{token}/{path}    approval-gated HTTP proxy
GET  /pricing                  four public plan tiers
GET  /signin                   open a workspace before checkout
GET  /console                  developer usage dashboard
GET  /widget.js                Shadow-DOM launcher script
GET  /v1/checkout/{plan}        redirect to a fixed Cashfree monthly form
POST /v1/billing/webhook        signed Grant/Cashfree plan-flag flip
GET  /v1/billing/renewal-reminders  day-27 reminder runner (scheduler only)
GET  /stats.json               aggregate usage only
GET  /health/live              process check
GET  /health/ready             database + signing check</code></pre></section>
"""


def docs_page() -> str:
    base = PUBLIC_BASE_URL or "https://grant.yourdomain.com"
    body = header() + DOCS_TEMPLATE.replace("__GRANT_BASE__", base)
    return page("Grant documentation", body, "Install and use Grant in any AI agent.")


def pricing_feature(item: str) -> str:
    """Do not advertise delivery channels Grant cannot actually send today."""
    text = str(item or "")
    if SMS_PROVIDER_CONFIGURED:
        return text
    if "sms" in text.lower() or "whatsapp" in text.lower():
        return f"{text} — coming soon"
    return text


def pricing_page(org_id: str = "") -> str:
    org = safe_org_id(org_id)
    workspace_ready = bool(org and get_workspace(org))
    checkout_note = (
        '<p class="checkout-note">Use your Grant account email '
        '(user@email.com) at checkout for instant activation.</p>'
    )
    sms_note = (
        ""
        if SMS_PROVIDER_CONFIGURED
        else '<p class="sub">SMS and WhatsApp approval alerts are Pro-tier features that are still '
        'being connected; they are marked “coming soon” until a provider is configured.</p>'
    )

    def checkout_href(plan_id: str) -> str:
        if workspace_ready:
            return "/v1/checkout/{}?{}".format(
                plan_id, urlencode({"org_id": org, "cycle": "monthly"})
            )
        return "/signin?{}".format(
            urlencode({"next": f"/pricing?plan={plan_id}&cycle=monthly"})
        )

    cards: list[str] = []
    for row in plans.public_pricing():
        plan_id = row["id"]
        badge = f'<span class="badge">{clean(row["badge"])}</span>' if row["badge"] else ""
        featured = " featured" if plan_id == "plus" else ""
        if plan_id == "free":
            price = '<span class="price">Free</span><span class="alt">14-day Pro Guardrails trial included</span>'
            cta = '<a class="btn ghost" href="/start">Start free</a>'
        elif plan_id == "enterprise":
            price = f'<span class="price">${row["monthly_usd"]:,}/mo</span><span class="alt">₹{row["monthly_inr"]:,}/mo · custom terms</span>'
            cta = f'<a class="btn" href="{checkout_href("enterprise")}">Book a call</a>'
        else:
            monthly_usd = f"${row['monthly_usd']}/mo"
            annual_usd = f"${row['annual_usd']:,.2f}/yr"
            monthly_inr = f"₹{row['monthly_inr']:,}/mo"
            annual_inr = f"₹{row['annual_inr']:,.2f}/yr"
            price = (
                f'<span class="price" data-grant-price data-monthly="{monthly_usd}" data-annual="{annual_usd}">{monthly_usd}</span>'
                f'<span class="alt" data-grant-price data-monthly="{monthly_inr}" data-annual="{annual_inr}">{monthly_inr}</span>'
            )
            cta = (
                f'<a class="btn" data-grant-checkout href="{checkout_href(plan_id)}">'
                f'Upgrade to {clean(row["name"])}</a>{checkout_note}'
            )
        items = "".join(f"<li>{clean(pricing_feature(item))}</li>" for item in row["features"])
        cards.append(
            f'<section class="tier{featured}">{badge}<h3>{clean(row["name"])}</h3>'
            f'<p class="position">{clean(row["positioning"])}</p>{price}'
            f'<ul>{items}</ul>{cta}</section>'
        )

    body = header() + f"""
<section class="hero glass">
  <span class="eyebrow"><span class="dot"></span> Pricing</span>
  <h1>Insurance for the moment<br><em>an agent acts.</em></h1>
  <p class="lede">Every plan starts with a 14-day Pro Guardrails trial. No card to try it. Paid plans use secure Cashfree-hosted payment links — Grant never touches money.</p>
  {sms_note}
</section>
<section class="section glass" style="text-align:center">
  <div class="toggle" role="group" aria-label="Billing cycle">
    <button type="button" data-grant-cycle-button="monthly" aria-pressed="true" onclick="grantSetCycle('monthly')">Monthly</button>
    <button type="button" data-grant-cycle-button="annual" aria-pressed="false" onclick="grantSetCycle('annual')">Annual <span class="lock">Save 20%</span></button>
  </div>
  <div class="tier-grid">{''.join(cards)}</div>
  <p class="sub" style="margin-top:20px">Annual prices are shown for comparison only; hosted checkout is monthly-only today. Enterprise is a contact CTA, not a payment link.</p>
</section>
<section class="section glass">
  <h2>Manual concierge upgrade</h2>
  <p class="sub">Validating paid guardrails before provider automation? Enter a workspace code and we will create a Cashfree-hosted payment link. No email is required.</p>
  <form method="get" action="/v1/checkout/concierge">
    <label for="concierge-org">Workspace code</label>
    <input class="field" id="concierge-org" name="org_id" value="{clean(org, 60)}" placeholder="ws_..." maxlength="60" required>
    <div class="decision"><button class="btn" type="submit">Request payment link</button></div>
  </form>
</section>
"""
    return page(
        "Pricing — Grant",
        body,
        "Grant plans for production safety, team compliance, and platform governance — Free, Plus $20/mo, Pro $150/mo, Enterprise $4,000/mo.",
    )


def console_index_page() -> str:
    body = header() + """
<section class="approval glass">
  <span class="eyebrow"><span class="dot"></span> Developer console</span>
  <h1>Open your approval dashboard.</h1>
  <p class="lede left">Your workspace code is the key. Paste it below to see the usage meter, trial status, and every agent you have authorized.</p>
  <form method="get" action="/console">
    <label for="code">Workspace code</label>
    <input class="field" id="code" name="code" placeholder="ws_..." maxlength="60" required>
    <div class="decision"><button class="btn" type="submit">Open console</button><a class="btn ghost" href="/start">Create a workspace</a></div>
  </form>
  <p class="alert">No account, no email, no analytics cookies. Just a capability-scoped view of your own approvals.</p>
</section>
"""
    return page("Developer console — Grant", body, "Open your Grant usage and approval dashboard.", private=True)


def protected_page(code: str, workspace_row: sqlite3.Row | None, perms: list[sqlite3.Row]) -> str:
    label = clean(workspace_row["name"] if workspace_row else "My agents", 80) or "My agents"
    safe_code = clean(code, 60)
    rows = "".join(
        f"<tr><td>{clean(p['agent'])}</td><td>{clean(p['action'])}</td>"
        f"<td>{clean(p['policy'])}</td><td>{friendly_expiry(p['expires_at'])}</td></tr>"
        for p in perms
    ) or "<tr><td colspan='4'>No active permissions yet.</td></tr>"
    query = urlencode({"org_id": safe_code, "from": "protected"})
    body = header() + f"""
<section class="section glass">
  <span class="eyebrow"><span class="dot"></span> Protected by Grant</span>
  <h1>{label}</h1>
  <p class="sub">These agents have explicit, signed permission from this workspace. No credentials or raw payloads are shown.</p>
  <table class="table"><thead><tr><th>Agent</th><th>Action</th><th>Policy</th><th>Expires</th></tr></thead><tbody>{rows}</tbody></table>
  <div class="grid" style="margin-top:20px">
    <div class="tile"><div class="num">{len(perms)}</div><h3>Active authorizations</h3><p>Each one came from a human decision.</p></div>
    <div class="tile"><h3>Deploying your own agents?</h3><p>Enforce conditional rules, team routing, and audit retention before agents touch money or data.</p><div class="actions"><a class="btn mini" href="/pricing?{query}">See Guardrails</a></div></div>
  </div>
</section>
"""
    return page("Protected by Grant", body, "Agents authorized through Grant for this workspace.", private=True)


OPS_PAGE_SCRIPT = """
<script>
(function(){
  var key = 'grant-ops-token';
  var params = new URLSearchParams(location.search);
  var hashParams = new URLSearchParams(location.hash.replace(/^#/, ''));
  if(hashParams.has('token')){
    sessionStorage.setItem(key, hashParams.get('token'));
    history.replaceState({}, '', location.pathname);
  }else if(params.has('token')){
    sessionStorage.setItem(key, params.get('token'));
    history.replaceState({}, '', location.pathname);
  }
  var token = sessionStorage.getItem(key) || '';
  var dot = document.getElementById('ops-dot');
  var stamp = document.getElementById('ops-stamp');
  var error = document.getElementById('ops-error');
  function render(body){
    Object.keys(body).forEach(function(id){
      var node = document.getElementById('ops-' + id);
      if(node && typeof body[id] === 'number'){node.textContent = body[id].toLocaleString();}
    });
    function list(id, entries, field){
      var node = document.getElementById(id);
      if(!node || !Array.isArray(entries)){return;}
      node.textContent = '';
      if(!entries.length){var empty = document.createElement('li');empty.textContent='No events yet.';node.appendChild(empty);}
      entries.forEach(function(item){
        var row = document.createElement('li');
        row.textContent = (item.device || 'Unknown device') + ' · ' + (item[field] || '');
        node.appendChild(row);
      });
    }
    list('ops-recent-logins', body.recent_logins, 'created_at');
    list('ops-device-breakdown', body.device_breakdown, 'count');
    if(stamp){stamp.textContent = new Date(body.generated_at).toLocaleTimeString();}
    if(dot){dot.classList.remove('error');}
    if(error){error.hidden = true;}
  }
  function load(){
    if(!token){if(error){error.hidden=false;error.textContent='Add ?token= once to store this view.';}return;}
    fetch('/ops.json', {headers:{'X-Grant-Ops-Token': token}, cache:'no-store'})
      .then(function(response){if(!response.ok){throw new Error('unauthorized');}return response.json();})
      .then(render)
      .catch(function(){if(dot){dot.classList.add('error');}if(error){error.hidden=false;error.textContent='Feed paused. Check the ops token.';}});
  }
  load();
  setInterval(function(){if(document.visibilityState === 'visible'){load();}}, 15000);
  document.addEventListener('visibilitychange', function(){if(document.visibilityState === 'visible'){load();}});
})();
</script>
"""


def ops_page() -> str:
    body = header() + """
<section class="section glass">
  <span class="eyebrow"><span class="dot"></span> Grant operations</span>
  <h1>User count, live.</h1>
  <p class="sub"><span class="live-dot" id="ops-dot"></span> Aggregate counts only · updates every 15 seconds · <span id="ops-stamp">connecting…</span> · <a href="/login-history">Login history</a></p>
  <p class="banner warn" id="ops-error" hidden></p>
  <div class="op-grid">
    <div class="op-card"><div class="num" id="ops-workspaces">—</div><div class="label">Workspaces</div></div>
    <div class="op-card"><div class="num" id="ops-total_users">—</div><div class="label">Total users</div></div>
    <div class="op-card"><div class="num" id="ops-unique_humans_reached">—</div><div class="label">Unique humans reached</div></div>
    <div class="op-card"><div class="num" id="ops-popup_impressions">—</div><div class="label">Pop-up triggers</div></div>
    <div class="op-card"><div class="num" id="ops-unique_devices">—</div><div class="label">Unique computers</div></div>
    <div class="op-card"><div class="num" id="ops-active_sessions">—</div><div class="label">Active sessions (24h)</div></div>
    <div class="op-card"><div class="num" id="ops-organizations">—</div><div class="label">Organizations</div></div>
    <div class="op-card"><div class="num" id="ops-requests">—</div><div class="label">Approval requests</div></div>
    <div class="op-card"><div class="num" id="ops-approved">—</div><div class="label">Approvals recorded</div></div>
    <div class="op-card"><div class="num" id="ops-paid">—</div><div class="label">Paid organizations</div></div>
    <div class="op-card"><div class="num" id="ops-trials">—</div><div class="label">Active trials</div></div>
  </div>
  <div class="op-grid" style="margin-top:14px">
    <div class="op-card"><div class="label">Recent logins</div><ul id="ops-recent-logins" class="device-list"><li>connecting…</li></ul></div>
    <div class="op-card"><div class="label">Device breakdown</div><ul id="ops-device-breakdown" class="device-list"><li>connecting…</li></ul></div>
  </div>
  <p class="alert">This view is token-gated and contains no emails, IDs, keys, or payloads. Devices are salted hashes and coarse browser/OS labels.</p>
</section>
""" + OPS_PAGE_SCRIPT
    return page("Grant operations", body, "Token-gated aggregate operations view for Grant.", private=True)


LOGIN_HISTORY_STYLE = """
<style>
.event-table{width:100%;border-collapse:collapse;margin-top:12px;font-size:.9rem}
.event-table th,.event-table td{text-align:left;padding:9px 10px;border-bottom:1px solid rgba(109,32,56,.12)}
.event-table th{text-transform:uppercase;letter-spacing:.08em;font-size:.68rem;color:var(--muted)}
.event-table td{color:var(--ink)}
</style>
"""

LOGIN_HISTORY_STRIP_SCRIPT = """
<script>
(function(){
  var params = new URLSearchParams(location.search);
  if(params.has('token')){
    params.delete('token');
    history.replaceState({}, '', location.pathname + (params.toString() ? '?' + params.toString() : ''));
  }
})();
</script>
"""


def login_history_page() -> str:
    """Dedicated, token-gated login and pop-up history space."""
    data = login_library.report()
    cards = (
        ("total_users", "Users"),
        ("total_logins", "Logins"),
        ("popup_impressions", "Pop-ups shown"),
        ("unique_computers", "Computers"),
        ("unique_humans_reached", "Humans reached"),
        ("decided_popups", "Decided pop-ups"),
        ("active_sessions", "Active sessions (24h)"),
    )
    card_html = "".join(
        f'<div class="op-card"><div class="num">{int(data[key])}</div>'
        f'<div class="label">{label}</div></div>'
        for key, label in cards
    )
    login_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            clean(row["created_at"], 40),
            clean(row["source"], 40),
            clean(row["device"], 80),
        )
        for row in data["login_history"]
    ) or '<tr><td colspan="3">No logins recorded yet.</td></tr>'
    popup_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            clean(row["opened_at"], 40),
            clean(row["channel"], 40),
            clean(row["device"], 80),
            clean(row["decision"], 20),
        )
        for row in data["popup_history"]
    ) or '<tr><td colspan="4">No pop-ups recorded yet.</td></tr>'
    device_rows = "".join(
        f"<li>{clean(row['device'], 80)} — {int(row['count'])}</li>" for row in data["devices"]
    ) or "<li>No devices recorded yet.</li>"
    body = header() + LOGIN_HISTORY_STYLE + f"""
<section class="section glass">
  <span class="eyebrow"><span class="dot"></span> Grant · login history</span>
  <h1>Who reached Grant, live.</h1>
  <p class="sub">Aggregate counts and coarse device labels · generated {clean(data['generated_at'], 40)} · <a href="/ops">operations</a></p>
  <p class="banner warn">Add <code>?token=…</code> once to open this private view. The token is removed from the address bar on load.</p>
  <div class="op-grid">{card_html}</div>
  <h2 style="margin-top:22px">Login events</h2>
  <table class="event-table"><thead><tr><th>When</th><th>Source</th><th>Device</th></tr></thead><tbody>{login_rows}</tbody></table>
  <h2 style="margin-top:22px">Pop-up events</h2>
  <table class="event-table"><thead><tr><th>When</th><th>Channel</th><th>Device</th><th>Decision</th></tr></thead><tbody>{popup_rows}</tbody></table>
  <h2 style="margin-top:22px">Computers</h2>
  <ul class="device-list">{device_rows}</ul>
  <p class="alert">No emails, IPs, device IDs, workspace codes, or approval tokens are stored in this view. Values are salted hashes and coarse browser/OS labels.</p>
</section>
""" + LOGIN_HISTORY_STRIP_SCRIPT
    return page("Login history", body, "Token-gated login and pop-up history for Grant.", private=True)


SIGNUP_SCRIPT = """
<script>
(function(){
  var stored = false;
  try{stored = localStorage.getItem('grant-shortcut-added') === '1';}catch(error){}
  if(stored){
    document.querySelectorAll('[data-grant-install-enable]').forEach(function(node){node.disabled = false;});
    var status = document.getElementById('grant-install-status');
    if(status){status.textContent = 'Shortcut added. Continue to your account.';}
  }
})();
</script>
"""


def checkpoint_page(row: Any) -> str:
    """Pop-Up 1: the quiet Continue / Always allow / Cancel checkpoint."""
    request_id = clean(str(row["id"] or ""), 120)
    agent = clean(row["agent"], 120)
    tool = clean(row["action"], 120)
    scope_hash = clean(row["scope_hash"], 64)
    expires = friendly_expiry(row["expires_at"])
    body = header() + f"""
<section class="checkpoint glass">
  <span class="eyebrow"><span class="dot"></span> Grant checkpoint</span>
  <h1>Let {tool} continue?</h1>
  <p class="lede left">{agent} is asking for one scoped action. Grant records the decision; it never sees credentials or payment details.</p>
  <dl class="kv">
    <dt>Agent</dt><dd>{agent}</dd>
    <dt>Action</dt><dd>{tool}</dd>
    <dt>Scope fingerprint</dt><dd class="scope-fingerprint">{scope_hash}</dd>
    <dt>Window</dt><dd>{expires}</dd>
  </dl>
  <form method="post" action="/approve/{request_id}/decide" class="checkpoint-actions">
    <button class="btn" name="decision" value="approve" type="submit">Continue</button>
    <button class="btn ghost" name="decision" value="always" type="submit">Always allow</button>
  </form>
  <form method="post" action="/approve/{request_id}/decide">
    <button class="cancel-link" name="decision" value="reject" type="submit">Cancel</button>
  </form>
  <p class="zero-note">Grant never sees your credentials or payment details. It only records what you allowed.</p>
  <p class="watermark">● Protected by Grant · Zero-custody consent infrastructure</p>
</section>
"""
    return page(
        "Grant checkpoint", body, "A quiet, one-tap human checkpoint for an AI agent action.", private=True
    )


def signup_page(next_path: str = "/account", error: bool = False) -> str:
    """Pop-Up 2: sign-up requires adding the Grant shortcut before continuing."""
    target = clean(safe_next_path(next_path or "/account"), 200)
    message = (
        '<p class="banner warn">Add the Grant shortcut first. This step is required so your next checkpoint is one tap away.</p>'
        if error
        else ""
    )
    body = header() + f"""
<section class="intro glass">
  <span class="eyebrow"><span class="dot"></span> Welcome to Grant</span>
  <h1>Keep the checkpoint<br><em>one tap away.</em></h1>
  <p class="lede left">Grant gives your agents a human decision without ever holding credentials or money. Three quiet steps, then you are in.</p>
  {message}
  <div class="intro-step"><span class="step-num">01</span> <strong>Save your account.</strong> Use an email link or a one-time code. No passwords, no card needed.</div>
  <div class="intro-step">
    <span class="step-num">02</span> <strong>Add Shortcut.</strong> Install Grant as an app so the next approval opens like a native window.
    <div class="install-card">
      <button class="btn" type="button" data-grant-install data-grant-install-stay="1">Add Shortcut</button>
      <p class="sub" id="grant-install-status">Required before continuing.</p>
      <ol><li>Use your browser's Add to Home Screen / Install app action if a prompt does not appear.</li><li>Return here and continue.</li></ol>
    </div>
  </div>
  <div class="intro-step"><span class="step-num">03</span> <strong>Open your account.</strong> Plan, usage, rules, receipts, and keys live in one standalone space.</div>
  <form method="post" action="/signup" class="stack-form">
    <input type="hidden" name="installed" value="1">
    <input type="hidden" name="next" value="{target}">
    <label for="signup-email">Email address</label>
    <input class="field" id="signup-email" type="email" name="email" maxlength="254" placeholder="you@example.com">
    <div class="decision"><button class="btn" type="submit" data-grant-install-enable disabled>Continue to account</button></div>
  </form>
  <details class="claim" style="margin-top:16px">
    <summary>Prefer a one-time code?</summary>
    <form method="post" action="/v1/auth/otp" class="form-row">
      <input type="hidden" name="next" value="{target}">
      <input type="email" name="email" maxlength="254" placeholder="you@example.com" required>
      <button class="btn mini" type="submit">Email me a code</button>
    </form>
  </details>
  <p class="watermark">● Protected by Grant · Zero-custody consent infrastructure</p>
</section>
""" + SIGNUP_SCRIPT
    return page("Set up Grant", body, "Create your Grant account and add the standalone shortcut.", private=True)


def receipt_page(row: Any, verified: bool, payload: dict[str, Any] | None) -> str:
    """Public, signed Magic Receipt: no raw scope values, no PII, no secrets."""
    payload = payload or {}
    request_id = clean(payload.get("request_id") or row["id"], 120)
    status = clean(payload.get("status") or row["status"], 20)
    decision_type = clean(payload.get("decision_type") or row["decision"] or "recorded", 40)
    agent = clean(payload.get("agent_name") or row["agent"], 120)
    tool = clean(payload.get("tool_name") or row["action"], 120)
    scope_hash = clean(payload.get("scope_hash") or row["scope_hash"], 64)
    permission_id = clean(payload.get("permission_id") or "", 120) or "—"
    decided_at = clean(payload.get("decided_at") or row["decision_at"] or "", 40) or "recorded"
    receipt = str(row["signed_receipt"] or "") if "signed_receipt" in (row.keys() if hasattr(row, "keys") else row) else ""
    seal = "✓" if status == "approved" else "×"
    badge = "badge ok" if verified else "badge"
    proof = clean(receipt[:160] + ("…" if len(receipt) > 160 else ""), 200) or "Legacy receipt · signature verified from permission ledger"
    body = header() + f"""
<section class="receipt-cert glass">
  <span class="eyebrow"><span class="dot"></span> Magic Receipt</span>
  <div class="seal">{seal}</div>
  <h1>{status.title()} · {decision_type.replace('_', ' ').title()}</h1>
  <p class="lede left">Grant recorded this decision with an HMAC-SHA256 receipt. It holds no credentials, no payment details, and no raw scope values.</p>
  <p class="badge-row"><span class="{badge}">{'Signature verified' if verified else 'Signature unavailable'}</span><span class="eyebrow">Zero custody</span></p>
  <dl class="kv">
    <dt>Request</dt><dd class="mono">{request_id}</dd>
    <dt>Agent</dt><dd>{agent}</dd>
    <dt>Action</dt><dd>{tool}</dd>
    <dt>Scope fingerprint</dt><dd class="scope-fingerprint">{scope_hash}</dd>
    <dt>Permission</dt><dd class="mono">{permission_id}</dd>
    <dt>Recorded</dt><dd>{decided_at}</dd>
  </dl>
  <p class="sub">Receipt proof: <code class="scope-fingerprint">{proof}</code></p>
  <div class="receipt-cta">
    <p>Want every AI agent you have authorized in one quiet place?</p>
    <a class="btn" href="/account">Open Your Grant Account →</a>
    <a class="btn ghost" href="/start?from=receipt">Get Your Free API Key →</a>
  </div>
  <p class="watermark">● Protected by Grant · Zero-custody consent infrastructure</p>
</section>
"""
    return page("Grant receipt", body, "A signed, privacy-preserving receipt for one agent decision.", private=True)


def mcp_setup_page() -> str:
    base = PUBLIC_BASE_URL or "https://grant-approve.vercel.app"
    snippet = (
        "curl " + base + "/api/mcp \\\n"
        '  -H "Authorization: Bearer gr_live_..." \\\n'
        '  -H "Content-Type: application/json" \\\n'
        "  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}'"
    )
    body = header() + f"""
<section class="section glass">
  <span class="eyebrow"><span class="dot"></span> Grant MCP</span>
  <h1>One endpoint. No wrapper.</h1>
  <p class="sub">Point any MCP client at <code>{html.escape(base, quote=True)}/api/mcp</code>. Send JSON-RPC over POST with a <code>gr_live_</code> Bearer key, or use the 20-per-hour demo mode without a key.</p>
  <pre><code>{html.escape(snippet, quote=True)}</code></pre>
  <p class="sub">Methods: <code>initialize</code>, <code>tools/list</code>, <code>tools/call</code>. The machine-readable contract lives at <a href="/openapi.json">/openapi.json</a>.</p>
</section>
"""
    return page("Grant MCP setup", body, "Connect an MCP client directly to Grant.", private=True)


def account_page(
    http_request: Request,
    principal: dict[str, Any] | None,
    *,
    raw_key: str = "",
    claim: str = "",
) -> str:
    """The standalone /account app: plan, controls, history, and integrations."""
    user: dict[str, Any] | None = None
    org = str(principal.get("org_id") or "") if principal else ""
    context: dict[str, Any] | None = None
    rules: list[Any] = []
    keys: list[Any] = []
    audit: list[Any] = []
    if principal:
        with closing(db()) as conn:
            user_row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (principal.get("user_id") or "",)
            ).fetchone()
            user = dict(user_row) if user_row else None
            rules = conn.execute(
                "SELECT * FROM auto_approve_rules WHERE org_id = ? OR user_id = ? "
                "ORDER BY created_at DESC LIMIT 30",
                (org, principal.get("user_id") or ""),
            ).fetchall()
            keys = conn.execute(
                "SELECT * FROM api_keys WHERE org_id = ? ORDER BY created_at DESC LIMIT 30", (org,)
            ).fetchall()
            audit = conn.execute(
                "SELECT * FROM approval_requests WHERE org_id = ? OR owner_user_id = ? "
                "ORDER BY created_at DESC LIMIT 30",
                (org, principal.get("user_id") or ""),
            ).fetchall()
        context = plan_context(org)
    history = login_library.report(limit=10)
    base = PUBLIC_BASE_URL or str(http_request.base_url).rstrip("/")
    profile_value = emailer.mask_email(str(user["email"] or "")) if user and user.get("email") else "Not signed in"
    account_state = "Connected" if principal else "Sign in required"
    tier_value = plans.effective_tier(context["plan"]) if context else "free"
    usage_html = usage_meter_html(context) if context else '<div class="meter"><span class="label">Sign in to see your monthly usage.</span></div>'
    cashfree_plus = cashfree.MONTHLY_FORM_URLS["plus"]
    cashfree_pro = cashfree.MONTHLY_FORM_URLS["pro"]
    enterprise = billing.enterprise_contact_url(org) or "/pricing#enterprise"
    rule_rows = []
    for row in rules:
        rule_id = clean(row["id"], 120)
        cap = row_value(row, "max_amount", None)
        cap_label = f"${float(cap):,.2f}" if cap is not None else "No spend cap"
        condition = str(row_value(row, "condition_json", "") or "")
        scope_label = clean(condition[:80] or "Any scoped action", 100)
        rule_rows.append(
            f'<div class="kill-row"><div><strong>{clean(row["agent"], 80)} → {clean(row["action"], 80)}</strong>'
            f'<div class="sub">{scope_label} · {cap_label}</div></div><div class="actions">'
            f'<form method="post" action="/account/rules/{rule_id}/cap" class="form-row">'
            f'<input type="number" name="max_amount" min="0" step="0.01" value="{html.escape(str(cap or ""), quote=True)}" placeholder="Spend cap" aria-label="Spend cap">'
            f'<button class="btn ghost mini" type="submit">Save cap</button></form>'
            f'<form method="post" action="/account/rules/{rule_id}/revoke">'
            f'<button class="btn ghost mini" type="submit">Kill switch</button></form></div></div>'
        )
    rule_html = "".join(rule_rows) or '<p class="sub">No auto-approve rules yet. Rules created from an approval are listed here.</p>'
    key_rows = "".join(
        f'<p class="sub"><code>{clean(row["key_prefix"])}</code> {clean(row["name"], 60)} '
        f'<form method="post" action="/api/keys/{clean(row["id"], 120)}/revoke" style="display:inline">'
        f'<button class="btn ghost mini" type="submit">Revoke</button></form></p>'
        for row in keys
        if not row["revoked_at"]
    ) or '<p class="sub">No live API keys yet.</p>'
    audit_rows = "".join(
        f'<tr><td class="mono">{clean(row["id"])}</td><td>{clean(row_value(row, "agent_name", row["agent"]), 80)}</td>'
        f'<td>{clean(row_value(row, "tool_name", row["action"]), 80)}</td><td>{clean(row["status"], 20)}</td>'
        f'<td>{clean(row["decision"] or "—", 20)}</td></tr>'
        for row in audit
    ) or '<tr><td colspan="5">No approvals recorded yet.</td></tr>'
    login_rows = "".join(
        f'<tr><td>{clean(item["created_at"], 40)}</td><td>{clean(item["source"], 30)}</td><td>{clean(item["device"], 60)}</td></tr>'
        for item in history["login_history"]
    ) or '<tr><td colspan="3">No logins recorded yet.</td></tr>'
    popup_rows = "".join(
        f'<tr><td>{clean(item["opened_at"], 40)}</td><td>{clean(item["channel"], 30)}</td>'
        f'<td>{clean(item["device"], 60)}</td><td>{clean(item["decision"], 20)}</td></tr>'
        for item in history["popup_history"]
    ) or '<tr><td colspan="4">No pop-ups recorded yet.</td></tr>'
    new_key_html = (
        f'<div class="key-once"><strong>Save this key now.</strong><br><code>{html.escape(raw_key, quote=True)}</code></div>'
        if raw_key
        else ""
    )
    claim_note = (
        '<p class="banner">Payment claimed and plan activated.</p>' if claim == "ok" else
        ('<p class="banner warn">No unclaimed payment matched that email or payment ID.</p>' if claim == "missing" else "")
    )
    signin_form = "" if principal else """
<section class="section glass">
  <h2>Sign in to see your private account</h2>
  <p class="sub">Use a magic link or one-time code. Grant does not use passwords.</p>
  <form method="post" action="/v1/auth/magic-link" class="form-row">
    <input type="hidden" name="next" value="/account">
    <input type="email" name="email" maxlength="254" placeholder="you@example.com" required>
    <button class="btn mini" type="submit">Send sign-in link</button>
  </form>
  <form method="post" action="/v1/auth/otp" class="form-row">
    <input type="hidden" name="next" value="/account">
    <input type="email" name="email" maxlength="254" placeholder="you@example.com" required>
    <button class="btn ghost mini" type="submit">Email a code</button>
  </form>
</section>
"""
    body = header() + f"""
<section class="account-app">
  <span class="eyebrow"><span class="dot"></span> Grant account · {clean(account_state, 30)}</span>
  <h1>Your quiet control room.</h1>
  <p class="sub">Profile, plan, rules, receipts, and integrations. No credential custody. No clutter.</p>
  {signin_form}
  {claim_note}
  {new_key_html}
  <div class="account-grid">
    <section class="section glass"><h2>Profile & plan</h2>
      <dl class="kv"><dt>Account</dt><dd>{clean(profile_value, 100)}</dd>
      <dt>Workspace</dt><dd class="mono">{clean(org or '—', 60)}</dd>
      <dt>Plan</dt><dd>{clean(tier_value, 20)}</dd>
      <dt>Trial</dt><dd>{int(context['usage']['trial_days_left']) if context else 0} days left</dd></dl>
      {usage_html}
      <p class="sub">Monthly approvals reset automatically. Exceeding the plan limit returns a hard 402.</p>
    </section>
    <section class="section glass"><h2>Cashfree checkout</h2>
      <p class="sub">Hosted monthly forms only. Grant never handles payment details. Annual pricing is display-only.</p>
      <p><a class="btn mini" href="/v1/checkout/plus?org_id={clean(org, 60)}">Plus · $20/mo · ₹2,400</a></p>
      <p><a class="btn ghost mini" href="/v1/checkout/pro?org_id={clean(org, 60)}">Pro · $150/mo</a></p>
      <p><a class="btn ghost mini" href="{html.escape(str(enterprise), quote=True)}">Enterprise · $4,000/mo · contact</a></p>
      <p class="sub">Form links: <a href="{html.escape(cashfree_plus, quote=True)}">Plus</a> · <a href="{html.escape(cashfree_pro, quote=True)}">Pro</a></p>
      <form method="post" action="/account/claim" class="form-row">
        <input name="claim" maxlength="254" placeholder="Checkout email or Payment ID" required>
        <button class="btn mini" type="submit">Claim payment</button>
      </form>
    </section>
    <section class="section glass"><h2>Auto-approve rules</h2>
      <p class="sub">Kill switches and spend/scope caps. Conditional rules require Plus.</p>
      {rule_html}
    </section>
    <section class="section glass"><h2>Audit trail</h2>
      <table class="table"><thead><tr><th>Request</th><th>Agent</th><th>Action</th><th>Status</th><th>Decision</th></tr></thead><tbody>{audit_rows}</tbody></table>
    </section>
    <section class="section glass"><h2>Login & device history</h2>
      <table class="event-table"><thead><tr><th>When</th><th>Source</th><th>Device</th></tr></thead><tbody>{login_rows}</tbody></table>
      <h3 style="margin-top:18px">Pop-ups</h3>
      <table class="event-table"><thead><tr><th>When</th><th>Channel</th><th>Device</th><th>Decision</th></tr></thead><tbody>{popup_rows}</tbody></table>
      <p class="sub">Only salted hashes and coarse device labels are stored. No IPs or raw device IDs.</p>
    </section>
    <section class="section glass"><h2>API keys & integrations</h2>
      <p class="sub">Mint a <code>gr_live_</code> key. Raw material is shown once; Grant stores only its SHA-256 hash.</p>
      <form method="post" action="/account/keys" class="form-row">
        <input type="text" name="name" maxlength="60" placeholder="Key name">
        <button class="btn mini" type="submit">Mint key</button>
      </form>
      {key_rows}
      <p class="sub">OpenAPI: <a href="/openapi.json">{html.escape(base, quote=True)}/openapi.json</a></p>
      <p class="sub">MCP: <a href="/api/mcp">{html.escape(base, quote=True)}/api/mcp</a></p>
      <p class="sub">Gate webhook: <code>{html.escape(base, quote=True)}/v1/gate/webhook</code></p>
    </section>
  </div>
  <p class="zero-note">Grant never sees your credentials or payment details. It only records what you allowed.</p>
  <div class="install-card">
    <button class="btn ghost mini" type="button" data-grant-install>Add Shortcut</button>
    <a class="btn ghost mini" href="/signup?next=/account">Sign-up flow</a>
  </div>
  <p class="watermark">● Protected by Grant · Zero-custody consent infrastructure</p>
</section>
"""
    return page("Grant account", body, "Your Grant account, plan, rules, receipts, and integrations.", private=True)


@app.get("/", response_class=HTMLResponse)
async def home() -> HTMLResponse:
    return HTMLResponse(home_page())


@app.get("/start", response_class=HTMLResponse)
async def start(next: str = "") -> HTMLResponse:
    return HTMLResponse(start_page(next))


@app.get("/signin", response_class=HTMLResponse)
async def signin(next: str = "/pricing", error: int = 0) -> HTMLResponse:
    return HTMLResponse(signin_page(next, bool(error)))


@app.post("/signin")
async def signin_submit(
    http_request: Request, code: str = Form(""), next: str = Form("/pricing")
) -> RedirectResponse:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many attempts. Slow down.")
    safe = billing.safe_org_id(code)
    target = safe_next_path(next)
    if safe and get_workspace(safe):
        telemetry.record_login(
            http_request,
            subject=safe,
            email=get_billing_email(safe),
            source="signin",
        )
        if target == "/pricing" or target.startswith("/pricing?"):
            target = f"{target}{'&' if '?' in target else '?'}{urlencode({'org_id': safe})}"
        elif not target.startswith("/a/"):
            target = f"/w/{safe}"
        return RedirectResponse(target, status_code=303)
    return RedirectResponse(
        f"/signin?{urlencode({'next': target, 'error': 1})}", status_code=303
    )


async def _request_fields(http_request: Request) -> dict[str, Any]:
    content_type = http_request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            value = await http_request.json()
            return value if isinstance(value, dict) else {}
        except (ValueError, json.JSONDecodeError):
            return {}
    form = await http_request.form()
    return dict(form)


@app.post("/v1/auth/magic-link")
async def send_magic_link(http_request: Request) -> Response:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many sign-in links. Slow down.")
    data = await _request_fields(http_request)
    email = normalize_billing_email(data.get("email", ""))
    if not valid_email(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    org = billing.safe_org_id(data.get("org_id", "")) or ""
    claim = str(data.get("claim_token", ""))[:120]
    next_path = safe_next_path(str(data.get("next", ""))) if data.get("next") else ""
    raw = "ml_" + new_code(24)
    with transaction() as conn:
        conn.execute(
            "INSERT INTO magic_links (token_hash, email, org_id, claim_token, expires_at, "
            "used_at, created_at) VALUES (?, ?, ?, ?, ?, NULL, ?)",
            (
                hash_token(raw),
                email,
                org or None,
                claim or None,
                iso_plus(MAGIC_LINK_TTL_MINUTES),
                iso(),
            ),
        )
    base = PUBLIC_BASE_URL or str(http_request.base_url).rstrip("/")
    query = {"token": raw}
    if next_path:
        query["next"] = next_path
    link = f"{base}/auth/verify?{urlencode(query)}"
    try:
        provider = emailer.send_magic_link(email, link, env=os.environ)
    except emailer.EmailError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None

    if "application/json" in http_request.headers.get("content-type", ""):
        result: dict[str, Any] = {"ok": True, "delivery": provider}
        if provider == "console":
            result["dev_link"] = link
        return JSONResponse(result)
    message = "Check your email for a one-time Grant sign-in link."
    dev = f'<p class="sub"><a href="{html.escape(link, quote=True)}">Open the development link</a></p>' if provider == "console" else ""
    body = header() + f"""<section class="done glass"><div class="seal">✓</div>
<h1>Sign-in link sent.</h1><p class="lede">{message}</p>{dev}
<p class="sub">The link expires in {MAGIC_LINK_TTL_MINUTES} minutes and works once.</p></section>"""
    return HTMLResponse(page("Sign-in link sent — Grant", body, "Check your email for your Grant sign-in link.", private=True))


@app.get("/auth/verify")
async def verify_magic_link(
    http_request: Request, token: str = "", next: str = ""
) -> RedirectResponse:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many attempts. Slow down.")
    raw = str(token or "")[:120]
    if not raw:
        raise HTTPException(status_code=400, detail="Sign-in link is missing.")
    digest = hash_token(raw)
    with transaction() as conn:
        row = conn.execute(
            "SELECT * FROM magic_links WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ?",
            (digest, iso()),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="This sign-in link is invalid or expired.")
        conn.execute("UPDATE magic_links SET used_at = ? WHERE token_hash = ?", (iso(), digest))
        user = find_or_create_user(conn, str(row["email"]))
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (iso(), user["id"]))
        org = billing.safe_org_id(row["org_id"]) or ""
        existing = conn.execute("SELECT 1 FROM workspaces WHERE code = ?", (org,)).fetchone() if org else None
        if not existing:
            org = "ws_" + new_code(9)
            create_org_record(conn, org, "My agents", user["id"])
        else:
            conn.execute(
                "UPDATE organizations SET owner_user_id = ? WHERE id = ? "
                "AND (owner_user_id IS NULL OR owner_user_id = '')",
                (user["id"], org),
            )
        link_claim_rules(conn, str(row["claim_token"] or ""), user["id"])
        session_id = create_session(conn, user["id"], org, str(row["email"]))
    telemetry.record_login(
        http_request, subject=user["id"], email=str(row["email"]), source="magic_link"
    )
    target = safe_next_path(next) if next else ""
    if not target or target == "/pricing" or not target.startswith("/"):
        target = f"/w/{org}"
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        max_age=SESSION_DAYS * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=http_request.url.scheme == "https",
        path="/",
    )
    return response


@app.post("/v1/auth/otp")
async def send_otp(http_request: Request) -> Response:
    """Email a six-digit sign-in code as an alternative to magic links."""
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many sign-in codes. Slow down.")
    data = await _request_fields(http_request)
    email = normalize_billing_email(data.get("email", ""))
    if not valid_email(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    org = billing.safe_org_id(data.get("org_id", "")) or ""
    claim = str(data.get("claim_token", ""))[:120]
    next_path = safe_next_path(str(data.get("next", ""))) if data.get("next") else ""
    code = f"{secrets.randbelow(1_000_000):06d}"
    otp_digest = hash_token(f"otp|{email}|{code}")
    with transaction() as conn:
        conn.execute(
            "INSERT INTO magic_links (token_hash, email, org_id, claim_token, otp_hash, "
            "expires_at, used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)",
            (
                hash_token("otp_" + new_code(24)),
                email,
                org or None,
                claim or None,
                otp_digest,
                iso_plus(10),
                iso(),
            ),
        )
    try:
        provider = emailer.send_otp(email, code, env=os.environ)
    except emailer.EmailError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    if "application/json" in http_request.headers.get("content-type", ""):
        result: dict[str, Any] = {"ok": True, "delivery": provider}
        if provider == "console":
            result["dev_code"] = code
        return JSONResponse(result)
    dev = (
        f'<p class="sub">Development code: <code>{html.escape(code, quote=True)}</code></p>'
        if provider == "console"
        else ""
    )
    body = header() + f"""<section class="done glass"><div class="seal">✓</div>
<h1>Sign-in code sent.</h1><p class="lede">Enter the six-digit Grant code to continue.</p>{dev}
<p class="sub">The code expires in 10 minutes and works once.</p></section>"""
    return HTMLResponse(
        page("Sign-in code sent — Grant", body, "Check your email for your Grant sign-in code.", private=True)
    )


@app.post("/v1/auth/otp/verify")
async def verify_otp(http_request: Request) -> Response:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many attempts. Slow down.")
    data = await _request_fields(http_request)
    email = normalize_billing_email(data.get("email", ""))
    code = re.sub(r"\D", "", str(data.get("code", "")))[:12]
    if not valid_email(email) or not code:
        raise HTTPException(status_code=400, detail="Enter your email and sign-in code.")
    digest = hash_token(f"otp|{email}|{code}")
    with transaction() as conn:
        row = conn.execute(
            "SELECT * FROM magic_links WHERE otp_hash = ? AND used_at IS NULL AND expires_at >= ? "
            "ORDER BY created_at DESC LIMIT 1",
            (digest, iso()),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="This sign-in code is invalid or expired.")
        conn.execute("UPDATE magic_links SET used_at = ? WHERE token_hash = ?", (iso(), row["token_hash"]))
        user = find_or_create_user(conn, str(row["email"]))
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (iso(), user["id"]))
        org = billing.safe_org_id(row["org_id"]) or ""
        existing = conn.execute("SELECT 1 FROM workspaces WHERE code = ?", (org,)).fetchone() if org else None
        if not existing:
            org = "ws_" + new_code(9)
            create_org_record(conn, org, "My agents", user["id"])
        else:
            conn.execute(
                "UPDATE organizations SET owner_user_id = ? WHERE id = ? "
                "AND (owner_user_id IS NULL OR owner_user_id = '')",
                (user["id"], org),
            )
        link_claim_rules(conn, str(row["claim_token"] or ""), user["id"])
        session_id = create_session(conn, user["id"], org, str(row["email"]))
    telemetry.record_login(http_request, subject=user["id"], email=str(row["email"]), source="otp")
    target = safe_next_path(str(data.get("next", ""))) if data.get("next") else ""
    if not target or not target.startswith("/"):
        target = f"/w/{org}"
    if "application/json" in http_request.headers.get("content-type", ""):
        response: Response = JSONResponse({"ok": True, "next": target, "org_id": org})
    else:
        response = RedirectResponse(target, status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        max_age=SESSION_DAYS * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=http_request.url.scheme == "https",
        path="/",
    )
    return response


@app.get("/api/keys")
async def list_api_keys(http_request: Request) -> JSONResponse:
    """List live key metadata. Raw key material is never stored or returned."""
    principal = require_user_principal(http_request)
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT * FROM api_keys WHERE org_id = ? ORDER BY created_at DESC LIMIT 50",
            (principal["org_id"],),
        ).fetchall()
    return JSONResponse({"keys": [api_key_public(row) for row in rows]})


@app.post("/api/keys")
async def create_api_key(http_request: Request) -> Response:
    is_json = "application/json" in http_request.headers.get("content-type", "")
    principal = principal_from_request(http_request)
    if not principal or not principal.get("user_id"):
        if is_json:
            raise HTTPException(
                status_code=401,
                detail="Sign in with an email link or provide a valid API key.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        target = f"/w/{principal['org_id']}" if principal and principal.get("org_id") else "/pricing"
        return RedirectResponse(f"/signin?{urlencode({'next': target})}", status_code=303)

    data = await _request_fields(http_request)
    name = str(data.get("name", "")).strip()[:60] or "Grant API key"
    with transaction() as conn:
        meta, raw = mint_api_key(conn, principal["org_id"], principal["user_id"], name)

    if is_json:
        return JSONResponse(
            status_code=201,
            content={
                **meta,
                "key": raw,
                "warning": "Store this key now. Grant stores only its SHA-256 hash.",
            },
            headers={"Cache-Control": "no-store"},
        )
    escaped = html.escape(raw, quote=True)
    org = html.escape(principal["org_id"], quote=True)
    body = header() + f"""
<section class="done glass">
  <div class="seal">✓</div>
  <h1>Save your Grant API key.</h1>
  <p class="lede">This is the only time we will show it. Copy it into your agent's environment now.</p>
  <pre><code id="grant-api-key">{escaped}</code></pre>
  <div class="actions">
    <button class="btn mini" type="button" onclick="copyText({js_literal(raw)})">Copy key</button>
    <a class="btn ghost mini" href="/w/{org}">Back to workspace</a>
  </div>
  <p class="alert">Grant stores only a SHA-256 digest. Send it as <code>Authorization: Bearer {API_KEY_PREFIX}…</code>.</p>
</section>
"""
    return HTMLResponse(
        page("Your new Grant API key", body, "Save your one-time Grant API key.", private=True),
        status_code=201,
        headers={"Cache-Control": "no-store"},
    )


@app.delete("/api/keys/{key_id}")
async def revoke_api_key(http_request: Request, key_id: str) -> JSONResponse:
    principal = require_user_principal(http_request)
    with transaction() as conn:
        cursor = conn.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND org_id = ? AND revoked_at IS NULL",
            (iso(), key_id[:120], principal["org_id"]),
        )
        revoked = int(cursor.rowcount) == 1
    if not revoked:
        raise HTTPException(status_code=404, detail="API key not found.")
    return JSONResponse({"ok": True, "id": key_id[:120], "revoked": True})


@app.post("/api/keys/{key_id}/revoke")
async def revoke_api_key_form(http_request: Request, key_id: str) -> RedirectResponse:
    principal = principal_from_request(http_request)
    if not principal or not principal.get("user_id"):
        return RedirectResponse("/signin", status_code=303)
    with transaction() as conn:
        conn.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND org_id = ? AND revoked_at IS NULL",
            (iso(), key_id[:120], principal["org_id"]),
        )
    return RedirectResponse(f"/w/{principal['org_id']}", status_code=303)


def rule_public(row: Any) -> dict[str, Any]:
    """Rule metadata only — never expose a claim capability token."""
    return {
        "id": str(row["id"]),
        "org_id": str(row["org_id"]),
        "agent": str(row["agent"]),
        "action": str(row["action"]),
        "max_amount": row["max_amount"],
        "multi_approver": bool(row["multi_approver"]),
        "status": str(row["status"]),
        "created_at": str(row["created_at"]),
    }


@app.get("/v1/rules")
async def list_rules(http_request: Request, workspace: str = "public") -> JSONResponse:
    validate_bearer_if_present(http_request)
    org = safe_org_id(workspace)
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT * FROM auto_approve_rules WHERE org_id = ? ORDER BY created_at DESC LIMIT 50",
            (org,),
        ).fetchall()
    return JSONResponse({"rules": [rule_public(row) for row in rows]})


@app.post("/v1/rules")
async def create_rule(body: RuleIn, http_request: Request) -> JSONResponse:
    validate_bearer_if_present(http_request)
    org = safe_org_id(body.workspace)
    if body.multi_approver:
        require_feature(org, "multi_approver_routing")
    if body.max_amount is not None or body.scope:
        require_feature(org, "conditional_auto_approve")
    scope_json, _ = canonical_scope(body.scope)
    condition_json = canonical_json(body.condition) if body.condition else ""
    rule_id = "rule_" + new_code(12)
    created = iso()
    expires = iso_plus(round((body.expires_in_seconds or 30 * 86_400) / 60))
    principal = principal_from_request(http_request)
    owner = str(body.owner_user_id or (principal.get("user_id") if principal else "") or "")[:120]
    device = telemetry.device_hash(http_request)
    with transaction() as conn:
        conn.execute(
            "INSERT INTO auto_approve_rules (id, org_id, user_id, agent, action, agent_name, "
            "tool_name, scope_json, condition_json, max_amount, multi_approver, claim_token, "
            "device_hash, expires_at, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)",
            (
                rule_id,
                org,
                owner or None,
                body.agent.strip()[:120],
                body.action.strip()[:120],
                body.agent.strip()[:120],
                body.action.strip()[:120],
                scope_json,
                condition_json[:2000],
                body.max_amount,
                1 if body.multi_approver else 0,
                str(body.claim_token or "")[:120] or None,
                device,
                expires,
                created,
            ),
        )
    return JSONResponse(
        status_code=201,
        content={
            "id": rule_id,
            "org_id": org,
            "agent": body.agent.strip()[:120],
            "action": body.action.strip()[:120],
            "multi_approver": bool(body.multi_approver),
            "max_amount": body.max_amount,
            "status": "active",
            "created_at": created,
        },
    )


@app.get("/docs", response_class=HTMLResponse)
async def docs() -> HTMLResponse:
    return HTMLResponse(docs_page(), headers={"Cache-Control": "public, s-maxage=60"})


@app.get("/pricing", response_class=HTMLResponse)
async def pricing(org_id: str = "") -> HTMLResponse:
    return HTMLResponse(pricing_page(org_id))


@app.get("/console", response_class=HTMLResponse)
async def console(http_request: Request, code: str = "") -> HTMLResponse:
    safe_code = billing.safe_org_id(code)
    if safe_code:
        workspace_row = get_workspace(safe_code)
        if workspace_row:
            telemetry.record_login(
                http_request,
                subject=safe_code,
                email=get_billing_email(safe_code),
                source="console",
            )
            with closing(db()) as conn:
                rows = conn.execute(
                    "SELECT * FROM requests WHERE workspace = ? ORDER BY created_at DESC LIMIT 100",
                    (safe_code,),
                ).fetchall()
                perms = conn.execute(
                    "SELECT * FROM permissions WHERE workspace = ? ORDER BY created_at DESC LIMIT 100",
                    (safe_code,),
                ).fetchall()
            return HTMLResponse(
                workspace_page(
                    workspace_row,
                    safe_code,
                    workspace_row["name"],
                    rows,
                    perms,
                    context=plan_context(safe_code),
                    billing_email=get_billing_email(safe_code),
                )
            )
    return HTMLResponse(console_index_page())


@app.get("/widget.js", response_class=PlainTextResponse)
async def widget_js() -> PlainTextResponse:
    return PlainTextResponse(WIDGET_JS, media_type="application/javascript")


@app.get("/grant-popup.js", response_class=PlainTextResponse)
async def grant_popup_js() -> PlainTextResponse:
    return PlainTextResponse(POPUP_JS, media_type="application/javascript")


@app.get("/grant-inject.js", response_class=PlainTextResponse)
async def grant_inject_js() -> PlainTextResponse:
    return PlainTextResponse(INJECT_JS, media_type="application/javascript")


@app.get("/v1/policies/oauth-scopes")
async def oauth_scope_templates() -> JSONResponse:
    """Machine-readable OAuth scope → Grant rule templates (no token custody)."""
    return JSONResponse(content=policies.load_oauth_templates())


@app.get("/v1/policies/oauth-scopes/{scope:path}")
async def oauth_scope_template(scope: str) -> JSONResponse:
    template = policies.template_for(scope)
    if not template:
        raise HTTPException(status_code=404, detail="OAuth scope template not found.")
    return JSONResponse(content={"scope": scope, "template": template})


@app.get("/protected/{code}", response_class=HTMLResponse)
async def protected(code: str) -> HTMLResponse:
    safe_code = code[:60]
    workspace_row = get_workspace(safe_code)
    if not workspace_row:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    with closing(db()) as conn:
        perms = conn.execute(
            "SELECT * FROM permissions WHERE workspace = ? AND expires_at >= ? "
            "ORDER BY created_at DESC LIMIT 100",
            (safe_code, iso()),
        ).fetchall()
    return HTMLResponse(protected_page(safe_code, workspace_row, perms))


def ops_authorized(http_request: Request, token: str = "") -> bool:
    if not OPS_TOKEN:
        return False
    candidate = str(token or "").strip() or str(
        http_request.headers.get("x-grant-ops-token") or ""
    ).strip()
    auth = str(http_request.headers.get("authorization") or "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth[6:].strip(), validate=True).decode("utf-8")
            candidate = decoded.split(":", 1)[-1]
        except (ValueError, UnicodeDecodeError):
            candidate = ""
    return bool(candidate) and hmac.compare_digest(candidate, OPS_TOKEN)


def ops_stats() -> dict[str, Any]:
    with closing(db()) as conn:
        row = conn.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM workspaces) AS workspaces, "
            "(SELECT COUNT(*) FROM plans) AS organizations, "
            "(SELECT COUNT(*) FROM requests) AS requests, "
            "(SELECT COUNT(*) FROM requests WHERE decision IN ('approve','always')) AS approved, "
            "(SELECT COUNT(*) FROM plans WHERE status='active' AND tier IN ('plus','pro','enterprise')) AS paid, "
            "(SELECT COUNT(*) FROM plans WHERE status='trial' AND trial_ends_at >= ?) AS trials",
            (iso(),),
        ).fetchone()
    return {
        "generated_at": iso(),
        "workspaces": int(row["workspaces"]),
        "organizations": int(row["organizations"]),
        "requests": int(row["requests"]),
        "approved": int(row["approved"]),
        "paid": int(row["paid"]),
        "trials": int(row["trials"]),
        **telemetry.overview(),
    }


@app.get("/ops", response_class=HTMLResponse)
async def ops(http_request: Request, token: str = "") -> Response:
    if not OPS_TOKEN:
        return PlainTextResponse("Set GRANT_OPS_TOKEN to enable the operations view.", status_code=503)
    if not ops_authorized(http_request, token):
        return PlainTextResponse(
            "Ops token required.",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Grant Ops"'},
        )
    return HTMLResponse(ops_page())


@app.get("/ops.json")
async def ops_json(http_request: Request, token: str = "") -> JSONResponse:
    if not ops_authorized(http_request, token):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized.",
            headers={"WWW-Authenticate": 'Basic realm="Grant Ops"'},
        )
    return JSONResponse(content=ops_stats(), headers={"Cache-Control": "no-store"})


@app.get("/login-history", response_class=HTMLResponse)
async def login_history_view(http_request: Request, token: str = "") -> Response:
    if not OPS_TOKEN:
        return PlainTextResponse(
            "Set GRANT_OPS_TOKEN to enable the login history view.", status_code=503
        )
    if not ops_authorized(http_request, token):
        return PlainTextResponse(
            "Ops token required.",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Grant Ops"'},
        )
    return HTMLResponse(login_history_page())


@app.get("/login-history.json")
async def login_history_json(
    http_request: Request, token: str = "", limit: int = 100
) -> JSONResponse:
    if not ops_authorized(http_request, token):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized.",
            headers={"WWW-Authenticate": 'Basic realm="Grant Ops"'},
        )
    return JSONResponse(
        content=login_library.report(limit=limit), headers={"Cache-Control": "no-store"}
    )


def webhook_signature(signature: str, timestamp: str) -> tuple[str, str]:
    raw = str(signature or "").strip()
    stamp = str(timestamp or "").strip()
    if raw.startswith("t="):
        parts = dict(item.split("=", 1) for item in raw.split(",") if "=" in item)
        stamp = parts.get("t", stamp)
        raw = parts.get("v1", "")
    return raw, stamp


@app.post("/v1/checkout/{plan}")
async def checkout_not_allowed() -> None:
    raise HTTPException(status_code=405, detail="Use GET for hosted checkout redirects.")


@app.get("/v1/checkout/{plan}")
async def checkout(plan: str, cycle: str = "monthly", org_id: str = "public") -> Response:
    """Redirect to a fixed, hosted monthly Cashfree form. No API call, no annual."""
    org = billing.safe_org_id(org_id)
    if not org:
        raise HTTPException(status_code=400, detail="A valid org_id is required.")
    key = str(plan or "").strip().lower()
    hosted = key in {"plus", "pro", "concierge"}
    if key == "enterprise":
        url = billing.enterprise_contact_url(org) or f"{PUBLIC_BASE_URL}/pricing#enterprise"
    elif hosted:
        if not get_workspace(org):
            return RedirectResponse(
                f"/signin?{urlencode({'next': '/pricing'})}", status_code=303
            )
        get_plan(org)
        try:
            url = cashfree.monthly_form_url(key, env=os.environ)
        except cashfree.CashfreeError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from None
    else:
        raise HTTPException(status_code=404, detail="Plan not found.")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise HTTPException(status_code=502, detail="Checkout provider is misconfigured.")
    if hosted and (parts.scheme != "https" or parts.hostname not in cashfree.ALLOWED_LINK_HOSTS):
        raise HTTPException(status_code=502, detail="Checkout provider is misconfigured.")
    return RedirectResponse(url, status_code=302)


def action_from_receipt(receipt: dict[str, str]) -> dict[str, str] | None:
    """Map a verified Cashfree receipt to a user-owned org when possible."""
    org = org_for_checkout_email(str(receipt.get("email") or ""))
    if not org:
        return None
    return {
        "org_id": org,
        "tier": str(receipt.get("tier") or "plus"),
        "status": "active",
        "event_type": str(receipt.get("event_type") or "cashfree_payment"),
        "event_id": str(receipt.get("event_id") or "")[:120],
        "email": str(receipt.get("email") or ""),
        "customer_ref": str(receipt.get("payment_ref") or "")[:120],
        "checkout_id": str(receipt.get("payment_ref") or "")[:120],
        "payment_ref": str(receipt.get("payment_ref") or "")[:120],
        "paid_at": str(receipt.get("paid_at") or "")[:40],
    }


async def handle_billing_webhook(http_request: Request) -> JSONResponse:
    raw = await http_request.body()
    payload = billing.decode_webhook_body(raw)
    if payload is None:
        return JSONResponse(content={"ok": True, "applied": False, "reason": "ignored"})
    receipt = billing.normalize_cashfree_receipt(payload)
    action = billing.normalize_event(payload)
    if not action and receipt:
        action = billing.normalize_form_event(payload, org_resolver=org_for_checkout_email)
        if not action:
            action = action_from_receipt(receipt)
    if action and receipt and receipt.get("email"):
        action["email"] = str(receipt["email"])
    if not action and not receipt:
        return JSONResponse(content={"ok": True, "applied": False, "reason": "ignored"})

    cashfree_signature = str(http_request.headers.get("x-webhook-signature") or "").strip()
    cashfree_timestamp = str(http_request.headers.get("x-webhook-timestamp") or "").strip()
    grant_signature = str(http_request.headers.get("x-grant-signature") or "").strip()
    grant_timestamp = str(http_request.headers.get("x-grant-timestamp") or "").strip()
    if cashfree_signature and cashfree_timestamp:
        if not CASHFREE_WEBHOOK_SECRET:
            raise HTTPException(status_code=503, detail="Cashfree webhook is not configured.")
        if not billing.verify_webhook(
            raw,
            cashfree_signature,
            cashfree_timestamp,
            secret=CASHFREE_WEBHOOK_SECRET,
            mode="cashfree",
        ):
            raise HTTPException(status_code=401, detail="Invalid webhook signature.")
    elif grant_signature or grant_timestamp:
        if not BILLING_WEBHOOK_SECRET:
            raise HTTPException(status_code=503, detail="Billing webhook is not configured.")
        signature, timestamp = webhook_signature(grant_signature, grant_timestamp)
        if not billing.verify_webhook(raw, signature, timestamp, secret=BILLING_WEBHOOK_SECRET):
            raise HTTPException(status_code=401, detail="Invalid webhook signature.")
    else:
        raise HTTPException(status_code=401, detail="Invalid webhook signature.")
    if action:
        return JSONResponse(
            content={"ok": True, "applied": apply_billing_event(action)}
        )
    return JSONResponse(
        content={
            "ok": True,
            "applied": False,
            "stored_unclaimed": bool(receipt and record_unclaimed_payment(receipt)),
        }
    )


@app.post("/v1/billing/webhook")
async def billing_webhook(http_request: Request) -> JSONResponse:
    return await handle_billing_webhook(http_request)


@app.post("/api/webhooks/cashfree")
async def cashfree_webhook(http_request: Request) -> JSONResponse:
    """Aliased signed Cashfree endpoint used by the account integration docs."""
    return await handle_billing_webhook(http_request)


@app.get("/api/billing/status")
async def billing_status(
    http_request: Request, org_id: str = "", token: str = ""
) -> JSONResponse:
    """Ops-gated tier check used to verify webhook-driven activation."""
    if not ops_authorized(http_request, token):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized.",
            headers={"WWW-Authenticate": 'Basic realm="Grant Ops"'},
        )
    org = billing.safe_org_id(org_id)
    if not org:
        raise HTTPException(status_code=400, detail="A valid org_id is required.")
    get_plan(org)
    context = plan_context(org)
    stored = get_organization(org)
    return JSONResponse(
        content={
            "org_id": org,
            "tier": plans.effective_tier(context["plan"]),
            "stored_tier": str(stored["plan_tier"]) if stored else "",
            "plan_status": str(context["plan"]["status"]),
            "used": context["used"],
            "limit": context["usage"]["limit"],
            "trial_days_left": context["usage"]["trial_days_left"],
            "cashfree_webhook_configured": bool(CASHFREE_WEBHOOK_SECRET),
        },
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/webhooks/cashfree/test")
async def cashfree_test_webhook(http_request: Request, token: str = "") -> JSONResponse:
    """Ops-only simulation of the signed webhook activation path.

    No money moves. It runs the same ``apply_billing_event`` used by
    ``/v1/billing/webhook`` so a live checkout can be verified end to end with
    ``scripts/verify_cashfree.py``.
    """
    if IS_PRODUCTION and not ALLOW_TEST_WEBHOOK:
        raise HTTPException(
            status_code=403,
            detail="Test webhook is disabled in production. Set GRANT_ALLOW_TEST_WEBHOOK=true to enable.",
        )
    if not ops_authorized(http_request, token):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized.",
            headers={"WWW-Authenticate": 'Basic realm="Grant Ops"'},
        )
    data = await _request_fields(http_request)
    org = billing.safe_org_id(data.get("org_id", ""))
    plan = str(data.get("plan", "plus") or "plus").strip().lower()
    if not org or plan not in {"plus", "pro"}:
        raise HTTPException(status_code=400, detail="Supply a valid org_id and plan (plus or pro).")
    get_plan(org)
    before = plans.effective_tier(get_plan(org))
    event_id = str(data.get("event_id", "") or "")[:120] or "test_" + new_code(12)
    applied = apply_billing_event(
        {
            "org_id": org,
            "event_id": event_id,
            "tier": plan,
            "status": "active",
            "checkout_id": f"test_{new_code(9)}",
            "customer_ref": "",
        }
    )
    after = plans.effective_tier(get_plan(org))
    return JSONResponse(
        content={
            "ok": True,
            "simulation": True,
            "applied": applied,
            "org_id": org,
            "event_id": event_id,
            "before_tier": before,
            "after_tier": after,
            "note": "No payment was collected. This exercises the signed webhook activation path.",
        },
        headers={"Cache-Control": "no-store"},
    )


def renewal_authorized(http_request: Request, token: str = "") -> bool:
    auth = str(http_request.headers.get("authorization") or "")
    if CRON_SECRET and auth.lower().startswith("bearer "):
        candidate = auth[7:].strip()
        if hmac.compare_digest(candidate, CRON_SECRET):
            return True
    return ops_authorized(http_request, token)


def send_renewal_email(email: str, form_url: str, tier: str) -> bool:
    """Send a renewal reminder through a configured external email webhook.

    No provider is built into Grant. If no HTTPS webhook is configured, nothing
    is sent and the reminder remains pending. No payload is logged.
    """
    if not RENEWAL_EMAIL_WEBHOOK_URL:
        return False
    try:
        cashfree.validate_link_url(form_url)
    except cashfree.CashfreeError:
        return False
    parts = urlsplit(RENEWAL_EMAIL_WEBHOOK_URL)
    if parts.scheme != "https" or not parts.netloc:
        return False
    body = json.dumps(
        {
            "to": email,
            "subject": "Renew your Grant plan",
            "text": (
                "Your Grant plan renews soon. Complete your monthly payment here: "
                f"{form_url}"
            ),
            "tier": tier,
            "renewal_url": form_url,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    headers = {"content-type": "application/json"}
    if RENEWAL_EMAIL_WEBHOOK_TOKEN:
        headers["authorization"] = f"Bearer {RENEWAL_EMAIL_WEBHOOK_TOKEN}"
    request = urlrequest.Request(
        RENEWAL_EMAIL_WEBHOOK_URL, data=body, headers=headers, method="POST"
    )
    try:
        with urlrequest.build_opener().open(request, timeout=8) as response:
            status = int(getattr(response, "status", 0) or response.getcode())
    except (urlerror.URLError, TimeoutError, OSError, ValueError):
        return False
    return 200 <= status < 300


@app.get("/v1/billing/renewal-reminders")
async def renewal_reminders(http_request: Request, token: str = "") -> JSONResponse:
    """Run day-27 renewal reminders. Called by a scheduler, never by buyers."""
    if not CRON_SECRET and not OPS_TOKEN:
        return JSONResponse(
            status_code=503,
            content={"ok": False, "detail": "Reminder scheduler is not configured."},
        )
    if not renewal_authorized(http_request, token):
        raise HTTPException(status_code=401, detail="Unauthorized.")
    send = str(http_request.query_params.get("send", "1")).strip().lower() not in {
        "0",
        "false",
        "no",
    }
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT * FROM renewal_reminders "
            "WHERE status = 'pending' AND due_at <= ? ORDER BY due_at LIMIT 50",
            (iso(),),
        ).fetchall()
    if not rows or not send or not RENEWAL_EMAIL_WEBHOOK_URL:
        return JSONResponse(
            content={
                "ok": True,
                "due": len(rows),
                "sent": 0,
                "skipped": len(rows) if rows else 0,
                "failed": 0,
                "delivery_configured": bool(RENEWAL_EMAIL_WEBHOOK_URL),
            }
        )
    sent = skipped = failed = 0
    for row in rows:
        email = get_billing_email(str(row["org_id"]))
        if not email:
            skipped += 1
            continue
        delivered = await asyncio.to_thread(
            send_renewal_email,
            email,
            str(row["form_url"]),
            str(row["tier"]),
        )
        if not delivered:
            failed += 1
            continue
        with transaction() as conn:
            conn.execute(
                "UPDATE renewal_reminders SET status = 'sent', sent_at = ? "
                "WHERE reminder_key = ? AND status = 'pending'",
                (iso(), str(row["reminder_key"])),
            )
        sent += 1
    return JSONResponse(
        content={
            "ok": True,
            "due": len(rows),
            "sent": sent,
            "skipped": skipped,
            "failed": failed,
            "delivery_configured": True,
        }
    )


@app.get("/health/live")
async def health_live() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
async def health_ready() -> dict[str, str]:
    init_db()
    return {
        "status": "ready",
        "database": "connected",
        "environment": APP_ENV,
        "signing": signing_mode(),
        "api_version": "0.1.0",
    }


def stats_snapshot() -> dict[str, Any]:
    """Public aggregate counters only — never request details or identities."""
    with closing(db()) as conn:
        row = conn.execute(
            "SELECT (SELECT COUNT(*) FROM requests) AS requests, "
            "(SELECT COUNT(*) FROM requests WHERE status='pending') AS pending, "
            "(SELECT COUNT(*) FROM requests WHERE status='decided') AS decided, "
            "(SELECT COUNT(*) FROM permissions) AS permissions"
        ).fetchone()
    reach = telemetry.overview()
    return {
        "generated_at": iso(),
        "requests": int(row["requests"]),
        "pending": int(row["pending"]),
        "decided": int(row["decided"]),
        "permissions": int(row["permissions"]),
        "total_users": reach["total_users"],
        "unique_humans_reached": reach["unique_humans_reached"],
        "popup_impressions": reach["popup_impressions"],
        "unique_devices": reach["unique_devices"],
        "active_sessions": reach["active_sessions"],
    }


def stats_page() -> str:
    data = stats_snapshot()
    cards = (
        ("total_users", "Workspaces"),
        ("requests", "Approval requests"),
        ("decided", "Decisions made"),
        ("popup_impressions", "Approval windows opened"),
        ("unique_devices", "Different computers"),
        ("active_sessions", "Active in the last day"),
    )
    cards_html = "".join(
        f'<div class="op-card"><div class="num">{int(data[key])}</div>'
        f'<div class="label">{label}</div></div>'
        for key, label in cards
    )
    body = header() + f"""
<section class="section glass">
  <span class="eyebrow"><span class="dot"></span> Grant activity</span>
  <h1>Quiet numbers.</h1>
  <p class="sub">Only totals. No names, emails, or approval details are ever published. Updated {clean(data['generated_at'], 40)}.</p>
  <div class="op-grid">{cards_html}</div>
  <p class="alert">Counts refresh at most once a minute. For the raw totals, use <a href="/stats.json">the numbers feed</a>.</p>
</section>
"""
    return page("Grant activity", body, "Public aggregate activity totals for Grant.")


@app.get("/stats", response_class=HTMLResponse)
async def stats() -> HTMLResponse:
    return HTMLResponse(stats_page(), headers={"Cache-Control": "public, s-maxage=60"})


@app.get("/stats.json")
async def stats_json() -> JSONResponse:
    return JSONResponse(content=stats_snapshot(), headers={"Cache-Control": "no-store"})


@app.post("/v1/a2a/gate")
async def a2a_gate(body: A2AGateIn, http_request: Request) -> JSONResponse:
    """Layer 4: halt an agent-to-agent handoff until a human signs it."""
    validate_bearer_if_present(http_request)
    if not body.require_approval and not a2a_needs_approval(body.task, body.payload):
        return JSONResponse(
            {
                "status": "passed",
                "grant_id": "",
                "message": "This handoff fits your standing rules.",
            },
            headers={"Cache-Control": "no-store"},
        )
    sender = str(redact_text(body.sender))[:120]
    receiver = str(redact_text(body.receiver))[:120]
    action = f"delegate to {receiver}"[:120]
    safe_task = str(redact_text(body.task))[:300]
    summary = f"{sender} wants to hand a task to {receiver}: {safe_task}"[:500]
    result = create_request(
        RequestIn(
            agent=sender,
            action=action,
            summary=summary,
            scope=body.payload,
            requester="agent-to-agent",
            workspace=body.workspace,
            ttl_minutes=body.ttl_minutes,
            parent_origin=body.parent_origin,
            channel="a2a",
        )
    )
    return JSONResponse(
        {
            "status": "pending",
            "grant_id": result["id"],
            "approval_url": result["approval_url"],
            "message": grant_message(sender, action, result["approval_url"]),
            "expires_at": result["expires_at"],
            "retry_header": "X-Grant-Request-Id",
        },
        status_code=202,
        headers={"Cache-Control": "no-store"},
    )


@app.post("/v1/requests")
async def create_request_api(
    payload: RequestIn,
    http_request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many requests. Slow down.")
    validate_bearer_if_present(http_request)

    key = idempotency_key[:120] if idempotency_key else ""
    owner = False
    wait_event: threading.Event | None = None
    if key:
        with _IDEMPOTENCY_LOCK:
            cached = _IDEMPOTENCY.get(key)
            if cached and cached[1]:
                return JSONResponse(status_code=201, content=json.loads(cached[1]))
            if cached:
                wait_event = _IDEMPOTENCY_EVENTS.get(key)
            else:
                _IDEMPOTENCY[key] = ("pending", "")
                wait_event = threading.Event()
                _IDEMPOTENCY_EVENTS[key] = wait_event
                owner = True
        if not owner and wait_event is not None:
            await asyncio.to_thread(wait_event.wait, 5)
            with _IDEMPOTENCY_LOCK:
                cached = _IDEMPOTENCY.get(key)
            if cached and cached[1]:
                return JSONResponse(status_code=201, content=json.loads(cached[1]))
            raise HTTPException(status_code=409, detail="Duplicate request in progress.")

    try:
        result = create_request(payload)
        created_row = get_request_by_id(result["id"])
        if created_row:
            await blob_put_request(created_row)
        response_body = {
            "id": result["id"],
            "url": result["url"],
            "approval_url": result["approval_url"],
            "expires_at": result["expires_at"],
            "scope_hash": result["scope_hash"],
            "status": "pending",
            "message": result["message"],
        }
        if key:
            with _IDEMPOTENCY_LOCK:
                _IDEMPOTENCY[key] = (result["id"], json.dumps(response_body))
        return JSONResponse(status_code=201, content=response_body)
    except Exception:
        if key and owner:
            with _IDEMPOTENCY_LOCK:
                _IDEMPOTENCY.pop(key, None)
                _IDEMPOTENCY_EVENTS.pop(key, None)
        raise
    finally:
        if key and owner and wait_event is not None:
            wait_event.set()


@app.get("/v1/requests/{request_id}")
async def request_status(request_id: str) -> JSONResponse:
    row = await resolve_request_by_id(request_id[:120])
    if not row:
        raise HTTPException(status_code=404, detail="Request not found.")
    body: dict[str, Any] = {
        "id": row["id"],
        "status": row["status"],
        "decision": row["decision"],
        "decision_at": row["decision_at"],
        "expires_at": row["expires_at"],
        "scope_hash": row["scope_hash"],
    }
    permission = get_permission_by_request(row["id"])
    if permission:
        body["permission"] = permission_dict(permission)
    return JSONResponse(content=body)


@app.get("/v1/permissions/{agent}")
async def permissions_for_agent(agent: str) -> JSONResponse:
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT * FROM permissions WHERE agent = ? AND expires_at >= ? "
            "ORDER BY created_at DESC LIMIT 100",
            (agent[:120], iso()),
        ).fetchall()
    return JSONResponse(
        content={
            "agent": agent,
            "count": len(rows),
            "permissions": [permission_dict(row) for row in rows],
        }
    )


@app.post("/v1/permissions/verify")
async def verify_permission(payload: VerifyIn) -> JSONResponse:
    row = get_permission_by_id(payload.id[:120])
    if not row:
        return JSONResponse(status_code=200, content={"valid": False, "reason": "not_found"})
    expected = sign_permission(permission_payload(row))
    if not hmac.compare_digest(expected, payload.signature):
        return JSONResponse(status_code=200, content={"valid": False, "reason": "bad_signature"})
    if expired(row):
        return JSONResponse(status_code=200, content={"valid": False, "reason": "expired"})
    return JSONResponse(
        content={
            "valid": True,
            "id": row["id"],
            "agent": row["agent"],
            "action": row["action"],
            "policy": row["policy"],
            "scope_hash": row["scope_hash"],
            "expires_at": row["expires_at"],
        }
    )


def gateway_call_scope_hash(
    policy: dict[str, Any],
    *,
    method: str,
    path: str,
    query: str,
    parsed_body: Any,
    tool: str,
    reason: str,
) -> str:
    """Recompute the approved scope hash for the call being retried."""
    _, _, scope = gateway_request_info(
        str(policy["name"]),
        method=method,
        path=path,
        query=query,
        tool=tool,
        payload=parsed_body,
        reason=reason,
    )
    return canonical_scope(scope)[1]


def verify_gateway_receipt(
    row: sqlite3.Row,
    policy: dict[str, Any],
    token: str,
    receipt: str,
) -> tuple[bool, str]:
    """A gateway retry must present a signed, bound Grant receipt."""
    bound = str(row["gateway_hash"] if "gateway_hash" in row.keys() else "")
    if bound and not hmac.compare_digest(bound, gateway_token_hash(token)):
        return False, "receipt is bound to a different gateway"
    permission = get_permission_by_request(str(row["id"]))
    if not permission:
        return False, "no signed receipt exists for this request"
    expected = sign_permission(permission_payload(permission))
    if not receipt or not hmac.compare_digest(expected, str(receipt)[:160]):
        return False, "missing or invalid X-Grant-Receipt"
    if not hmac.compare_digest(str(permission["scope_hash"]), str(row["scope_hash"])):
        return False, "receipt scope does not match the request"
    if str(permission["workspace"]) != str(policy["workspace"]):
        return False, "receipt workspace does not match the gateway"
    if str(permission["agent"]) != f"gateway:{policy['name']}"[:120]:
        return False, "receipt agent does not match the gateway"
    if expired(permission):
        return False, "receipt has expired"
    return True, ""


def pending_from_row(row: sqlite3.Row, policy: dict[str, Any]) -> tuple[str, dict[str, str]]:
    channel = str(row["channel"] if "channel" in row.keys() else "mcp_gateway")
    path = approval_path(
        row["token"],
        channel=channel,
        parent_origin=str(policy.get("parent_origin") or ""),
    )
    url = f"{PUBLIC_BASE_URL}{path}" if PUBLIC_BASE_URL else path
    message = grant_message(f"Grant gateway {policy['name']}", "continue this action", url)
    return url, {
        "grant_id": row["id"],
        "status": "pending",
        "approval_url": url,
        "message": message,
        "retry_header": "X-Grant-Request-Id",
        "expires_at": row["expires_at"],
    }


def mcp_error(mcp_id: Any, status: int, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=200,
        content={"jsonrpc": "2.0", "id": mcp_id, "error": {"code": status, "message": message}},
    )


async def gateway_call(
    token: str,
    *,
    method: str,
    path: str,
    query: str,
    body: bytes | None,
    parsed_body: Any,
    headers: dict[str, str],
    mcp_id: Any = None,
    tool: str = "",
) -> Response:
    gateway = await resolve_gateway(token)
    if not gateway:
        raise HTTPException(status_code=404, detail="Grant gateway not found.")
    policy = policy_from_row(gateway)

    retry_id = str(headers.get("x-grant-request-id") or "")[:120]
    if retry_id:
        row = await resolve_request_by_id(retry_id)
        if not row or row["workspace"] != policy["workspace"]:
            raise HTTPException(status_code=404, detail="Grant request not found for this gateway.")
        if expired(row):
            return mcp_error(mcp_id, 410, "This Grant request expired.") if mcp_id is not None else JSONResponse(
                status_code=410, content={"detail": "This Grant request expired."}
            )
        if row["status"] == "pending":
            _, pending = pending_from_row(row, policy)
            content = (
                {"jsonrpc": "2.0", "id": mcp_id, "result": {"grant": pending}}
                if mcp_id is not None
                else pending
            )
            return JSONResponse(
                status_code=202,
                content=content,
                headers={"X-Grant-Request-Id": row["id"]},
            )
        if row["decision"] == "reject":
            return mcp_error(mcp_id, 403, "The human rejected this action.") if mcp_id is not None else JSONResponse(
                status_code=403, content={"detail": "The human rejected this action."}
            )
        _, reason = policy_is_sensitive(
            policy, method=method, path=path, tool=tool, payload=parsed_body
        )
        current_hash = gateway_call_scope_hash(
            policy,
            method=method,
            path=path,
            query=query,
            parsed_body=parsed_body,
            tool=tool,
            reason=reason,
        )
        if not hmac.compare_digest(current_hash, str(row["scope_hash"])):
            return mcp_error(mcp_id, 403, "The signed scope does not match this call.") if mcp_id is not None else JSONResponse(
                status_code=403, content={"detail": "The signed scope does not match this call."}
            )
        verified, problem = verify_gateway_receipt(
            row, policy, token, str(headers.get("x-grant-receipt") or "")
        )
        if not verified:
            return mcp_error(mcp_id, 403, problem) if mcp_id is not None else JSONResponse(
                status_code=403, content={"detail": problem}
            )
        status, response_headers, content = await forward_upstream(
            policy, method=method, path=path, query=query, body=body, headers=headers
        )
        response_headers["X-Grant-Request-Id"] = row["id"]
        if mcp_id is not None:
            try:
                return JSONResponse(
                    status_code=status, content=json.loads(content), headers=response_headers
                )
            except (ValueError, UnicodeDecodeError):
                pass
        return Response(content=content, status_code=status, headers=response_headers)

    sensitive, reason = policy_is_sensitive(
        policy, method=method, path=path, tool=tool, payload=parsed_body
    )
    if not sensitive:
        status, response_headers, content = await forward_upstream(
            policy, method=method, path=path, query=query, body=body, headers=headers
        )
        if mcp_id is not None:
            try:
                return JSONResponse(status_code=status, content=json.loads(content), headers=response_headers)
            except (ValueError, UnicodeDecodeError):
                pass
        return Response(content=content, status_code=status, headers=response_headers)

    action, summary, scope = gateway_request_info(
        policy["name"],
        method=method,
        path=path,
        query=query,
        tool=tool,
        payload=parsed_body,
        reason=reason,
    )
    result = create_request(
        RequestIn(
            agent=f"gateway:{policy['name']}"[:120],
            action=action,
            summary=summary,
            scope=scope,
            workspace=policy["workspace"],
            ttl_minutes=int(policy.get("ttl_minutes", 15)),
            parent_origin=str(policy.get("parent_origin") or ""),
            channel="mcp_gateway",
        ),
        gateway_hash=gateway_token_hash(token),
    )
    created_row = get_request_by_id(result["id"])
    if created_row:
        await blob_put_request(created_row)
    store_pending(
        result["id"],
        {
            "token_hash": gateway_token_hash(token),
            "created_monotonic": time.monotonic(),
            "expires_monotonic": time.monotonic() + int(policy.get("ttl_minutes", 15)) * 60,
        },
    )

    decision_row = await wait_for_decision(result["id"], GATEWAY_WAIT_SECONDS)
    if decision_row is None:
        return JSONResponse(
            status_code=202,
            content=gateway_pending_payload(result, mcp_id=mcp_id),
            headers={"X-Grant-Request-Id": result["id"]},
        )
    if expired(decision_row):
        return mcp_error(mcp_id, 410, "This Grant request expired.") if mcp_id is not None else JSONResponse(
            status_code=410, content={"detail": "This Grant request expired."}
        )
    if decision_row["decision"] == "reject":
        return mcp_error(mcp_id, 403, "The human rejected this action.") if mcp_id is not None else JSONResponse(
            status_code=403, content={"detail": "The human rejected this action."}
        )
    inline_permission = get_permission_by_request(result["id"])
    inline_receipt = (
        sign_permission(permission_payload(inline_permission)) if inline_permission else ""
    )
    verified, problem = verify_gateway_receipt(decision_row, policy, token, inline_receipt)
    if not verified:
        return mcp_error(mcp_id, 403, problem) if mcp_id is not None else JSONResponse(
            status_code=403, content={"detail": problem}
        )

    status, response_headers, content = await forward_upstream(
        policy, method=method, path=path, query=query, body=body, headers=headers
    )
    pop_pending(result["id"])
    response_headers["X-Grant-Request-Id"] = result["id"]
    if mcp_id is not None:
        try:
            return JSONResponse(status_code=status, content=json.loads(content), headers=response_headers)
        except (ValueError, UnicodeDecodeError):
            pass
    return Response(content=content, status_code=status, headers=response_headers)


@app.post("/v1/gateways")
async def register_gateway(payload: GatewayIn, http_request: Request) -> JSONResponse:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many gateways. Slow down.")
    parsed = urlparse(payload.upstream_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="upstream_url must be a valid HTTP(S) URL.")
    if parsed.scheme == "http" and APP_ENV == "production" and not ALLOW_HTTP_UPSTREAMS:
        raise HTTPException(status_code=400, detail="Production gateways require an https:// upstream.")

    token = "gw_" + new_code(18)
    policy = {
        "name": payload.name.strip(),
        "sensitive_tools": [item.strip() for item in payload.sensitive_tools if item.strip()],
        "sensitive_paths": [item.strip() for item in payload.sensitive_paths if item.strip()],
        "sensitive_methods": [item.strip().upper() for item in payload.sensitive_methods if item.strip()],
        "body_keys": [item.strip() for item in payload.body_keys if item.strip()],
        "default_action": payload.default_action,
        "ttl_minutes": payload.ttl_minutes,
        "parent_origin": clean_parent_origin(payload.parent_origin),
    }
    with transaction() as conn:
        conn.execute(
            "INSERT INTO gateways (token_hash, name, upstream_url, policy_json, workspace, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                gateway_token_hash(token),
                policy["name"],
                payload.upstream_url.rstrip("/"),
                canonical_json(policy),
                payload.workspace.strip() or "public",
                iso(),
            ),
        )
    gateway_row = get_gateway(token)
    if gateway_row:
        await blob_put_gateway(gateway_row)
    base = PUBLIC_BASE_URL or str(http_request.base_url).rstrip("/")
    return JSONResponse(
        status_code=201,
        content={
            "id": "gw_" + token[3:11],
            "token": token,
            "name": policy["name"],
            "http_url": f"{base}/g/http/{token}/",
            "mcp_url": f"{base}/g/mcp/{token}",
            "policy": policy,
            "note": "Store the token privately. Anyone with this URL can use your gateway.",
        },
    )


@app.get("/v1/gateways/{token}")
async def inspect_gateway(token: str) -> JSONResponse:
    gateway = await resolve_gateway(token)
    if not gateway:
        raise HTTPException(status_code=404, detail="Grant gateway not found.")
    policy = policy_from_row(gateway)
    return JSONResponse(
        content={
            "id": "gw_" + token[3:11],
            "name": gateway["name"],
            "upstream_url": gateway["upstream_url"],
            "workspace": gateway["workspace"],
            "policy": policy,
            "created_at": gateway["created_at"],
        }
    )


@app.api_route(
    "/g/http/{token}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def gateway_http(token: str, path: str, http_request: Request) -> Response:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many gateway calls. Slow down.")
    body = await http_request.body()
    parsed_body: Any = None
    if body:
        content_type = http_request.headers.get("content-type", "").lower()
        if "json" in content_type:
            try:
                parsed_body = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                parsed_body = body.decode("utf-8", errors="replace")
        else:
            parsed_body = body.decode("utf-8", errors="replace")
    return await gateway_call(
        token,
        method=http_request.method,
        path="/" + path.lstrip("/"),
        query=http_request.url.query,
        body=body,
        parsed_body=parsed_body,
        headers=dict(http_request.headers),
    )


@app.post("/g/mcp/{token}")
async def gateway_mcp(token: str, http_request: Request) -> Response:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many gateway calls. Slow down.")
    try:
        payload = await http_request.json()
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="MCP request must be JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="MCP request must be a JSON object.")
    body = await http_request.body()
    method = str(payload.get("method", ""))
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    tool = str(params.get("name", "")) if method == "tools/call" else ""
    arguments = params.get("arguments", {}) if method == "tools/call" else payload
    return await gateway_call(
        token,
        method="POST",
        path="",
        query="",
        body=body,
        parsed_body=arguments,
        headers=dict(http_request.headers),
        mcp_id=payload.get("id"),
        tool=tool,
    )


@app.post("/v1/demo")
async def demo_request(http_request: Request) -> RedirectResponse:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many demos. Slow down.")
    payload = RequestIn(
        agent="demo-agent",
        action="send_a_summary",
        summary="Send a weekly summary to the team channel",
        scope={"channel": "team", "entries": 5},
        requester="Grant demo",
        workspace="demo",
        ttl_minutes=30,
    )
    result = create_request(payload)
    created_row = get_request_by_id(result["id"])
    if created_row:
        await blob_put_request(created_row)
    return RedirectResponse(result["url"], status_code=303)


@app.post("/v1/workspaces")
async def create_workspace(
    http_request: Request,
    name: str = Form("My agents"),
    next: str = Form(""),
) -> RedirectResponse:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many workspaces. Slow down.")
    code = "ws_" + new_code(9)
    label = (name or "").strip()[:80] or "My agents"
    with transaction() as conn:
        create_org_record(conn, code, label)
    telemetry.record_login(http_request, subject=code, source="workspace")
    target = safe_next_path(next) if next else ""
    if not (target.startswith("/a/") or target.startswith("/pricing")):
        target = f"/w/{code}"
    return RedirectResponse(target, status_code=303)


@app.get("/w/{code}", response_class=HTMLResponse)
async def workspace(http_request: Request, code: str, name: str = "My agents") -> HTMLResponse:
    code = code[:60]
    workspace_row = get_workspace(code)
    if workspace_row:
        telemetry.record_login(
            http_request,
            subject=code,
            email=get_billing_email(code),
            source="workspace",
        )
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT * FROM requests WHERE workspace = ? ORDER BY created_at DESC LIMIT 100", (code,)
        ).fetchall()
        perms = conn.execute(
            "SELECT * FROM permissions WHERE workspace = ? ORDER BY created_at DESC LIMIT 100", (code,)
        ).fetchall()
    return HTMLResponse(
        workspace_page(
            workspace_row,
            code,
            name[:80],
            rows,
            perms,
            billing_email=get_billing_email(code),
            claim_token=http_request.cookies.get(DASHBOARD_COOKIE, ""),
        )
    )


@app.post("/w/{code}/billing-email")
async def save_billing_email(
    http_request: Request, code: str, email: str = Form("")
) -> RedirectResponse:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many updates. Slow down.")
    safe = code[:60]
    if get_workspace(safe) and set_billing_email(safe, email):
        return RedirectResponse(f"/w/{safe}?billing=saved", status_code=303)
    return RedirectResponse(f"/w/{safe}?billing=invalid", status_code=303)


@app.post("/w/{code}/claim-payment")
async def claim_payment(
    http_request: Request, code: str, claim: str = Form("")
) -> RedirectResponse:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many claims. Slow down.")
    safe = code[:60]
    marker = "ok" if claim_unclaimed_payment(safe, claim) else "missing"
    return RedirectResponse(f"/w/{safe}?claim={marker}", status_code=303)


@app.get("/a/{token}", response_class=HTMLResponse)
async def approval(
    http_request: Request,
    token: str,
    done: str = "",
    parent_origin: str = "",
    compact: bool = False,
    channel: str = "",
) -> HTMLResponse:
    row = await resolve_request_by_token(token[:80])
    if not row:
        raise HTTPException(status_code=404, detail="Approval link not found.")
    if row["status"] != "decided" and not done:
        # One impression per human render of the approval card. The decision
        # redirect is deliberately not counted a second time.
        telemetry.record_popup(
            http_request,
            request_id=str(row["id"]),
            org_id=str(row["workspace"]),
            channel=channel or str(row["channel"] if "channel" in row.keys() else "browser_popup"),
        )
    owned = dashboard_code_from_cookie(http_request.cookies.get(DASHBOARD_COOKIE, ""))
    if owned and not get_workspace(owned):
        owned = ""
    return HTMLResponse(
        approval_page(
            row,
            done[:20],
            parent_origin=clean_parent_origin(parent_origin),
            compact=compact,
            dashboard_code=owned,
        )
    )


@app.post("/a/{token}/decide")
async def decide(
    http_request: Request,
    token: str,
    decision: str = Form(""),
    parent_origin: str = Form(""),
    compact: bool = Form(False),
) -> RedirectResponse:
    if decision not in ALLOWED_DECISIONS:
        raise HTTPException(status_code=400, detail="Invalid decision.")
    row = await resolve_request_by_token(token[:80])
    if not row:
        raise HTTPException(status_code=404, detail="Approval link not found.")
    if expired(row):
        raise HTTPException(status_code=410, detail="This request has expired.")
    if decision == "auto_rule":
        # The UI labels this Plus; the server enforces the same lock.
        require_feature(str(row["workspace"]), "conditional_auto_approve")
    if not decide_request(row, decision):
        # A concurrent or repeated decision already won; never overwrite the
        # decided snapshot or the signed permission with a second choice.
        return RedirectResponse(
            approval_path(token, parent_origin=parent_origin, compact=compact), status_code=303
        )
    telemetry.mark_decision(str(row["id"]), decision, http_request)
    snapshot = dict(row)
    snapshot.update(
        {"status": "decided", "decision": decision, "decision_at": iso(), "policy": decision}
    )
    await blob_put_request(snapshot, decided=True)
    await dispatch_callback(row, decision)

    response = RedirectResponse(
        approval_path(token, parent_origin=parent_origin, compact=compact), status_code=303
    )
    if decision in {"approve", "always", "auto_rule"}:
        # Silent, passwordless workspace creation: the receipt itself is the
        # one-click magic link to a real dashboard. No email is required.
        owned = dashboard_code_from_cookie(http_request.cookies.get(DASHBOARD_COOKIE, ""))
        if not owned or not get_workspace(owned):
            owned = "ws_" + new_code(9)
            with transaction() as conn:
                create_org_record(conn, owned, "My agents")
            telemetry.record_login(http_request, subject=owned, source="workspace")
        response.set_cookie(
            DASHBOARD_COOKIE,
            dashboard_cookie(owned),
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite="lax",
            secure=http_request.url.scheme == "https",
            path="/",
        )
    return response


def _approval_snapshots(request_id: str) -> tuple[sqlite3.Row | dict[str, Any] | None, sqlite3.Row | None]:
    """Return the hot request row plus its durable approval ledger row."""
    rid = str(request_id or "")[:120]
    request_row = get_request_by_id(rid)
    with closing(db()) as conn:
        canonical = conn.execute(
            "SELECT * FROM approval_requests WHERE id = ?", (rid,)
        ).fetchone()
    if request_row is None and canonical is not None:
        request_row = {
            "id": canonical["id"],
            "workspace": canonical["org_id"],
            "agent": canonical["agent"],
            "action": canonical["action"],
            "summary": canonical["summary"],
            "scope_json": canonical["scope_json"],
            "scope_hash": canonical["scope_hash"],
            "requester": canonical["requester"],
            "channel": canonical["channel"],
            "gateway_hash": canonical["gateway_hash"],
            "created_at": canonical["created_at"],
            "expires_at": canonical["expires_at"],
            "status": canonical["status"],
            "decision": canonical["decision"],
            "decision_at": canonical["decision_at"],
            "policy": canonical["policy"],
        }
    return request_row, canonical


def _signed_receipt_for(canonical: sqlite3.Row | None) -> tuple[bool, dict[str, Any] | None]:
    stored = str(row_value(canonical, "signed_receipt", "") or "") if canonical is not None else ""
    if not stored:
        return False, None
    return verify_signed_receipt(stored)


def _receipt_response(
    request_row: sqlite3.Row | dict[str, Any], canonical: sqlite3.Row | None
) -> HTMLResponse:
    verified, payload = _signed_receipt_for(canonical)
    if not verified or payload is None:
        verified = False
        payload = None
    return HTMLResponse(
        receipt_page(request_row, verified, payload),
        headers={"Cache-Control": "no-store"},
    )


MCP_PROTOCOL_VERSION = "2025-06-18"
MCP_TOOLS = (
    {
        "name": "grant.request_approval",
        "description": (
            "Create one scoped human checkpoint. Returns a private approval URL; "
            "Grant never receives credentials or payment details."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_name": {"type": "string", "minLength": 1, "maxLength": 120},
                "tool_name": {"type": "string", "minLength": 1, "maxLength": 120},
                "summary": {"type": "string", "minLength": 1, "maxLength": 500},
                "scope": {"type": "object", "default": {}},
                "workspace": {"type": "string", "maxLength": 60},
                "callback_url": {"type": "string", "maxLength": 500},
                "callback_secret": {"type": "string", "maxLength": 200},
            },
            "required": ["agent_name", "tool_name", "summary"],
        },
    },
    {
        "name": "grant.get_request",
        "description": "Read the public status and signed receipt of one Grant request.",
        "inputSchema": {
            "type": "object",
            "properties": {"request_id": {"type": "string", "minLength": 1, "maxLength": 120}},
            "required": ["request_id"],
        },
    },
)


def public_openapi_document() -> dict[str, Any]:
    """A hand-written OpenAPI 3.1 contract for the zero-wrapper surfaces."""
    base = PUBLIC_BASE_URL or "https://grant-approve.vercel.app"
    ok_json = {
        "description": "Success. Public responses never include credentials, raw PII, or scope values.",
        "content": {"application/json": {"schema": {"type": "object"}}},
    }
    error_json = {
        "description": "Hard gate, invalid request, or demo limit.",
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/GrantError"}}},
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Grant Zero-Wrapper API",
            "version": "0.1.0",
            "description": (
                "Consent infrastructure for AI agents. API keys are Bearer "
                "gr_live_... strings. Credential-less calls are limited to "
                "20/hour per hashed IP. Every HTML screen carries: Grant never "
                "sees your credentials or payment details. It only records what "
                "you allowed."
            ),
        },
        "servers": [{"url": base}],
        "tags": [
            {"name": "Discovery", "description": "Machine-readable contract and MCP setup."},
            {"name": "Gate", "description": "Zero-wrapper agent approval gate."},
            {"name": "Receipts", "description": "Public signed Magic Receipts."},
        ],
        "paths": {
            "/openapi.json": {
                "get": {
                    "tags": ["Discovery"],
                    "summary": "This OpenAPI 3.1 document",
                    "operationId": "getOpenApi",
                    "responses": {"200": ok_json},
                }
            },
            "/api/openapi.json": {
                "get": {
                    "tags": ["Discovery"],
                    "summary": "Aliased OpenAPI 3.1 document",
                    "operationId": "getOpenApiAlias",
                    "responses": {"200": ok_json},
                }
            },
            "/api/mcp": {
                "get": {
                    "tags": ["Discovery"],
                    "summary": "Browser setup card for the MCP endpoint",
                    "operationId": "mcpSetup",
                    "responses": {
                        "200": {
                            "description": "MCP setup HTML",
                            "content": {"text/html": {"schema": {"type": "string"}}},
                        }
                    },
                },
                "post": {
                    "tags": ["Discovery"],
                    "summary": "MCP JSON-RPC (initialize, tools/list, tools/call)",
                    "operationId": "mcpRpc",
                    "security": [{"GrantLiveKey": []}, {}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/JsonRpcRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "JSON-RPC result or error",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/JsonRpcResponse"}
                                }
                            },
                        },
                        "429": error_json,
                    },
                },
            },
            "/v1/gate/webhook": {
                "post": {
                    "tags": ["Gate"],
                    "summary": "Create a human checkpoint (or apply an active rule first)",
                    "operationId": "gateWebhook",
                    "security": [{"GrantLiveKey": []}, {}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/GateRequest"}
                            }
                        },
                    },
                    "responses": {
                        "201": ok_json,
                        "202": ok_json,
                        "402": error_json,
                        "403": error_json,
                        "429": error_json,
                    },
                }
            },
            "/receipt/{req_id}": {
                "get": {
                    "tags": ["Receipts"],
                    "summary": "Public HMAC-signed Magic Receipt",
                    "operationId": "getReceipt",
                    "parameters": [
                        {
                            "name": "req_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Magic Receipt HTML",
                            "content": {"text/html": {"schema": {"type": "string"}}},
                        },
                        "404": error_json,
                    },
                }
            },
        },
        "components": {
            "securitySchemes": {
                "GrantLiveKey": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "gr_live_",
                    "description": "A live Grant API key. Omit it for the 20/hour demo mode.",
                }
            },
            "schemas": {
                "JsonRpcRequest": {
                    "type": "object",
                    "properties": {
                        "jsonrpc": {"const": "2.0"},
                        "id": {"type": ["string", "integer", "null"]},
                        "method": {"type": "string"},
                        "params": {"type": "object"},
                    },
                    "required": ["jsonrpc", "method"],
                },
                "JsonRpcResponse": {
                    "type": "object",
                    "properties": {
                        "jsonrpc": {"const": "2.0"},
                        "id": {"type": ["string", "integer", "null"]},
                        "result": {"type": "object"},
                        "error": {"type": "object"},
                    },
                },
                "GateRequest": {
                    "type": "object",
                    "properties": {
                        "agent": {"type": "string"},
                        "action": {"type": "string"},
                        "summary": {"type": "string"},
                        "scope": {"type": "object"},
                        "workspace": {"type": "string"},
                        "callback_url": {"type": "string"},
                        "callback_secret": {"type": "string"},
                    },
                    "required": ["agent", "action", "summary"],
                    "description": "Aliases agent_name/tool_name/reason/why are accepted.",
                },
                "GrantError": {
                    "type": "object",
                    "properties": {
                        "detail": {
                            "type": "object",
                            "properties": {
                                "error": {"type": "string"},
                                "required_tier": {"type": "string"},
                                "code": {"type": "string"},
                            },
                        }
                    },
                },
            },
        },
        "x-grant": {
            "demo_limit_per_hour": DEMO_LIMIT_PER_HOUR,
            "callback_max_retries": CALLBACK_MAX_RETRIES,
            "cors": "Public integration paths send Access-Control-Allow-Origin: *.",
            "privacy": "No credentials, payment details, raw scope values, or raw PII are returned.",
        },
    }


@app.get("/openapi.json", include_in_schema=False)
async def openapi_json() -> JSONResponse:
    return JSONResponse(
        public_openapi_document(),
        headers={"Cache-Control": "public, s-maxage=300", "Access-Control-Allow-Origin": "*"},
    )


@app.get("/api/openapi.json", include_in_schema=False)
async def openapi_json_alias() -> JSONResponse:
    return await openapi_json()


@app.get("/api/mcp", response_class=HTMLResponse)
async def mcp_setup(http_request: Request) -> HTMLResponse:
    return HTMLResponse(
        mcp_setup_page(), headers={"Cache-Control": "no-store"}
    )


def _mcp_arguments(params: dict[str, Any]) -> dict[str, Any]:
    arguments = params.get("arguments")
    return arguments if isinstance(arguments, dict) else {}


def _callback_url_is_valid(value: str) -> bool:
    url = str(value or "").strip()
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return False
    return not IS_PRODUCTION or parts.scheme == "https"


@app.post("/api/mcp")
async def mcp(http_request: Request) -> Response:
    principal = validate_bearer_if_present(http_request)
    if not public_call_allowed(http_request, bucket="mcp", authorized=bool(principal)):
        raise HTTPException(status_code=429, detail="Demo limit reached. Add a Grant API key.")
    try:
        body = await http_request.json()
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="MCP request must be JSON.")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="MCP request must be a JSON object.")
    mcp_id = body.get("id")
    method = str(body.get("method", ""))
    params = body.get("params") if isinstance(body.get("params"), dict) else {}
    if not method:
        return mcp_error(mcp_id, -32600, "Missing JSON-RPC method.")
    if method == "notifications/initialized":
        return Response(status_code=204)
    if method == "initialize":
        requested = str(params.get("protocolVersion") or MCP_PROTOCOL_VERSION)
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": mcp_id,
                "result": {
                    "protocolVersion": requested if requested == MCP_PROTOCOL_VERSION else MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "grant", "version": "0.1.0"},
                    "instructions": (
                        "Grant records one scoped human decision. It never sees credentials "
                        "or payment details."
                    ),
                },
            }
        )
    if method == "tools/list":
        return JSONResponse(
            content={"jsonrpc": "2.0", "id": mcp_id, "result": {"tools": list(MCP_TOOLS)}}
        )
    if method != "tools/call":
        return mcp_error(mcp_id, -32601, "Method not found.")
    tool_name = str(params.get("name", ""))
    args = _mcp_arguments(params)
    try:
        if tool_name == "grant.request_approval":
            agent = str(args.get("agent_name") or args.get("agent") or "").strip()[:120]
            action = str(args.get("tool_name") or args.get("action") or "").strip()[:120]
            summary = str(args.get("summary") or args.get("reason") or args.get("why") or "").strip()[:500]
            if not agent or not action or not summary:
                return mcp_error(mcp_id, -32602, "agent_name, tool_name, and summary are required.")
            scope = args.get("scope") if isinstance(args.get("scope"), dict) else {}
            callback_url = str(args.get("callback_url") or "").strip()[:500]
            if callback_url and not _callback_url_is_valid(callback_url):
                return mcp_error(mcp_id, -32602, "callback_url must be a valid HTTPS URL.")
            org = principal["org_id"] if principal else safe_org_id(args.get("workspace"))
            if callback_url:
                require_feature(org, "instant_delivery")
            result = create_request(
                RequestIn(
                    agent=agent,
                    action=action,
                    summary=summary,
                    scope=scope,
                    requester="mcp-client",
                    workspace=org,
                    callback_url=callback_url,
                    callback_secret=str(args.get("callback_secret") or "").strip()[:200],
                    owner_user_id=str(
                        args.get("owner_user_id")
                        or (principal.get("user_id") if principal else "")
                        or ""
                    )[:120],
                    ttl_minutes=int(args.get("ttl_minutes") or 30),
                    channel="mcp",
                )
            )
            content = {
                "request_id": result["id"],
                "status": "pending",
                "approval_url": result["approval_url"],
                "receipt_url": f"/receipt/{result['id']}",
                "expires_at": result["expires_at"],
                "scope_hash": result["scope_hash"],
            }
        elif tool_name == "grant.get_request":
            request_id = str(args.get("request_id") or "").strip()[:120]
            if not request_id:
                return mcp_error(mcp_id, -32602, "request_id is required.")
            request_row, canonical = _approval_snapshots(request_id)
            if request_row is None:
                return mcp_error(mcp_id, -32602, "Grant request not found.")
            verified, payload = _signed_receipt_for(canonical)
            content = {
                "request_id": request_id,
                "status": str(row_value(canonical, "status", request_row["status"])),
                "decision": str(row_value(canonical, "decision", request_row["decision"]) or ""),
                "decision_type": str(row_value(canonical, "decision_type", "") or ""),
                "signed_receipt": str(row_value(canonical, "signed_receipt", "") or ""),
                "receipt_verified": bool(verified),
                "receipt": payload or {},
                "receipt_url": f"/receipt/{request_id}",
            }
        else:
            return mcp_error(mcp_id, -32602, "Unknown Grant tool.")
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
        return mcp_error(mcp_id, exc.status_code, str(detail.get("message", detail)))
    except (TypeError, ValueError):
        return mcp_error(mcp_id, -32602, "Invalid tool arguments.")
    return JSONResponse(content={"jsonrpc": "2.0", "id": mcp_id, "result": content})


@app.post("/v1/gate/webhook")
async def gate_webhook(payload: GateWebhookIn, http_request: Request) -> JSONResponse:
    """Zero-wrapper gate call: rules first, then a quiet human checkpoint."""
    principal = validate_bearer_if_present(http_request)
    if not public_call_allowed(http_request, bucket="gate", authorized=bool(principal)):
        raise HTTPException(status_code=429, detail="Demo limit reached. Add a Grant API key.")
    org = principal["org_id"] if principal else safe_org_id(payload.workspace)
    if payload.callback_url and not _callback_url_is_valid(payload.callback_url):
        raise HTTPException(status_code=400, detail="callback_url must be a valid HTTPS URL.")
    if payload.callback_url:
        require_feature(org, "instant_delivery")
    scope_json, _ = canonical_scope(payload.scope)
    rule = find_matching_rule(org, payload.agent, payload.action, scope_json)
    if rule:
        require_feature(org, "conditional_auto_approve")
    result = create_request(
        RequestIn(
            agent=payload.agent,
            action=payload.action,
            summary=payload.summary,
            scope=payload.scope,
            requester="gate-webhook",
            workspace=org,
            callback_url=payload.callback_url,
            callback_secret=payload.callback_secret,
            owner_user_id=str(
                payload.owner_user_id
                or (principal.get("user_id") if principal else "")
                or ""
            )[:120],
            ttl_minutes=payload.ttl_minutes,
            channel=payload.channel,
        )
    )
    row = get_request_by_id(result["id"])
    decision = "auto_rule" if rule else ""
    if decision and row and decide_request(row, decision):
        await blob_put_request(dict(row), decided=True)
    if row:
        await dispatch_callback(row, decision)
    canonical_row = None
    with closing(db()) as conn:
        canonical_row = conn.execute(
            "SELECT signed_receipt, decision_type FROM approval_requests WHERE id = ?",
            (result["id"],),
        ).fetchone()
    decision_type = str(row_value(canonical_row, "decision_type", "") or "")
    return JSONResponse(
        status_code=201 if rule else 202,
        content={
            "id": result["id"],
            "status": "approved" if rule else "pending",
            "rule_id": str(rule["id"]) if rule else "",
            "approval_url": result["approval_url"],
            "receipt_url": f"/receipt/{result['id']}",
            "decision_type": decision_type,
            "signed_receipt": str(row_value(canonical_row, "signed_receipt", "") or ""),
            "expires_at": result["expires_at"],
        },
        headers={"Cache-Control": "no-store"},
    )


@app.get("/receipt/{req_id}", response_class=HTMLResponse)
async def public_receipt(req_id: str) -> HTMLResponse:
    request_row, canonical = _approval_snapshots(req_id)
    if request_row is None:
        raise HTTPException(status_code=404, detail="Receipt not found.")
    return _receipt_response(request_row, canonical)


@app.get("/approve/{req_id}", response_class=HTMLResponse)
async def checkpoint(http_request: Request, req_id: str) -> HTMLResponse:
    request_row, canonical = _approval_snapshots(req_id)
    if request_row is None:
        raise HTTPException(status_code=404, detail="Approval request not found.")
    if row_value(canonical, "status", request_row["status"]) == "decided":
        return _receipt_response(request_row, canonical)
    if expired(request_row):
        raise HTTPException(status_code=410, detail="This request has expired.")
    telemetry.record_popup(
        http_request,
        request_id=str(request_row["id"]),
        org_id=str(request_row["workspace"]),
        channel="browser_popup",
    )
    return HTMLResponse(checkpoint_page(request_row), headers={"Cache-Control": "no-store"})


@app.post("/approve/{req_id}/decide")
async def checkpoint_decide(
    http_request: Request, req_id: str, decision: str = Form("")
) -> RedirectResponse:
    choice = str(decision or "").strip().lower()
    if choice not in {"approve", "always", "reject"}:
        raise HTTPException(status_code=400, detail="Invalid decision.")
    request_row, canonical = _approval_snapshots(req_id)
    if request_row is None:
        raise HTTPException(status_code=404, detail="Approval request not found.")
    if row_value(canonical, "status", request_row["status"]) == "decided":
        return RedirectResponse(f"/receipt/{req_id}", status_code=303)
    if expired(request_row):
        raise HTTPException(status_code=410, detail="This request has expired.")
    if not decide_request(request_row, choice):
        return RedirectResponse(f"/receipt/{req_id}", status_code=303)
    if choice == "always":
        rule_id = "rule_" + new_code(12)
        with transaction() as conn:
            conn.execute(
                "INSERT INTO auto_approve_rules (id, org_id, user_id, agent, action, agent_name, "
                "tool_name, scope_json, max_amount, status, created_at, expires_at, device_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 'active', ?, ?, ?)",
                (
                    rule_id,
                    safe_org_id(request_row["workspace"]),
                    str(row_value(canonical, "owner_user_id", "") or "")[:120] or None,
                    request_row["agent"][:120],
                    request_row["action"][:120],
                    request_row["agent"][:120],
                    request_row["action"][:120],
                    str(request_row["scope_json"])[:4000],
                    iso(),
                    iso_plus(365 * 24 * 60),
                    telemetry.device_hash(http_request),
                ),
            )
    telemetry.mark_decision(str(request_row["id"]), choice, http_request)
    snapshot = dict(request_row)
    snapshot.update({"status": "decided", "decision": choice, "decision_at": iso()})
    await blob_put_request(snapshot, decided=True)
    await dispatch_callback(request_row, choice)
    return RedirectResponse(f"/receipt/{req_id}", status_code=303)


@app.get("/signup", response_class=HTMLResponse)
async def signup(next: str = "/account", error: int = 0) -> HTMLResponse:
    return HTMLResponse(
        signup_page(next, bool(error)), headers={"Cache-Control": "no-store"}
    )


@app.post("/signup")
async def signup_submit(http_request: Request) -> Response:
    if rate_limited(http_request):
        raise HTTPException(status_code=429, detail="Too many sign-ups. Slow down.")
    data = await _request_fields(http_request)
    target = safe_next_path(str(data.get("next") or "/account"))
    if str(data.get("installed") or "") != "1":
        return RedirectResponse(
            f"/signup?{urlencode({'next': target, 'error': 1})}", status_code=303
        )
    email = normalize_billing_email(data.get("email", ""))
    if not valid_email(email):
        return RedirectResponse(
            f"/signup?{urlencode({'next': target, 'error': 1})}", status_code=303
        )
    raw = "ml_" + new_code(24)
    with transaction() as conn:
        conn.execute(
            "INSERT INTO magic_links (token_hash, email, org_id, claim_token, expires_at, "
            "used_at, created_at) VALUES (?, ?, ?, NULL, ?, NULL, ?)",
            (hash_token(raw), email, None, iso_plus(MAGIC_LINK_TTL_MINUTES), iso()),
        )
    base = PUBLIC_BASE_URL or str(http_request.base_url).rstrip("/")
    link = f"{base}/auth/verify?{urlencode({'token': raw, 'next': target})}"
    try:
        provider = emailer.send_magic_link(email, link, env=os.environ)
    except emailer.EmailError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    dev = (
        f'<p class="sub"><a href="{html.escape(link, quote=True)}">Open the development link</a></p>'
        if provider == "console"
        else ""
    )
    body = header() + f"""<section class="intro glass"><div class="seal">✓</div>
<h1>Check your email.</h1><p class="lede left">Your one-time Grant sign-in link is on its way. Add the shortcut now so the next checkpoint opens as an app.</p>{dev}
<div class="install-card"><button class="btn" type="button" data-grant-install>Add Shortcut</button></div>
<p class="sub">The link expires in {MAGIC_LINK_TTL_MINUTES} minutes and works once.</p>
<p class="watermark">● Protected by Grant · Zero-custody consent infrastructure</p></section>"""
    return HTMLResponse(
        page("Check your email — Grant", body, "Your Grant sign-in link is ready.", private=True),
        headers={"Cache-Control": "no-store"},
    )


@app.get("/account", response_class=HTMLResponse)
async def account(http_request: Request, claim: str = "") -> HTMLResponse:
    principal = principal_from_request(http_request)
    return HTMLResponse(
        account_page(http_request, principal, claim=claim),
        headers={"Cache-Control": "no-store"},
    )


@app.post("/account/keys")
async def account_mint_key(http_request: Request, name: str = Form("")) -> HTMLResponse:
    principal = require_user_principal(http_request)
    with transaction() as conn:
        _, raw = mint_api_key(conn, principal["org_id"], principal["user_id"], name)
    return HTMLResponse(
        account_page(http_request, principal, raw_key=raw),
        headers={"Cache-Control": "no-store"},
    )


@app.post("/account/claim")
async def account_claim(http_request: Request, claim: str = Form("")) -> RedirectResponse:
    principal = require_user_principal(http_request)
    marker = "ok" if claim_unclaimed_payment(principal["org_id"], claim) else "missing"
    return RedirectResponse(f"/account?claim={marker}", status_code=303)


@app.post("/account/rules/{rule_id}/revoke")
async def account_revoke_rule(http_request: Request, rule_id: str) -> RedirectResponse:
    principal = require_user_principal(http_request)
    with transaction() as conn:
        conn.execute(
            "UPDATE auto_approve_rules SET status = 'revoked', revoked_at = ? WHERE id = ? "
            "AND (org_id = ? OR user_id = ?)",
            (iso(), rule_id[:120], principal["org_id"], principal["user_id"]),
        )
    return RedirectResponse("/account?rule=revoked", status_code=303)


@app.post("/account/rules/{rule_id}/cap")
async def account_rule_cap(http_request: Request, rule_id: str) -> RedirectResponse:
    principal = require_user_principal(http_request)
    require_feature(principal["org_id"], "conditional_auto_approve")
    data = await _request_fields(http_request)
    raw_cap = str(data.get("max_amount") or "").strip()
    try:
        cap = float(raw_cap) if raw_cap else None
    except ValueError:
        return RedirectResponse("/account?cap=invalid", status_code=303)
    if cap is not None and (cap < 0 or cap > 1_000_000_000):
        return RedirectResponse("/account?cap=invalid", status_code=303)
    raw_condition = str(data.get("condition") or "").strip()
    condition = "{}"
    if raw_condition:
        try:
            parsed = json.loads(raw_condition)
            condition = canonical_json(parsed) if isinstance(parsed, dict) else ""
        except json.JSONDecodeError:
            return RedirectResponse("/account?cap=invalid", status_code=303)
    with transaction() as conn:
        conn.execute(
            "UPDATE auto_approve_rules SET max_amount = ?, condition_json = ? WHERE id = ? "
            "AND (org_id = ? OR user_id = ?)",
            (cap, condition, rule_id[:120], principal["org_id"], principal["user_id"]),
        )
    return RedirectResponse("/account?cap=saved", status_code=303)


@app.get("/manifest.webmanifest")
async def manifest() -> JSONResponse:
    return JSONResponse(
        content={
            "name": "Grant — Zero-custody consent",
            "short_name": "Grant",
            "description": "One quiet human checkpoint for every AI agent action.",
            "start_url": "/account",
            "scope": "/",
            "display": "standalone",
            "background_color": "#FAF8F5",
            "theme_color": "#FAF8F5",
            "icons": [
                {
                    "src": "/icons/icon-192.svg",
                    "sizes": "192x192",
                    "type": "image/svg+xml",
                    "purpose": "any maskable",
                },
                {
                    "src": "/icons/icon-512.svg",
                    "sizes": "512x512",
                    "type": "image/svg+xml",
                    "purpose": "any maskable",
                },
            ],
        },
        media_type="application/manifest+json",
        headers={"Cache-Control": "public, s-maxage=3600"},
    )


@app.get("/sw.js", response_class=PlainTextResponse)
async def service_worker() -> PlainTextResponse:
    script = """
const CACHE = 'grant-shell-v1';
const PUBLIC_ASSETS = ['/', '/manifest.webmanifest', '/icons/icon-192.svg', '/icons/icon-512.svg'];
self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(PUBLIC_ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') { return; }
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) { return; }
  if (PUBLIC_ASSETS.includes(url.pathname)) {
    event.respondWith(caches.match(request).then((cached) => cached || fetch(request).then((response) => {
      const copy = response.clone();
      caches.open(CACHE).then((cache) => cache.put(request, copy));
      return response;
    })));
    return;
  }
  // Private screens such as /account are never cached.
  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).catch(() => caches.match('/')));
  }
});
"""
    return PlainTextResponse(
        script.strip(),
        media_type="application/javascript",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/icons/icon-{size}.svg", response_class=PlainTextResponse)
async def pwa_icon(size: int) -> PlainTextResponse:
    if size not in {192, 512}:
        raise HTTPException(status_code=404, detail="Icon size not found.")
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img" aria-label="Grant">
<rect width="{size}" height="{size}" rx="{size // 5}" fill="#FAF8F5"/>
<rect x="{size // 10}" y="{size // 10}" width="{size - size // 5}" height="{size - size // 5}" rx="{size // 6}" fill="#6d2038"/>
<text x="{size // 2}" y="{int(size * 0.66)}" font-size="{int(size * 0.5)}" text-anchor="middle" fill="#fff8f2" font-family="Georgia, serif" font-weight="700">G</text>
</svg>"""
    return PlainTextResponse(
        svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, s-maxage=3600"},
    )


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt() -> str:
    return (
        "User-agent: *\nAllow: /\nDisallow: /a/\nDisallow: /r/\nDisallow: /v1/\n"
        "Disallow: /w/\nDisallow: /console\nDisallow: /ops\nDisallow: /login-history\n"
        "Disallow: /protected/\n\n"
        f"Sitemap: {PUBLIC_BASE_URL or 'https://grant-approve.vercel.app'}/sitemap.xml\n"
    )


@app.get("/sitemap.xml", response_class=PlainTextResponse)
async def sitemap_xml() -> str:
    base = PUBLIC_BASE_URL or "https://grant-approve.vercel.app"
    pages = (("/", "1.0"), ("/docs", "0.9"), ("/pricing", "0.8"), ("/stats", "0.7"), ("/start", "0.6"))
    urls = "".join(
        f"<url><loc>{html.escape(base)}{path}</loc><priority>{priority}</priority></url>"
        for path, priority in pages
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{urls}</urlset>"
    )
