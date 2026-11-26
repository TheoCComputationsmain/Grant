"""Privacy-preserving login and pop-up telemetry for Grant.

The module is intentionally dependency-free and lazy about importing the FastAPI
app so it can be reused from tests and scripts. It stores salted SHA-256 hashes,
never raw IP addresses, device identifiers, or approval tokens. Stats returned
to callers are aggregate counts plus coarse device labels only.
"""
from __future__ import annotations

import hashlib
import os
import re
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any

CHANNELS = frozenset(
    {"mcp_gateway", "browser_popup", "browser_inject", "a2a", "email", "slack", "console"}
)
DEFAULT_CHANNEL = "browser_popup"


def _main():  # pragma: no cover - trivial indirection
    import main

    return main


def _salt() -> str:
    return (
        os.environ.get("GRANT_TELEMETRY_SALT")
        or os.environ.get("GRANT_SIGNING_SECRET")
        or "grant-local-telemetry"
    )


def hash_value(value: str) -> str:
    return hashlib.sha256((_salt() + "|" + str(value or "")).encode("utf-8")).hexdigest()


def normalize_channel(value: str | None) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if candidate in CHANNELS else DEFAULT_CHANNEL


def _header(request: Any, name: str) -> str:
    try:
        return str(request.headers.get(name, "") or "")[:500]
    except (AttributeError, TypeError):
        return ""


def client_ip(request: Any) -> str:
    forwarded = _header(request, "x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    try:
        return str(request.client.host if request.client else "")  # type: ignore[union-attr]
    except AttributeError:
        return ""


def ip_hash(request: Any) -> str:
    return hash_value("ip|" + client_ip(request))


def user_agent(request: Any) -> str:
    return _header(request, "user-agent")[:300]


def device_hash(request: Any) -> str:
    fingerprint = "|".join(
        (
            _header(request, "x-grant-device-id"),
            user_agent(request),
            _header(request, "sec-ch-ua"),
            _header(request, "sec-ch-ua-platform"),
            _header(request, "sec-ch-ua-mobile"),
            client_ip(request),
        )
    )
    return hash_value("device|" + fingerprint)


def user_hash(subject: str) -> str:
    return hash_value("user|" + str(subject or ""))


def approver_hash(device: str, request_id: str) -> str:
    return hash_value("approver|" + device + "|" + request_id)


def session_hash(subject: str, device: str, *, now: datetime | None = None) -> str:
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d")
    return hash_value("session|" + subject + "|" + device + "|" + stamp)


def device_label(ua: str) -> str:
    text = str(ua or "")
    browser = "Unknown browser"
    for name, pattern in (
        ("Edge", r"Edg/"),
        ("Chrome", r"Chrome/"),
        ("Firefox", r"Firefox/"),
        ("Safari", r"Safari/"),
    ):
        if re.search(pattern, text):
            browser = name
            break
    os_name = "Unknown OS"
    for name, pattern in (
        ("Windows", r"Windows"),
        ("Android", r"Android"),
        ("iOS", r"iPhone|iPad"),
        ("macOS", r"Macintosh|Mac OS"),
        ("Linux", r"Linux"),
    ):
        if re.search(pattern, text):
            os_name = name
            break
    return f"{browser} / {os_name}"


def ensure_sqlite_tables(conn: Any) -> None:
    """Telemetry tables for the local/SQLite path (Neon uses migrations/)."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS login_history (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            email TEXT,
            ip_hash TEXT NOT NULL,
            device_hash TEXT NOT NULL,
            user_agent TEXT,
            session_id TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'workspace',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS popup_impressions (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            org_id TEXT NOT NULL,
            channel TEXT NOT NULL,
            device_hash TEXT NOT NULL,
            user_agent TEXT,
            opened_at TEXT NOT NULL,
            decision TEXT,
            approver_hash TEXT
        )
        """
    )
    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_login_created ON login_history(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_login_user ON login_history(user_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_login_session ON login_history(session_id, created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_popup_opened ON popup_impressions(opened_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_popup_request ON popup_impressions(request_id)",
        "CREATE INDEX IF NOT EXISTS idx_popup_device ON popup_impressions(device_hash)",
    ):
        conn.execute(statement)


def record_login(
    request: Any,
    *,
    subject: str,
    email: str = "",
    source: str = "workspace",
) -> str:
    """Record a silent workspace session. Returns only an internal row id."""
    main = _main()
    try:
        uid = user_hash(subject)
        device = device_hash(request)
        event_id = "login_" + main.new_code(9)
        with main.transaction() as conn:
            conn.execute(
                """
                INSERT INTO login_history
                    (id, user_id, email, ip_hash, device_hash, user_agent,
                     session_id, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    uid,
                    main.normalize_billing_email(email) or None,
                    ip_hash(request),
                    device,
                    user_agent(request),
                    session_hash(subject, device),
                    str(source or "workspace")[:40],
                    main.iso(),
                ),
            )
        return event_id
    except Exception:
        return ""


def record_popup(
    request: Any,
    *,
    request_id: str,
    org_id: str,
    channel: str = DEFAULT_CHANNEL,
) -> str:
    """Record one approval card render/open. Never stores raw identifiers."""
    main = _main()
    try:
        event_id = "popup_" + main.new_code(9)
        with main.transaction() as conn:
            conn.execute(
                """
                INSERT INTO popup_impressions
                    (id, request_id, org_id, channel, device_hash, user_agent, opened_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    str(request_id)[:120],
                    str(org_id)[:120],
                    normalize_channel(channel),
                    device_hash(request),
                    user_agent(request),
                    main.iso(),
                ),
            )
        return event_id
    except Exception:
        return ""


def mark_decision(request_id: str, decision: str, request: Any = None) -> bool:
    """Attach the human decision to the most recent impression for a request."""
    main = _main()
    try:
        with main.transaction() as conn:
            cursor = conn.execute(
                """
                UPDATE popup_impressions
                SET decision = ?, approver_hash = ?
                WHERE request_id = ? AND (decision IS NULL OR decision = '')
                """,
                (
                    str(decision)[:20],
                    approver_hash(device_hash(request) if request is not None else "", request_id),
                    str(request_id)[:120],
                ),
            )
        return bool(cursor.rowcount)
    except Exception:
        return False


def _count(conn: Any, sql: str, params: tuple[Any, ...] = ()) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row else 0


def overview() -> dict[str, Any]:
    """Live reach metrics. Publicly safe: counts and coarse device labels only."""
    main = _main()
    with closing(main.db()) as conn:
        total_users = _count(
            conn,
            "SELECT COUNT(*) FROM ("
            "SELECT code AS subject FROM workspaces UNION "
            "SELECT user_id AS subject FROM login_history WHERE user_id <> ''"
            ") AS subjects",
        )
        humans = _count(
            conn,
            "SELECT COUNT(*) FROM ("
            "SELECT user_id AS subject FROM login_history WHERE user_id <> '' UNION "
            "SELECT approver_hash AS subject FROM popup_impressions "
            "WHERE approver_hash IS NOT NULL AND approver_hash <> ''"
            ") AS subjects",
        )
        impressions = _count(conn, "SELECT COUNT(*) FROM popup_impressions")
        devices = _count(
            conn,
            "SELECT COUNT(*) FROM ("
            "SELECT device_hash AS subject FROM login_history UNION "
            "SELECT device_hash AS subject FROM popup_impressions"
            ") AS subjects",
        )
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
        active = _count(
            conn,
            "SELECT COUNT(DISTINCT session_id) FROM login_history WHERE created_at >= ?",
            (cutoff,),
        )
        recent = conn.execute(
            "SELECT created_at, source, user_agent FROM login_history "
            "ORDER BY created_at DESC LIMIT 8"
        ).fetchall()
        breakdown = conn.execute(
            "SELECT user_agent, COUNT(*) AS total FROM login_history "
            "GROUP BY user_agent ORDER BY total DESC LIMIT 5"
        ).fetchall()
    return {
        "total_users": total_users,
        "unique_humans_reached": humans,
        "popup_impressions": impressions,
        "unique_devices": devices,
        "active_sessions": active,
        "recent_logins": [
            {
                "created_at": str(row["created_at"]),
                "source": str(row["source"] or "workspace"),
                "device": device_label(str(row["user_agent"] or "")),
            }
            for row in recent
        ],
        "device_breakdown": [
            {"device": device_label(str(row["user_agent"] or "")), "count": int(row["total"])}
            for row in breakdown
        ],
    }
