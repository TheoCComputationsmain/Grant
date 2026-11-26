"""Grant login & pop-up reach library.

Read-only queries behind the token-gated `/login-history` views. This library
answers four concrete questions without exposing private data:

* how many users we have (``total_users``),
* how many times we popped up (``popup_impressions``),
* on how many computers (``unique_computers``),
* how many login sessions happened (``total_logins``).

Every value is an aggregate count or a coarse browser/OS label. Raw emails,
IP addresses, device identifiers, workspace codes, and approval tokens are
never returned. Storage is the same SQLite/Neon adapter the rest of Grant uses.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any

from . import telemetry


def _main():  # pragma: no cover - trivial indirection, avoids an import cycle
    import main

    return main


SAFE_SOURCES = frozenset({"workspace", "console", "signin"})


def summary() -> dict[str, Any]:
    """One snapshot of users, logins, pop-ups, and distinct computers."""
    main = _main()
    with closing(main.db()) as conn:
        users = _count(
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
        logins = _count(conn, "SELECT COUNT(*) FROM login_history")
        popups = _count(conn, "SELECT COUNT(*) FROM popup_impressions")
        decided = _count(
            conn,
            "SELECT COUNT(*) FROM popup_impressions "
            "WHERE decision IS NOT NULL AND decision <> ''",
        )
        computers = _count(
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
    return {
        "generated_at": main.iso(),
        "total_users": users,
        "unique_humans_reached": humans,
        "total_logins": logins,
        "popup_impressions": popups,
        "decided_popups": decided,
        "unique_computers": computers,
        "active_sessions": active,
    }


def login_history(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    """Sanitized login events: timestamp, source, and coarse device label."""
    main = _main()
    size = max(1, min(500, int(limit)))
    start = max(0, int(offset))
    with closing(main.db()) as conn:
        rows = conn.execute(
            "SELECT created_at, source, user_agent FROM login_history "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (size, start),
        ).fetchall()
    return [
        {
            "created_at": str(row["created_at"]),
            "source": str(row["source"] or "workspace")
            if str(row["source"] or "workspace") in SAFE_SOURCES
            else "workspace",
            "device": telemetry.device_label(str(row["user_agent"] or "")),
        }
        for row in rows
    ]


def popup_history(limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    """Sanitized pop-up events: timestamp, channel, device, and decision."""
    main = _main()
    size = max(1, min(500, int(limit)))
    start = max(0, int(offset))
    with closing(main.db()) as conn:
        rows = conn.execute(
            "SELECT opened_at, channel, user_agent, decision FROM popup_impressions "
            "ORDER BY opened_at DESC LIMIT ? OFFSET ?",
            (size, start),
        ).fetchall()
    return [
        {
            "opened_at": str(row["opened_at"]),
            "channel": telemetry.normalize_channel(str(row["channel"] or "")),
            "device": telemetry.device_label(str(row["user_agent"] or "")),
            "decision": str(row["decision"] or "pending")[:20],
        }
        for row in rows
    ]


def devices() -> list[dict[str, Any]]:
    """Coarse device breakdown across login and pop-up events."""
    main = _main()
    with closing(main.db()) as conn:
        rows = conn.execute(
            "SELECT user_agent, COUNT(*) AS total FROM login_history "
            "GROUP BY user_agent "
            "UNION ALL "
            "SELECT user_agent, COUNT(*) AS total FROM popup_impressions "
            "GROUP BY user_agent"
        ).fetchall()
    combined: dict[str, int] = {}
    for row in rows:
        label = telemetry.device_label(str(row["user_agent"] or ""))
        combined[label] = combined.get(label, 0) + int(row["total"])
    return [
        {"device": label, "count": total}
        for label, total in sorted(combined.items(), key=lambda item: item[1], reverse=True)
    ]


def report(limit: int = 100) -> dict[str, Any]:
    """Everything the login-history space needs in one privacy-safe payload."""
    return {
        **summary(),
        "login_history": login_history(limit=limit),
        "popup_history": popup_history(limit=limit),
        "devices": devices(),
    }


def _count(conn: Any, sql: str, params: tuple[Any, ...] = ()) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row else 0
