"""Small SQLite/Neon Postgres adapter for Grant.

The app intentionally uses one very small query dialect (SQLite-style ``?``
parameters). When ``DATABASE_URL``, ``NEON_DATABASE_URL`` or
``GRANT_NEON_DATABASE_URL`` is present, this module translates those queries to
psycopg's ``%s`` style and applies the durable schema in ``migrations/``.
Without a DSN, behavior is unchanged for local development: a new SQLite
connection per call. Production refuses to boot on that ephemeral fallback
unless ``GRANT_ALLOW_SQLITE_IN_PROD=true`` is explicitly set.
"""
from __future__ import annotations

import os
import re
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from threading import Lock
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
SQLITE_PATH = Path(os.environ.get("GRANT_DB", ROOT / "grant.db"))
SCHEMA_PATH = ROOT / "migrations" / "001_neon_schema.sql"

_DSN = (
    os.environ.get("DATABASE_URL")
    or os.environ.get("NEON_DATABASE_URL")
    or os.environ.get("GRANT_NEON_DATABASE_URL")
    or ""
).strip()
_DB_LOCK = Lock()
_APP_ENV = os.environ.get("GRANT_APP_ENV", "development").strip().lower()
_ALLOW_SQLITE_IN_PROD = os.environ.get(
    "GRANT_ALLOW_SQLITE_IN_PROD", ""
).strip().lower() in {"1", "true", "yes"}


def postgres_enabled() -> bool:
    return bool(_DSN)


def require_production_store() -> None:
    """Fail fast instead of silently serving ephemeral SQLite in production."""
    if _APP_ENV == "production" and not _DSN and not _ALLOW_SQLITE_IN_PROD:
        raise RuntimeError(
            "DATABASE_URL is required in production. Set a Neon Postgres DSN "
            "or explicitly set GRANT_ALLOW_SQLITE_IN_PROD=true."
        )


def schema_sql() -> str:
    return SCHEMA_PATH.read_text(encoding="utf-8")


def _translate(sql: str) -> str:
    query = sql.replace("?", "%s")
    if re.search(r"INSERT\s+OR\s+IGNORE", query, re.IGNORECASE):
        query = re.sub(r"INSERT\s+OR\s+IGNORE", "INSERT", query, count=1, flags=re.IGNORECASE)
        stripped = query.rstrip().rstrip(";").rstrip()
        if not re.search(r"ON\s+CONFLICT", stripped, re.IGNORECASE):
            query = stripped + " ON CONFLICT DO NOTHING"
    return query


class Cursor:
    """psycopg cursor adapter exposing the sqlite3 methods Grant uses."""

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> "Cursor":
        query = _translate(sql)
        # A schema bootstrap contains several statements; passing an empty
        # parameter tuple can force server-side preparation in psycopg.
        if params:
            self._cursor.execute(query, params)
        else:
            self._cursor.execute(query)
        return self

    def executemany(self, sql: str, seq: Any) -> "Cursor":
        self._cursor.executemany(_translate(sql), seq)
        return self

    def fetchone(self) -> dict[str, Any] | None:
        row = self._cursor.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self._cursor.fetchall()]

    @property
    def rowcount(self) -> int:
        return int(self._cursor.rowcount)

    @property
    def description(self) -> Any:
        return self._cursor.description


class Connection:
    """psycopg connection adapter exposing ``conn.execute`` like sqlite3."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Cursor:
        return Cursor(self._connection.cursor()).execute(sql, params)

    def executemany(self, sql: str, seq: Any) -> Cursor:
        return Cursor(self._connection.cursor()).executemany(sql, seq)

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        self.close()


def connection():
    if postgres_enabled():
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - dependency declared in requirements
            raise RuntimeError("psycopg is required when a Neon DATABASE_URL is configured") from exc
        return Connection(psycopg.connect(_DSN, row_factory=dict_row))
    SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(SQLITE_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def transaction() -> Iterator[Any]:
    if postgres_enabled():
        conn = connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        return
    with _DB_LOCK, closing(connection()) as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def ensure_column(conn: Any, table: str, column: str, declaration: str) -> None:
    """Portable column backfill for small schema additions."""
    if postgres_enabled():
        row = conn.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = ? AND column_name = ? LIMIT 1",
            (table, column),
        ).fetchone()
        if not row:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
        return
    names = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in names:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
