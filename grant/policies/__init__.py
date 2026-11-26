"""Machine-readable, zero-custody OAuth scope policy templates."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

TEMPLATE_PATH = Path(__file__).resolve().parent / "oauth_scopes.json"


def load_oauth_templates() -> dict[str, Any]:
    """Return the full template document. Never contains provider credentials."""
    return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))


def template_for(scope: str) -> dict[str, Any] | None:
    document = load_oauth_templates()
    return document.get("templates", {}).get(str(scope or "").strip().lower())


def gateway_policy_for(scope: str, *, workspace: str = "public") -> dict[str, Any] | None:
    """Translate one OAuth scope template into a GrantGateway policy payload."""
    template = template_for(scope)
    if not template:
        return None
    return {
        "name": f"{template['provider']}:{scope}",
        "workspace": workspace,
        "sensitive_tools": list(template.get("sensitive_tools") or []),
        "sensitive_paths": [],
        "body_keys": list(template.get("body_keys") or []),
        "default_action": "review",
        "scope": template.get("scope") or {},
        "decision_hint": template.get("decision_hint", "require_human"),
        "risk": template.get("risk", "medium"),
        "custody": "zero",
    }
