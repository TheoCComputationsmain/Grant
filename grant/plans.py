"""Plan tiers, limits, and trial rules for Grant.

This module is intentionally dependency-free. It defines the commercial contract
that the approval UI, console, usage meter, and billing webhook all share.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

ANNUAL_DISCOUNT = 0.20
TRIAL_DAYS = 14


@dataclass(frozen=True)
class Tier:
    id: str
    name: str
    monthly_usd: int | None
    annual_usd: float | None
    monthly_inr: int | None
    annual_inr: float | None
    approvals_per_month: int | None
    log_retention_days: int | None
    approvers: int | None
    channels: tuple[str, ...]
    spend_caps: bool
    conditional_rules: bool
    badge: str = ""
    positioning: str = ""
    features: tuple[str, ...] = ()
    conditional_auto_approve: bool = False
    instant_delivery: bool = False
    multi_approver_routing: bool = False
    mobile_channels: bool = False
    compliance_exports: bool = False
    white_label: bool = False
    sso_saml: bool = False
    siem_streaming: bool = False


TIERS: dict[str, Tier] = {
    "free": Tier(
        id="free",
        name="Free",
        monthly_usd=0,
        annual_usd=0,
        monthly_inr=0,
        annual_inr=0,
        approvals_per_month=1_000,
        log_retention_days=7,
        approvers=1,
        channels=("email", "web"),
        spend_caps=False,
        conditional_rules=False,
        positioning="For trying an agent safely before it touches real money or users.",
        features=(
            "Basic Approve once / Always allow pop-up",
            "Email & Web links (1,000/mo)",
            "7-day audit trail",
        ),
    ),
    "plus": Tier(
        id="plus",
        name="Plus",
        monthly_usd=20,
        annual_usd=round(20 * 12 * (1 - ANNUAL_DISCOUNT), 2),
        monthly_inr=2_400,
        annual_inr=round(2_400 * 12 * (1 - ANNUAL_DISCOUNT), 2),
        approvals_per_month=15_000,
        log_retention_days=30,
        approvers=1,
        channels=("email", "web", "slack", "webhook"),
        spend_caps=True,
        conditional_rules=True,
        badge="Most popular for production",
        positioning="For solo builders putting an agent into production with real users or money.",
        features=(
            "Auto-approve rules (spend/scope caps)",
            "Slack & Webhook instant approvals (15,000/mo)",
            "30-day audit log retention",
        ),
        conditional_auto_approve=True,
        instant_delivery=True,
    ),
    "pro": Tier(
        id="pro",
        name="Pro",
        monthly_usd=150,
        annual_usd=round(150 * 12 * (1 - ANNUAL_DISCOUNT), 2),
        monthly_inr=12_600,
        annual_inr=round(12_600 * 12 * (1 - ANNUAL_DISCOUNT), 2),
        approvals_per_month=100_000,
        log_retention_days=365,
        approvers=15,
        channels=("email", "web", "slack", "webhook", "sms", "whatsapp"),
        spend_caps=True,
        conditional_rules=True,
        badge="For compliance teams",
        positioning="For companies and engineering teams running agents across departments with compliance needs.",
        features=(
            "Multi-approver routing & role rules",
            "SMS / WhatsApp approval alerts (100,000/mo)",
            "1-year audit trail + CSV/JSON exports",
        ),
        conditional_auto_approve=True,
        instant_delivery=True,
        multi_approver_routing=True,
        mobile_channels=True,
        compliance_exports=True,
    ),
    "enterprise": Tier(
        id="enterprise",
        name="Enterprise",
        monthly_usd=4_000,
        annual_usd=None,
        monthly_inr=340_000,
        annual_inr=None,
        approvals_per_month=None,
        log_retention_days=None,
        approvers=None,
        channels=("email", "web", "slack", "webhook", "sms", "whatsapp", "custom"),
        spend_caps=True,
        conditional_rules=True,
        badge="Book a call",
        positioning="For large organizations and platforms embedding Grant at scale under strict security and legal procurement.",
        features=(
            "White-label domain & custom branding",
            "SSO / SAML & org directory sync",
            "99.99% SLA + real-time SIEM log streaming",
        ),
        conditional_auto_approve=True,
        instant_delivery=True,
        multi_approver_routing=True,
        mobile_channels=True,
        compliance_exports=True,
        white_label=True,
        sso_saml=True,
        siem_streaming=True,
    ),
}

ORDER = ("free", "plus", "pro", "enterprise")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or utcnow()).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def tier(name: str) -> Tier:
    key = str(name or "").strip().lower()
    return TIERS.get(key, TIERS["free"])


def feature_locks(name: str) -> dict[str, bool]:
    """Explicit commercial locks shared by the pricing page and plan payloads."""
    selected = tier(name)
    return {
        "conditional_auto_approve": selected.conditional_auto_approve,
        "instant_delivery": selected.instant_delivery,
        "multi_approver_routing": selected.multi_approver_routing,
        "mobile_channels": selected.mobile_channels,
        "compliance_exports": selected.compliance_exports,
        "white_label": selected.white_label,
        "sso_saml": selected.sso_saml,
        "siem_streaming": selected.siem_streaming,
    }


def limits(name: str) -> dict[str, Any]:
    selected = tier(name)
    return {
        "tier": selected.id,
        "name": selected.name,
        "approvals_per_month": selected.approvals_per_month,
        "log_retention_days": selected.log_retention_days,
        "approvers": selected.approvers,
        "channels": list(selected.channels),
        "spend_caps": selected.spend_caps,
        "conditional_rules": selected.conditional_rules,
        "positioning": selected.positioning,
        "features": list(selected.features),
        "locks": feature_locks(selected.id),
    }


def default_plan(org_id: str, *, trial_days: int = TRIAL_DAYS, created_at: str | None = None) -> dict[str, Any]:
    """New organizations get a 14-day Pro Guardrails reverse trial."""
    created = parse(created_at) or utcnow()
    return {
        "org_id": str(org_id)[:120],
        "tier": "free",
        "status": "trial",
        "trial_tier": "pro",
        "trial_ends_at": iso(created + timedelta(days=max(0, trial_days))),
        "plan_expires_at": "",
        "quota_reset_at": "",
        "checkout_id": "",
        "customer_ref": "",
        "created_at": iso(created),
        "updated_at": iso(created),
    }


def effective_tier(plan: dict[str, Any] | None, *, now: datetime | None = None) -> str:
    if not plan:
        return "free"
    current = now or utcnow()
    if plan.get("status") == "trial":
        ends = parse(plan.get("trial_ends_at"))
        if ends and ends > current:
            return str(plan.get("trial_tier") or "pro")
    paid = str(plan.get("tier") or "free")
    if plan.get("status") in {"active", "trial"} and paid in TIERS:
        expiry = parse(plan.get("plan_expires_at"))
        if expiry and expiry <= current:
            return "free"
        return paid
    return "free"


def trial_days_left(plan: dict[str, Any] | None, *, now: datetime | None = None) -> int:
    if not plan or plan.get("status") != "trial":
        return 0
    ends = parse(plan.get("trial_ends_at"))
    if not ends:
        return 0
    return max(0, (ends - (now or utcnow())).days)


def usage_state(plan: dict[str, Any] | None, used: int, *, now: datetime | None = None) -> dict[str, Any]:
    selected = tier(effective_tier(plan, now=now))
    limit = selected.approvals_per_month
    state = "ok"
    if limit is not None and used >= limit:
        state = "over"
    elif limit is not None and used >= int(limit * 0.85):
        state = "near"
    return {
        "used": max(0, int(used)),
        "limit": limit,
        "remaining": None if limit is None else max(0, limit - used),
        "state": state,
        "tier": selected.id,
        "trial_days_left": trial_days_left(plan, now=now),
    }


def public_pricing() -> list[dict[str, Any]]:
    rows = []
    for key in ORDER:
        selected = TIERS[key]
        rows.append(
            {
                "id": selected.id,
                "name": selected.name,
                "monthly_usd": selected.monthly_usd,
                "annual_usd": selected.annual_usd,
                "monthly_inr": selected.monthly_inr,
                "annual_inr": selected.annual_inr,
                "approvals_per_month": selected.approvals_per_month,
                "log_retention_days": selected.log_retention_days,
                "approvers": selected.approvers,
                "channels": list(selected.channels),
                "spend_caps": selected.spend_caps,
                "conditional_rules": selected.conditional_rules,
                "badge": selected.badge,
                "positioning": selected.positioning,
                "features": list(selected.features),
                "locks": feature_locks(selected.id),
            }
        )
    return rows
