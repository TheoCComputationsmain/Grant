"""Hosted checkout links and provider-agnostic billing webhook helpers.

Grant never handles card data, wallet balances, escrow, refunds, or auto-deduction.
This module keeps one webhook verification and normalization pipeline; the
provider-specific link creation lives in :mod:`grant.cashfree`.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit

SAFE_ORG_ID = re.compile(r"^[A-Za-z0-9_-]{1,120}$")
SAFE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_WEBHOOK_AGE_SECONDS = 300
ENTERPRISE_ENV_KEY = "GRANT_ENTERPRISE_CONTACT_URL"
WEBHOOK_SECRET_ENV_KEY = "GRANT_BILLING_WEBHOOK_SECRET"
PAID_TIERS = frozenset({"plus", "pro", "enterprise"})


def safe_org_id(value: str | None) -> str:
    candidate = str(value or "").strip()
    return candidate if SAFE_ORG_ID.fullmatch(candidate) else ""


def _with_params(url: str, params: dict[str, str]) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update({key: value for key, value in params.items() if value})
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )


def enterprise_contact_url(
    org_id: str | None,
    *,
    env: Mapping[str, str] | None = None,
) -> str | None:
    environ = env if env is not None else os.environ
    base = str(environ.get(ENTERPRISE_ENV_KEY, "")).strip()
    org = safe_org_id(org_id)
    if not base or not org:
        return None
    return _with_params(base, {"org_id": org, "plan": "enterprise"})


def _fresh(timestamp: str | None, *, now: float | None, milliseconds: bool) -> bool:
    try:
        sent_at = int(str(timestamp or "").strip())
    except (TypeError, ValueError):
        return False
    if milliseconds and sent_at > 10**12:
        sent_at //= 1000
    current = int(now if now is not None else time.time())
    return abs(current - sent_at) <= MAX_WEBHOOK_AGE_SECONDS


def verify_webhook(
    raw_body: bytes,
    signature: str | None,
    timestamp: str | None,
    *,
    secret: str | None = None,
    now: float | None = None,
    mode: str = "grant",
) -> bool:
    """Verify an HMAC-SHA256 webhook signature.

    ``grant`` uses hex over ``timestamp.raw_body``. ``cashfree`` uses Base64
    over ``timestamp + raw_body`` with millisecond timestamps. All comparisons
    are constant-time. No secret material is logged or returned.
    """
    if not raw_body or not signature or not timestamp or not secret:
        return False
    if not _fresh(timestamp, now=now, milliseconds=mode == "cashfree"):
        return False

    supplied = str(signature).strip()
    if mode == "cashfree":
        if supplied.startswith("sha256="):
            supplied = supplied[7:]
        signed = str(timestamp).strip().encode("ascii") + raw_body
        expected = base64.b64encode(
            hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).digest()
        ).decode("ascii")
        return hmac.compare_digest(expected, supplied)

    if supplied.startswith("sha256="):
        supplied = supplied[7:]
    try:
        supplied_bytes = bytes.fromhex(supplied)
    except ValueError:
        return False
    signed = str(timestamp).strip().encode("ascii") + b"." + raw_body
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).digest()
    return hmac.compare_digest(expected, supplied_bytes)


def _first(mapping: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = mapping.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def normalize_email(value: str | None) -> str:
    """Return a comparable email or an empty string. Never logged."""
    candidate = str(value or "").strip().lower()
    if len(candidate) > 254 or not SAFE_EMAIL.fullmatch(candidate):
        return ""
    return candidate


# Grant-only Cashfree identifiers and fixed monthly amounts. Annual IDs and
# amounts are deliberately absent: annual checkout is not implemented.
LINK_PLANS = {
    "grant_plus_monthly_inr": "plus",
    "grant-plus-monthly-inr": "plus",
    "grant_plus_monthly_inr_link": "plus",
    "grant-plus-monthly-inr-link": "plus",
    "grant_pro_monthly_inr": "pro",
    "grant-pro-monthly-inr": "pro",
    "grant_pro_monthly_inr_link": "pro",
    "grant-pro-monthly-inr-link": "pro",
}
AMOUNT_PLANS = {
    "INR": {Decimal("2400"): "plus", Decimal("12600"): "pro"},
    "USD": {Decimal("20"): "plus", Decimal("150"): "pro"},
}


def _decimal(value: str | None) -> Decimal | None:
    try:
        return Decimal(str(value or "").strip())
    except (InvalidOperation, ValueError):
        return None


def plan_from_ids_and_amount(*mappings: Mapping[str, Any]) -> str:
    """Resolve a tier from permanent link/form IDs or the paid amount."""
    for mapping in mappings:
        if not isinstance(mapping, Mapping):
            continue
        identifier = _first(mapping, "link_id", "form_id", "form_code", "cf_link_id")
        plan = LINK_PLANS.get(identifier.lower()) if identifier else ""
        if plan:
            return plan
        currency = _first(mapping, "link_currency", "order_currency", "currency").upper() or "INR"
        for key in (
            "link_amount_paid",
            "link_amount",
            "order_amount_paid",
            "order_amount",
            "amount",
        ):
            amount = _decimal(_first(mapping, key))
            if amount is not None and amount > 0:
                plan = AMOUNT_PLANS.get(currency, {}).get(amount)
                if plan:
                    return plan
    return ""


def customer_email_from(*mappings: Mapping[str, Any]) -> str:
    for mapping in mappings:
        if not isinstance(mapping, Mapping):
            continue
        email = normalize_email(_first(mapping, "customer_email", "email"))
        if email:
            return email
        customer = mapping.get("customer_details")
        if isinstance(customer, Mapping):
            email = normalize_email(_first(customer, "customer_email", "email"))
            if email:
                return email
    return ""


def payment_ref_from(*mappings: Mapping[str, Any]) -> str:
    for mapping in mappings:
        if not isinstance(mapping, Mapping):
            continue
        found = _first(
            mapping,
            "cf_payment_id",
            "payment_id",
            "transaction_id",
            "order_id",
            "cf_link_id",
            "link_id",
        )
        if found:
            return found
    return ""


def paid_at_from(*mappings: Mapping[str, Any]) -> str:
    for mapping in mappings:
        if not isinstance(mapping, Mapping):
            continue
        found = _first(mapping, "event_time", "payment_time", "paid_at", "created_at")
        if found:
            return found
    return ""


def _notes(mapping: Mapping[str, Any]) -> Mapping[str, Any]:
    notes = mapping.get("link_notes") or mapping.get("metadata")
    return notes if isinstance(notes, Mapping) else {}


def _org_from_payload(payload: Mapping[str, Any]) -> str:
    notes = _notes(payload)
    if notes:
        found = safe_org_id(_first(notes, "org_id", "grant_org_id", "client_reference_id"))
        if found:
            return found
    found = safe_org_id(_first(payload, "client_reference_id", "org_id"))
    if found:
        return found
    meta = payload.get("link_meta")
    if isinstance(meta, Mapping):
        for key in ("return_url", "notify_url"):
            raw = _first(meta, key)
            if not raw:
                continue
            try:
                query = dict(parse_qsl(urlsplit(raw).query, keep_blank_values=True))
            except ValueError:
                continue
            found = safe_org_id(query.get("org_id"))
            if found:
                return found
    for key in ("success_url", "cancel_url", "return_url"):
        raw = _first(payload, key)
        if not raw:
            continue
        try:
            query = dict(parse_qsl(urlsplit(raw).query, keep_blank_values=True))
        except ValueError:
            continue
        found = safe_org_id(query.get("org_id"))
        if found:
            return found
    return ""


def _cashfree_event_id(payload: Mapping[str, Any], obj: Mapping[str, Any], status: str) -> str:
    top_level = _first(payload, "id")
    if top_level:
        return top_level
    order = obj.get("order")
    order = order if isinstance(order, Mapping) else {}
    parts = [
        "cashfree",
        _first(obj, "cf_link_id", "link_id"),
        status,
        _first(order, "transaction_id", "order_id"),
    ]
    cleaned = [part for part in parts if part]
    return ":".join(cleaned) if len(cleaned) > 1 else ""


def _plan_from_payload(payload: Mapping[str, Any], obj: Mapping[str, Any]) -> str:
    notes = _notes(obj) or _notes(payload)
    plan = _first(notes, "plan", "plan_tier", "grant_plan")
    plan = plan or _first(obj, "plan", "plan_tier") or _first(payload, "plan")
    plan = plan.strip().lower()
    if plan:
        return plan if plan in {"plus", "pro", "enterprise"} else "plus"
    return plan_from_ids_and_amount(obj, payload) or "plus"


def normalize_event(payload: Mapping[str, Any]) -> dict[str, str] | None:
    """Normalize generic hosted-checkout and Cashfree link events."""
    if not isinstance(payload, Mapping):
        return None

    event_type = _first(payload, "type", "event_type").lower()
    data = payload.get("data")
    obj: Mapping[str, Any] = {}
    if isinstance(data, Mapping):
        candidate = data.get("object")
        obj = candidate if isinstance(candidate, Mapping) else data

    org_id = _org_from_payload(obj) or _org_from_payload(payload)
    if not org_id:
        return None

    status = _first(obj, "link_status", "payment_status", "order_status").upper()
    order = obj.get("order")
    order = order if isinstance(order, Mapping) else {}
    transaction_status = _first(order, "transaction_status", "status").upper()
    is_cashfree = event_type == "payment_link_event" or bool(status)

    if is_cashfree:
        cancelled = status in {"CANCELLED", "EXPIRED"} or transaction_status in {
            "FAILED",
            "CANCELLED",
            "VOID",
        }
        paid = status == "PAID" and transaction_status in {"", "SUCCESS", "PAID"}
        if not cancelled and not paid:
            return None
        order = obj.get("order")
        order = order if isinstance(order, Mapping) else {}
        return {
            "org_id": org_id,
            "tier": "free" if cancelled else _plan_from_payload(payload, obj),
            "status": "canceled" if cancelled else "active",
            "event_type": event_type or "payment_link_event",
            "event_id": _cashfree_event_id(payload, obj, status),
            "customer_ref": _first(obj, "cf_link_id", "link_id"),
            "checkout_id": _first(obj, "link_id", "cf_link_id", "id"),
            "payment_ref": payment_ref_from(order, obj, payload),
            "paid_at": paid_at_from(payload, obj, order),
        }

    if any(word in event_type for word in ("deleted", "canceled", "cancelled", "expired")):
        return {
            "org_id": org_id,
            "tier": "free",
            "status": "canceled",
            "event_type": event_type,
            "event_id": _first(payload, "id"),
            "customer_ref": _first(obj, "customer", "customer_id"),
            "checkout_id": _first(obj, "id", "checkout_id"),
        }

    if any(word in event_type for word in ("completed", "paid", "active", "updated")):
        return {
            "org_id": org_id,
            "tier": _plan_from_payload(payload, obj),
            "status": "active",
            "event_type": event_type,
            "event_id": _first(payload, "id"),
            "customer_ref": _first(obj, "customer", "customer_id"),
            "checkout_id": _first(obj, "id", "checkout_id"),
            "payment_ref": _first(obj, "id", "checkout_id"),
            "paid_at": paid_at_from(payload, obj),
        }

    return None


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def normalize_cashfree_receipt(payload: Mapping[str, Any]) -> dict[str, str] | None:
    """Normalize a successful Cashfree payment into a minimal receipt.

    The email is normalized with LOWER(TRIM(...)) and is only used for the
    internal workspace match or unclaimed-receipt claim. It is never returned
    to a public response.
    """
    if not isinstance(payload, Mapping):
        return None
    event_type = _first(payload, "type", "event_type").lower()
    data = _as_mapping(payload.get("data"))
    obj = _as_mapping(data.get("object")) or data
    form = _as_mapping(data.get("form"))
    order = _as_mapping(data.get("order"))
    status = (
        _first(obj, "link_status", "order_status", "payment_status", "status").upper()
        or _first(order, "order_status", "payment_status", "status").upper()
    )
    transaction_status = _first(order, "transaction_status", "status").upper()
    paid_status = status in {"PAID", "SUCCESS"} or (
        any(word in event_type for word in ("success", "paid"))
        and transaction_status in {"", "SUCCESS", "PAID"}
    )
    recognized = (
        event_type
        in {
            "payment_form_order_webhook",
            "payment_link_event",
            "payment_link_payment",
            "payment_form_payment",
            "payment_success_webhook",
        }
        or any(word in event_type for word in ("success", "paid"))
    )
    if not recognized or not paid_status:
        return None
    plan = plan_from_ids_and_amount(form, order, obj, data, payload)
    if plan not in PAID_TIERS:
        return None
    email = customer_email_from(order, obj, data, payload)
    if not email:
        return None
    payment_ref = payment_ref_from(order, obj, form, data, payload)
    if event_type == "payment_form_order_webhook":
        parts = ["cashfree_form", _first(form, "cf_form_id", "form_id"), payment_ref]
        event_id = ":".join(part for part in parts if part)
    else:
        event_id = _cashfree_event_id(payload, obj, status)
    event_id = event_id or payment_ref
    if not event_id:
        return None
    return {
        "event_id": event_id,
        "event_type": event_type or "cashfree_payment",
        "tier": plan,
        "email": email,
        "payment_ref": payment_ref,
        "paid_at": paid_at_from(payload, data, obj, order),
        "amount": _first(order, "order_amount", "order_amount_paid")
        or _first(obj, "link_amount", "link_amount_paid"),
        "currency": _first(order, "order_currency", "currency")
        or _first(obj, "link_currency", "currency")
        or "INR",
    }


def normalize_form_event(
    payload: Mapping[str, Any], *, org_resolver: Any | None = None
) -> dict[str, str] | None:
    """Normalize a paid Cashfree payment-form submission to a plan-flip action.

    The payer's email is matched to a Grant workspace by ``org_resolver``. The
    email itself is never stored in the returned action, logged, or displayed.
    """
    receipt = normalize_cashfree_receipt(payload)
    if not receipt or receipt["event_type"] != "payment_form_order_webhook":
        return None
    org = ""
    if org_resolver is not None:
        org = safe_org_id(org_resolver(receipt["email"]))
    if not org:
        return None
    return {
        "org_id": org,
        "tier": receipt["tier"],
        "status": "active",
        "event_type": receipt["event_type"],
        "event_id": receipt["event_id"],
        "customer_ref": receipt["payment_ref"],
        "checkout_id": receipt["payment_ref"],
        "payment_ref": receipt["payment_ref"],
        "paid_at": receipt["paid_at"],
    }


def decode_webhook_body(raw_body: bytes) -> dict[str, Any] | None:
    try:
        text = raw_body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        payload = json.loads(text)
        return payload if isinstance(payload, dict) else None
    except json.JSONDecodeError:
        pass
    parsed = parse_qs(text, keep_blank_values=True)
    for key in ("payload", "body", "data"):
        raw = parsed.get(key, [""])[0]
        if not raw:
            continue
        try:
            candidate = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            return candidate
    return None
