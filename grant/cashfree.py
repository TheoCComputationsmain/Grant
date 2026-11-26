"""Cashfree hosted payment-link client for Grant.

Grant never handles card data, wallet balances, escrow, refunds, or auto-debits.
This module only creates a hosted Cashfree link and returns its URL.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import uuid
from typing import Any, Mapping
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlencode, urlsplit

from . import billing, plans

APP_ID_ENV_KEY = "GRANT_CASHFREE_APP_ID"
SECRET_KEY_ENV_KEY = "GRANT_CASHFREE_SECRET_KEY"
API_VERSION_ENV_KEY = "GRANT_CASHFREE_API_VERSION"
MODE_ENV_KEY = "GRANT_CASHFREE_MODE"
WEBHOOK_SECRET_ENV_KEY = "GRANT_CASHFREE_WEBHOOK_SECRET"
RETURN_URL_ENV_KEY = "GRANT_CASHFREE_RETURN_URL"
CURRENCY_ENV_KEY = "GRANT_CASHFREE_CURRENCY"
PHONE_ENV_KEY = "GRANT_CASHFREE_PLACEHOLDER_PHONE"

DEFAULT_API_VERSION = "2026-01-01"
SANDBOX_BASE_URL = "https://sandbox.cashfree.com/pg"
PRODUCTION_BASE_URL = "https://api.cashfree.com/pg"
ALLOWED_LINK_HOSTS = frozenset({"payments.cashfree.com", "payments-test.cashfree.com"})
SUPPORTED_CURRENCIES = frozenset({"INR", "USD"})
MAX_LINK_ID_LENGTH = 50
SAFE_LINK_ID = re.compile(r"^[A-Za-z0-9_-]+$")
IDEMPOTENCY_NAMESPACE = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")


class CashfreeError(Exception):
    """Safe, displayable Cashfree integration error."""


def provider_mode(env: Mapping[str, str] | None = None) -> str:
    environ = env if env is not None else os.environ
    raw = str(environ.get(MODE_ENV_KEY, "sandbox")).strip().lower()
    if raw in {"", "sandbox", "test", "development"}:
        return "sandbox"
    if raw in {"prod", "production", "live"}:
        return "production"
    raise CashfreeError("Cashfree mode must be sandbox or production.")


def _config(environ: Mapping[str, str]) -> tuple[str, str, str]:
    app_id = str(environ.get(APP_ID_ENV_KEY, "")).strip()
    secret = str(environ.get(SECRET_KEY_ENV_KEY, "")).strip()
    if not app_id or not secret:
        raise CashfreeError("Cashfree payment links are not configured.")
    version = str(environ.get(API_VERSION_ENV_KEY, DEFAULT_API_VERSION)).strip() or DEFAULT_API_VERSION
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", version):
        raise CashfreeError("Cashfree API version is invalid.")
    return app_id, secret, version


def _currency(environ: Mapping[str, str]) -> str:
    currency = str(environ.get(CURRENCY_ENV_KEY, "INR")).strip().upper() or "INR"
    if currency not in SUPPORTED_CURRENCIES:
        raise CashfreeError("Cashfree currency is not supported.")
    return currency


def price_for(plan: str, cycle: str, currency: str) -> float:
    selected = plans.tier(plan)
    if selected.id not in {"plus", "pro"}:
        raise CashfreeError("This plan does not use Cashfree payment links.")
    value = (
        selected.annual_inr if currency == "INR" else selected.annual_usd
    ) if cycle == "annual" else (
        selected.monthly_inr if currency == "INR" else selected.monthly_usd
    )
    if value is None or float(value) <= 0:
        raise CashfreeError("Plan price is not configured.")
    return round(float(value), 2)


def make_link_id(org_id: str, plan: str, cycle: str, *, nonce: str | None = None) -> str:
    base = re.sub(r"[^A-Za-z0-9_-]", "_", f"grant_{org_id}_{plan}_{cycle}").strip("_")
    base = (base or "grant")[:38].rstrip("_") or "grant"
    salt = nonce or secrets.token_hex(5)
    digest = hashlib.sha256(f"{org_id}|{plan}|{cycle}|{salt}".encode("utf-8")).hexdigest()[:10]
    return f"{base}_{digest}"[:MAX_LINK_ID_LENGTH].rstrip("_")


def _https_url(value: str, label: str) -> str:
    candidate = str(value or "").strip()
    parts = urlsplit(candidate)
    if parts.scheme != "https" or not parts.netloc:
        raise CashfreeError(f"Cashfree {label} is invalid.")
    return candidate


def _return_url(environ: Mapping[str, str], public_base_url: str, *, org: str, plan: str, cycle: str) -> str:
    configured = str(environ.get(RETURN_URL_ENV_KEY, "")).strip()
    if configured:
        return _https_url(configured, "return URL")
    base = str(public_base_url or environ.get("GRANT_PUBLIC_BASE_URL", "")).rstrip("/")
    if not base:
        base = "https://grant-approve.vercel.app"
    query = urlencode({"org_id": org, "plan": plan, "cycle": cycle, "checkout": "returned"})
    return _https_url(f"{base}/console?{query}", "return URL")


def _placeholder_phone(environ: Mapping[str, str], mode: str) -> str:
    configured = str(environ.get(PHONE_ENV_KEY, "")).strip()
    if configured:
        digits = re.sub(r"\D", "", configured)
        if 6 <= len(digits) <= 15:
            return digits
        raise CashfreeError("Cashfree placeholder phone is invalid.")
    if mode == "production":
        raise CashfreeError("Cashfree placeholder phone is required in production.")
    return "9999999999"


def validate_link_url(url: str) -> str:
    candidate = str(url or "").strip()
    parts = urlsplit(candidate)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_LINK_HOSTS:
        raise CashfreeError("Cashfree returned an invalid payment URL.")
    return candidate


# Fixed, dashboard-created hosted forms. Grant only redirects; it never creates
# links through the API and never handles card data, wallets, or funds.
MONTHLY_FORM_URLS = {
    "plus": "https://payments.cashfree.com/forms/grant-plus-monthly-inr",
    "pro": "https://payments.cashfree.com/forms/grant-pro-monthly-inr",
}
MONTHLY_FORM_URL_ENV_KEYS = {
    "plus": "GRANT_CASHFREE_PLUS_MONTHLY_URL",
    "pro": "GRANT_CASHFREE_PRO_MONTHLY_URL",
}


def monthly_form_url(plan: str, *, env: Mapping[str, str] | None = None) -> str:
    """Return the fixed hosted monthly form for a paid plan.

    Concierge uses the Plus monthly form. Only allowlisted Cashfree hosts are
    accepted, so a misconfigured URL can never redirect a buyer off-site.
    """
    environ = env if env is not None else os.environ
    key = "plus" if str(plan).strip().lower() == "concierge" else str(plan).strip().lower()
    if key not in MONTHLY_FORM_URLS:
        raise CashfreeError("This plan does not use Cashfree payment links.")
    configured = str(environ.get(MONTHLY_FORM_URL_ENV_KEYS[key], "")).strip()
    return validate_link_url(configured or MONTHLY_FORM_URLS[key])


def _post_json(
    url: str,
    headers: Mapping[str, str],
    body: Mapping[str, Any],
    *,
    timeout: float,
    opener: Any | None,
) -> dict[str, Any]:
    payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    request = urlrequest.Request(url, data=payload, headers=dict(headers), method="POST")
    transport = opener or urlrequest.build_opener()
    try:
        with transport.open(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 0) or response.getcode())
            raw = response.read()
    except urlerror.HTTPError as exc:
        status_code = int(getattr(exc, "code", 0) or 0)
        error_code = ""
        try:
            decoded_error = json.loads(exc.read().decode("utf-8"))
            error_code = str(decoded_error.get("code") or "") if isinstance(decoded_error, dict) else ""
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        if error_code == "PaymentLink_link_creation_api_failed":
            raise CashfreeError("Cashfree payment links are not enabled for this account.") from None
        if status_code in {401, 403}:
            raise CashfreeError("Cashfree credentials are invalid.") from None
        if status_code == 429:
            raise CashfreeError("Cashfree is rate limiting requests.") from None
        if status_code >= 500:
            raise CashfreeError("Cashfree is temporarily unavailable.") from None
        raise CashfreeError("Cashfree rejected the checkout request.") from None
    except (urlerror.URLError, TimeoutError, OSError):
        raise CashfreeError("Cashfree could not be reached.") from None
    if status not in {200, 201}:
        raise CashfreeError(f"Cashfree rejected the request (HTTP {status}).")
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CashfreeError("Cashfree returned an invalid response.") from None
    if not isinstance(decoded, dict):
        raise CashfreeError("Cashfree returned an invalid response.")
    return decoded


def create_payment_link(
    plan: str,
    cycle: str,
    org_id: str,
    *,
    env: Mapping[str, str] | None = None,
    public_base_url: str = "",
    opener: Any | None = None,
    timeout: float = 8.0,
    nonce: str | None = None,
) -> dict[str, str]:
    """Create a Cashfree-hosted payment link for a paid Grant plan."""
    environ = env if env is not None else os.environ
    requested_plan = str(plan).strip().lower()
    is_concierge = requested_plan == "concierge"
    selected_plan = "plus" if is_concierge else requested_plan
    selected_cycle = "monthly" if is_concierge else (
        "annual" if str(cycle).strip().lower() == "annual" else "monthly"
    )
    org = billing.safe_org_id(org_id)
    if not org:
        raise CashfreeError("A valid org_id is required.")

    mode = provider_mode(environ)
    app_id, secret, version = _config(environ)
    currency = _currency(environ)
    amount = price_for(selected_plan, selected_cycle, currency)

    link_id = make_link_id(org, selected_plan, selected_cycle, nonce=nonce)
    request_id = str(uuid.uuid4())
    idempotency_key = str(uuid.uuid5(IDEMPOTENCY_NAMESPACE, link_id))
    base_url = SANDBOX_BASE_URL if mode == "sandbox" else PRODUCTION_BASE_URL
    purpose = f"Grant {plans.tier(selected_plan).name} ({selected_cycle.title()})"

    body: dict[str, Any] = {
        "link_id": link_id,
        "link_amount": amount,
        "link_currency": currency,
        "link_purpose": purpose,
        "link_partial_payments": False,
        "customer_details": {"customer_phone": _placeholder_phone(environ, mode)},
        "link_meta": {
            "notify_url": _https_url(
                f"{str(public_base_url or environ.get('GRANT_PUBLIC_BASE_URL', '')).rstrip('/')}/v1/billing/webhook",
                "notify URL",
            ),
            "return_url": _return_url(
                environ,
                public_base_url,
                org=org,
                plan=selected_plan,
                cycle=selected_cycle,
            ),
            "upi_intent": False,
        },
        "link_notes": {
            "org_id": org,
            "plan": selected_plan,
            "cycle": selected_cycle,
            "grant_ref": request_id[:36],
        },
        "link_notify": {"send_sms": False, "send_email": False, "send_whatsapp": False},
    }
    headers = {
        "content-type": "application/json",
        "accept": "application/json",
        "x-client-id": app_id,
        "x-client-secret": secret,
        "x-api-version": version,
        "x-request-id": request_id,
        "x-idempotency-key": idempotency_key,
    }

    response = _post_json(
        f"{base_url}/links",
        headers,
        body,
        timeout=timeout,
        opener=opener,
    )
    return {
        "link_url": validate_link_url(str(response.get("link_url") or "")),
        "link_id": str(response.get("link_id") or link_id)[:MAX_LINK_ID_LENGTH],
        "cf_link_id": str(response.get("cf_link_id") or ""),
        "request_id": request_id,
        "mode": mode,
    }
