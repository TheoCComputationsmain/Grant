import base64
import hashlib
import hmac
import io
import json
import re
import time
import uuid
from urllib import error as urlerror
from urllib.parse import parse_qsl, urlsplit

from grant import billing, cashfree, plans


ENV = {
    "GRANT_CASHFREE_APP_ID": "app_test_not_real",
    "GRANT_CASHFREE_SECRET_KEY": "secret_test_not_real",
    "GRANT_CASHFREE_API_VERSION": "2026-01-01",
    "GRANT_CASHFREE_MODE": "sandbox",
    "GRANT_CASHFREE_RETURN_URL": "https://grant.test/console?org_id=org_123",
    "GRANT_CASHFREE_PLACEHOLDER_PHONE": "9999999999",
    "GRANT_PUBLIC_BASE_URL": "https://grant.test",
    "GRANT_ENTERPRISE_CONTACT_URL": "https://grant.test/contact",
}


class FakeResponse:
    status = 200

    def __init__(self, payload: dict):
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def getcode(self) -> int:
        return 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    def __init__(self, payload: dict):
        self.payload = payload
        self.request = None
        self.timeout = None

    def open(self, request, timeout=None):
        self.request = request
        self.timeout = timeout
        return FakeResponse(self.payload)


def linked_payload(host: str = "payments-test.cashfree.com") -> dict:
    return {
        "link_url": f"https://{host}/links/test_link",
        "link_id": "grant_org_123_pro_monthly_abc",
        "cf_link_id": "12345",
    }


def test_cashfree_link_request_is_hosted_and_pii_minimal():
    opener = FakeOpener(linked_payload())
    result = cashfree.create_payment_link(
        "pro",
        "annual",
        "org_123",
        env=ENV,
        public_base_url="https://grant.test",
        opener=opener,
        nonce="fixednonce",
    )
    request = opener.request
    headers = {key.lower(): value for key, value in request.headers.items()}
    body = json.loads(request.data.decode("utf-8"))

    assert request.full_url == "https://sandbox.cashfree.com/pg/links"
    assert headers["x-client-id"] == ENV["GRANT_CASHFREE_APP_ID"]
    assert headers["x-client-secret"] == ENV["GRANT_CASHFREE_SECRET_KEY"]
    assert headers["x-api-version"] == "2026-01-01"
    assert headers["x-request-id"] == result["request_id"]
    assert uuid.UUID(headers["x-idempotency-key"])
    assert body["link_amount"] == plans.tier("pro").annual_inr
    assert body["link_currency"] == "INR"
    assert "Annual" in body["link_purpose"]
    assert body["link_partial_payments"] is False
    assert "subscription" not in body
    assert "link_expiry_time" not in body
    assert body["customer_details"] == {"customer_phone": "9999999999"}
    assert body["link_meta"]["notify_url"] == "https://grant.test/v1/billing/webhook"
    assert body["link_meta"]["return_url"] == ENV["GRANT_CASHFREE_RETURN_URL"]
    assert set(body["link_notes"]) == {"org_id", "plan", "cycle", "grant_ref"}
    assert body["link_notes"]["org_id"] == "org_123"
    assert body["link_notes"]["plan"] == "pro"
    assert body["link_notes"]["cycle"] == "annual"
    assert not any("@" in value for value in body["link_notes"].values())
    assert re.fullmatch(r"[A-Za-z0-9_-]{1,50}", body["link_id"])
    assert result["link_url"].startswith("https://payments-test.cashfree.com/")


def test_cashfree_link_id_and_idempotency_are_stable_for_same_nonce():
    first_opener = FakeOpener(linked_payload())
    second_opener = FakeOpener(linked_payload())
    first = cashfree.create_payment_link(
        "plus", "monthly", "org_123", env=ENV, opener=first_opener, nonce="stable"
    )
    second = cashfree.create_payment_link(
        "plus", "monthly", "org_123", env=ENV, opener=second_opener, nonce="stable"
    )
    first_headers = {k.lower(): v for k, v in first_opener.request.headers.items()}
    second_headers = {k.lower(): v for k, v in second_opener.request.headers.items()}

    assert first["request_id"] != second["request_id"]
    assert first_headers["x-request-id"] != second_headers["x-request-id"]
    assert first_headers["x-idempotency-key"] == second_headers["x-idempotency-key"]
    assert cashfree.make_link_id("org_123", "plus", "monthly", nonce="stable") == cashfree.make_link_id(
        "org_123", "plus", "monthly", nonce="stable"
    )


def test_cashfree_production_mode_uses_usd_price_and_production_host():
    env = dict(ENV, GRANT_CASHFREE_MODE="production", GRANT_CASHFREE_CURRENCY="USD")
    opener = FakeOpener(linked_payload("payments.cashfree.com"))
    cashfree.create_payment_link(
        "pro", "monthly", "org_123", env=env, opener=opener, nonce="prodtest"
    )
    body = json.loads(opener.request.data.decode("utf-8"))
    assert opener.request.full_url == "https://api.cashfree.com/pg/links"
    assert body["link_amount"] == 150
    assert body["link_currency"] == "USD"


def test_concierge_creates_fixed_plus_monthly_cashfree_link():
    opener = FakeOpener(linked_payload())
    cashfree.create_payment_link(
        "concierge", "annual", "org_123", env=ENV, opener=opener, nonce="concierge"
    )
    body = json.loads(opener.request.data.decode("utf-8"))
    assert body["link_notes"]["plan"] == "plus"
    assert body["link_notes"]["cycle"] == "monthly"
    assert body["link_amount"] == plans.tier("plus").monthly_inr


def test_cashfree_reports_disabled_payment_link_api_safely():
    class DisabledOpener(FakeOpener):
        def open(self, request, timeout=None):
            body = json.dumps({"code": "PaymentLink_link_creation_api_failed"}).encode("utf-8")
            raise urlerror.HTTPError(request.full_url, 400, "Bad Request", {}, io.BytesIO(body))

    try:
        cashfree.create_payment_link(
            "plus", "monthly", "org_123", env=ENV, opener=DisabledOpener({})
        )
    except cashfree.CashfreeError as exc:
        assert str(exc) == "Cashfree payment links are not enabled for this account."
    else:
        raise AssertionError("disabled API should fail safely")


def test_cashfree_rejects_bad_config_and_bad_provider_url():
    try:
        cashfree.create_payment_link("plus", "monthly", "org_123", env={})
    except cashfree.CashfreeError as exc:
        assert "not configured" in str(exc)
    else:
        raise AssertionError("missing config should fail")

    try:
        cashfree.validate_link_url("https://evil.example.test/pay")
    except cashfree.CashfreeError:
        pass
    else:
        raise AssertionError("unexpected link host should fail")

    try:
        cashfree.provider_mode({"GRANT_CASHFREE_MODE": "moon"})
    except cashfree.CashfreeError:
        pass
    else:
        raise AssertionError("invalid mode should fail")


def signed_body(payload: bytes, secret: str, timestamp: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"), timestamp.encode("ascii") + b"." + payload, hashlib.sha256
    ).hexdigest()
    return "sha256=" + digest


def signed_cashfree_body(payload: bytes, secret: str, timestamp: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"), timestamp.encode("ascii") + payload, hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def test_webhook_signature_verification_round_trip():
    raw = b'{"type":"checkout.session.completed"}'
    timestamp = str(int(time.time()))
    signature = signed_body(raw, "secret", timestamp)
    assert billing.verify_webhook(raw, signature, timestamp, secret="secret") is True
    assert billing.verify_webhook(raw, "bad", timestamp, secret="secret") is False
    assert billing.verify_webhook(raw, signature, timestamp, secret="other") is False

    cashfree_timestamp = str(int(time.time() * 1000))
    cashfree_signature = signed_cashfree_body(raw, "cf-secret", cashfree_timestamp)
    assert billing.verify_webhook(
        raw, cashfree_signature, cashfree_timestamp, secret="cf-secret", mode="cashfree"
    )
    assert not billing.verify_webhook(
        raw, cashfree_signature, cashfree_timestamp, secret="wrong", mode="cashfree"
    )


def test_webhook_rejects_stale_and_malformed_requests():
    raw = b"{}"
    now = 2_000_000_000
    fresh = str(now - 10)
    stale = str(now - 10_000)
    fresh_signature = signed_body(raw, "secret", fresh)
    assert billing.verify_webhook(raw, fresh_signature, fresh, secret="secret", now=now)
    assert not billing.verify_webhook(raw, fresh_signature, stale, secret="secret", now=now)
    assert not billing.verify_webhook(raw, "zz", fresh, secret="secret", now=now)
    assert not billing.verify_webhook(raw, fresh_signature, "nope", secret="secret")
    assert not billing.verify_webhook(
        raw, signed_cashfree_body(raw, "secret", str(now * 1000)), str((now - 10_000) * 1000),
        secret="secret", mode="cashfree", now=now
    )


def test_normalize_completed_checkout_flips_plan_flag():
    payload = {
        "id": "evt_1",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "cs_1",
                "customer": "cus_1",
                "metadata": {"org_id": "org_123", "plan": "pro"},
            }
        },
    }
    action = billing.normalize_event(payload)
    assert action is not None
    assert action["org_id"] == "org_123"
    assert action["tier"] == "pro"
    assert action["status"] == "active"
    assert action["checkout_id"] == "cs_1"


def test_normalize_cancellation_reverts_to_free():
    payload = {
        "type": "customer.subscription.deleted",
        "client_reference_id": "org_123",
    }
    action = billing.normalize_event(payload)
    assert action is not None
    assert action["tier"] == "free"
    assert action["status"] == "canceled"


def test_normalize_ignores_events_without_org_reference():
    assert billing.normalize_event({"type": "checkout.session.completed"}) is None
    assert billing.normalize_event({"type": "ping", "metadata": {"org_id": "org_1"}}) is None


def test_org_id_can_be_recovered_from_success_or_return_url():
    payload = {
        "type": "checkout.session.completed",
        "success_url": "https://grant.example.test/console?org_id=org_123",
    }
    action = billing.normalize_event(payload)
    assert action is not None and action["org_id"] == "org_123"

    cashfree = {
        "type": "PAYMENT_LINK_EVENT",
        "data": {
            "link_status": "PAID",
            "link_notes": {"plan": "plus"},
            "link_meta": {"return_url": "https://grant.example.test/console?org_id=org_456"},
        },
    }
    action = billing.normalize_event(cashfree)
    assert action is not None and action["org_id"] == "org_456"


def test_normalize_cashfree_paid_event_is_pii_free_and_idempotent():
    payload = {
        "type": "PAYMENT_LINK_EVENT",
        "data": {
            "cf_link_id": "12345",
            "link_id": "grant_org_123_pro_monthly_abc",
            "link_status": "PAID",
            "link_notes": {"org_id": "org_123", "plan": "pro", "cycle": "monthly"},
            "customer_details": {"customer_phone": "9000000000", "customer_email": "x@example.test"},
            "order": {"transaction_id": "txn_9", "transaction_status": "SUCCESS"},
        },
    }
    first = billing.normalize_event(payload)
    second = billing.normalize_event(payload)
    assert first is not None
    assert first["org_id"] == "org_123"
    assert first["tier"] == "pro"
    assert first["status"] == "active"
    assert first["event_id"] == second["event_id"]
    assert "9000000000" not in json.dumps(first)
    assert "x@example.test" not in json.dumps(first)


def test_normalize_cashfree_cancelled_and_partial_events():
    base = {
        "type": "PAYMENT_LINK_EVENT",
        "data": {
            "link_id": "grant_org_123_plus_monthly_abc",
            "link_notes": {"org_id": "org_123", "plan": "plus"},
        },
    }
    cancelled = json.loads(json.dumps(base))
    cancelled["data"]["link_status"] = "CANCELLED"
    action = billing.normalize_event(cancelled)
    assert action is not None and action["tier"] == "free"

    partial = json.loads(json.dumps(base))
    partial["data"]["link_status"] = "PARTIALLY_PAID"
    assert billing.normalize_event(partial) is None


def test_decode_webhook_body_supports_json_and_form_encoded_json():
    payload = {"type": "PAYMENT_LINK_EVENT", "data": {"link_status": "PAID"}}
    raw = json.dumps(payload).encode("utf-8")
    assert billing.decode_webhook_body(raw) == payload
    form = "payload=" + raw.decode("utf-8").replace("&", "%26").replace("=", "%3D")
    assert billing.decode_webhook_body(form.encode("utf-8")) == payload
    assert billing.decode_webhook_body(b"not json") is None
