"""Verify Grant's Cashfree checkout and automatic Neon tier activation.

Dependency-free CLI. It never prints or stores an ops token, API key, or card
data. Use ``--mode checkout`` to get the hosted form, pay manually, then
``--mode verify`` to confirm the signed webhook activated the plan.

Examples::

    $env:GRANT_OPS_TOKEN="..."
    python scripts/verify_cashfree.py --org ws_live --mode checkout
    python scripts/verify_cashfree.py --org ws_live --mode verify --timeout 900
    python scripts/verify_cashfree.py --org ws_test --mode simulate --plan plus

``simulate`` exercises the same activation path as the signed webhook and is
disabled in production unless ``GRANT_ALLOW_TEST_WEBHOOK=true`` is configured.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any
from urllib import error, parse, request

DEFAULT_BASE = "https://grant-approve.vercel.app"
PLANS = ("plus", "pro")


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def base_url(value: str) -> str:
    candidate = str(value or os.environ.get("GRANT_VERIFY_BASE_URL", DEFAULT_BASE)).strip().rstrip("/")
    parts = parse.urlsplit(candidate)
    if parts.scheme != "https" or not parts.netloc:
        raise SystemExit("Base URL must be an https:// URL.")
    return candidate


def call(url: str, *, method: str = "GET", body: dict[str, Any] | None = None, headers: dict[str, str] | None = None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = request.Request(url, data=data, method=method, headers=headers or {})
    opener = request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=20) as response:
            raw = response.read()
            status = int(getattr(response, "status", 0) or response.getcode())
            location = response.headers.get("location", "")
    except error.HTTPError as exc:
        raw = exc.read()
        status = int(exc.code)
        location = exc.headers.get("location", "") if exc.headers else ""
    except (error.URLError, TimeoutError, OSError) as exc:
        raise SystemExit(f"Could not reach Grant: {exc}") from None
    try:
        decoded = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded = {}
    return status, decoded, location


def status_for(base: str, org: str, token: str) -> dict[str, Any]:
    url = f"{base}/api/billing/status?{parse.urlencode({'org_id': org, 'token': token})}"
    status, body, _ = call(url)
    if status != 200:
        raise SystemExit(f"Status check failed (HTTP {status}): {body.get('detail', 'unauthorized')}")
    return body


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="", help="Grant base URL (default: GRANT_VERIFY_BASE_URL or live alias)")
    parser.add_argument("--org", default=os.environ.get("GRANT_VERIFY_ORG", ""), help="Workspace / org id")
    parser.add_argument("--plan", default=os.environ.get("GRANT_VERIFY_PLAN", "plus"), choices=PLANS)
    parser.add_argument(
        "--mode",
        default="status",
        choices=("checkout", "simulate", "status", "verify"),
        help="checkout=hosted form, simulate=test webhook, status=tier, verify=poll for paid tier",
    )
    parser.add_argument("--timeout", type=int, default=900, help="verify mode timeout in seconds")
    parser.add_argument("--interval", type=int, default=15, help="verify mode poll interval in seconds")
    args = parser.parse_args()

    base = base_url(args.base)
    org = str(args.org or "").strip()
    if not org:
        raise SystemExit("Set --org or GRANT_VERIFY_ORG.")

    if args.mode == "checkout":
        url = f"{base}/v1/checkout/{args.plan}?{parse.urlencode({'org_id': org, 'cycle': 'monthly'})}"
        status, body, location = call(url)
        if status != 302 or not location.startswith("https://"):
            raise SystemExit(f"Checkout failed (HTTP {status}): {body.get('detail', 'no hosted URL')}")
        print("Hosted monthly Cashfree form:")
        print(location)
        print("Pay there manually, then run --mode verify. Grant never handles card data.")
        return 0

    token = os.environ.get("GRANT_OPS_TOKEN", "").strip()
    if not token:
        raise SystemExit("Set GRANT_OPS_TOKEN for status, simulate, and verify modes.")

    if args.mode == "simulate":
        url = f"{base}/api/webhooks/cashfree/test?{parse.urlencode({'token': token})}"
        status, body, _ = call(
            url,
            method="POST",
            body={"org_id": org, "plan": args.plan},
            headers={"content-type": "application/json"},
        )
        if status != 200:
            raise SystemExit(f"Simulation failed (HTTP {status}): {body.get('detail', 'unknown')}")
        print(json.dumps(body, indent=2))
        if body.get("after_tier") != args.plan:
            raise SystemExit(f"Tier activation failed: expected {args.plan}, got {body.get('after_tier')}")
        return 0

    deadline = time.monotonic() + max(1, args.timeout) if args.mode == "verify" else 0
    interval = max(2, args.interval)
    while True:
        state = status_for(base, org, token)
        tier = str(state.get("tier") or "free")
        print(f"org={org} tier={tier} stored={state.get('stored_tier')} used={state.get('used')}/{state.get('limit')}")
        if args.mode == "status":
            return 0
        if tier == args.plan:
            print(f"Verified: {args.plan} activated in the durable store.")
            return 0
        if time.monotonic() >= deadline:
            raise SystemExit(
                f"Timed out waiting for {args.plan}. Check the Cashfree webhook and GRANT_CASHFREE_WEBHOOK_SECRET."
            )
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())
