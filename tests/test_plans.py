from datetime import datetime, timedelta, timezone

from grant import plans


def test_tier_catalog_contains_all_public_tiers():
    assert list(plans.TIERS) == ["free", "plus", "pro", "enterprise"]
    assert [row["id"] for row in plans.public_pricing()] == list(plans.ORDER)


def test_plus_and_pro_pricing_contract():
    plus = plans.tier("plus")
    pro = plans.tier("pro")

    assert plus.monthly_usd == 20
    assert plus.monthly_inr == 2400
    assert plus.approvals_per_month == 15_000
    assert plus.log_retention_days == 30
    assert plus.approvers == 1
    assert "slack" in plus.channels
    assert "webhook" in plus.channels
    assert plus.spend_caps is True

    assert pro.monthly_usd == 150
    assert pro.monthly_inr == 12_600
    assert pro.approvals_per_month == 100_000
    assert pro.log_retention_days == 365
    assert pro.approvers == 15
    assert "sms" in pro.channels
    assert "whatsapp" in pro.channels


def test_enterprise_is_contact_only_with_fixed_price():
    enterprise = plans.tier("enterprise")
    assert enterprise.monthly_usd == 4_000
    assert enterprise.monthly_inr == 340_000
    assert enterprise.annual_usd is None
    assert enterprise.annual_inr is None
    assert enterprise.badge == "Book a call"


def test_tier_matrix_exposes_exact_locked_features():
    expected = {
        "free": (
            "Basic Approve once / Always allow pop-up",
            "Email & Web links (1,000/mo)",
            "7-day audit trail",
        ),
        "plus": (
            "Auto-approve rules (spend/scope caps)",
            "Slack & Webhook instant approvals (15,000/mo)",
            "30-day audit log retention",
        ),
        "pro": (
            "Multi-approver routing & role rules",
            "SMS / WhatsApp approval alerts (100,000/mo)",
            "1-year audit trail + CSV/JSON exports",
        ),
        "enterprise": (
            "White-label domain & custom branding",
            "SSO / SAML & org directory sync",
            "99.99% SLA + real-time SIEM log streaming",
        ),
    }
    for tier_id, bullets in expected.items():
        assert plans.tier(tier_id).features == bullets
    assert [row["features"] for row in plans.public_pricing()] == [
        list(bullets) for bullets in expected.values()
    ]


def test_feature_locks_progress_from_free_to_enterprise():
    free = plans.feature_locks("free")
    plus = plans.feature_locks("plus")
    pro = plans.feature_locks("pro")
    enterprise = plans.feature_locks("enterprise")

    assert not any(free.values())
    assert plus["conditional_auto_approve"] is True
    assert plus["instant_delivery"] is True
    assert plus["multi_approver_routing"] is False
    assert pro["multi_approver_routing"] is True
    assert pro["mobile_channels"] is True
    assert pro["compliance_exports"] is True
    assert pro["white_label"] is False
    assert all(enterprise.values())
    assert plans.limits("enterprise")["locks"] == enterprise


def test_annual_pricing_is_twenty_percent_off():
    plus = plans.tier("plus")
    pro = plans.tier("pro")

    assert plus.annual_usd == round(20 * 12 * 0.8, 2)
    assert plus.annual_inr == round(2400 * 12 * 0.8, 2)
    assert pro.annual_usd == round(150 * 12 * 0.8, 2)
    assert pro.annual_inr == round(12_600 * 12 * 0.8, 2)


def test_unknown_tier_falls_back_safely():
    assert plans.tier("UNKNOWN").id == "free"
    assert plans.limits("nope")["approvals_per_month"] == 1_000


def test_new_organization_gets_fourteen_day_pro_trial():
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    plan = plans.default_plan("org_123", created_at=plans.iso(created))

    assert plan["org_id"] == "org_123"
    assert plan["status"] == "trial"
    assert plan["trial_tier"] == "pro"
    assert plan["trial_ends_at"] == plans.iso(created + timedelta(days=14))


def test_effective_tier_uses_trial_then_paid_then_safe_free():
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    plan = plans.default_plan("org_123", created_at=plans.iso(created))
    during = created + timedelta(days=5)
    after = created + timedelta(days=15)

    assert plans.effective_tier(plan, now=during) == "pro"
    assert plans.effective_tier(plan, now=after) == "free"
    assert plans.effective_tier(None, now=during) == "free"

    paid = dict(plan, status="active", tier="plus", trial_ends_at=plans.iso(created))
    assert plans.effective_tier(paid, now=after) == "plus"


def test_trial_days_left_never_negative():
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    plan = plans.default_plan("org_123", created_at=plans.iso(created))

    assert plans.trial_days_left(plan, now=created + timedelta(days=2)) == 12
    assert plans.trial_days_left(plan, now=created + timedelta(days=30)) == 0


def test_usage_state_tracks_ok_near_and_over_without_blocking():
    free = {"status": "active", "tier": "free", "trial_ends_at": None}
    paid = {"status": "active", "tier": "plus", "trial_ends_at": None}

    assert plans.usage_state(free, 500)["state"] == "ok"
    assert plans.usage_state(free, 850)["state"] == "near"
    assert plans.usage_state(free, 1_050)["state"] == "over"
    assert plans.usage_state(free, 1_050)["used"] == 1_050
    assert plans.usage_state(paid, 1_050)["state"] == "ok"

    enterprise = plans.usage_state({"status": "active", "tier": "enterprise"}, 999_999)
    assert enterprise["limit"] is None
    assert enterprise["remaining"] is None
    assert enterprise["state"] == "ok"


def test_trial_usage_reports_trial_tier_and_days():
    created = datetime(2026, 1, 1, tzinfo=timezone.utc)
    plan = plans.default_plan("org_123", created_at=plans.iso(created))
    usage = plans.usage_state(plan, 500, now=created + timedelta(days=3))

    assert usage["tier"] == "pro"
    assert usage["limit"] == 100_000
    assert usage["trial_days_left"] == 11
