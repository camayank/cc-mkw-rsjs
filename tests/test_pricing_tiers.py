"""Pricing / tier alignment tests.

Verifies the commercial tier ladder, ARR/MRR derivation, Stripe webhook
mapping, and that diagnostic clients are blocked from the live portal.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Tier table shape ────────────────────────────────────────


def test_canonical_tier_names_present(fresh_client_manager):
    cm = fresh_client_manager
    assert set(cm.TIERS.keys()) == {
        "diagnostic", "essentials", "professional", "enterprise_plus"
    }


def test_tier_pricing_matches_commercial_spec(fresh_client_manager):
    cm = fresh_client_manager
    assert cm.TIERS["diagnostic"]["billing_model"] == "one_time"
    assert cm.TIERS["diagnostic"]["annual_price_min"] == 5_000
    assert cm.TIERS["diagnostic"]["annual_price_max"] == 10_000

    assert cm.TIERS["essentials"]["billing_model"] == "annual_prepaid"
    assert cm.TIERS["essentials"]["annual_price"] == 24_000

    assert cm.TIERS["professional"]["billing_model"] == "annual_prepaid"
    assert cm.TIERS["professional"]["annual_price"] == 48_000

    assert cm.TIERS["enterprise_plus"]["billing_model"] == "annual_prepaid"
    assert cm.TIERS["enterprise_plus"]["annual_price_min"] == 96_000


def test_legacy_tier_names_normalize(fresh_client_manager):
    cm = fresh_client_manager
    assert cm.normalize_tier("assessment") == "diagnostic"
    assert cm.normalize_tier("basic") == "essentials"
    assert cm.normalize_tier("pro") == "professional"
    # Unknown tiers pass through.
    assert cm.normalize_tier("foo") == "foo"


def test_arr_contribution_per_tier(fresh_client_manager):
    cm = fresh_client_manager
    # Diagnostic is one-time, contributes nothing to ARR.
    assert cm.annual_revenue_for_tier("diagnostic") == 0
    assert cm.annual_revenue_for_tier("essentials") == 24_000
    assert cm.annual_revenue_for_tier("professional") == 48_000
    assert cm.annual_revenue_for_tier("enterprise_plus") == 96_000
    # Legacy aliases route correctly.
    assert cm.annual_revenue_for_tier("basic") == 24_000
    assert cm.annual_revenue_for_tier("pro") == 48_000


def test_portal_access_only_on_paid_retainers(fresh_client_manager):
    cm = fresh_client_manager
    assert cm.has_portal_access("diagnostic") is False
    assert cm.has_portal_access("essentials") is True
    assert cm.has_portal_access("professional") is True
    assert cm.has_portal_access("enterprise_plus") is True


def test_included_services_present_for_every_tier(fresh_client_manager):
    cm = fresh_client_manager
    for name, cfg in cm.TIERS.items():
        assert isinstance(cfg.get("included_services"), list), name
        assert len(cfg["included_services"]) >= 4, name


# ─── Stripe webhook tier mapping ────────────────────────────


def _sub_event(annual_cents: int, interval: str = "year"):
    return {
        "type": "customer.subscription.created",
        "data": {"object": {
            "customer": "cus_test",
            "items": {"data": [{"price": {
                "unit_amount": annual_cents if interval == "year" else annual_cents // 12,
                "recurring": {"interval": interval, "interval_count": 1},
            }}]},
        }},
    }


def test_webhook_tier_thresholds_match_commercial_tiers(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    import billing
    import json

    # Stub stripe.Webhook.construct_event so we don't need a real signature.
    if billing.stripe is None:
        pytest.skip("stripe library not installed")

    cases = [
        (24_000_00, "essentials"),
        (24_500_00, "essentials"),
        (48_000_00, "professional"),
        (60_000_00, "professional"),
        (96_000_00, "enterprise_plus"),
        (150_000_00, "enterprise_plus"),
        (10_000_00, "diagnostic"),  # below floor → diagnostic, never silently essentials
    ]

    for annual_cents, expected_tier in cases:
        evt = _sub_event(annual_cents, interval="year")
        monkeypatch.setattr(
            billing.stripe.Webhook, "construct_event",
            lambda payload, sig, secret, _evt=evt: _evt,
        )
        result = billing.handle_webhook(b"{}", "sig")
        assert result["action"] == "update_tier"
        assert result["details"]["tier"] == expected_tier, (
            f"${annual_cents/100:,} → {result['details']['tier']}, expected {expected_tier}"
        )


def test_webhook_flags_monthly_billing_as_unsupported(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    import billing
    if billing.stripe is None:
        pytest.skip("stripe library not installed")

    # $4,000/month subscription extrapolates to $48,000/year → professional,
    # but should be flagged for operator review.
    evt = _sub_event(48_000_00, interval="month")  # cents/yr; helper divides
    monkeypatch.setattr(
        billing.stripe.Webhook, "construct_event",
        lambda payload, sig, secret, _evt=evt: _evt,
    )
    result = billing.handle_webhook(b"{}", "sig")
    assert "monthly_billing_not_supported_for_flagship_tier" in result.get("warnings", [])


def test_webhook_subscription_deleted_drops_to_diagnostic(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    import billing
    if billing.stripe is None:
        pytest.skip("stripe library not installed")
    evt = {
        "type": "customer.subscription.deleted",
        "data": {"object": {"customer": "cus_test"}},
    }
    monkeypatch.setattr(
        billing.stripe.Webhook, "construct_event",
        lambda payload, sig, secret, _evt=evt: _evt,
    )
    result = billing.handle_webhook(b"{}", "sig")
    assert result["action"] == "downgrade_tier"
    assert result["details"]["tier"] == "diagnostic"


# ─── Dashboard ARR / MRR endpoint ───────────────────────────


def _operator_get(test_app, path):
    from starlette.testclient import TestClient
    c = TestClient(test_app, raise_server_exceptions=False)
    return c.get(path, params={"password": "testpass"})


def test_mrr_endpoint_returns_arr_mrr_breakdown(test_app, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("a", "A", "a.com", tier="essentials")
    cm.create_client("b", "B", "b.com", tier="professional")
    cm.create_client("c", "C", "c.com", tier="enterprise_plus")
    cm.create_client("d", "D", "d.com", tier="diagnostic")  # contributes 0

    resp = _operator_get(test_app, "/api/operator/mrr")
    assert resp.status_code == 200
    body = resp.json()
    assert body["arr"] == 24_000 + 48_000 + 96_000  # 168k
    assert body["mrr"] == round(168_000 / 12)        # 14k
    assert body["client_count"] == 4
    assert body["retainer_count"] == 3               # diagnostic excluded
    assert body["by_tier"]["essentials"] == 1
    assert body["by_tier"]["diagnostic"] == 1


def test_mrr_endpoint_with_only_diagnostic_clients_is_zero(test_app, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("a", "A", "a.com", tier="diagnostic")
    cm.create_client("b", "B", "b.com", tier="diagnostic")

    resp = _operator_get(test_app, "/api/operator/mrr")
    assert resp.json()["arr"] == 0
    assert resp.json()["mrr"] == 0
    assert resp.json()["retainer_count"] == 0


# ─── Portal access gate by tier ─────────────────────────────


def test_diagnostic_client_cannot_access_live_portal(test_app, fresh_client_manager):
    """Diagnostic engagements are operator-managed deliverables — no self-serve portal."""
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("d_co", "Diag Co", "diag.com", tier="diagnostic")
    cm.set_portal_password("d_co", "Pass123!")
    token = cm.create_jwt("d_co")

    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token)
    resp = c.get("/portal/d_co")
    assert resp.status_code == 200
    assert "Portal access is part of paid plans" in resp.text


def test_essentials_client_can_access_portal(test_app, fresh_client_manager):
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("e_co", "Ess Co", "ess.com", tier="essentials")
    cm.set_portal_password("e_co", "Pass123!")
    token = cm.create_jwt("e_co")

    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token)
    resp = c.get("/portal/e_co")
    assert resp.status_code == 200
    assert "Ess Co" in resp.text
    # Plan scope panel must show the tier and included services.
    assert "Plan &amp; Scope" in resp.text or "Plan & Scope" in resp.text
    assert "Essentials" in resp.text
    assert "Annual prepaid" in resp.text


def test_portal_shows_tier_label_and_included_services(test_app, fresh_client_manager):
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("p_co", "Pro Co", "pro.com", tier="professional")
    cm.set_portal_password("p_co", "Pass123!")
    token = cm.create_jwt("p_co")

    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token)
    resp = c.get("/portal/p_co")
    assert resp.status_code == 200
    # At least one service unique to professional is listed.
    assert "Quarterly authorized active security validation" in resp.text \
        or "Daily dark-web monitoring" in resp.text


# ─── No discount language anywhere customer-visible ─────────


def test_landing_has_no_discount_language():
    """Customer UI must not promise discounts. Competitor monthly pricing
    in the comparison column is intentional and not affected."""
    landing = open("templates/landing.html").read()
    forbidden = ["discount", "% off", "save $", "limited time", "early bird", "promo code"]
    lower = landing.lower()
    for phrase in forbidden:
        assert phrase.lower() not in lower, f"landing.html still contains '{phrase}'"


def test_landing_pricing_section_is_annual_only():
    """The pricing section advertising our plans must not list monthly billing."""
    landing = open("templates/landing.html").read()
    # Locate just the pricing section to ignore the competitor comparison column.
    start = landing.find('<section id="pricing">')
    end = landing.find('</section>', start)
    pricing_section = landing[start:end]
    assert "Annual prepaid" in pricing_section
    assert "/ month" not in pricing_section
    assert "/month" not in pricing_section
    assert "per month" not in pricing_section.lower()


def test_report_has_no_discount_or_monthly_retainer_language():
    report = open("templates/report.html").read()
    lower = report.lower()
    assert "discount" not in lower
    assert "% off" not in lower
    assert "per month" not in lower
    assert "/month" not in lower
    # Monthly billing for retainers is not offered to new flagship clients.
    assert "$3,000" not in report  # old vCISO monthly card removed


def test_landing_lists_all_four_commercial_tiers():
    landing = open("templates/landing.html").read()
    for label in [
        "Paid Diagnostic", "Essentials", "Professional", "Enterprise+",
        "$5,000", "$24,000", "$48,000", "$96,000",
    ]:
        assert label in landing, f"landing.html missing '{label}'"
