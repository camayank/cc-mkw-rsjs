"""Delivery console tests.

Proves:
  - Build_row produces all 14 spec'd signals with correct types.
  - Filter classification matches the spec for each bucket.
  - Health score boundaries work.
  - Summary counts aggregate correctly.
  - High-value clients = professional + enterprise_plus tiers.
  - Authorization-missing detection consults the legal record.
  - Operator route requires auth and returns the aggregated view.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def dc(fresh_client_manager):
    if "delivery_console" in sys.modules:
        del sys.modules["delivery_console"]
    if "security_validation" in sys.modules:
        del sys.modules["security_validation"]
    if "advisor_review" in sys.modules:
        del sys.modules["advisor_review"]
    import delivery_console
    return delivery_console


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _days_ago(n):
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def _good_legal_record(client_id):
    import legal_authorization as _legal
    now = datetime.now(timezone.utc)
    return {
        "client_id": client_id,
        "msa": {"name": "MSA", "status": "signed"},
        "sow": {"name": "SOW", "status": "signed"},
        "nda": {"name": "NDA", "status": "signed"},
        "dpa": {"name": "DPA", "status": "signed"},
        "authorized_representative": {"full_name": "X", "title": "CEO",
                                       "email": "x@a.com",
                                       "verified_at": now.isoformat()},
        "ownership": {"domains_owned": ["a.com"], "confirmed_at": now.isoformat(),
                       "proof_method": "dns_txt", "proof_artifact": "tok"},
        "passive_scan": {"status": "approved"},
        "active_validation": {
            "status": "approved",
            "target_domains": ["a.com"],
            "testing_window": {"start_at": (now - timedelta(hours=1)).isoformat(),
                                "end_at": (now + timedelta(hours=2)).isoformat()},
            "authorized_at": now.isoformat(),
            "authorized_by_name": "X", "authorized_by_title": "CEO",
            "authorized_by_email": "x@a.com",
            "operator_approved_at": now.isoformat(),
            "operator_approved_by": "Op",
            "expires_at": (now + timedelta(days=7)).isoformat(),
            "emergency_contact": {"name": "X", "phone_24x7": "+1"},
        },
        "acknowledgments": {"client_responsibility": True, "no_legal_advice": True,
                              "no_breach_prevention_guarantee": True,
                              "acknowledged_at": now.isoformat(),
                              "acknowledged_by": "X"},
    }


# ─── Structure ───────────────────────────────────────────────


def test_build_row_returns_all_required_signals(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com", tier="professional")
    row = dc.build_row("c1")
    required = {
        "client_id", "company_name", "domain",
        "tier", "tier_label", "annual_value", "is_high_value",
        "is_qualified", "authorization_status", "authorization_missing",
        "setup_completeness_pct", "setup_missing",
        "pending_advisor_reviews", "open_critical_risks",
        "reports_due", "evidence_packages_due", "security_validations_due",
        "payment_status", "next_call_date", "last_client_activity",
        "compliance_pct", "current_score", "health_score", "health_label",
        "filters",
    }
    missing = required - set(row.keys())
    assert not missing, f"missing: {missing}"


def test_filters_dict_has_all_seven_buckets(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    row = dc.build_row("c1")
    expected = {"needs_attention", "review_pending", "setup_incomplete",
                "high_risk", "renewal_risk", "high_value_client",
                "authorization_missing"}
    assert set(row["filters"].keys()) == expected


def test_returns_none_for_unknown_client(dc, fresh_client_manager):
    assert dc.build_row("nonexistent") is None


# ─── Tier / value ────────────────────────────────────────────


def test_high_value_classification(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c_d", "D", "d.com", tier="diagnostic")
    cm.create_client("c_e", "E", "e.com", tier="essentials")
    cm.create_client("c_p", "P", "p.com", tier="professional")
    cm.create_client("c_x", "X", "x.com", tier="enterprise_plus")
    assert dc.build_row("c_d")["is_high_value"] is False
    assert dc.build_row("c_e")["is_high_value"] is False
    assert dc.build_row("c_p")["is_high_value"] is True
    assert dc.build_row("c_x")["is_high_value"] is True


def test_annual_value_per_tier(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("d", "D", "d.com", tier="diagnostic")
    cm.create_client("e", "E", "e.com", tier="essentials")
    cm.create_client("p", "P", "p.com", tier="professional")
    cm.create_client("x", "X", "x.com", tier="enterprise_plus")
    assert dc.build_row("d")["annual_value"] == 0
    assert dc.build_row("e")["annual_value"] == 24_000
    assert dc.build_row("p")["annual_value"] == 48_000
    assert dc.build_row("x")["annual_value"] == 96_000


# ─── Authorization missing ───────────────────────────────────


def test_authorization_missing_for_active_validation_tiers(dc, fresh_client_manager):
    """Authorization is 'missing' only for tiers that include active
    validation (professional / enterprise_plus). Lower tiers don't need it."""
    cm = fresh_client_manager
    cm.create_client("d", "D", "d.com", tier="diagnostic")
    cm.create_client("e", "E", "e.com", tier="essentials")
    cm.create_client("p", "P", "p.com", tier="professional")
    cm.create_client("x", "X", "x.com", tier="enterprise_plus")
    assert dc.build_row("d")["authorization_missing"] is False
    assert dc.build_row("e")["authorization_missing"] is False
    assert dc.build_row("p")["authorization_missing"] is True
    assert dc.build_row("x")["authorization_missing"] is True


def test_authorization_present_when_active_approved(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.save_legal_authorization("c1", _good_legal_record("c1"))
    row = dc.build_row("c1")
    assert row["authorization_missing"] is False
    assert row["filters"]["authorization_missing"] is False


# ─── Setup completeness ──────────────────────────────────────


def test_setup_incomplete_filter_when_missing_integrations(dc, fresh_client_manager,
                                                          monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    monkeypatch.delenv("GOPHISH_API_KEY", raising=False)
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    row = dc.build_row("c1")
    assert row["setup_completeness_pct"] < 100
    assert row["filters"]["setup_incomplete"] is True
    assert row["setup_missing"]


# ─── Open critical risks + needs attention ──────────────────


def test_open_critical_risks_count(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.add_task("c1", "Open S3", "CRITICAL", "Cloud")
    cm.add_task("c1", "Old version", "LOW", "Headers")
    row = dc.build_row("c1")
    assert row["open_critical_risks"] == 1


def test_needs_attention_when_critical_open(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.add_task("c1", "Open S3", "CRITICAL", "Cloud")
    row = dc.build_row("c1")
    assert row["filters"]["needs_attention"] is True


# ─── Pending advisor reviews ─────────────────────────────────


def test_review_pending_filter(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    import advisor_review as ar
    ar.set_review("c1", "policy:wisp",
                  prepared_by="System", review_status="in_review")
    row = dc.build_row("c1")
    assert row["pending_advisor_reviews"] >= 1
    assert row["filters"]["review_pending"] is True


def test_signed_off_review_does_not_count_as_pending(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    import advisor_review as ar
    ar.set_review("c1", "policy:wisp",
                  prepared_by="System", reviewed_by="Alice",
                  reviewed_on="2026-04-12", review_status="approved",
                  sign_off_timestamp="2026-04-12T12:00:00+00:00")
    row = dc.build_row("c1")
    assert row["pending_advisor_reviews"] == 0


# ─── Security validations due ────────────────────────────────


def test_validations_due_counts_open_engagements(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.save_legal_authorization("c1", _good_legal_record("c1"))
    import security_validation as sv
    eng = sv.create_engagement("c1")
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(),
                            "end_at": (datetime.now(timezone.utc)
                                       + timedelta(hours=2)).isoformat()},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    sv.approve_engagement("c1", eng["engagement_id"], "Op")
    sv.schedule_engagement("c1", eng["engagement_id"])
    row = dc.build_row("c1")
    assert row["security_validations_due"] == 1


# ─── Health score ────────────────────────────────────────────


def test_health_score_high_for_strong_posture(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.add_score("c1", 90, "A")  # current_score 90
    cm.update_field("c1", "payment_status", "paid")
    cm.update_field("c1", "score_history", [
        {"score": 90, "grade": "A", "date": _days_ago(2)},
    ])
    row = dc.build_row("c1")
    assert row["current_score"] == 90
    assert row["health_score"] >= 50


def test_health_score_critical_when_overdue_and_low_score(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.add_score("c1", 20, "F")
    cm.update_field("c1", "payment_status", "overdue")
    cm.add_task("c1", "Critical 1", "CRITICAL", "x")
    cm.add_task("c1", "Critical 2", "CRITICAL", "y")
    row = dc.build_row("c1")
    assert row["health_score"] < 50
    assert row["filters"]["high_risk"] is True
    assert row["filters"]["renewal_risk"] is True


# ─── Renewal risk ────────────────────────────────────────────


def test_renewal_risk_when_payment_overdue(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.update_field("c1", "payment_status", "overdue")
    row = dc.build_row("c1")
    assert row["filters"]["renewal_risk"] is True


# ─── Console aggregation ─────────────────────────────────────


def test_build_console_returns_summary_with_correct_counts(dc, fresh_client_manager,
                                                          monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    cm = fresh_client_manager
    cm.create_client("a", "A", "a.com", tier="essentials")
    cm.create_client("b", "B", "b.com", tier="professional")
    cm.create_client("c", "C", "c.com", tier="enterprise_plus")
    cm.create_client("d", "D", "d.com", tier="diagnostic")
    out = dc.build_console()
    assert out["summary"]["total"] == 4
    assert out["summary"]["high_value"] == 2  # b (professional) + c (enterprise_plus)
    # Total ARR = 24k + 48k + 96k = 168k (diagnostic contributes 0)
    assert out["summary"]["total_arr"] == 168_000
    # Only the active-validation-bearing tiers (b + c) are flagged
    # authorization_missing — diagnostic and essentials don't include it.
    assert out["summary"]["authorization_missing"] == 2


def test_summary_zero_when_no_clients(dc, fresh_client_manager):
    out = dc.build_console()
    assert out["summary"]["total"] == 0
    assert out["clients"] == []


# ─── Operator route ──────────────────────────────────────────


def test_console_route_requires_operator_auth(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    public = TestClient(test_app, raise_server_exceptions=False)
    resp = public.get("/api/operator/delivery-console")
    assert resp.status_code == 401


def test_console_route_returns_aggregated_payload(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com", tier="professional")
    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.get("/api/operator/delivery-console", params={"password": "testpass"})
    assert resp.status_code == 200
    body = resp.json()
    assert "clients" in body
    assert "summary" in body
    assert body["summary"]["total"] >= 1
    assert body["clients"][0]["company_name"] == "Co"


def test_console_route_high_value_classification(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("a", "A", "a.com", tier="diagnostic")
    cm.create_client("b", "B", "b.com", tier="professional")
    op = TestClient(test_app, raise_server_exceptions=False)
    body = op.get("/api/operator/delivery-console",
                  params={"password": "testpass"}).json()
    rows_by_id = {r["client_id"]: r for r in body["clients"]}
    assert rows_by_id["a"]["is_high_value"] is False
    assert rows_by_id["b"]["is_high_value"] is True
    assert body["summary"]["high_value"] == 1


# ─── Filter classification ──────────────────────────────────


def test_high_value_filter_chip_count(dc, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("a", "A", "a.com", tier="essentials")
    cm.create_client("b", "B", "b.com", tier="professional")
    out = dc.build_console()
    high_value = [r for r in out["clients"] if r["filters"]["high_value_client"]]
    assert len(high_value) == 1
    assert high_value[0]["client_id"] == "b"


def test_setup_incomplete_filter_chip_count(dc, fresh_client_manager, monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    cm = fresh_client_manager
    cm.create_client("a", "A", "a.com")
    cm.create_client("b", "B", "b.com")
    out = dc.build_console()
    incomplete = [r for r in out["clients"] if r["filters"]["setup_incomplete"]]
    assert len(incomplete) == 2
