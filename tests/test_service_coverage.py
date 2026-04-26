"""Service coverage model tests.

Proves:
  - All 11 service areas are present.
  - Tier-availability gating works (Not included).
  - Integration gating works (Not connected).
  - Active never appears without a successful check timestamp.
  - Stale checks degrade Active to Pending setup.
  - Owner is one of Client / Advisor / System for every row.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import service_coverage as sc


# ─── Helpers ─────────────────────────────────────────────────


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _days_ago(n: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def _build(**overrides):
    base = dict(
        tier="essentials",
        score_history=[{"score": 70, "grade": "B", "date": _days_ago(5)[:10]}],
        open_tasks=[],
        alerts=[],
        reports=[],
        policies=[],
        frameworks=["IRS 4557"],
        compliance_pct=80,
        advisor_name="Alice CISSP",
        next_call_date="2026-05-15",
        advisor_reviewed_at=_days_ago(7),
        monthly_summary_reviewed_at=_days_ago(7),
        last_darkweb_check_at=_days_ago(2),
        dark_web_exposures=0,
        last_vuln_scan_at="",
        vuln_findings=0,
        last_phishing_campaign_at="",
        employee_emails=[],
        last_m365_sync_at="",
        legal_view={"active_validation": "Not included"},
        hibp_configured=True,
        gophish_configured=False,
        nuclei_available=False,
        m365_configured=False,
    )
    base.update(overrides)
    return sc.build_coverage(**base)


def _by_key(rows, key):
    return next(r for r in rows if r["key"] == key)


# ─── Structure ───────────────────────────────────────────────


def test_eleven_service_areas_present():
    rows = _build()
    keys = [r["key"] for r in rows]
    assert keys == [
        "external_attack_surface",
        "dark_web_monitoring",
        "threat_intelligence",
        "vulnerability_scanning",
        "identity_m365_monitoring",
        "phishing_readiness",
        "compliance_tracking",
        "policy_management",
        "evidence_package",
        "advisor_review",
        "security_validation",
    ]


def test_every_row_has_required_fields():
    rows = _build()
    required = {"key", "service", "plan_availability", "included_in_plan",
                "status", "last_successful_check", "data_source",
                "coverage_note", "next_action", "owner"}
    for r in rows:
        missing = required - set(r.keys())
        assert not missing, f"{r['key']} missing {missing}"


def test_owner_is_one_of_three_values():
    rows = _build()
    valid = {sc.OWNER_CLIENT, sc.OWNER_ADVISOR, sc.OWNER_SYSTEM}
    for r in rows:
        assert r["owner"] in valid, f"{r['key']} has invalid owner {r['owner']}"


def test_status_is_one_of_five_values():
    rows = _build()
    for r in rows:
        assert r["status"] in sc.ALL_STATUSES, (
            f"{r['key']} has invalid status {r['status']}"
        )


# ─── Plan availability gating ────────────────────────────────


def test_diagnostic_tier_excludes_dark_web_threat_intel_and_validation():
    rows = _build(tier="diagnostic")
    assert _by_key(rows, "dark_web_monitoring")["status"] == sc.STATUS_NOT_INCLUDED
    assert _by_key(rows, "threat_intelligence")["status"] == sc.STATUS_NOT_INCLUDED
    assert _by_key(rows, "vulnerability_scanning")["status"] == sc.STATUS_NOT_INCLUDED
    assert _by_key(rows, "phishing_readiness")["status"] == sc.STATUS_NOT_INCLUDED
    assert _by_key(rows, "security_validation")["status"] == sc.STATUS_NOT_INCLUDED


def test_essentials_excludes_phishing_and_validation():
    rows = _build(tier="essentials")
    assert _by_key(rows, "phishing_readiness")["status"] == sc.STATUS_NOT_INCLUDED
    assert _by_key(rows, "security_validation")["status"] == sc.STATUS_NOT_INCLUDED
    assert _by_key(rows, "vulnerability_scanning")["status"] == sc.STATUS_NOT_INCLUDED


def test_professional_includes_validation_and_phishing_and_vuln():
    rows = _build(tier="professional", legal_view={"active_validation": "Pending setup"})
    assert _by_key(rows, "phishing_readiness")["status"] != sc.STATUS_NOT_INCLUDED
    assert _by_key(rows, "security_validation")["status"] != sc.STATUS_NOT_INCLUDED
    assert _by_key(rows, "vulnerability_scanning")["status"] != sc.STATUS_NOT_INCLUDED


def test_not_included_rows_show_advisor_owner_and_referral_text():
    rows = _build(tier="diagnostic")
    not_included = [r for r in rows if r["status"] == sc.STATUS_NOT_INCLUDED]
    assert not_included
    for r in not_included:
        assert r["owner"] == sc.OWNER_ADVISOR
        assert "higher plan" in r["next_action"].lower()


# ─── No "Active" without a successful check ─────────────────


def test_external_attack_surface_active_only_with_recent_scan():
    # No score history → not Active.
    rows = _build(score_history=[])
    r = _by_key(rows, "external_attack_surface")
    assert r["status"] != sc.STATUS_ACTIVE
    assert r["last_successful_check"] == ""

    # Fresh scan → Active.
    rows = _build(score_history=[{"score": 70, "grade": "B", "date": _days_ago(5)[:10]}])
    r = _by_key(rows, "external_attack_surface")
    assert r["status"] == sc.STATUS_ACTIVE
    assert r["last_successful_check"]

    # Stale scan (>35d) → no longer Active.
    rows = _build(score_history=[{"score": 70, "grade": "B", "date": _days_ago(60)[:10]}])
    r = _by_key(rows, "external_attack_surface")
    assert r["status"] != sc.STATUS_ACTIVE


def test_external_attack_surface_critical_findings_flag_attention():
    rows = _build(
        score_history=[{"score": 70, "grade": "B", "date": _days_ago(5)[:10]}],
        open_tasks=[{"severity": "CRITICAL", "title": "Open SMB"}],
    )
    r = _by_key(rows, "external_attack_surface")
    assert r["status"] == sc.STATUS_NEEDS_ATTENTION
    assert "critical" in r["next_action"].lower()


def test_dark_web_not_connected_when_hibp_missing():
    rows = _build(hibp_configured=False)
    r = _by_key(rows, "dark_web_monitoring")
    assert r["status"] == sc.STATUS_NOT_CONNECTED
    assert r["last_successful_check"] == ""
    assert r["owner"] == sc.OWNER_CLIENT
    assert "hibp" in r["next_action"].lower() or "haveibeenpwned" in r["next_action"].lower()


def test_dark_web_pending_when_no_check_recorded():
    rows = _build(hibp_configured=True, last_darkweb_check_at="")
    r = _by_key(rows, "dark_web_monitoring")
    assert r["status"] == sc.STATUS_PENDING_SETUP
    # Critical: cannot claim Active without proof.
    assert r["status"] != sc.STATUS_ACTIVE


def test_dark_web_active_only_when_recent_check_and_no_exposures():
    rows = _build(hibp_configured=True, last_darkweb_check_at=_days_ago(1),
                  dark_web_exposures=0)
    r = _by_key(rows, "dark_web_monitoring")
    assert r["status"] == sc.STATUS_ACTIVE


def test_dark_web_needs_attention_when_exposures_present():
    rows = _build(hibp_configured=True, last_darkweb_check_at=_days_ago(1),
                  dark_web_exposures=3)
    r = _by_key(rows, "dark_web_monitoring")
    assert r["status"] == sc.STATUS_NEEDS_ATTENTION
    assert "password" in r["next_action"].lower() or "advisor" in r["next_action"].lower()


def test_threat_intelligence_pending_when_no_alerts_recorded():
    rows = _build(alerts=[])
    r = _by_key(rows, "threat_intelligence")
    assert r["status"] != sc.STATUS_ACTIVE  # never Active without proof
    assert r["last_successful_check"] == ""


def test_threat_intelligence_active_with_recent_alert_run():
    rows = _build(alerts=[{"type": "threat", "severity": "MEDIUM",
                           "date": _days_ago(1)}])
    r = _by_key(rows, "threat_intelligence")
    assert r["status"] == sc.STATUS_ACTIVE


def test_vulnerability_scanning_not_connected_when_nuclei_missing():
    rows = _build(tier="professional", nuclei_available=False)
    r = _by_key(rows, "vulnerability_scanning")
    assert r["status"] == sc.STATUS_NOT_CONNECTED


def test_vulnerability_scanning_active_only_with_recent_run():
    rows = _build(tier="professional", nuclei_available=True,
                  last_vuln_scan_at=_days_ago(10), vuln_findings=0)
    assert _by_key(rows, "vulnerability_scanning")["status"] == sc.STATUS_ACTIVE

    rows = _build(tier="professional", nuclei_available=True, last_vuln_scan_at="")
    assert _by_key(rows, "vulnerability_scanning")["status"] == sc.STATUS_PENDING_SETUP


def test_m365_not_connected_when_credentials_missing():
    rows = _build(m365_configured=False)
    r = _by_key(rows, "identity_m365_monitoring")
    assert r["status"] == sc.STATUS_NOT_CONNECTED
    assert r["owner"] == sc.OWNER_CLIENT


def test_phishing_readiness_pending_when_employee_list_missing():
    rows = _build(tier="professional", employee_emails=[], gophish_configured=True)
    r = _by_key(rows, "phishing_readiness")
    assert r["status"] == sc.STATUS_PENDING_SETUP
    assert r["owner"] == sc.OWNER_CLIENT


def test_phishing_readiness_not_connected_when_gophish_missing():
    rows = _build(tier="professional", employee_emails=["a@b.com"],
                  gophish_configured=False)
    r = _by_key(rows, "phishing_readiness")
    assert r["status"] == sc.STATUS_NOT_CONNECTED


def test_compliance_pending_without_frameworks():
    rows = _build(frameworks=[])
    r = _by_key(rows, "compliance_tracking")
    assert r["status"] == sc.STATUS_PENDING_SETUP
    assert r["owner"] == sc.OWNER_CLIENT


def test_compliance_needs_attention_when_below_threshold():
    rows = _build(frameworks=["SOC 2"], compliance_pct=20,
                  monthly_summary_reviewed_at=_days_ago(7))
    r = _by_key(rows, "compliance_tracking")
    assert r["status"] == sc.STATUS_NEEDS_ATTENTION


def test_policies_active_only_after_advisor_review():
    rows = _build(policies=[{"filename": "wisp.pdf"}], advisor_reviewed_at="")
    assert _by_key(rows, "policy_management")["status"] != sc.STATUS_ACTIVE

    rows = _build(policies=[{"filename": "wisp.pdf"}],
                  advisor_reviewed_at=_days_ago(10))
    assert _by_key(rows, "policy_management")["status"] == sc.STATUS_ACTIVE


def test_evidence_package_pending_until_artifacts_exist():
    rows = _build(reports=[], policies=[])
    assert _by_key(rows, "evidence_package")["status"] == sc.STATUS_PENDING_SETUP

    rows = _build(reports=[{"filename": "r.pdf", "date": _days_ago(3)[:10]}], policies=[])
    assert _by_key(rows, "evidence_package")["status"] == sc.STATUS_ACTIVE


def test_advisor_review_active_only_with_recent_review():
    rows = _build(advisor_reviewed_at="", monthly_summary_reviewed_at="")
    assert _by_key(rows, "advisor_review")["status"] != sc.STATUS_ACTIVE

    rows = _build(advisor_reviewed_at=_days_ago(7))
    assert _by_key(rows, "advisor_review")["status"] == sc.STATUS_ACTIVE


def test_security_validation_status_mirrors_legal_view():
    rows = _build(tier="professional", legal_view={"active_validation": "Approved"})
    assert _by_key(rows, "security_validation")["status"] == sc.STATUS_ACTIVE
    # Important: even when Approved, last_successful_check stays empty —
    # authorization is a precondition, not evidence of a successful run.
    assert _by_key(rows, "security_validation")["last_successful_check"] == ""

    rows = _build(tier="professional", legal_view={"active_validation": "Pending setup"})
    assert _by_key(rows, "security_validation")["status"] == sc.STATUS_PENDING_SETUP

    rows = _build(tier="professional", legal_view={"active_validation": "Withdrawn"})
    assert _by_key(rows, "security_validation")["status"] == sc.STATUS_NEEDS_ATTENTION


# ─── The hard rule: no Active without a successful check ────


def test_no_row_can_be_active_without_some_proof_of_success():
    """For any row showing 'Active', the last_successful_check must be set
    OR the status must be backed by an external authoritative source
    (security_validation Approved is the only documented exception, and even
    then we don't claim a successful run — only that authorization is in place).
    """
    rows = _build(
        tier="professional",
        legal_view={"active_validation": "Approved"},
        score_history=[{"score": 70, "grade": "B", "date": _days_ago(5)[:10]}],
        alerts=[{"type": "threat", "severity": "LOW", "date": _days_ago(1)}],
        reports=[{"filename": "r.pdf", "date": _days_ago(3)[:10]}],
        policies=[{"filename": "wisp.pdf"}],
        advisor_reviewed_at=_days_ago(7),
        monthly_summary_reviewed_at=_days_ago(7),
        hibp_configured=True, last_darkweb_check_at=_days_ago(1),
        gophish_configured=True, employee_emails=["a@b.com"],
        last_phishing_campaign_at=_days_ago(20),
        nuclei_available=True, last_vuln_scan_at=_days_ago(10),
        m365_configured=True, last_m365_sync_at=_days_ago(1),
    )
    for r in rows:
        if r["status"] == sc.STATUS_ACTIVE and r["key"] != "security_validation":
            assert r["last_successful_check"], (
                f"{r['key']} is Active but has no last_successful_check"
            )


def test_stale_dark_web_check_falls_back_to_pending():
    rows = _build(hibp_configured=True, last_darkweb_check_at=_days_ago(30),
                  dark_web_exposures=0)
    r = _by_key(rows, "dark_web_monitoring")
    # 30 days exceeds the weekly cadence by a wide margin.
    assert r["status"] == sc.STATUS_PENDING_SETUP


def test_stale_advisor_review_falls_back_to_pending():
    rows = _build(advisor_reviewed_at=_days_ago(120),
                  monthly_summary_reviewed_at=_days_ago(120))
    r = _by_key(rows, "advisor_review")
    assert r["status"] == sc.STATUS_PENDING_SETUP


def test_active_status_label_never_says_safe_clean_or_normal():
    rows = _build(
        tier="professional",
        score_history=[{"score": 70, "grade": "B", "date": _days_ago(5)[:10]}],
        alerts=[{"type": "threat", "severity": "LOW", "date": _days_ago(1)}],
        hibp_configured=True, last_darkweb_check_at=_days_ago(1),
    )
    forbidden = {"safe", "clean", "normal", "all clear", "all good"}
    for r in rows:
        for field in ("status", "coverage_note", "next_action", "data_source"):
            text = (r[field] or "").lower()
            for f in forbidden:
                assert f not in text, f"{r['key']}.{field} contains forbidden word '{f}': {r[field]!r}"
