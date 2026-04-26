"""Document library tests.

Proves:
  - All 8 canonical reports + 8 canonical policies are always rendered.
  - Each item carries the spec'd 8 fields.
  - Status mapping uses the spec vocabulary.
  - Review-due dates compute correctly from cadence + last review.
  - Tier availability gates report visibility (Not in plan).
  - Filename matching pulls in real artifacts and produces download URLs.
  - Expired status fires when the review-due date is past.
"""
from __future__ import annotations

import os
import sys
from datetime import date, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import document_library as dl


def _today() -> str:
    return date.today().isoformat()


def _days_ago(n: int) -> str:
    return (date.today() - timedelta(days=n)).isoformat()


def _build(**overrides):
    base = dict(
        client_id="c1", tier="essentials",
        reports=[], policies=[], frameworks=[],
        advisor_name="Alice CISSP",
        advisor_reviewed_at="",
        monthly_summary_reviewed_at="",
        legal_view={},
        review_records=None,
    )
    base.update(overrides)
    return dl.build_library(**base)


def _approved_review(reviewer="Alice CISSP", on="2026-04-12",
                     credential="CISSP"):
    return {
        "review_status": "approved",
        "reviewed_by": reviewer,
        "reviewed_on": on,
        "sign_off_timestamp": f"{on}T12:00:00+00:00",
        "reviewer_credential": credential,
        "client_facing_recommendation": "",
        "advisor_notes": "",
        "prepared_by": "System",
    }


def _r(out, key):
    return next(d for d in out["reports"] if d["key"] == key)


def _p(out, key):
    return next(d for d in out["policies"] if d["key"] == key)


# ─── Structure ───────────────────────────────────────────────


def test_eight_reports_always_present_in_canonical_order():
    out = _build()
    keys = [r["key"] for r in out["reports"]]
    assert keys == [
        "paid_diagnostic",
        "security_assessment",
        "monthly_security",
        "compliance_progress",
        "advisor_call_agenda",
        "audit_evidence_package",
        "security_validation",
        "qbr",
    ]


def test_eight_policies_always_present_in_canonical_order():
    out = _build()
    keys = [p["key"] for p in out["policies"]]
    assert keys == [
        "wisp",
        "incident_response_plan",
        "access_control_policy",
        "vendor_management_policy",
        "data_classification_policy",
        "ai_acceptable_use_policy",
        "security_awareness_policy",
        "business_continuity_plan",
    ]


def test_canonical_titles_match_spec():
    out = _build()
    report_titles = {r["business_title"] for r in out["reports"]}
    assert report_titles == {
        "Paid Diagnostic Report",
        "Security Assessment Report",
        "Monthly Security Report",
        "Compliance Progress Summary",
        "Advisor Call Agenda",
        "Audit Evidence Package",
        "Security Validation Report",
        "Quarterly Business Review",
    }
    policy_titles = {p["business_title"] for p in out["policies"]}
    assert policy_titles == {
        "Written Information Security Plan",
        "Incident Response Plan",
        "Access Control Policy",
        "Vendor Management Policy",
        "Data Classification Policy",
        "AI Acceptable Use Policy",
        "Security Awareness Policy",
        "Business Continuity Plan",
    }


def test_every_document_has_required_fields():
    out = _build(
        reports=[{"filename": "monthly_2026-04.pdf", "date": _today()}],
        policies=[{"filename": "wisp.pdf"}],
        advisor_reviewed_at=_today(),
        monthly_summary_reviewed_at=_today(),
    )
    required = {"business_title", "type", "generated_date", "version",
                "review_status", "reviewed_by", "reviewed_on",
                "review_due_date", "framework_mapping", "download_url",
                "kind", "key", "present", "frequency_label", "available_in_plan"}
    for d in out["reports"] + out["policies"]:
        missing = required - set(d.keys())
        assert not missing, f"{d['key']}: missing {missing}"


# ─── Status mapping ──────────────────────────────────────────


def test_status_is_one_of_five_values():
    out = _build(
        reports=[
            {"filename": "monthly_2026-04.pdf", "date": _today()},
            {"filename": "qbr_2026-q1.pdf", "date": _days_ago(120)},  # cadence 90 -> review pending
        ],
        policies=[{"filename": "wisp.pdf"}, {"filename": "byod_policy.pdf"}],
        advisor_reviewed_at=_today(),
        monthly_summary_reviewed_at=_today(),
        tier="professional",
    )
    for d in out["reports"] + out["policies"]:
        assert d["review_status"] in dl.ALL_STATUSES, (
            f"{d['business_title']}: {d['review_status']}"
        )


def test_missing_artifact_renders_as_draft():
    out = _build()
    # WISP not on disk → Draft
    wisp = _p(out, "wisp")
    assert wisp["present"] is False
    assert wisp["review_status"] == dl.STATUS_DRAFT
    assert wisp["download_url"] == ""


def test_present_artifact_with_recent_review_is_advisor_reviewed():
    """An approved review record for policy:wisp produces Advisor reviewed."""
    out = _build(
        policies=[{"filename": "wisp.pdf"}],
        advisor_reviewed_at=_today(),
        review_records={"policy:wisp": _approved_review(on=_today())},
    )
    wisp = _p(out, "wisp")
    assert wisp["present"] is True
    assert wisp["review_status"] == dl.STATUS_ADVISOR_REVIEWED
    assert wisp["reviewed_by"] == "Alice CISSP"
    assert wisp["reviewed_on"] == _today()


def test_static_reviewed_claim_removed_without_review_record():
    """Without a real review record, the heuristic timestamp is not enough."""
    out = _build(
        policies=[{"filename": "wisp.pdf"}],
        advisor_reviewed_at=_today(),
        review_records={},
    )
    wisp = _p(out, "wisp")
    assert wisp["review_status"] != dl.STATUS_ADVISOR_REVIEWED
    assert wisp["reviewed_by"] == ""


def test_present_but_unreviewed_artifact_is_review_pending():
    out = _build(
        policies=[{"filename": "wisp.pdf"}],
        advisor_reviewed_at="",
    )
    wisp = _p(out, "wisp")
    assert wisp["present"] is True
    assert wisp["review_status"] == dl.STATUS_REVIEW_PENDING
    assert wisp["reviewed_by"] == ""


def test_stale_review_falls_back_to_review_pending():
    """Annual policy reviewed 400 days ago → Review pending (overdue)."""
    out = _build(
        policies=[{"filename": "wisp.pdf"}],
        advisor_reviewed_at=_days_ago(400),
    )
    wisp = _p(out, "wisp")
    # 400 days > 365 cadence, but the review-due date is also past, so Expired wins.
    assert wisp["review_status"] in (dl.STATUS_EXPIRED, dl.STATUS_REVIEW_PENDING)


def test_review_due_in_past_renders_expired():
    out = _build(
        policies=[{"filename": "wisp.pdf"}],
        advisor_reviewed_at=_days_ago(400),
    )
    wisp = _p(out, "wisp")
    assert wisp["review_status"] == dl.STATUS_EXPIRED


# ─── Review-due-date computation ─────────────────────────────


def test_policy_review_due_date_is_one_year_after_review():
    review_iso = _days_ago(30)
    out = _build(
        policies=[{"filename": "wisp.pdf"}],
        advisor_reviewed_at=review_iso,
    )
    wisp = _p(out, "wisp")
    expected = (date.today() - timedelta(days=30) + timedelta(days=365)).isoformat()
    assert wisp["review_due_date"] == expected


def test_monthly_report_review_due_date_is_thirty_days_out():
    out = _build(
        reports=[{"filename": "monthly_2026-04.pdf", "date": _today()}],
        monthly_summary_reviewed_at=_today(),
    )
    monthly = _r(out, "monthly_security")
    expected = (date.today() + timedelta(days=30)).isoformat()
    assert monthly["review_due_date"] == expected


def test_one_time_diagnostic_has_no_review_due_date():
    out = _build(
        reports=[{"filename": "diagnostic_report.pdf", "date": _today()}],
        tier="diagnostic",
    )
    diag = _r(out, "paid_diagnostic")
    assert diag["review_due_date"] == ""


def test_qbr_review_due_is_quarterly():
    out = _build(
        reports=[{"filename": "qbr_2026-q1.pdf", "date": _today()}],
        monthly_summary_reviewed_at=_today(),
        tier="professional",
    )
    qbr = _r(out, "qbr")
    expected = (date.today() + timedelta(days=90)).isoformat()
    assert qbr["review_due_date"] == expected


# ─── Tier availability ───────────────────────────────────────


def test_qbr_not_in_essentials_plan():
    out = _build(tier="essentials")
    qbr = _r(out, "qbr")
    assert qbr["available_in_plan"] is False


def test_qbr_in_professional_plan():
    out = _build(tier="professional")
    qbr = _r(out, "qbr")
    assert qbr["available_in_plan"] is True


def test_security_validation_report_only_when_authorized():
    """Even on Professional, with no Approved authorization, the validation
    report is not yet available — it should not show as present."""
    out = _build(tier="professional",
                 legal_view={"active_validation": "Pending setup"})
    sv = _r(out, "security_validation")
    assert sv["present"] is False


def test_security_validation_report_present_when_authorized_and_artifact_exists():
    out = _build(
        tier="professional",
        reports=[{"filename": "validation_report_2026-04.pdf", "date": _today()}],
        legal_view={"active_validation": "Approved"},
    )
    sv = _r(out, "security_validation")
    assert sv["present"] is True


def test_diagnostic_tier_locks_monthly_and_quarterly_reports():
    out = _build(tier="diagnostic")
    assert _r(out, "monthly_security")["available_in_plan"] is False
    assert _r(out, "qbr")["available_in_plan"] is False
    assert _r(out, "paid_diagnostic")["available_in_plan"] is True
    assert _r(out, "audit_evidence_package")["available_in_plan"] is True


# ─── Filename matching ──────────────────────────────────────


def test_policy_filename_match_picks_correct_template():
    out = _build(
        policies=[
            {"filename": "wisp.pdf"},
            {"filename": "incident-response-plan.pdf"},
            {"filename": "data-classification.pdf"},
            {"filename": "vendor-management.pdf"},
            {"filename": "ai_use_policy.pdf"},
            {"filename": "security_awareness.pdf"},
            {"filename": "business_continuity.pdf"},
            {"filename": "access-control.pdf"},
        ],
        advisor_reviewed_at=_today(),
    )
    for key in ("wisp", "incident_response_plan", "data_classification_policy",
                "vendor_management_policy", "ai_acceptable_use_policy",
                "security_awareness_policy", "business_continuity_plan",
                "access_control_policy"):
        d = _p(out, key)
        assert d["present"] is True, f"{key} not picked up"


def test_download_url_uses_portal_path_with_filename():
    out = _build(
        policies=[{"filename": "wisp.pdf"}],
        advisor_reviewed_at=_today(),
    )
    wisp = _p(out, "wisp")
    assert wisp["download_url"] == "/portal/c1/download/policies/wisp.pdf"


def test_audit_evidence_package_uses_dedicated_zip_url():
    out = _build(
        reports=[{"filename": "audit-package-2026.zip", "date": _today()}],
        monthly_summary_reviewed_at=_today(),
    )
    aep = _r(out, "audit_evidence_package")
    assert aep["download_url"] == "/portal/c1/download/audit-package"


# ─── Framework mapping ──────────────────────────────────────


def test_wisp_carries_canonical_framework_mapping():
    out = _build(policies=[{"filename": "wisp.pdf"}])
    wisp = _p(out, "wisp")
    assert "IRS 4557" in wisp["framework_mapping"]
    assert "FTC Safeguards" in wisp["framework_mapping"]
    assert "NIST CSF 2.0" in wisp["framework_mapping"]


def test_compliance_progress_inherits_client_frameworks():
    out = _build(
        frameworks=["IRS 4557", "FTC Safeguards", "SOC 2"],
        reports=[{"filename": "compliance-progress.pdf", "date": _today()}],
    )
    cp = _r(out, "compliance_progress")
    assert "SOC 2" in cp["framework_mapping"]


def test_ai_policy_maps_to_ai_frameworks():
    out = _build(policies=[{"filename": "ai_acceptable_use.pdf"}])
    ai = _p(out, "ai_acceptable_use_policy")
    assert "NIST AI RMF" in ai["framework_mapping"]
    assert "EU AI Act" in ai["framework_mapping"]


# ─── No raw filenames as labels ─────────────────────────────


def test_business_titles_never_contain_filename_extensions():
    out = _build(
        reports=[
            {"filename": "monthly_2026-04.pdf", "date": _today()},
            {"filename": "qbr_2026-q1.pdf", "date": _today()},
        ],
        policies=[
            {"filename": "wisp_v2.pdf"},
            {"filename": "ai_use_policy.pdf"},
        ],
        tier="professional",
    )
    for d in out["reports"] + out["policies"]:
        t = d["business_title"]
        assert ".pdf" not in t.lower()
        assert ".zip" not in t.lower()
        assert "_" not in t


def test_version_extracted_from_filename_when_present():
    out = _build(
        policies=[{"filename": "wisp_v2.3.pdf"}],
        advisor_reviewed_at=_today(),
    )
    wisp = _p(out, "wisp")
    assert wisp["version"] == "v2.3"
