"""Evidence Vault tests.

Proves:
  - All 10 categories present in display order.
  - Business titles replace raw filenames.
  - Status mapping uses the spec vocabulary only.
  - Framework mapping is populated for items that have a known mapping.
  - Reviewed-by / reviewed-on metadata propagates correctly.
  - Empty categories show calm empty-state copy.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence_vault as ev


# ─── Helpers ─────────────────────────────────────────────────


def _build(**overrides):
    base = dict(
        client_id="c1",
        policies=[],
        reports=[],
        scans=[],
        alerts=[],
        frameworks=[],
        compliance_pct=0,
        advisor_name="",
        advisor_reviewed_at="",
        monthly_summary_reviewed_at="",
        last_phishing_campaign_at="",
        last_m365_sync_at="",
        m365_configured=False,
        legal_view={},
        authorization_audit=[],
    )
    base.update(overrides)
    return ev.build_vault(**base)


def _by_key(vault, key):
    return next(c for c in vault["categories"] if c["key"] == key)


# ─── Structure ───────────────────────────────────────────────


def test_ten_categories_in_display_order():
    out = _build()
    keys = [c["key"] for c in out["categories"]]
    assert keys == [
        "policies",
        "security_reports",
        "scan_results",
        "access_reviews",
        "training_phishing",
        "incident_response",
        "vendor_compliance",
        "cyber_insurance",
        "security_validation",
        "legal_authorizations",
    ]


def test_every_category_has_label_count_items_empty_state():
    out = _build()
    for cat in out["categories"]:
        assert {"key", "label", "items", "count", "empty_state"} <= set(cat.keys())
        assert isinstance(cat["items"], list)
        assert cat["count"] == len(cat["items"])


def test_category_labels_use_human_titles():
    expected = {
        "policies": "Policies",
        "security_reports": "Security reports",
        "scan_results": "Scan results",
        "access_reviews": "Access reviews",
        "training_phishing": "Training & phishing records",
        "incident_response": "Incident response",
        "vendor_compliance": "Vendor & compliance documents",
        "cyber_insurance": "Cyber insurance evidence",
        "security_validation": "Security validation evidence",
        "legal_authorizations": "Legal authorizations",
    }
    out = _build()
    for cat in out["categories"]:
        assert cat["label"] == expected[cat["key"]]


# ─── Business titles, never raw filenames ───────────────────


def test_policies_use_business_titles():
    out = _build(policies=[
        {"filename": "wisp.pdf"},
        {"filename": "aup_v2.pdf"},
        {"filename": "incident-response-plan.pdf"},
        {"filename": "byod_policy.pdf"},
        {"filename": "vendor-risk.pdf"},
    ], advisor_name="Alice CISSP", advisor_reviewed_at="2026-04-12")

    items = _by_key(out, "policies")["items"]
    titles = [i["business_title"] for i in items]
    assert "Written Information Security Plan" in titles
    assert "Acceptable Use Policy" in titles
    assert "Incident Response Plan" in titles
    assert "Mobile Device & BYOD Policy" in titles
    assert "Vendor & Third-Party Risk Policy" in titles
    # No item should expose the raw filename as the customer label.
    for i in items:
        assert ".pdf" not in i["business_title"].lower()
        assert "_" not in i["business_title"]


def test_reports_use_business_titles():
    out = _build(reports=[
        {"filename": "monthly_2026-04.pdf", "date": "2026-04-12"},
        {"filename": "audit-package-2026.zip", "date": "2026-04-12"},
        {"filename": "executive_summary.pdf", "date": "2026-04-12"},
    ])
    items = _by_key(out, "security_reports")["items"]
    titles = [i["business_title"] for i in items]
    assert any("Monthly Security Report" in t for t in titles)
    assert "Audit Evidence Package" in titles
    assert "Executive Summary" in titles
    for i in items:
        assert ".pdf" not in i["business_title"].lower()
        assert ".zip" not in i["business_title"].lower()


def test_scans_use_business_titles():
    out = _build(scans=[
        {"filename": "2026-04-12-monthly.json", "date": "2026-04-12"},
        {"filename": "2026-04-15-vuln.json", "date": "2026-04-15"},
    ])
    items = _by_key(out, "scan_results")["items"]
    assert all("External Scan" in i["business_title"] for i in items)
    for i in items:
        assert ".json" not in i["business_title"].lower()


# ─── Required per-item fields ───────────────────────────────


def test_every_item_has_required_fields():
    out = _build(
        policies=[{"filename": "wisp.pdf"}],
        reports=[{"filename": "monthly_2026-04.pdf", "date": "2026-04-12"}],
        scans=[{"filename": "2026-04-12-monthly.json", "date": "2026-04-12"}],
        frameworks=["IRS 4557"],
        compliance_pct=80,
        advisor_name="Alice", advisor_reviewed_at="2026-04-12",
        monthly_summary_reviewed_at="2026-04-12",
        m365_configured=True, last_m365_sync_at="2026-04-13",
        legal_view={
            "documents": {"msa": "Signed", "sow": "Signed",
                          "nda": "Signed", "dpa": "Signed"},
            "authorized_representative_recorded": True,
            "ownership_confirmed": True,
            "active_validation": "Approved",
        },
        authorization_audit=[
            {"event": "active_validation_approved", "at": "2026-04-10"}
        ],
    )
    required = {"id", "category", "category_label", "business_title",
                "type", "date", "version", "status", "framework_mapping",
                "uploaded_by", "reviewed_by", "reviewed_on", "download_url"}
    for cat in out["categories"]:
        for item in cat["items"]:
            missing = required - set(item.keys())
            assert not missing, f"{cat['key']} item missing {missing}"


# ─── Status vocabulary ──────────────────────────────────────


def test_status_is_one_of_five_values():
    out = _build(
        policies=[{"filename": "wisp.pdf"}],
        reports=[{"filename": "monthly_2026-04.pdf", "date": "2026-04-12"}],
        scans=[{"filename": "2026-04-12-monthly.json", "date": "2026-04-12"}],
        frameworks=["IRS 4557"], compliance_pct=80,
        advisor_name="Alice", advisor_reviewed_at="2026-04-12",
        monthly_summary_reviewed_at="2026-04-12",
        legal_view={"documents": {"msa": "Signed", "sow": "Pending setup",
                                  "nda": "Pending setup", "dpa": "Pending setup"},
                    "active_validation": "Pending setup"},
    )
    for cat in out["categories"]:
        for item in cat["items"]:
            assert item["status"] in ev.ALL_STATUSES, (
                f"{item['business_title']}: {item['status']}"
            )


def test_advisor_reviewed_status_when_review_metadata_present():
    """A real review record for policy:wisp produces Advisor reviewed."""
    out = _build(
        policies=[{"filename": "wisp.pdf"}],
        advisor_name="Alice CISSP",
        review_records={
            "policy:wisp": {
                "subject_key": "policy:wisp",
                "review_status": "approved",
                "reviewed_by": "Alice CISSP",
                "reviewed_on": "2026-04-12",
                "sign_off_timestamp": "2026-04-12T12:00:00+00:00",
                "reviewer_credential": "CISSP",
            },
        },
    )
    item = _by_key(out, "policies")["items"][0]
    assert item["status"] == ev.STATUS_ADVISOR_REVIEWED
    assert item["reviewed_by"] == "Alice CISSP"
    assert item["reviewed_on"] == "2026-04-12"


def test_static_advisor_reviewed_claim_is_removed_without_review_record():
    """Old heuristic (advisor_reviewed_at on client profile) is no longer
    sufficient to claim Advisor reviewed."""
    out = _build(policies=[{"filename": "wisp.pdf"}],
                 advisor_name="Alice CISSP", advisor_reviewed_at="2026-04-12",
                 review_records={})
    item = _by_key(out, "policies")["items"][0]
    assert item["status"] != ev.STATUS_ADVISOR_REVIEWED
    assert item["reviewed_by"] == ""


def test_review_pending_when_no_review_metadata():
    out = _build(policies=[{"filename": "wisp.pdf"}])
    item = _by_key(out, "policies")["items"][0]
    assert item["status"] == ev.STATUS_REVIEW_PENDING
    assert item["reviewed_by"] == ""


def test_legal_authorizations_signed_documents_show_advisor_reviewed():
    out = _build(legal_view={
        "documents": {"msa": "Signed", "sow": "Signed",
                      "nda": "Signed", "dpa": "Signed"},
    })
    items = _by_key(out, "legal_authorizations")["items"]
    titles = [i["business_title"] for i in items]
    assert "Master Services Agreement" in titles
    assert "Statement of Work" in titles
    assert "Mutual Non-Disclosure Agreement" in titles
    assert "Data Processing Agreement" in titles
    for i in items[:4]:
        assert i["status"] == ev.STATUS_ADVISOR_REVIEWED


def test_legal_authorizations_pending_documents_show_draft():
    out = _build(legal_view={
        "documents": {"msa": "Pending setup", "sow": "Pending setup",
                      "nda": "Pending setup", "dpa": "Pending setup"},
    })
    items = _by_key(out, "legal_authorizations")["items"]
    for i in items:
        assert i["status"] == ev.STATUS_DRAFT


def test_security_validation_status_mirrors_authorization():
    out = _build(legal_view={"active_validation": "Approved"})
    sv = _by_key(out, "security_validation")["items"]
    auth_items = [i for i in sv if "Authorization" in i["business_title"]]
    assert auth_items
    assert auth_items[0]["status"] == ev.STATUS_ADVISOR_REVIEWED


# ─── Framework mapping ──────────────────────────────────────


def test_policies_carry_framework_mapping():
    out = _build(policies=[
        {"filename": "wisp.pdf"},
        {"filename": "incident-response.pdf"},
        {"filename": "byod_policy.pdf"},
    ])
    items = _by_key(out, "policies")["items"]
    wisp = next(i for i in items if "Written Information" in i["business_title"])
    assert "IRS 4557" in wisp["framework_mapping"]
    assert "FTC Safeguards" in wisp["framework_mapping"]
    irp = next(i for i in items if "Incident Response" in i["business_title"])
    assert "NIST CSF 2.0" in irp["framework_mapping"]
    byod = next(i for i in items if "BYOD" in i["business_title"])
    assert "HIPAA Security Rule" in byod["framework_mapping"]


def test_reports_inherit_client_frameworks():
    out = _build(reports=[{"filename": "monthly_2026-04.pdf", "date": "2026-04-12"}],
                 frameworks=["IRS 4557", "FTC Safeguards"])
    item = _by_key(out, "security_reports")["items"][0]
    assert "IRS 4557" in item["framework_mapping"]


# ─── Empty categories ───────────────────────────────────────


def test_empty_categories_show_calm_copy():
    out = _build()
    # Most categories are empty in this minimal build (incident_response and
    # legal_authorizations populate by default with playbooks/agreements).
    expected_empty = ["policies", "security_reports", "scan_results",
                      "access_reviews", "training_phishing",
                      "vendor_compliance", "cyber_insurance",
                      "security_validation"]
    for key in expected_empty:
        cat = _by_key(out, key)
        if cat["items"]:
            continue  # OK: defaults populated
        assert cat["empty_state"]
        # No alarming language.
        for word in ("error", "fail", "missing", "unsafe"):
            assert word not in cat["empty_state"].lower()


def test_incident_response_always_has_default_playbooks():
    out = _build()
    items = _by_key(out, "incident_response")["items"]
    titles = [i["business_title"] for i in items]
    assert any("Ransomware" in t for t in titles)
    assert any("Business Email Compromise" in t for t in titles)
    assert any("Data Breach" in t for t in titles)


def test_access_reviews_only_when_m365_configured():
    out = _build(m365_configured=False)
    assert _by_key(out, "access_reviews")["count"] == 0
    out2 = _build(m365_configured=True, last_m365_sync_at="2026-04-12")
    assert _by_key(out2, "access_reviews")["count"] == 1


# ─── No raw filenames as primary labels ─────────────────────


def test_no_business_title_contains_raw_filename_pattern():
    out = _build(
        policies=[{"filename": "abc-xyz_policy_v3.pdf"}],
        reports=[{"filename": "report_2026-04-12.pdf", "date": "2026-04-12"}],
        scans=[{"filename": "2026-04-12-initial.json", "date": "2026-04-12"}],
    )
    for cat in out["categories"]:
        for item in cat["items"]:
            t = item["business_title"]
            assert ".pdf" not in t.lower()
            assert ".json" not in t.lower()
            assert ".zip" not in t.lower()


def test_by_id_lookup_works():
    out = _build(policies=[{"filename": "wisp.pdf"}])
    item = _by_key(out, "policies")["items"][0]
    assert out["by_id"][item["id"]] is item


def test_uploaded_by_uses_human_label():
    out = _build(policies=[{"filename": "wisp.pdf"}],
                 advisor_name="Alice CISSP", advisor_reviewed_at="2026-04-12")
    item = _by_key(out, "policies")["items"][0]
    assert item["uploaded_by"] == "Advisor — Alice CISSP"


def test_version_extracted_from_filename_when_present():
    out = _build(policies=[{"filename": "aup_v2.3.pdf"}])
    item = _by_key(out, "policies")["items"][0]
    assert item["version"] == "v2.3"


def test_cyber_insurance_evidence_only_when_reports_and_policies_exist():
    # Without evidence: only the readiness letter as Draft.
    out = _build()
    items = _by_key(out, "cyber_insurance")["items"]
    assert any(i["business_title"] == "Cyber Insurance Readiness Letter"
               and i["status"] == ev.STATUS_DRAFT for i in items)

    # With evidence: bundle item appears.
    out2 = _build(reports=[{"filename": "monthly_2026-04.pdf", "date": "2026-04-12"}],
                  policies=[{"filename": "wisp.pdf"}],
                  advisor_name="Alice", advisor_reviewed_at="2026-04-12")
    bundle_titles = [i["business_title"]
                     for i in _by_key(out2, "cyber_insurance")["items"]]
    assert "Insurer Underwriting Evidence Bundle" in bundle_titles
