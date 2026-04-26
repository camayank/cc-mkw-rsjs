"""Advisor-review metadata tests.

Proves:
  - All 9 spec fields are stored.
  - APPROVED status requires reviewed_by + reviewed_on + sign_off_timestamp.
  - customer_view() strips internal_operator_notes.
  - is_signed_off() returns True only for fully-signed records.
  - Subject-key helpers produce stable namespaced keys.
  - verify_task() mirrors verification into the review store.
  - Reviewer credentials are validated against the allowlist.
  - Operator routes require auth; portal route hides internal notes.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import advisor_review as ar


# ─── Schema ──────────────────────────────────────────────────


def test_record_has_all_nine_spec_fields(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    rec = ar.set_review(
        "c1", "report:monthly_security",
        prepared_by="System",
        reviewed_by="Alice",
        reviewed_on="2026-04-12",
        review_status=ar.REVIEW_APPROVED,
        advisor_notes="Looks good.",
        client_facing_recommendation="Apply DMARC reject.",
        internal_operator_notes="Customer pushed back on cadence.",
        reviewer_credential="CISSP",
        sign_off_timestamp="2026-04-12T15:30:00+00:00",
    )
    for k in ("prepared_by", "reviewed_by", "reviewed_on", "review_status",
              "advisor_notes", "client_facing_recommendation",
              "internal_operator_notes", "reviewer_credential",
              "sign_off_timestamp"):
        assert k in rec, f"missing {k}"


def test_subject_key_helpers():
    assert ar.report_key("monthly_security") == "report:monthly_security"
    assert ar.policy_key("wisp") == "policy:wisp"
    assert ar.monthly_summary_key("2026-04") == "monthly_summary:2026-04"
    assert ar.evidence_package_key("2026-04") == "evidence_package:2026-04"
    assert ar.audit_package_key("2026-04") == "audit_package:2026-04"
    assert ar.task_key("task_001") == "task:task_001"
    assert ar.validation_finding_key("vf_1") == "validation_finding:vf_1"


# ─── Sign-off rules ──────────────────────────────────────────


def test_approval_requires_complete_sign_off_identity(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    with pytest.raises(ValueError):
        ar.set_review("c1", "report:monthly_security",
                      review_status=ar.REVIEW_APPROVED)
    with pytest.raises(ValueError):
        ar.set_review("c1", "report:monthly_security",
                      review_status=ar.REVIEW_APPROVED,
                      reviewed_by="Alice", reviewed_on="2026-04-12")
    # Now provide everything → succeeds.
    rec = ar.set_review("c1", "report:monthly_security",
                       review_status=ar.REVIEW_APPROVED,
                       reviewed_by="Alice", reviewed_on="2026-04-12",
                       sign_off_timestamp="2026-04-12T12:00:00+00:00")
    assert rec["review_status"] == ar.REVIEW_APPROVED


def test_is_signed_off_only_for_fully_signed_records():
    assert ar.is_signed_off({}) is False
    assert ar.is_signed_off({"review_status": "approved"}) is False
    assert ar.is_signed_off({"review_status": "approved",
                             "reviewed_by": "Alice"}) is False
    assert ar.is_signed_off({"review_status": "approved",
                             "reviewed_by": "Alice",
                             "reviewed_on": "2026-04-12"}) is False
    assert ar.is_signed_off({"review_status": "approved",
                             "reviewed_by": "Alice",
                             "reviewed_on": "2026-04-12",
                             "sign_off_timestamp": "2026-04-12T12:00:00+00:00"}) is True


def test_invalid_review_status_rejected(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    with pytest.raises(ValueError):
        ar.set_review("c1", "report:monthly_security",
                      review_status="cooked")


def test_unrecognized_credential_rejected(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    with pytest.raises(ValueError):
        ar.set_review("c1", "report:monthly_security",
                      reviewer_credential="WIZARD")


def test_recognized_credentials_pass(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    for cred in ("CISSP", "CISA", "OSCP", "QSA"):
        ar.set_review("c1", f"report:monthly_security",
                      reviewer_credential=cred)


# ─── Customer view strips internal notes ────────────────────


def test_customer_view_hides_internal_operator_notes(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    rec = ar.set_review(
        "c1", "policy:wisp",
        prepared_by="System",
        reviewed_by="Alice", reviewed_on="2026-04-12",
        review_status=ar.REVIEW_APPROVED,
        sign_off_timestamp="2026-04-12T12:00:00+00:00",
        advisor_notes="Customer-visible rationale.",
        client_facing_recommendation="Apply password rotation policy.",
        internal_operator_notes="Customer's prior advisor missed this.",
        reviewer_credential="CISSP",
    )
    safe = ar.customer_view(rec)
    assert "internal_operator_notes" not in safe
    assert safe["advisor_notes"] == "Customer-visible rationale."
    assert safe["client_facing_recommendation"] == "Apply password rotation policy."
    assert safe["status_label"] == "Advisor reviewed"


def test_customer_view_handles_empty_record():
    assert ar.customer_view({}) == {}


def test_display_status_falls_back_to_review_pending():
    assert ar.display_status({}) == "Review pending"
    assert ar.display_status({"review_status": "pending"}) == "Review pending"
    assert ar.display_status({"review_status": "in_review"}) == "Review pending"
    # Approved without sign-off identity is NOT signed off — falls back.
    assert ar.display_status({"review_status": "approved"}) == "Review pending"


# ─── Persistence ────────────────────────────────────────────


def test_set_then_get_roundtrips(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    ar.set_review("c1", "policy:wisp", prepared_by="System")
    rec = ar.get_review("c1", "policy:wisp")
    assert rec["prepared_by"] == "System"


def test_set_partial_fields_preserves_others(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    ar.set_review("c1", "policy:wisp",
                  prepared_by="System",
                  client_facing_recommendation="Original recommendation")
    ar.set_review("c1", "policy:wisp", advisor_notes="Now reviewing")
    rec = ar.get_review("c1", "policy:wisp")
    assert rec["prepared_by"] == "System"
    assert rec["client_facing_recommendation"] == "Original recommendation"
    assert rec["advisor_notes"] == "Now reviewing"


def test_list_reviews_returns_all_subjects(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    ar.set_review("c1", "policy:wisp", prepared_by="System")
    ar.set_review("c1", "policy:incident_response_plan", prepared_by="System")
    out = ar.list_reviews("c1")
    assert "policy:wisp" in out
    assert "policy:incident_response_plan" in out


# ─── Task verification mirrors into review store ────────────


def test_verify_task_writes_review_record(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix DMARC", "HIGH", "Email")
    cm.submit_task_for_review("c1", t["id"], by="customer")
    cm.verify_task("c1", t["id"], by="Alice CISSP",
                   method="rescan",
                   note="Verified via rescan",
                   reviewer_credential="CISSP",
                   client_facing_recommendation="Keep DMARC at p=reject.",
                   internal_operator_notes="Watch for SaaS senders that fail.")
    rec = ar.get_review("c1", ar.task_key(t["id"]))
    assert ar.is_signed_off(rec) is True
    assert rec["reviewed_by"] == "Alice CISSP"
    assert rec["reviewer_credential"] == "CISSP"
    assert rec["client_facing_recommendation"] == "Keep DMARC at p=reject."
    # Customer view strips operator notes.
    safe = ar.customer_view(rec)
    assert "internal_operator_notes" not in safe


# ─── Operator routes ────────────────────────────────────────


def test_operator_set_review_requires_auth(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    public = TestClient(test_app, raise_server_exceptions=False)
    resp = public.post("/api/operator/clients/c1/reviews/policy:wisp",
                       json={"prepared_by": "System"})
    assert resp.status_code == 401


def test_operator_set_review_writes_record(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.post(
        "/api/operator/clients/c1/reviews/policy:wisp",
        json={
            "prepared_by": "System",
            "reviewed_by": "Alice",
            "reviewed_on": "2026-04-12",
            "review_status": "approved",
            "reviewer_credential": "CISSP",
            "client_facing_recommendation": "Sign annually.",
            "internal_operator_notes": "Audit due in Q3.",
        },
        params={"password": "testpass"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["review"]["review_status"] == "approved"
    assert body["review"]["sign_off_timestamp"]  # auto-stamped


def test_operator_approval_without_sign_off_returns_400(test_app, fresh_client_manager):
    """Server auto-stamps sign_off_timestamp when missing for approved status,
    so validation should pass when reviewed_by + reviewed_on are present."""
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    op = TestClient(test_app, raise_server_exceptions=False)
    # Approved without reviewed_by → 400 from set_review
    resp = op.post(
        "/api/operator/clients/c1/reviews/policy:wisp",
        json={"review_status": "approved"},
        params={"password": "testpass"},
    )
    assert resp.status_code == 400


def test_portal_review_route_strips_internal_notes(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com", tier="essentials")
    cm.set_portal_password("c1", "Pass123!")
    ar.set_review(
        "c1", "policy:wisp",
        prepared_by="System",
        reviewed_by="Alice", reviewed_on="2026-04-12",
        review_status=ar.REVIEW_APPROVED,
        sign_off_timestamp="2026-04-12T12:00:00+00:00",
        advisor_notes="Visible.",
        internal_operator_notes="SECRET INTERNAL.",
    )
    token = cm.create_jwt("c1")
    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token)
    resp = c.get("/api/portal/c1/reviews/policy:wisp")
    assert resp.status_code == 200
    body = resp.json()
    assert "internal_operator_notes" not in body
    assert "SECRET INTERNAL" not in (str(body))
    assert body["status_label"] == "Advisor reviewed"


def test_one_client_cannot_read_another_clients_review(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c_a", "A", "a.com", tier="essentials")
    cm.create_client("c_b", "B", "b.com", tier="essentials")
    ar.set_review("c_b", "policy:wisp", prepared_by="System")
    token_a = cm.create_jwt("c_a")
    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token_a)
    resp = c.get("/api/portal/c_b/reviews/policy:wisp")
    assert resp.status_code == 401
