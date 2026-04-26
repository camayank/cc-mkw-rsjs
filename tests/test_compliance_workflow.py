"""Compliance task workflow tests.

Proves:
  - All 13 task fields exist on a new task with sensible defaults.
  - State machine accepts only the documented transitions.
  - Customers cannot mark a task verified — only the operator endpoint can.
  - Verification metadata (verified_by / verified_at) is recorded.
  - Customer/advisor notes and evidence flow into the right buckets.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Schema ──────────────────────────────────────────────────


def test_new_task_has_all_required_fields(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix DMARC", "HIGH", "Email auth",
                    description="DMARC policy missing", fix="Add DMARC record")
    required = {
        "id", "title", "severity", "business_impact", "category",
        "owner", "due_date",
        "evidence_required", "evidence_attached",
        "customer_notes", "advisor_notes",
        "verification_method", "status",
        "verified_by", "verified_at",
    }
    missing = required - set(t.keys())
    assert not missing, f"missing: {missing}"
    assert t["status"] == cm.TASK_STATUS_OPEN
    assert t["evidence_required"], "evidence_required should default to a non-empty list"
    assert t["verification_method"]


def test_severity_drives_default_evidence_and_method(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    crit = cm.add_task("c1", "Public S3", "CRITICAL", "Cloud config")
    low = cm.add_task("c1", "Banner version exposed", "LOW", "headers")
    assert crit["verification_method"] == "advisor_inspection"
    assert any("screenshot" in e.lower() or "screen" in e.lower()
               for e in crit["evidence_required"])
    assert low["verification_method"] in ("self_attestation", "rescan",
                                          "configuration_check")


# ─── State machine ───────────────────────────────────────────


def test_customer_submit_transitions_open_to_submitted(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    out = cm.submit_task_for_review("c1", t["id"], by="customer",
                                    notes="Done — verify here", evidence=["dmarc.png"])
    assert out["status"] == cm.TASK_STATUS_SUBMITTED
    assert out["submitted_at"]
    assert out["submitted_by"] == "customer"
    assert any(n["note"].startswith("Done") for n in out["customer_notes"])
    assert any(e["filename"] == "dmarc.png" for e in out["evidence_attached"])


def test_customer_submit_works_from_in_progress(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    cm.start_task("c1", t["id"], by="customer")
    out = cm.submit_task_for_review("c1", t["id"], by="customer")
    assert out["status"] == cm.TASK_STATUS_SUBMITTED


def test_customer_cannot_jump_directly_to_verified(fresh_client_manager):
    """The legacy update_task_status() must refuse to set 'verified'."""
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    with pytest.raises(cm.TaskTransitionError):
        cm.update_task_status("c1", t["id"], cm.TASK_STATUS_VERIFIED)


def test_legacy_update_status_resolved_routes_to_submitted(fresh_client_manager):
    """Old callers that used status='resolved' end up at submitted_for_review,
    not verified — preserving the rule that only verify_task() can verify."""
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    cm.update_task_status("c1", t["id"], "resolved")
    after = cm.get_tasks("c1")[0]
    assert after["status"] == cm.TASK_STATUS_SUBMITTED


def test_advisor_verify_only_works_after_submission(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    # Verifying an open task should fail.
    with pytest.raises(cm.TaskTransitionError):
        cm.verify_task("c1", t["id"], by="advisor")
    # Submit, then verify, succeeds.
    cm.submit_task_for_review("c1", t["id"], by="customer")
    out = cm.verify_task("c1", t["id"], by="Alice CISSP",
                         method="rescan", note="Passes new scan")
    assert out["status"] == cm.TASK_STATUS_VERIFIED
    assert out["verified_by"] == "Alice CISSP"
    assert out["verified_at"]
    assert out["verification_method"] == "rescan"
    assert any("Passes new scan" in n["note"] for n in out["advisor_notes"])


def test_advisor_reject_returns_to_in_progress(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    cm.submit_task_for_review("c1", t["id"], by="customer")
    out = cm.reject_task("c1", t["id"], by="advisor",
                         reason="Need a screenshot")
    assert out["status"] == cm.TASK_STATUS_IN_PROGRESS
    assert any("Need a screenshot" in n["note"] for n in out["advisor_notes"])


def test_defer_then_reopen(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "MEDIUM", "Hygiene")
    out = cm.defer_task("c1", t["id"], by="advisor",
                        until="2026-07-01", reason="Pending vendor input")
    assert out["status"] == cm.TASK_STATUS_DEFERRED
    assert out["deferred_until"] == "2026-07-01"
    re = cm.reopen_task("c1", t["id"], by="advisor")
    assert re["status"] == cm.TASK_STATUS_OPEN


def test_invalid_transitions_raise(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "MEDIUM", "Hygiene")
    # cannot verify from open
    with pytest.raises(cm.TaskTransitionError):
        cm.verify_task("c1", t["id"], by="advisor")
    # cannot reject from open
    with pytest.raises(cm.TaskTransitionError):
        cm.reject_task("c1", t["id"], by="advisor", reason="x")


# ─── Notes + evidence ────────────────────────────────────────


def test_customer_notes_and_advisor_notes_are_kept_separate(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    cm.add_customer_note("c1", t["id"], "Did the change at 3pm", by="customer")
    cm.add_advisor_note("c1", t["id"], "Will rescan tomorrow", by="advisor")
    after = cm.get_tasks("c1")[0]
    assert any("3pm" in n["note"] for n in after["customer_notes"])
    assert any("rescan" in n["note"] for n in after["advisor_notes"])


def test_attach_evidence_records_filename_and_uploader(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    cm.attach_evidence("c1", t["id"], "spf-after.png", by="customer")
    after = cm.get_tasks("c1")[0]
    assert after["evidence_attached"][0]["filename"] == "spf-after.png"
    assert after["evidence_attached"][0]["uploaded_by"] == "customer"
    assert after["evidence_attached"][0]["uploaded_at"]


# ─── Route-level: customer cannot reach Verified ────────────


def _login(client, fresh_client_manager, client_id):
    cm = fresh_client_manager
    cm.create_client(client_id, "Co", "co.com", tier="essentials")
    cm.set_portal_password(client_id, "Pass123!")
    token = cm.create_jwt(client_id)
    client.cookies.set("portal_token", token)
    return cm


def test_portal_submit_route_is_not_verified(test_client, fresh_client_manager):
    cm = _login(test_client, fresh_client_manager, "c1")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    resp = test_client.post(
        f"/portal/c1/task/{t['id']}/submit",
        json={"notes": "applied", "evidence": ["dmarc.png"]},
    )
    assert resp.status_code == 200
    after = cm.get_tasks("c1")[0]
    assert after["status"] == cm.TASK_STATUS_SUBMITTED
    assert after["status"] != cm.TASK_STATUS_VERIFIED


def test_portal_status_route_refuses_verified(test_client, fresh_client_manager):
    cm = _login(test_client, fresh_client_manager, "c1")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    resp = test_client.post(
        f"/portal/c1/task/{t['id']}/status",
        json={"status": "verified"},
    )
    assert resp.status_code == 403


def test_portal_resolve_alias_still_only_submits(test_client, fresh_client_manager):
    """Backwards-compat: legacy POST .../resolve should not mark verified."""
    cm = _login(test_client, fresh_client_manager, "c1")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    resp = test_client.post(f"/portal/c1/task/{t['id']}/resolve")
    assert resp.status_code == 200
    after = cm.get_tasks("c1")[0]
    assert after["status"] == cm.TASK_STATUS_SUBMITTED
    assert after["status"] != cm.TASK_STATUS_VERIFIED


def test_operator_verify_route_requires_auth_and_submission(test_app, fresh_client_manager):
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com", tier="essentials")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")

    # Unauthenticated → 401.
    public = TestClient(test_app, raise_server_exceptions=False)
    resp = public.post(f"/api/operator/clients/c1/tasks/{t['id']}/verify",
                       json={"operator_name": "Op"})
    assert resp.status_code == 401

    # Operator auth, but task is still Open → 400 (illegal transition).
    op = TestClient(test_app, raise_server_exceptions=False)
    op_params = {"password": "testpass"}
    resp = op.post(f"/api/operator/clients/c1/tasks/{t['id']}/verify",
                   json={"operator_name": "Op"}, params=op_params)
    assert resp.status_code == 400

    # Submit, then verify succeeds.
    cm.submit_task_for_review("c1", t["id"], by="customer")
    resp = op.post(f"/api/operator/clients/c1/tasks/{t['id']}/verify",
                   json={"operator_name": "Op", "method": "rescan",
                         "note": "Verified by rescan"},
                   params=op_params)
    assert resp.status_code == 200, resp.text
    after = cm.get_tasks("c1")[0]
    assert after["status"] == cm.TASK_STATUS_VERIFIED
    assert after["verified_by"] == "Op"


def test_operator_verify_requires_operator_name(test_app, fresh_client_manager):
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    cm.submit_task_for_review("c1", t["id"], by="customer")

    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.post(f"/api/operator/clients/c1/tasks/{t['id']}/verify",
                   json={}, params={"password": "testpass"})
    assert resp.status_code == 400


def test_operator_verify_rejects_invalid_method(test_app, fresh_client_manager):
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    cm.submit_task_for_review("c1", t["id"], by="customer")

    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.post(
        f"/api/operator/clients/c1/tasks/{t['id']}/verify",
        json={"operator_name": "Op", "method": "wave_a_magic_wand"},
        params={"password": "testpass"},
    )
    assert resp.status_code == 400


def test_operator_reject_route_returns_to_in_progress(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    cm.submit_task_for_review("c1", t["id"], by="customer")
    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.post(
        f"/api/operator/clients/c1/tasks/{t['id']}/reject",
        json={"operator_name": "Op", "reason": "Need updated screenshot"},
        params={"password": "testpass"},
    )
    assert resp.status_code == 200
    after = cm.get_tasks("c1")[0]
    assert after["status"] == cm.TASK_STATUS_IN_PROGRESS


def test_one_client_cannot_submit_another_clients_task(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c_a", "A", "a.com", tier="essentials")
    cm.create_client("c_b", "B", "b.com", tier="essentials")
    t_b = cm.add_task("c_b", "Fix", "HIGH", "Email")
    token_a = cm.create_jwt("c_a")

    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token_a)
    resp = c.post(f"/portal/c_b/task/{t_b['id']}/submit", json={})
    assert resp.status_code in (401, 403)
    after = cm.get_tasks("c_b")[0]
    assert after["status"] == cm.TASK_STATUS_OPEN
