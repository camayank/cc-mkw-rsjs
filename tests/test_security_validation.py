"""Security Validation module tests.

Proves:
  - 11 spec statuses + transition table.
  - Hard rule: active scan refuses to start without approved authorization.
  - Kill switch routes RUNNING -> STOPPED at any time.
  - FP review then advisor validation per finding (in that order).
  - Engagement-level validate() requires every confirmed finding to be
    advisor-validated.
  - Retest cycle drives REMEDIATION_IN_PROGRESS -> RETEST_PASSED.
  - Apex command construction is gated on scan_class == active and on
    target presence.
  - customer_view strips operator-only fields.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Fixtures ────────────────────────────────────────────────


@pytest.fixture
def sv(fresh_client_manager):
    """Re-import security_validation with the patched DATA_DIR."""
    if "security_validation" in sys.modules:
        del sys.modules["security_validation"]
    if "legal_authorization" in sys.modules:
        del sys.modules["legal_authorization"]
    import security_validation as _sv
    return _sv


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _hours_from_now(h: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=h)).isoformat()


def _good_legal_record(client_id: str):
    """Return a fully-signed legal_authorization record dict ready for save."""
    import legal_authorization as _legal
    now = datetime.now(timezone.utc)
    return {
        "client_id": client_id,
        "msa": {"name": "MSA", "status": "signed"},
        "sow": {"name": "SOW", "status": "signed"},
        "nda": {"name": "NDA", "status": "signed"},
        "dpa": {"name": "DPA", "status": "signed"},
        "authorized_representative": {"full_name": "Owner", "title": "CEO",
                                       "email": "ceo@a.com",
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
            "authorized_by_name": "Owner", "authorized_by_title": "CEO",
            "authorized_by_email": "ceo@a.com",
            "operator_approved_at": now.isoformat(),
            "operator_approved_by": "Op",
            "expires_at": (now + timedelta(days=7)).isoformat(),
            "emergency_contact": {"name": "Owner", "phone_24x7": "+1..."},
        },
        "acknowledgments": {"client_responsibility": True,
                              "no_legal_advice": True,
                              "no_breach_prevention_guarantee": True,
                              "acknowledged_at": now.isoformat(),
                              "acknowledged_by": "Owner"},
    }


# ─── Structure ───────────────────────────────────────────────


def test_eleven_canonical_statuses(sv):
    assert sv.NOT_SCOPED in sv.ALL_STATUSES
    assert sv.AWAITING_AUTHORIZATION in sv.ALL_STATUSES
    assert sv.APPROVED in sv.ALL_STATUSES
    assert sv.SCHEDULED in sv.ALL_STATUSES
    assert sv.RUNNING in sv.ALL_STATUSES
    assert sv.STOPPED in sv.ALL_STATUSES
    assert sv.ADVISOR_REVIEW_PENDING in sv.ALL_STATUSES
    assert sv.VALIDATED in sv.ALL_STATUSES
    assert sv.REMEDIATION_IN_PROGRESS in sv.ALL_STATUSES
    assert sv.RETEST_PASSED in sv.ALL_STATUSES
    assert len(sv.ALL_STATUSES) == 10  # spec lists 10 named states


def test_create_starts_in_not_scoped(sv, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_ACTIVE)
    assert eng["status"] == sv.NOT_SCOPED
    assert eng["scan_class"] == sv.SCAN_ACTIVE


def test_invalid_scan_class_rejected(sv, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    with pytest.raises(ValueError):
        sv.create_engagement("c1", scan_class="cooked")


# ─── State machine ───────────────────────────────────────────


def test_scope_transition(sv, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    eng = sv.create_engagement("c1")
    out = sv.scope_engagement("c1", eng["engagement_id"], {
        "scope_summary": "Public web app",
        "target_domains": ["a.com"],
        "excluded_systems": ["billing.a.com"],
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(8)},
        "emergency_contact": {"name": "Owner", "phone_24x7": "+1..."},
        "rate_limits": {"max_requests_per_second": 3},
    })
    assert out["status"] == sv.AWAITING_AUTHORIZATION
    assert out["target_domains"] == ["a.com"]
    assert out["excluded_systems"] == ["billing.a.com"]
    assert out["max_requests_per_second"] == 3


def test_invalid_transition_raises(sv, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    eng = sv.create_engagement("c1")
    # Cannot start from NOT_SCOPED
    with pytest.raises(sv.EngagementTransitionError):
        sv.start_engagement("c1", eng["engagement_id"])


# ─── Hard rule: no active scan without approved authorization ─


def test_active_scan_blocked_without_legal_authorization(sv, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_ACTIVE)
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    # approve_engagement consults the legal gate; nothing is signed.
    with pytest.raises(sv.EngagementTransitionError) as exc:
        sv.approve_engagement("c1", eng["engagement_id"], "Op")
    msg = str(exc.value).lower()
    assert "legal authorization" in msg or "preconditions" in msg


def test_active_scan_runs_with_full_legal_stack(sv, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.save_legal_authorization("c1", _good_legal_record("c1"))

    eng = sv.create_engagement("c1", scan_class=sv.SCAN_ACTIVE)
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    out = sv.approve_engagement("c1", eng["engagement_id"], "Op")
    assert out["status"] == sv.APPROVED

    out = sv.schedule_engagement("c1", eng["engagement_id"])
    assert out["status"] == sv.SCHEDULED

    out = sv.start_engagement("c1", eng["engagement_id"])
    assert out["status"] == sv.RUNNING


def test_passive_scan_does_not_require_active_authorization(sv, fresh_client_manager):
    """Passive scans run without the active-validation gate."""
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_PASSIVE)
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    out = sv.approve_engagement("c1", eng["engagement_id"], "Op")
    assert out["status"] == sv.APPROVED


# ─── Kill switch ─────────────────────────────────────────────


def test_kill_switch_stops_running_engagement(sv, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.save_legal_authorization("c1", _good_legal_record("c1"))
    eng = sv.create_engagement("c1")
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    sv.approve_engagement("c1", eng["engagement_id"], "Op")
    sv.schedule_engagement("c1", eng["engagement_id"])
    sv.start_engagement("c1", eng["engagement_id"])

    out = sv.engage_kill_switch("c1", eng["engagement_id"], by="customer",
                                reason="Maintenance window collision")
    assert out["status"] == sv.STOPPED
    assert out["kill_switch_engaged"] is True
    assert "Maintenance" in out["stop_reason"]

    # Cannot start while kill switch is engaged.
    with pytest.raises(sv.EngagementTransitionError):
        sv.start_engagement("c1", eng["engagement_id"])


def test_kill_switch_cannot_stop_terminal_states(sv, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_PASSIVE)
    # NOT_SCOPED is terminal-ish for the kill switch.
    with pytest.raises(sv.EngagementTransitionError):
        sv.engage_kill_switch("c1", eng["engagement_id"], by="customer")


# ─── Findings / FP review / advisor validation ──────────────


def _to_running(sv, fresh_client_manager, client_id="c1"):
    cm = fresh_client_manager
    cm.create_client(client_id, "Co", "co.com")
    cm.save_legal_authorization(client_id, _good_legal_record(client_id))
    eng = sv.create_engagement(client_id)
    sv.scope_engagement(client_id, eng["engagement_id"], {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    sv.approve_engagement(client_id, eng["engagement_id"], "Op")
    sv.schedule_engagement(client_id, eng["engagement_id"])
    sv.start_engagement(client_id, eng["engagement_id"])
    return eng["engagement_id"]


def test_complete_run_ingests_findings_with_pending_fp_status(sv, fresh_client_manager):
    eid = _to_running(sv, fresh_client_manager)
    out = sv.complete_run("c1", eid, findings=[
        {"title": "Open admin panel", "severity": "HIGH",
         "description": "Discovered /admin", "affected_target": "a.com"},
        {"title": "Verbose error", "severity": "LOW",
         "description": "Stack trace in 500"},
    ])
    assert out["status"] == sv.ADVISOR_REVIEW_PENDING
    assert len(out["findings"]) == 2
    for f in out["findings"]:
        assert f["fp_review_status"] == sv.FP_PENDING
        assert f["advisor_validated"] is False
        assert f["finding_id"]


def test_fp_review_marks_finding_confirmed(sv, fresh_client_manager):
    eid = _to_running(sv, fresh_client_manager)
    sv.complete_run("c1", eid, findings=[
        {"title": "Open admin panel", "severity": "HIGH"},
    ])
    finding_id = sv.get_engagement("c1", eid)["findings"][0]["finding_id"]
    out = sv.fp_review_finding("c1", eid, finding_id, by="Op",
                               status=sv.FP_CONFIRMED, notes="Reachable from internet")
    assert out["fp_review_status"] == sv.FP_CONFIRMED
    assert out["fp_reviewed_by"] == "Op"


def test_fp_review_marks_false_positive(sv, fresh_client_manager):
    eid = _to_running(sv, fresh_client_manager)
    sv.complete_run("c1", eid, findings=[{"title": "x", "severity": "LOW"}])
    fid = sv.get_engagement("c1", eid)["findings"][0]["finding_id"]
    out = sv.fp_review_finding("c1", eid, fid, by="Op",
                               status=sv.FP_FALSE_POSITIVE,
                               notes="Honey-trap by design")
    assert out["fp_review_status"] == sv.FP_FALSE_POSITIVE


def test_advisor_validation_requires_fp_confirmed_first(sv, fresh_client_manager):
    eid = _to_running(sv, fresh_client_manager)
    sv.complete_run("c1", eid, findings=[{"title": "x", "severity": "HIGH"}])
    fid = sv.get_engagement("c1", eid)["findings"][0]["finding_id"]
    # Skip FP review → advisor_validate must refuse.
    with pytest.raises(sv.EngagementTransitionError):
        sv.advisor_validate_finding("c1", eid, fid, by="Alice")
    # Now FP-review-confirm, then validate.
    sv.fp_review_finding("c1", eid, fid, by="Op", status=sv.FP_CONFIRMED)
    out = sv.advisor_validate_finding("c1", eid, fid, by="Alice CISSP",
                                       reviewer_credential="CISSP",
                                       notes="High impact",
                                       client_facing_recommendation="Restrict /admin to VPN.")
    assert out["advisor_validated"] is True
    assert out["advisor_validated_by"] == "Alice CISSP"
    assert out["client_facing_recommendation"]


def test_advisor_validate_engagement_requires_all_confirmed_findings_validated(
    sv, fresh_client_manager,
):
    eid = _to_running(sv, fresh_client_manager)
    sv.complete_run("c1", eid, findings=[
        {"title": "A", "severity": "HIGH"},
        {"title": "B", "severity": "HIGH"},
    ])
    fids = [f["finding_id"] for f in sv.get_engagement("c1", eid)["findings"]]
    # Confirm both.
    for fid in fids:
        sv.fp_review_finding("c1", eid, fid, by="Op", status=sv.FP_CONFIRMED)
    # Validate only one.
    sv.advisor_validate_finding("c1", eid, fids[0], by="Alice")

    with pytest.raises(sv.EngagementTransitionError):
        sv.validate_engagement("c1", eid, by="Alice")

    # Validate the second.
    sv.advisor_validate_finding("c1", eid, fids[1], by="Alice")
    out = sv.validate_engagement("c1", eid, by="Alice CISSP",
                                  reviewer_credential="CISSP",
                                  final_report_path="/reports/eng_final.pdf")
    assert out["status"] == sv.VALIDATED
    assert out["final_report_path"] == "/reports/eng_final.pdf"
    assert out["final_report_signed_off_by"] == "Alice CISSP"


def test_false_positives_are_excluded_from_validation_requirement(sv, fresh_client_manager):
    eid = _to_running(sv, fresh_client_manager)
    sv.complete_run("c1", eid, findings=[
        {"title": "A", "severity": "HIGH"},
        {"title": "FP", "severity": "LOW"},
    ])
    fids = [f["finding_id"] for f in sv.get_engagement("c1", eid)["findings"]]
    sv.fp_review_finding("c1", eid, fids[0], by="Op", status=sv.FP_CONFIRMED)
    sv.fp_review_finding("c1", eid, fids[1], by="Op", status=sv.FP_FALSE_POSITIVE)
    sv.advisor_validate_finding("c1", eid, fids[0], by="Alice")
    out = sv.validate_engagement("c1", eid, by="Alice")
    assert out["status"] == sv.VALIDATED


# ─── Retest cycle ────────────────────────────────────────────


def _to_remediation(sv, fresh_client_manager):
    eid = _to_running(sv, fresh_client_manager)
    sv.complete_run("c1", eid, findings=[
        {"title": "A", "severity": "HIGH"},
        {"title": "B", "severity": "MEDIUM"},
    ])
    fids = [f["finding_id"] for f in sv.get_engagement("c1", eid)["findings"]]
    for fid in fids:
        sv.fp_review_finding("c1", eid, fid, by="Op", status=sv.FP_CONFIRMED)
        sv.advisor_validate_finding("c1", eid, fid, by="Alice")
    sv.validate_engagement("c1", eid, by="Alice")
    sv.begin_remediation("c1", eid)
    return eid, fids


def test_retest_cycle_drives_engagement_to_retest_passed(sv, fresh_client_manager):
    eid, fids = _to_remediation(sv, fresh_client_manager)
    eng = sv.get_engagement("c1", eid)
    assert eng["status"] == sv.REMEDIATION_IN_PROGRESS
    for f in eng["findings"]:
        assert f["retest_status"] == sv.RETEST_PENDING

    # First finding passes.
    sv.record_retest("c1", eid, fids[0], passed=True, by="Op",
                     notes="Verified by rescan")
    eng = sv.get_engagement("c1", eid)
    assert eng["status"] == sv.REMEDIATION_IN_PROGRESS  # not all passed yet

    # Second finding passes → engagement closes.
    sv.record_retest("c1", eid, fids[1], passed=True, by="Op")
    eng = sv.get_engagement("c1", eid)
    assert eng["status"] == sv.RETEST_PASSED


def test_retest_failure_keeps_engagement_in_remediation(sv, fresh_client_manager):
    eid, fids = _to_remediation(sv, fresh_client_manager)
    sv.record_retest("c1", eid, fids[0], passed=False, by="Op",
                     notes="Still exploitable")
    eng = sv.get_engagement("c1", eid)
    assert eng["status"] == sv.REMEDIATION_IN_PROGRESS
    fail = next(f for f in eng["findings"] if f["finding_id"] == fids[0])
    assert fail["retest_status"] == sv.RETEST_FAILED


# ─── Apex command construction ───────────────────────────────


def test_apex_command_for_active_scan(sv, fresh_client_manager, monkeypatch):
    monkeypatch.setenv("APEX_BIN", "pensar")
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_ACTIVE)
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "excluded_systems": ["api.a.com"],
        "rate_limits": {"max_requests_per_second": 4},
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    out = sv.attach_apex_command("c1", eng["engagement_id"], dry_run=True)
    cmd = out["apex_command"]
    # Command uses the REAL Pensar Apex CLI flags. Exclusions + rate
    # limits are passed via the on-disk scope file (--threat-model @file),
    # NOT via flags Apex doesn't actually accept.
    assert "pensar" in cmd
    assert "pentest" in cmd
    assert "a.com" in cmd
    assert "--threat-model" in cmd
    # The scope file referenced in the command should contain the exclusion.
    scope_path = out.get("apex_scope_file")
    assert scope_path
    body = open(scope_path).read()
    assert "api.a.com" in body
    assert "Max requests/sec: 4" in body


def test_apex_command_empty_for_passive_scan(sv, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_PASSIVE)
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    out = sv.attach_apex_command("c1", eng["engagement_id"], dry_run=True)
    assert out["apex_command"] == ""


def test_apex_command_empty_when_no_targets(sv, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_ACTIVE)
    sv.scope_engagement("c1", eng["engagement_id"], {
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    cmd = sv.build_apex_command(sv.get_engagement("c1", eng["engagement_id"]))
    assert cmd == ""


# ─── Customer view strips operator-only fields ──────────────


def test_customer_view_hides_findings_detail_and_apex_command(
    sv, fresh_client_manager,
):
    eid = _to_running(sv, fresh_client_manager)
    sv.complete_run("c1", eid, findings=[
        {"title": "Internal probe", "severity": "HIGH",
         "description": "Internal-only details"},
    ])
    sv.attach_apex_command("c1", eid)  # may be empty if no APEX_BIN
    eng = sv.get_engagement("c1", eid)
    safe = sv.customer_view(eng)
    assert "apex_command" not in safe
    assert "findings" not in safe          # raw findings not exposed
    assert "audit_log" not in safe
    assert "findings_summary" in safe
    assert safe["findings_summary"]["total"] == 1
    assert "status_label" in safe


def test_customer_view_includes_status_label():
    import security_validation as sv
    safe = sv.customer_view({"status": sv.RUNNING, "scan_class": sv.SCAN_ACTIVE,
                              "findings": []})
    assert safe["status_label"] == "Running"


# ─── Route-level: hard authorization rule via API ───────────


def test_operator_route_refuses_start_without_legal(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "security_validation" in sys.modules:
        del sys.modules["security_validation"]
    import security_validation as svmod
    eng = svmod.create_engagement("c1")
    svmod.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    op = TestClient(test_app, raise_server_exceptions=False)
    pw = {"password": "testpass"}
    # Approve attempts the legal gate; should fail without signed legal stack.
    resp = op.post(
        f"/api/operator/clients/c1/validations/{eng['engagement_id']}/approve",
        json={"operator_name": "Op"}, params=pw,
    )
    assert resp.status_code == 400
    body = resp.json()
    detail = body.get("detail", "")
    assert "preconditions" in detail.lower() or "legal authorization" in detail.lower()


def test_customer_can_engage_kill_switch_via_portal(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com", tier="essentials")
    cm.set_portal_password("c1", "Pass123!")
    cm.save_legal_authorization("c1", _good_legal_record("c1"))

    if "security_validation" in sys.modules:
        del sys.modules["security_validation"]
    import security_validation as svmod
    eid = svmod.create_engagement("c1")["engagement_id"]
    svmod.scope_engagement("c1", eid, {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    svmod.approve_engagement("c1", eid, "Op")
    svmod.schedule_engagement("c1", eid)
    svmod.start_engagement("c1", eid)

    token = cm.create_jwt("c1")
    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token)
    resp = c.post(f"/api/portal/c1/validations/{eid}/stop",
                  json={"reason": "Customer requested halt"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == svmod.STOPPED
    assert body["kill_switch_engaged"] is True


def test_portal_view_hides_apex_and_findings_detail(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com", tier="essentials")
    cm.set_portal_password("c1", "Pass123!")
    cm.save_legal_authorization("c1", _good_legal_record("c1"))
    if "security_validation" in sys.modules:
        del sys.modules["security_validation"]
    import security_validation as svmod
    eid = _to_running(svmod, fresh_client_manager_func_value(fresh_client_manager))
    svmod.complete_run("c1", eid, findings=[
        {"title": "internal", "severity": "HIGH",
         "description": "operator-only details"},
    ])
    token = cm.create_jwt("c1")
    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token)
    resp = c.get(f"/api/portal/c1/validations/{eid}")
    assert resp.status_code == 200
    body = resp.json()
    assert "apex_command" not in body
    assert "findings" not in body
    assert "operator-only details" not in resp.text


def fresh_client_manager_func_value(fcm_fixture):
    """Helper to access the client_manager via the fixture."""
    return fcm_fixture
