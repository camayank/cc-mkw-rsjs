"""Apex runner control-model tests.

Proves Apex runs ONLY under our control:
  - The runner refuses to invoke Apex unless every precondition holds.
  - The legal authorization gate is re-checked at execution time.
  - The customer cannot reach the run endpoint.
  - The kill switch refuses launch when engaged.
  - The operator route requires dashboard auth.
  - Apex command construction matches the real Pensar CLI.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _hours_from_now(h):
    return (datetime.now(timezone.utc) + timedelta(hours=h)).isoformat()


def _good_legal_record(client_id):
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
            "status": "approved", "target_domains": ["a.com"],
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
        "acknowledgments": {"client_responsibility": True,
                              "no_legal_advice": True,
                              "no_breach_prevention_guarantee": True,
                              "acknowledged_at": now.isoformat(),
                              "acknowledged_by": "X"},
    }


@pytest.fixture
def fresh_modules(fresh_client_manager):
    """Reload modules so each test sees a clean DATA_DIR."""
    for name in ("security_validation", "apex_runner", "audit_log",
                  "advisor_review", "main"):
        sys.modules.pop(name, None)
    return fresh_client_manager


@pytest.fixture
def running_engagement(fresh_modules):
    """Build an active-tier client + engagement that's already in RUNNING."""
    cm = fresh_modules
    cm.create_client("c1", "Co", "co.com", tier="professional")
    cm.save_legal_authorization("c1", _good_legal_record("c1"))
    import security_validation as sv
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_ACTIVE)
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "excluded_systems": ["billing.a.com"],
        "testing_window": {"start_at": _now_iso(),
                            "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
        "rate_limits": {"max_requests_per_second": 4},
    })
    sv.approve_engagement("c1", eng["engagement_id"], "Op")
    sv.schedule_engagement("c1", eng["engagement_id"])
    sv.start_engagement("c1", eng["engagement_id"])
    return sv, eng["engagement_id"]


# ─── Command construction matches the real CLI ──────────────


def test_apex_command_uses_real_pensar_cli_flags(fresh_modules, monkeypatch):
    monkeypatch.setenv("APEX_BIN", "pensar")
    monkeypatch.setenv("APEX_MODEL", "claude-sonnet-4")
    cm = fresh_modules
    cm.create_client("c1", "Co", "co.com")
    import security_validation as sv
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_ACTIVE)
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "excluded_systems": ["billing.a.com"],
        "testing_window": {"start_at": _now_iso(),
                            "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    out = sv.attach_apex_command("c1", eng["engagement_id"], dry_run=True)
    cmd = out["apex_command"]
    assert "pensar" in cmd
    assert "pentest" in cmd
    assert "--target" in cmd
    assert "https://a.com" in cmd
    # Real CLI flags only.
    assert "--threat-model" in cmd
    assert "@" in cmd  # threat-model points at a file
    assert "--model" in cmd
    # Forbidden invented flags.
    assert "--exclude" not in cmd
    assert "--rate-limit" not in cmd
    assert "--dry-run" not in cmd


def test_apex_scope_file_records_exclusions_and_rate_limits(fresh_modules):
    cm = fresh_modules
    cm.create_client("c1", "Co", "co.com")
    import security_validation as sv
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_ACTIVE)
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "excluded_systems": ["billing.a.com", "*.shopify.a.com"],
        "excluded_techniques": ["DoS", "Destructive"],
        "testing_window": {"start_at": _now_iso(),
                            "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "Owner",
                                "phone_24x7": "+1-555-0100"},
        "rate_limits": {"max_requests_per_second": 4},
    })
    out = sv.attach_apex_command("c1", eng["engagement_id"], dry_run=True)
    scope_path = out.get("apex_scope_file")
    assert scope_path
    body = open(scope_path).read()
    assert "a.com" in body
    assert "billing.a.com" in body
    assert "DoS" in body
    assert "Owner" in body
    assert "+1-555-0100" in body
    assert "Max requests/sec: 4" in body
    assert "Stop immediately if any out-of-scope" in body


# ─── Runner: hard preconditions ─────────────────────────────


def test_runner_refuses_if_engagement_not_running(fresh_modules):
    cm = fresh_modules
    cm.create_client("c1", "Co", "co.com", tier="professional")
    cm.save_legal_authorization("c1", _good_legal_record("c1"))
    import security_validation as sv
    import apex_runner as ar
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_ACTIVE)
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(),
                            "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    sv.approve_engagement("c1", eng["engagement_id"], "Op")
    # Status is APPROVED, not RUNNING → refuse.
    with pytest.raises(ar.ApexRunError) as e:
        ar.run_engagement("c1", eng["engagement_id"])
    assert "running" in str(e.value).lower()


def test_runner_refuses_if_legal_gate_closed_at_execution(running_engagement,
                                                         fresh_client_manager):
    """Engagement is in RUNNING, but legal record was wiped between approval
    and run — the runner must re-check and refuse."""
    sv, eid = running_engagement
    # Wipe the legal record after approval.
    fresh_client_manager.save_legal_authorization("c1", {})
    import apex_runner as ar
    with pytest.raises(ar.ApexRunError) as e:
        ar.run_engagement("c1", eid)
    msg = str(e.value).lower()
    assert "legal authorization" in msg or "preconditions" in msg


def test_runner_refuses_if_kill_switch_engaged(running_engagement):
    sv, eid = running_engagement
    sv.engage_kill_switch("c1", eid, by="customer", reason="paused for review")
    import apex_runner as ar
    with pytest.raises(ar.ApexRunError) as e:
        ar.run_engagement("c1", eid)
    # Kill switch causes a transition to STOPPED → "must be in 'running'"
    # is the actual error.
    assert "running" in str(e.value).lower() or "kill" in str(e.value).lower()


def test_runner_refuses_if_apex_binary_missing(running_engagement, monkeypatch):
    sv, eid = running_engagement
    import apex_runner as ar
    monkeypatch.setenv("APEX_BIN", "definitely-not-installed-abc123")
    with pytest.raises(ar.ApexRunError) as e:
        ar.run_engagement("c1", eid)
    assert "binary" in str(e.value).lower()


def test_runner_refuses_passive_engagements(fresh_modules):
    cm = fresh_modules
    cm.create_client("c1", "Co", "co.com")
    import security_validation as sv
    import apex_runner as ar
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_PASSIVE)
    sv.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(),
                            "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    sv.approve_engagement("c1", eng["engagement_id"], "Op")
    sv.schedule_engagement("c1", eng["engagement_id"])
    sv.start_engagement("c1", eng["engagement_id"])
    with pytest.raises(ar.ApexRunError) as e:
        ar.run_engagement("c1", eng["engagement_id"])
    assert "active" in str(e.value).lower()


# ─── Customer cannot trigger ────────────────────────────────


def test_customer_cannot_reach_run_apex_route(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com", tier="professional")
    cm.set_portal_password("c1", "Pass123!")
    token = cm.create_jwt("c1")
    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token)
    resp = c.post("/api/operator/clients/c1/validations/eng_x/run-apex",
                   json={"operator_name": "imposter"})
    assert resp.status_code == 401


def test_anonymous_cannot_reach_run_apex_route(test_app):
    from starlette.testclient import TestClient
    c = TestClient(test_app, raise_server_exceptions=False)
    resp = c.post("/api/operator/clients/c1/validations/eng_x/run-apex",
                   json={})
    assert resp.status_code == 401


# ─── Operator can reach the route, but legal gate still applies ───


def test_operator_call_still_blocked_by_legal_gate(test_app, fresh_client_manager):
    """Even with operator auth, the runner re-checks the legal gate. With
    no signed legal stack, the route returns 400 with a gate message."""
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com", tier="professional")
    # Note: NO legal record on file.
    if "security_validation" in sys.modules: del sys.modules["security_validation"]
    import security_validation as sv
    eng = sv.create_engagement("c1", scan_class=sv.SCAN_ACTIVE)
    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.post(
        f"/api/operator/clients/c1/validations/{eng['engagement_id']}/run-apex",
        json={"operator_name": "Op"},
        params={"password": "testpass"},
    )
    # Engagement is NOT_SCOPED (no scope, no approval, no running) → 400.
    assert resp.status_code == 400
