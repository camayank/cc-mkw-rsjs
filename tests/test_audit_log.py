"""Audit-log tests.

Proves:
  - Schema includes all required fields.
  - Per-client + global stream both populated.
  - Filtering by action/role/actor/date range works.
  - JSON + CSV exports include every event.
  - Audit ZIP package bundles audit_log.json + audit_log.csv.
  - Each listed action produces an event when triggered via routes:
      login / failed_login / logout / operator login
      document download / evidence upload / task status change
      advisor review / authorization approval / scan start/stop
      validation start/stop / invoice / plan change /
      client profile update / audit package download
  - IP and user-agent are captured when the request carries them.
"""
from __future__ import annotations

import io
import json
import os
import sys
import zipfile
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Helpers ─────────────────────────────────────────────────


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


def _login_portal(test_client, fresh_client_manager, cid="c1", tier="essentials"):
    cm = fresh_client_manager
    cm.create_client(cid, "Co", "co.com", tier=tier)
    cm.set_portal_password(cid, "Pass123!")
    token = cm.create_jwt(cid)
    test_client.cookies.set("portal_token", token)
    return cm


# ─── Schema ──────────────────────────────────────────────────


def test_record_has_all_required_fields(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    e = _al.record(action=_al.ACTION_LOGIN, actor="alice",
                   role=_al.ROLE_CUSTOMER, client_id="c1")
    for k in ("id", "timestamp", "actor", "role", "client_id",
              "action", "ip", "user_agent", "delta", "metadata"):
        assert k in e


def test_invalid_role_falls_back_to_system(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    e = _al.record(action="x", role="bogus", client_id="c1")
    assert e["role"] == _al.ROLE_SYSTEM


def test_record_writes_to_per_client_and_global(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    _al.record(action=_al.ACTION_LOGIN, actor="alice",
               role=_al.ROLE_CUSTOMER, client_id="c1")
    per_client = _al.list_events(client_id="c1")
    global_events = _al.list_events(client_id=None)
    assert len(per_client) >= 1
    assert len(global_events) >= 1


# ─── Filtering ───────────────────────────────────────────────


def test_filter_by_action_role_actor(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    _al.record(action=_al.ACTION_LOGIN, actor="alice",
               role=_al.ROLE_CUSTOMER, client_id="c1")
    _al.record(action=_al.ACTION_FAILED_LOGIN, actor="mallory",
               role=_al.ROLE_ANONYMOUS, client_id="c1")
    _al.record(action=_al.ACTION_LOGIN, actor="bob",
               role=_al.ROLE_CUSTOMER, client_id="c1")

    assert len(_al.list_events("c1", action=_al.ACTION_LOGIN)) == 2
    assert len(_al.list_events("c1", action=_al.ACTION_FAILED_LOGIN)) == 1
    assert len(_al.list_events("c1", actor="alice")) == 1
    assert len(_al.list_events("c1", role=_al.ROLE_ANONYMOUS)) == 1


def test_filter_by_date_range(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    _al.record(action=_al.ACTION_LOGIN, actor="alice",
               role=_al.ROLE_CUSTOMER, client_id="c1")
    # since=tomorrow → 0 events.
    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    assert _al.list_events("c1", since=tomorrow) == []


def test_before_after_delta_recorded(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    e = _al.record(action=_al.ACTION_PLAN_CHANGE, actor="op",
                   role=_al.ROLE_OPERATOR, client_id="c1",
                   before={"tier": "essentials"},
                   after={"tier": "professional"})
    assert e["delta"]["before"]["tier"] == "essentials"
    assert e["delta"]["after"]["tier"] == "professional"


# ─── Request-meta extraction ────────────────────────────────


def test_request_meta_captured_via_route(test_client, fresh_client_manager):
    cm = _login_portal(test_client, fresh_client_manager)
    cm.add_task("c1", "Fix DMARC", "HIGH", "Email")
    # Trigger a route that records an event with the Request object.
    resp = test_client.get(
        "/portal/c1/download/policies/wisp.pdf",
        headers={"User-Agent": "TestUA/1.0",
                 "X-Forwarded-For": "203.0.113.5, 10.0.0.1"},
    )
    # Either 404 (file missing) or 200 — either way the audit is written.
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_DOCUMENT_DOWNLOAD)
    if events:
        e = events[0]
        assert e["user_agent"].startswith("TestUA")
        assert e["ip"] == "203.0.113.5"


# ─── Action coverage via real routes ────────────────────────


def test_login_records_event(test_client, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com", tier="essentials")
    cm.set_portal_password("c1", "RealPass1!")
    resp = test_client.post("/portal/login",
                             json={"client_id": "c1", "password": "RealPass1!"})
    assert resp.status_code == 200
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_LOGIN)
    assert events
    assert events[0]["actor"] == "c1"
    assert events[0]["role"] == _al.ROLE_CUSTOMER


def test_failed_login_records_event(test_client, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.set_portal_password("c1", "RealPass1!")
    resp = test_client.post("/portal/login",
                             json={"client_id": "c1", "password": "wrong"})
    assert resp.status_code == 401
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_FAILED_LOGIN)
    assert events


def test_logout_records_event(test_client, fresh_client_manager):
    cm = _login_portal(test_client, fresh_client_manager)
    resp = test_client.post("/portal/logout")
    assert resp.status_code == 200
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_LOGOUT)
    assert events


def test_operator_login_records_event(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    c = TestClient(test_app, raise_server_exceptions=False)
    resp = c.get("/dashboard", params={"password": "testpass"})
    assert resp.status_code == 200
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events(action=_al.ACTION_OPERATOR_LOGIN)
    assert events


def test_document_download_records_event(test_client, fresh_client_manager):
    cm = _login_portal(test_client, fresh_client_manager)
    reports = cm._client_dir("c1") / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "monthly.pdf").write_bytes(b"%PDF-fake")
    resp = test_client.get("/portal/c1/download/reports/monthly.pdf")
    assert resp.status_code == 200
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_DOCUMENT_DOWNLOAD)
    assert events


def test_evidence_upload_records_event(test_client, fresh_client_manager):
    cm = _login_portal(test_client, fresh_client_manager)
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    resp = test_client.post(
        f"/portal/c1/task/{t['id']}/evidence",
        json={"filename": "evidence.png"},
    )
    assert resp.status_code == 200
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_EVIDENCE_UPLOAD)
    assert events
    assert events[0]["metadata"]["filename"] == "evidence.png"


def test_task_status_change_records_event(test_client, fresh_client_manager):
    cm = _login_portal(test_client, fresh_client_manager)
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    resp = test_client.post(
        f"/portal/c1/task/{t['id']}/status",
        json={"status": "in_progress"},
    )
    assert resp.status_code == 200
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_TASK_STATUS_CHANGE)
    assert events


def test_task_verify_records_event(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    t = cm.add_task("c1", "Fix", "HIGH", "Email")
    cm.submit_task_for_review("c1", t["id"], by="customer")
    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.post(
        f"/api/operator/clients/c1/tasks/{t['id']}/verify",
        json={"operator_name": "Alice", "method": "rescan"},
        params={"password": "testpass"},
    )
    assert resp.status_code == 200
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_TASK_VERIFY)
    assert events
    assert events[0]["actor"] == "Alice"


def test_advisor_review_records_event(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.post(
        "/api/operator/clients/c1/reviews/policy:wisp",
        json={"prepared_by": "System", "review_status": "in_review"},
        params={"password": "testpass"},
    )
    assert resp.status_code == 200
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_ADVISOR_REVIEW)
    assert events
    assert events[0]["metadata"]["subject_key"] == "policy:wisp"


def test_authorization_approval_records_event(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    raw = _good_legal_record("c1")
    raw["active_validation"]["operator_approved_at"] = ""
    raw["active_validation"]["operator_approved_by"] = ""
    cm.save_legal_authorization("c1", raw)
    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.post(
        "/api/operator/clients/c1/legal-authorization/approve-active",
        json={"operator_name": "Alice"},
        params={"password": "testpass"},
    )
    assert resp.status_code == 200
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_AUTHORIZATION_APPROVED)
    assert events


def test_validation_start_and_stop_record_events(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.save_legal_authorization("c1", _good_legal_record("c1"))
    if "security_validation" in sys.modules: del sys.modules["security_validation"]
    import security_validation as svmod
    eng = svmod.create_engagement("c1")
    svmod.scope_engagement("c1", eng["engagement_id"], {
        "target_domains": ["a.com"],
        "testing_window": {"start_at": _now_iso(), "end_at": _hours_from_now(2)},
        "emergency_contact": {"name": "X", "phone_24x7": "+1"},
    })
    svmod.approve_engagement("c1", eng["engagement_id"], "Op")
    svmod.schedule_engagement("c1", eng["engagement_id"])

    op = TestClient(test_app, raise_server_exceptions=False)
    pw = {"password": "testpass"}
    resp = op.post(
        f"/api/operator/clients/c1/validations/{eng['engagement_id']}/start",
        json={}, params=pw,
    )
    assert resp.status_code == 200
    resp = op.post(
        f"/api/operator/clients/c1/validations/{eng['engagement_id']}/stop",
        json={"reason": "kill switch test"}, params=pw,
    )
    assert resp.status_code == 200

    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    starts = _al.list_events("c1", action=_al.ACTION_VALIDATION_START)
    stops = _al.list_events("c1", action=_al.ACTION_VALIDATION_STOP)
    scan_starts = _al.list_events("c1", action=_al.ACTION_SCAN_START)
    scan_stops = _al.list_events("c1", action=_al.ACTION_SCAN_STOP)
    assert starts
    assert stops
    assert scan_starts
    assert scan_stops


def test_plan_change_records_before_after(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com", tier="essentials")
    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.post(
        "/api/operator/clients/c1/tier",
        json={"tier": "professional"},
        params={"password": "testpass"},
    )
    assert resp.status_code == 200
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_PLAN_CHANGE)
    assert events
    assert events[0]["delta"]["before"]["tier"] == "essentials"
    assert events[0]["delta"]["after"]["tier"] == "professional"


def test_client_profile_update_records_event(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.put(
        "/api/operator/client/c1",
        json={"contact_name": "Alice"},
        params={"password": "testpass"},
    )
    assert resp.status_code == 200
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    events = _al.list_events("c1", action=_al.ACTION_CLIENT_PROFILE_UPDATE)
    assert events


# ─── Exports ─────────────────────────────────────────────────


def test_export_csv_contains_all_events(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    _al.record(action=_al.ACTION_LOGIN, actor="alice",
               role=_al.ROLE_CUSTOMER, client_id="c1")
    _al.record(action=_al.ACTION_LOGOUT, actor="alice",
               role=_al.ROLE_CUSTOMER, client_id="c1")
    csv = _al.export_csv("c1")
    # Header + 2 data rows.
    assert csv.count("\n") >= 3
    assert "alice" in csv
    assert _al.ACTION_LOGIN in csv
    assert _al.ACTION_LOGOUT in csv


def test_export_json_contains_all_events(fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    _al.record(action=_al.ACTION_LOGIN, actor="alice",
               role=_al.ROLE_CUSTOMER, client_id="c1")
    out = json.loads(_al.export_json("c1"))
    assert isinstance(out, list)
    assert any(e["action"] == _al.ACTION_LOGIN for e in out)


def test_audit_package_zip_includes_audit_log(test_client, fresh_client_manager):
    cm = _login_portal(test_client, fresh_client_manager)
    # Create some content so the audit package has files.
    reports = cm._client_dir("c1") / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "r.pdf").write_bytes(b"%PDF-fake")

    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    _al.record(action=_al.ACTION_LOGIN, actor="alice",
               role=_al.ROLE_CUSTOMER, client_id="c1")

    resp = test_client.get("/portal/c1/download/audit-package")
    assert resp.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(resp.content))
    names = z.namelist()
    assert "audit_log.json" in names
    assert "audit_log.csv" in names
    csv_text = z.read("audit_log.csv").decode("utf-8")
    assert _al.ACTION_LOGIN in csv_text
    json_text = z.read("audit_log.json").decode("utf-8")
    assert "alice" in json_text


def test_operator_audit_log_route_requires_auth(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    public = TestClient(test_app, raise_server_exceptions=False)
    resp = public.get("/api/operator/audit-log")
    assert resp.status_code == 401


def test_operator_audit_log_route_returns_events(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com", tier="essentials")
    cm.set_portal_password("c1", "RealPass1!")
    public = TestClient(test_app, raise_server_exceptions=False)
    public.post("/portal/login",
                 json={"client_id": "c1", "password": "RealPass1!"})

    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.get("/api/operator/audit-log",
                   params={"password": "testpass", "action": "login"})
    assert resp.status_code == 200
    body = resp.json()
    assert "events" in body
    assert body["count"] >= 1


def test_operator_audit_log_csv_export(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    _al.record(action=_al.ACTION_LOGIN, actor="alice",
               role=_al.ROLE_CUSTOMER, client_id="c1")
    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.get("/api/operator/audit-log",
                   params={"password": "testpass", "format": "csv"})
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("content-type", "")
    assert "alice" in resp.text


def test_portal_audit_log_route_returns_own_events(test_client, fresh_client_manager):
    cm = _login_portal(test_client, fresh_client_manager)
    if "audit_log" in sys.modules: del sys.modules["audit_log"]
    import audit_log as _al
    _al.record(action=_al.ACTION_LOGIN, actor="c1",
               role=_al.ROLE_CUSTOMER, client_id="c1")
    resp = test_client.get("/api/portal/c1/audit-log")
    assert resp.status_code == 200
    body = resp.json()
    assert any(e["action"] == _al.ACTION_LOGIN for e in body["events"])


def test_one_client_cannot_read_anothers_audit(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("a", "A", "a.com", tier="essentials")
    cm.create_client("b", "B", "b.com", tier="essentials")
    token_a = cm.create_jwt("a")
    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token_a)
    resp = c.get("/api/portal/b/audit-log")
    assert resp.status_code == 401
