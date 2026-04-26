"""
Route security boundary tests.

Proves four invariants for the FastAPI surface:
  1. Unauthenticated callers cannot reach private data.
  2. One customer cannot read another customer's portal data or files.
  3. Public callers cannot trigger paid / privileged jobs.
  4. The Stripe webhook still rejects unsigned and bad-signature payloads.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Helpers ──────────────────────────────────────────────────


class _OperatorTestClient:
    """TestClient wrapper that auto-appends the dashboard password to every
    request. The dashboard cookie is set with secure=True, which TestClient
    over HTTP would drop — using the password query parameter mirrors the
    other valid path through check_dashboard_auth."""

    def __init__(self, test_app):
        from starlette.testclient import TestClient
        self._c = TestClient(test_app, raise_server_exceptions=False)

    def _add_pw(self, kwargs):
        params = dict(kwargs.get("params") or {})
        params.setdefault("password", "testpass")
        kwargs["params"] = params
        return kwargs

    def get(self, url, **kw):
        return self._c.get(url, **self._add_pw(kw))

    def post(self, url, **kw):
        return self._c.post(url, **self._add_pw(kw))

    def put(self, url, **kw):
        return self._c.put(url, **self._add_pw(kw))


def _operator_client(test_app):
    return _OperatorTestClient(test_app)


def _make_client_with_files(tmp_path_dir: str, dir_name: str = "acme_20260101"):
    """Create a fake operator-side client deliverable directory with files."""
    import main  # already initialized via test_app fixture
    out_dir = main.OUTPUT_DIR / dir_name
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scan_data.json").write_text(json.dumps({
        "scan": {"company_name": "Acme", "domain": "acme.com", "score": 50, "grade": "C"}
    }))
    (out_dir / "PROPOSAL_EMAIL.txt").write_text("hi")
    (out_dir / "report.pdf").write_bytes(b"%PDF-1.4 fake")
    (out_dir / "policies").mkdir(exist_ok=True)
    (out_dir / "policies" / "wisp.txt").write_text("WISP")
    return out_dir


# ─── 1. Unauthenticated callers blocked from private data ─────


PRIVATE_GET_ROUTES = [
    "/api/clients",
    "/api/leads",
    "/api/pipeline",
    "/api/operator/clients",
    "/api/operator/mrr",
    "/api/operator/qualifications",
    "/api/dashboard/test_co",
    "/api/falcon/threats",
    "/api/dispatch/playbooks",
    "/api/dispatch/playbook/ransomware",
    "/api/comply/crossmap",
    "/api/comply/evidence/soc2",
    "/api/vanguard/workflows",
    "/api/breach/scope-template",
    "/api/onboarding/questionnaire",
    "/api/guardian/policy-prompt/wisp",
    "/api/phantom/templates/cpa",
]


@pytest.mark.parametrize("path", PRIVATE_GET_ROUTES)
def test_unauthenticated_get_blocked(test_client, path):
    resp = test_client.get(path)
    assert resp.status_code == 401, (
        f"{path} returned {resp.status_code} for unauthenticated GET"
    )


PRIVATE_POST_ROUTES = [
    ("/api/scan/full", {"domain": "x.com"}),
    ("/api/onboarding/process", {"answers": {}}),
    ("/api/phantom/campaign", {"campaign_name": "x", "template_key": "k", "employee_emails": []}),
    ("/api/shadow/email-check", {"emails": ["a@b.com"]}),
    ("/api/vanguard/execute/full_assessment", {}),
    ("/api/clients/new-scan", {"domain": "x.com"}),
    ("/api/clients/foo/generate-policies", {}),
    ("/api/clients/foo/generate-emails", {}),
    ("/api/operator/clients", {"company_name": "X", "domain": "x.com"}),
    ("/api/operator/clients/test_co/portal-access", {}),
    ("/api/operator/clients/test_co/tier", {"tier": "pro"}),
    ("/api/operator/run-monthly-reports", {}),
    ("/api/operator/run-scan/test_co", {}),
    ("/api/operator/call-notes/test_co", {"notes": "n"}),
    ("/api/operator/phishing/launch/test_co", {}),
    ("/api/operator/clients/test_co/invoice", {"items": [{"description": "x", "amount": 1}]}),
    ("/api/operator/clients/test_co/active-validation/start", {"target": "x.com"}),
    ("/api/operator/clients/test_co/legal-authorization/approve-active",
        {"operator_name": "Op"}),
    ("/api/operator/clients/test_co/legal-authorization/revoke-active", {"reason": "x"}),
]


@pytest.mark.parametrize("path,payload", PRIVATE_POST_ROUTES)
def test_unauthenticated_post_blocked(test_client, path, payload):
    resp = test_client.post(path, json=payload)
    assert resp.status_code == 401, (
        f"{path} returned {resp.status_code} for unauthenticated POST"
    )


def test_unauthenticated_download_blocked(test_client):
    resp = test_client.get("/api/clients/anything/download/pdf")
    assert resp.status_code == 401


def test_unauthenticated_client_detail_blocked(test_client):
    resp = test_client.get("/api/clients/anything/detail")
    assert resp.status_code == 401


def test_unauthenticated_legal_authorization_get_blocked(test_client):
    resp = test_client.get("/api/operator/clients/test_co/legal-authorization")
    assert resp.status_code == 401


def test_unauthenticated_legal_authorization_audit_blocked(test_client):
    resp = test_client.get("/api/operator/clients/test_co/legal-authorization/audit")
    assert resp.status_code == 401


# ─── 2. Cross-client portal isolation ─────────────────────────


def test_client_a_cannot_read_client_b_portal(test_app, fresh_client_manager):
    """Portal JWT for client_a must NOT grant access to client_b's portal."""
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("client_a", "Alpha", "alpha.com")
    cm.create_client("client_b", "Bravo", "bravo.com")
    token_a = cm.create_jwt("client_a")

    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token_a)

    # Reading own portal should succeed.
    own = c.get("/portal/client_a")
    assert own.status_code == 200
    # Reading other client's portal must redirect to login (auth fail).
    other = c.get("/portal/client_b")
    assert 'window.location="/portal/login"' in other.text


def test_client_a_cannot_download_client_b_files(test_app, fresh_client_manager, tmp_path):
    """Portal-auth'd client_a cannot use the portal download endpoints to
    read client_b's reports or policies."""
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("client_a", "Alpha", "alpha.com")
    cm.create_client("client_b", "Bravo", "bravo.com")

    # Plant a file in client_b's reports dir
    b_reports = cm._client_dir("client_b") / "reports"
    b_reports.mkdir(parents=True, exist_ok=True)
    (b_reports / "secret.pdf").write_bytes(b"%PDF private")

    token_a = cm.create_jwt("client_a")
    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token_a)

    resp = c.get("/portal/client_b/download/reports/secret.pdf")
    # Either 401 (auth check) or redirected — never 200 with the file body
    assert resp.status_code in (401, 403, 404)
    assert b"private" not in resp.content


def test_client_a_cannot_resolve_client_b_task(test_app, fresh_client_manager):
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("client_a", "Alpha", "alpha.com")
    cm.create_client("client_b", "Bravo", "bravo.com")

    token_a = cm.create_jwt("client_a")
    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token_a)

    resp = c.post("/portal/client_b/task/abc/resolve")
    assert resp.status_code in (401, 403)


def test_client_a_cannot_read_client_b_legal_status(test_app, fresh_client_manager):
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("client_a", "Alpha", "alpha.com")
    cm.create_client("client_b", "Bravo", "bravo.com")
    token_a = cm.create_jwt("client_a")

    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token_a)
    resp = c.get("/api/portal/client_b/legal-authorization")
    assert resp.status_code == 401


def test_invalid_jwt_blocks_portal(test_app, fresh_client_manager):
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("client_a", "Alpha", "alpha.com")

    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", "not.a.real.token")
    resp = c.get("/portal/client_a")
    assert 'window.location="/portal/login"' in resp.text


# ─── 3. Public callers cannot trigger paid / privileged jobs ──


PAID_JOB_ROUTES = [
    ("/api/scan/full", {"domain": "x.com"}),
    ("/api/clients/new-scan", {"domain": "x.com"}),
    ("/api/clients/foo/generate-policies", {}),
    ("/api/clients/foo/generate-emails", {}),
    ("/api/phantom/campaign", {"campaign_name": "x", "template_key": "k", "employee_emails": []}),
    ("/api/operator/phishing/launch/test_co", {}),
    ("/api/operator/run-monthly-reports", {}),
    ("/api/operator/run-scan/test_co", {}),
    ("/api/vanguard/execute/full_assessment", {}),
    ("/api/operator/clients/test_co/invoice", {"items": [{"description": "x", "amount": 1}]}),
    ("/api/operator/clients/test_co/active-validation/start", {"target": "x.com"}),
]


@pytest.mark.parametrize("path,payload", PAID_JOB_ROUTES)
def test_public_cannot_trigger_paid_jobs(test_client, path, payload):
    resp = test_client.post(path, json=payload)
    assert resp.status_code == 401


def test_active_validation_start_requires_authorization_record_even_for_operator(test_app):
    """Even with operator auth, active validation must be Approved
    in the legal-authorization record. Default record blocks it."""
    op = _operator_client(test_app)
    resp = op.post(
        "/api/operator/clients/test_co/active-validation/start",
        json={"target": "test.com"},
    )
    # Operator auth passed (not 401), but authorization gate blocks it (403).
    assert resp.status_code == 403
    body = resp.json()
    detail = body.get("detail")
    if isinstance(detail, dict):
        assert detail.get("error") == "active_validation_not_authorized"
        assert detail.get("blockers")


def test_operator_can_list_clients_when_authed(test_app):
    op = _operator_client(test_app)
    resp = op.get("/api/clients")
    assert resp.status_code == 200
    assert "clients" in resp.json()


def test_operator_can_read_pipeline_when_authed(test_app):
    op = _operator_client(test_app)
    resp = op.get("/api/pipeline")
    assert resp.status_code == 200


def test_operator_can_read_leads_when_authed(test_app):
    op = _operator_client(test_app)
    resp = op.get("/api/leads")
    assert resp.status_code == 200
    assert "leads" in resp.json()


def test_operator_download_works_with_auth(test_app):
    _make_client_with_files("acme_20260101")
    op = _operator_client(test_app)
    resp = op.get("/api/clients/acme_20260101/download/scan_data")
    assert resp.status_code == 200
    assert b"Acme" in resp.content


def test_operator_download_path_traversal_rejected(test_app):
    op = _operator_client(test_app)
    resp = op.get("/api/clients/..%2Fetc/download/scan_data")
    assert resp.status_code in (400, 404)


# ─── 4. Stripe webhook signature verification still works ─────


def test_webhook_rejects_unsigned_payload(test_app, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_secret")
    from starlette.testclient import TestClient
    c = TestClient(test_app, raise_server_exceptions=False)
    resp = c.post("/api/webhooks/stripe", content=b"{}")
    assert resp.status_code == 400


def test_webhook_rejects_bad_signature(test_app, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_secret")
    from starlette.testclient import TestClient
    c = TestClient(test_app, raise_server_exceptions=False)
    resp = c.post(
        "/api/webhooks/stripe",
        content=b'{"type":"customer.subscription.created"}',
        headers={"stripe-signature": "t=1,v1=deadbeef"},
    )
    assert resp.status_code == 400


def test_webhook_rejects_when_secret_unset(test_app, monkeypatch):
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    from starlette.testclient import TestClient
    c = TestClient(test_app, raise_server_exceptions=False)
    resp = c.post(
        "/api/webhooks/stripe",
        content=b"{}",
        headers={"stripe-signature": "t=1,v1=anything"},
    )
    # Missing secret -> ValueError caught -> 400 OR stripe library raises -> 400
    assert resp.status_code == 400


# ─── 5. Public surfaces remain reachable ──────────────────────


def test_public_landing_reachable(test_client):
    assert test_client.get("/").status_code == 200


def test_public_scan_page_reachable(test_client):
    assert test_client.get("/scan").status_code == 200


def test_public_qualify_page_reachable(test_client):
    assert test_client.get("/qualify").status_code == 200


def test_public_health_reachable(test_client):
    assert test_client.get("/api/health").status_code == 200
