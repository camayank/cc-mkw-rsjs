"""Sell-readiness checklist tests.

Each invariant the module checks gets one explicit test here so a
due-diligence reviewer can read the file top-to-bottom and trust the
result. The final test gates the four-category classification.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def sr(fresh_client_manager, monkeypatch, tmp_path):
    """Reload sell_readiness against the test harness's fresh DATA_DIR.
    Also clear `main` so the cached app picks up the live sanitizer code."""
    monkeypatch.setenv("DASHBOARD_PASSWORD", "testpass")
    # Mock scheduler to avoid background side-effects on import.
    from unittest.mock import MagicMock
    import scheduler as _sch
    monkeypatch.setattr(_sch, "init_scheduler", lambda app=None: MagicMock())
    for name in ("sell_readiness", "security_validation", "advisor_review",
                  "audit_log", "document_library", "main"):
        sys.modules.pop(name, None)
    # Re-import in the right order so main sees the freshly-patched modules.
    import client_manager as _cm   # noqa: F401
    _cm.CLIENTS_DIR = tmp_path / "clients"
    import main                    # noqa: F401
    main.OUTPUT_DIR = tmp_path / "client-deliverables"
    main.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    import sell_readiness
    return sell_readiness


# ─── Individual invariants ──────────────────────────────────


def test_private_routes_require_auth(sr):
    c = sr.check_private_routes_require_auth()
    assert c.status == "pass", c.detail


def test_client_isolation(sr, fresh_client_manager):
    c = sr.check_client_isolation()
    assert c.status == "pass", c.detail


def test_active_validation_requires_authorization(sr, fresh_client_manager):
    c = sr.check_active_validation_gate()
    assert c.status == "pass", c.detail


def test_no_false_all_clear_states(sr):
    c = sr.check_no_false_all_clear_states()
    assert c.status == "pass", c.detail


def test_reviewed_claims_require_metadata(sr):
    c = sr.check_reviewed_claims_require_metadata()
    assert c.status == "pass", c.detail


def test_alert_html_escaped(sr):
    c = sr.check_alert_html_escaped()
    assert c.status == "pass", c.detail


def test_evidence_package_excludes_secrets(sr, fresh_client_manager):
    c = sr.check_evidence_package_excludes_secrets()
    assert c.status == "pass", c.detail


def test_pricing_thresholds_match(sr):
    c = sr.check_pricing_thresholds_match()
    assert c.status == "pass", c.detail


def test_task_verification_workflow(sr, fresh_client_manager):
    c = sr.check_task_verification_workflow()
    assert c.status == "pass", c.detail


def test_audit_logs_written(sr, fresh_client_manager):
    c = sr.check_audit_logs_written()
    assert c.status == "pass", c.detail


def test_portal_mobile_responsive(sr):
    c = sr.check_portal_mobile_responsive()
    assert c.status == "pass", c.detail


# ─── Classification ─────────────────────────────────────────


def test_run_checks_returns_full_payload(sr, fresh_client_manager):
    out = sr.run_checks()
    assert "category" in out
    assert out["category"] in (
        sr.READY_TO_SELL, sr.READY_WITH_ADVISOR_REVIEW,
        sr.NEEDS_LEGAL_REVIEW, sr.NOT_SAFE_TO_SELL,
    )
    assert out["category_label"] == sr.CATEGORY_LABELS[out["category"]]
    assert isinstance(out["checks"], list)
    assert len(out["checks"]) == 11
    for c in out["checks"]:
        assert {"id", "label", "status", "detail"} <= set(c.keys())


def test_classification_is_ready_to_sell_when_all_pass(sr, fresh_client_manager):
    out = sr.run_checks()
    # Either ready_to_sell or ready_with_advisor_review (when there are real
    # clients with deliverables but no advisor sign-off yet).
    assert out["category"] in (sr.READY_TO_SELL, sr.READY_WITH_ADVISOR_REVIEW), \
        f"Unexpected category: {out['category']} — {out['summary']}"


# ─── Operator route ─────────────────────────────────────────


def test_sell_readiness_route_requires_auth(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    public = TestClient(test_app, raise_server_exceptions=False)
    resp = public.get("/api/operator/sell-readiness")
    assert resp.status_code == 401


def test_sell_readiness_route_returns_classification(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    op = TestClient(test_app, raise_server_exceptions=False)
    resp = op.get("/api/operator/sell-readiness",
                   params={"password": "testpass"})
    assert resp.status_code == 200
    body = resp.json()
    assert "category" in body
    assert "category_label" in body
    assert "checks" in body
    assert len(body["checks"]) == 11


# ─── Top-level gate ─────────────────────────────────────────


def test_sell_readiness_gate(sr, fresh_client_manager):
    """The single test a due-diligence reviewer reads: are we shippable?"""
    out = sr.run_checks()
    fails = [c for c in out["checks"] if c["status"] == "fail"]
    assert not fails, (
        "Sell-readiness gate failed:\n"
        + "\n".join(f"  - {c['label']}: {c['detail']}" for c in fails)
    )
    assert out["category"] != sr.NOT_SAFE_TO_SELL, out["summary"]
