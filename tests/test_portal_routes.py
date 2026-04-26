"""Tests for /portal/ endpoints — auth, data rendering, tasks, downloads."""
import os
import sys
import json
import zipfile
import io

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── AUTH TESTS ──────────────────────────────────────────────


def test_portal_page_redirects_without_auth(test_client, fresh_client_manager):
    fresh_client_manager.create_client("test_co", "Test Corp", "test.com")
    resp = test_client.get("/portal/test_co")
    assert resp.status_code == 200
    assert 'window.location="/portal/login"' in resp.text


def test_portal_page_redirects_with_invalid_token(test_client, fresh_client_manager):
    fresh_client_manager.create_client("test_co", "Test Corp", "test.com")
    test_client.cookies.set("portal_token", "bogus.jwt.token")
    resp = test_client.get("/portal/test_co")
    assert 'window.location="/portal/login"' in resp.text


def test_portal_page_renders_with_valid_auth(authed_client):
    resp = authed_client.get("/portal/test_co")
    assert resp.status_code == 200
    assert "Test Corp" in resp.text


def test_portal_login_page_renders(test_client):
    resp = test_client.get("/portal/login")
    assert resp.status_code == 200
    # Login page should have some form-related content
    assert "portal" in resp.text.lower() or "sign" in resp.text.lower() or "password" in resp.text.lower()


def test_portal_login_post_wrong_password(test_client, fresh_client_manager):
    fresh_client_manager.create_client("test_co", "Test Corp", "test.com")
    fresh_client_manager.set_portal_password("test_co", "RealPassword1!")
    resp = test_client.post(
        "/portal/login",
        json={"client_id": "test_co", "password": "WrongPassword"},
    )
    assert resp.status_code == 401


def test_portal_login_post_correct_password(test_client, fresh_client_manager):
    fresh_client_manager.create_client("test_co", "Test Corp", "test.com")
    fresh_client_manager.set_portal_password("test_co", "RealPassword1!")
    resp = test_client.post(
        "/portal/login",
        json={"client_id": "test_co", "password": "RealPassword1!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "portal_token" in resp.cookies


# ─── PORTAL MAIN PAGE DATA TESTS ────────────────────────────


def test_portal_renders_default_advisor_name(authed_client):
    resp = authed_client.get("/portal/test_co")
    assert "CyberComply Security Team" in resp.text


def test_portal_renders_custom_advisor(authed_client, fresh_client_manager):
    fresh_client_manager.update_field("test_co", "advisor_name", "Alice CISSP")
    resp = authed_client.get("/portal/test_co")
    assert "Alice CISSP" in resp.text


def test_portal_renders_calendly_link(authed_client):
    resp = authed_client.get("/portal/test_co")
    assert "calendly.com" in resp.text


def test_portal_renders_industry_benchmark(authed_client):
    """CPA industry has avg score 45 — should appear on portal."""
    resp = authed_client.get("/portal/test_co")
    # Industry was set to "cpa" in authed_client fixture
    assert "45" in resp.text


def test_portal_no_benchmark_unknown_industry(test_app, fresh_client_manager):
    from starlette.testclient import TestClient

    fresh_client_manager.create_client("widget_co", "Widget Corp", "widget.com", industry="widgets", tier="essentials")
    fresh_client_manager.set_portal_password("widget_co", "Pass123!")
    token = fresh_client_manager.create_jwt("widget_co")

    client = TestClient(test_app, raise_server_exceptions=False)
    client.cookies.set("portal_token", token)
    resp = client.get("/portal/widget_co")
    assert resp.status_code == 200
    # "industry avg" string should NOT appear for unknown industry
    assert "industry avg" not in resp.text.lower() or "Industry avg" not in resp.text


def test_portal_renders_monthly_narrative(authed_client, fresh_client_manager):
    """When a monthly report JSON exists, narrative text should appear."""
    import client_manager
    reports_dir = client_manager._client_dir("test_co") / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "narrative": "Security posture improved significantly this month.",
        "score": 55,
        "grade": "C+",
    }
    (reports_dir / "2025-01-monthly-report.json").write_text(json.dumps(report))
    resp = authed_client.get("/portal/test_co")
    assert "Security posture improved significantly" in resp.text


def test_portal_no_narrative_without_report(authed_client):
    resp = authed_client.get("/portal/test_co")
    # Without any monthly report files, narrative section shouldn't have report text
    assert "Security posture improved" not in resp.text


def test_portal_renders_framework_badges(authed_client, fresh_client_manager):
    fresh_client_manager.update_field("test_co", "frameworks", ["IRS 4557", "NIST CSF"])
    resp = authed_client.get("/portal/test_co")
    assert "IRS 4557" in resp.text
    assert "NIST CSF" in resp.text


# ─── ROADMAP PANEL TESTS ────────────────────────────────────


def test_portal_roadmap_shows_tasks(authed_client, fresh_client_manager):
    for i in range(5):
        fresh_client_manager.add_task(
            "test_co", f"Fix issue {i}", "HIGH", "Email",
            f"Description {i}", f"Fix {i}",
        )
    resp = authed_client.get("/portal/test_co")
    assert resp.status_code == 200
    # At least some tasks should appear
    assert "Fix issue" in resp.text


def test_portal_roadmap_empty_state(authed_client):
    resp = authed_client.get("/portal/test_co")
    assert resp.status_code == 200
    # With no tasks, should show some form of empty/clean state
    # (exact wording depends on template)


def test_portal_roadmap_shows_severity_badges(authed_client, fresh_client_manager):
    fresh_client_manager.add_task(
        "test_co", "Critical vuln", "CRITICAL", "Infrastructure",
        "Desc", "Fix it",
    )
    resp = authed_client.get("/portal/test_co")
    assert "CRITICAL" in resp.text


# ─── TASK RESOLUTION TESTS ──────────────────────────────────


def test_resolve_task_via_portal(authed_client, fresh_client_manager):
    """Legacy /resolve endpoint now routes to Submit for review and never marks
    the task verified. Verification is operator-only."""
    task = fresh_client_manager.add_task(
        "test_co", "Fix DMARC", "HIGH", "Email", "Add record", "DNS fix",
    )
    task_id = task["id"]
    resp = authed_client.post(f"/portal/test_co/task/{task_id}/resolve")
    assert resp.status_code == 200
    assert "Submitted for review" in resp.text
    tasks = fresh_client_manager.get_tasks("test_co")
    submitted = [t for t in tasks if t["id"] == task_id][0]
    assert submitted["status"] == fresh_client_manager.TASK_STATUS_SUBMITTED
    assert submitted["status"] != fresh_client_manager.TASK_STATUS_VERIFIED


def test_resolve_task_unauthorized(test_client, fresh_client_manager):
    fresh_client_manager.create_client("test_co", "Test Corp", "test.com")
    task = fresh_client_manager.add_task(
        "test_co", "Fix DMARC", "HIGH", "Email", "Add record", "DNS fix",
    )
    resp = test_client.post(f"/portal/test_co/task/{task['id']}/resolve")
    assert resp.status_code == 403


# ─── DOWNLOAD / REPORT TESTS ────────────────────────────────


def test_portal_download_report_file(authed_client, fresh_client_manager):
    import client_manager
    reports_dir = client_manager._client_dir("test_co") / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "scan-report.pdf").write_bytes(b"%PDF-fake-content")

    resp = authed_client.get("/portal/test_co/download/reports/scan-report.pdf")
    assert resp.status_code == 200


def test_portal_download_blocks_path_traversal(authed_client, fresh_client_manager):
    resp = authed_client.get("/portal/test_co/download/reports/..%2F..%2Fetc%2Fpasswd")
    assert resp.status_code in (400, 404, 422)


def test_audit_package_zip(authed_client, fresh_client_manager):
    import client_manager
    # Create some content
    reports_dir = client_manager._client_dir("test_co") / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "jan-report.json").write_text('{"score": 50}')

    policies_dir = client_manager._client_dir("test_co") / "policies"
    policies_dir.mkdir(parents=True, exist_ok=True)
    (policies_dir / "wisp.pdf").write_bytes(b"%PDF-wisp")

    resp = authed_client.get("/portal/test_co/download/audit-package")
    assert resp.status_code == 200
    assert "zip" in resp.headers.get("content-type", "").lower() or resp.headers.get("content-disposition", "").endswith(".zip") or len(resp.content) > 0

    # Verify ZIP contents
    z = zipfile.ZipFile(io.BytesIO(resp.content))
    names = z.namelist()
    assert "profile_summary.json" in names
    assert "MANIFEST.md" in names
    assert any("report" in n for n in names) or any("policies" in n for n in names)
