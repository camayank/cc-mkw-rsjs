"""Tests for /portal/{id}/alerts/report HTMX endpoint."""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _write_monthly_report(client_id, data):
    """Helper: write a monthly report JSON file for a client."""
    import client_manager
    reports_dir = client_manager._client_dir(client_id) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "2025-01-monthly-report.json").write_text(json.dumps(data))


def test_report_renders_with_monthly_data(authed_client, fresh_client_manager):
    _write_monthly_report("test_co", {
        "narrative": "Overall security posture improved.",
        "score": 58,
        "grade": "C+",
        "score_delta": 5,
        "findings_summary": {"total": 12, "resolved": 8, "critical": 1},
    })
    resp = authed_client.get("/portal/test_co/alerts/report")
    assert resp.status_code == 200
    assert "58" in resp.text
    assert "Overall security posture improved" in resp.text


def test_report_no_monthly_files(authed_client, fresh_client_manager):
    resp = authed_client.get("/portal/test_co/alerts/report")
    assert resp.status_code == 200
    assert "No monthly reports yet" in resp.text


def test_report_shows_critical_count(authed_client, fresh_client_manager):
    _write_monthly_report("test_co", {
        "narrative": "Mixed results.",
        "score": 45,
        "grade": "D+",
        "score_delta": -2,
        "findings_summary": {"total": 20, "resolved": 10, "critical": 3},
    })
    resp = authed_client.get("/portal/test_co/alerts/report")
    assert "3 critical" in resp.text


def test_report_shows_cissp_badge(authed_client, fresh_client_manager):
    _write_monthly_report("test_co", {
        "narrative": "Good progress.",
        "score": 60,
        "grade": "B-",
        "score_delta": 3,
        "findings_summary": {"total": 8, "resolved": 6, "critical": 0},
    })
    resp = authed_client.get("/portal/test_co/alerts/report")
    assert "CISSP-Reviewed" in resp.text


def test_report_shows_industry_benchmark(authed_client, fresh_client_manager):
    """Client industry=cpa → 'Industry avg: 45' in report HTML."""
    _write_monthly_report("test_co", {
        "narrative": "Benchmark test.",
        "score": 55,
        "grade": "C",
        "score_delta": 2,
        "findings_summary": {"total": 5, "resolved": 3, "critical": 0},
    })
    resp = authed_client.get("/portal/test_co/alerts/report")
    assert "Industry avg: 45" in resp.text


def test_report_score_delta_positive(authed_client, fresh_client_manager):
    _write_monthly_report("test_co", {
        "narrative": "Improved.",
        "score": 55,
        "grade": "C",
        "score_delta": 7,
        "findings_summary": {"total": 5, "resolved": 4, "critical": 0},
    })
    resp = authed_client.get("/portal/test_co/alerts/report")
    # Positive delta → green arrow (▲ = &#x25b2;) and +7
    assert "+7" in resp.text


def test_report_score_delta_negative(authed_client, fresh_client_manager):
    _write_monthly_report("test_co", {
        "narrative": "Regression.",
        "score": 40,
        "grade": "D",
        "score_delta": -4,
        "findings_summary": {"total": 10, "resolved": 3, "critical": 2},
    })
    resp = authed_client.get("/portal/test_co/alerts/report")
    # Negative delta → red arrow (▼ = &#x25bc;) and -4
    assert "-4" in resp.text
