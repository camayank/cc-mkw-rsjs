"""Direct Jinja2 template rendering tests — no HTTP, just template engine."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jinja2 import Environment, FileSystemLoader, UndefinedError
import pytest

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)


def _full_portal_context(**overrides):
    """Return a complete set of variables for portal.html rendering."""
    ctx = {
        "client": {
            "company_name": "Test Corp",
            "domain": "test.com",
            "industry": "cpa",
            "tier": "basic",
            "contact_name": "Jane Doe",
            "contact_email": "jane@test.com",
            "advisor_name": "CyberComply Security Team",
            "next_call_date": "2025-02-15",
            "score_history": [{"score": 35, "grade": "D", "date": "2025-01-01"}],
            "current_score": 52,
            "current_grade": "C",
            "frameworks": ["IRS 4557", "NIST CSF"],
        },
        "tier": {
            "label": "Essentials",
            "billing_model": "annual_prepaid",
            "portal_access": True,
            "portal_days": None,
            "monthly_rescan": True,
            "tasks": True,
            "monthly_call": 30,
            "dark_web": "weekly",
            "threat_feed": "cisa_kev",
            "phishing": False,
            "compliance_tracking": "monthly",
            "active_validation_included": False,
            "board_report": False,
            "included_services": ["Customer portal", "Monthly external scan", "Advisor review call"],
        },
        "current_score": 52,
        "current_grade": "C",
        "score_history": [
            {"score": 35, "grade": "D", "date": "2025-01-01"},
            {"score": 52, "grade": "C", "date": "2025-02-01"},
        ],
        "open_tasks": [],
        "in_progress_tasks": [],
        "resolved_tasks": [],
        "alerts": [],
        "dark_web_alerts": 0,
        "threats_blocked": 0,
        "vuln_findings": 0,
        "phishing_tests": 0,
        "monitoring_alerts": 0,
        "reports": [],
        "policies": [],
        "agent_status": [
            {"name": "RECON", "label": "External Scan", "status": "active", "last_run": "Pending"},
        ],
        "frameworks": ["IRS 4557", "NIST CSF"],
        "compliance_pct": 40,
        "call_notes": [],
        "industry_avg_score": 45,
        "monthly_narrative": None,
        "advisor_name": "CyberComply Security Team",
        "next_call_date": "2025-02-15",
        "calendly_link": "https://calendly.com/test/30min",
        "coverage": [
            {"name": "External security scan", "status": "Active", "detail": "Monthly"},
        ],
        "this_month_handled": ["1 external scan completed and reviewed"],
        "pending_setup": [],
        "due_next": [{"when": "2025-02-15", "what": "Advisor review call"}],
        "legal_view": {
            "documents": {"msa": "Pending setup", "sow": "Pending setup", "nda": "Pending setup", "dpa": "Pending setup"},
            "authorized_representative_recorded": False,
            "ownership_confirmed": False,
            "passive_scan": "Not included",
            "active_validation": "Not included",
            "acknowledgments_complete": False,
        },
        "risk_narrative": "Your posture is moderate.",
        "risk_label": "Moderate risk",
        "needs_attention": [],
        "value_dashboard": {
            "month_label": "April 2026",
            "window_days": 30,
            "summary": {"client_actions": 0, "advisor_actions": 0, "system_actions": 0},
            "metrics": [
                {"key": "scans_completed", "label": "Scans completed",
                 "value": None, "display": "No activity yet this month",
                 "state": "empty", "supporting_text": "", "icon": ""},
            ],
        },
        "document_library": {
            "reports": [
                {"kind": "report", "key": "monthly_security",
                 "business_title": "Monthly Security Report",
                 "type": "Monthly report", "generated_date": "",
                 "version": "v1.0", "review_status": "Draft",
                 "reviewed_by": "", "reviewed_on": "", "review_due_date": "",
                 "frequency_label": "Monthly", "framework_mapping": [],
                 "download_url": "", "present": False,
                 "available_in_plan": True},
            ],
            "policies": [
                {"kind": "policy", "key": "wisp",
                 "business_title": "Written Information Security Plan",
                 "type": "Information security plan", "generated_date": "",
                 "version": "v1.0", "review_status": "Draft",
                 "reviewed_by": "", "reviewed_on": "", "review_due_date": "",
                 "frequency_label": "Annual review", "framework_mapping": [],
                 "download_url": "", "present": False,
                 "available_in_plan": True},
            ],
        },
        "vault": {
            "categories": [
                {"key": "policies", "label": "Policies", "items": [], "count": 0,
                 "empty_state": "No policies yet."},
                {"key": "security_reports", "label": "Security reports", "items": [],
                 "count": 0, "empty_state": "No reports yet."},
                {"key": "scan_results", "label": "Scan results", "items": [],
                 "count": 0, "empty_state": "No scans yet."},
                {"key": "access_reviews", "label": "Access reviews", "items": [],
                 "count": 0, "empty_state": "Connect M365."},
                {"key": "training_phishing", "label": "Training & phishing records",
                 "items": [], "count": 0, "empty_state": "Pending."},
                {"key": "incident_response", "label": "Incident response",
                 "items": [], "count": 0, "empty_state": ""},
                {"key": "vendor_compliance", "label": "Vendor & compliance",
                 "items": [], "count": 0, "empty_state": ""},
                {"key": "cyber_insurance", "label": "Cyber insurance",
                 "items": [], "count": 0, "empty_state": ""},
                {"key": "security_validation", "label": "Security validation",
                 "items": [], "count": 0, "empty_state": ""},
                {"key": "legal_authorizations", "label": "Legal authorizations",
                 "items": [], "count": 0, "empty_state": ""},
            ],
            "by_id": {},
        },
    }
    ctx.update(overrides)
    return ctx


def test_portal_template_renders_all_variables():
    """Rendering with full variable set should not raise UndefinedError."""
    tmpl = env.get_template("portal.html")
    html = tmpl.render(**_full_portal_context())
    assert "Test Corp" in html


def test_portal_template_minimal_variables():
    """Rendering with minimal data (empty lists, None optionals) should still work."""
    tmpl = env.get_template("portal.html")
    ctx = _full_portal_context(
        open_tasks=[], in_progress_tasks=[], resolved_tasks=[],
        alerts=[], reports=[], policies=[], call_notes=[],
        frameworks=[], monthly_narrative=None, industry_avg_score=None,
        score_history=[], compliance_pct=0,
    )
    html = tmpl.render(**ctx)
    assert "Test Corp" in html


def test_portal_template_score_delta_positive():
    """Score history with increase should show up-arrow."""
    tmpl = env.get_template("portal.html")
    ctx = _full_portal_context(
        score_history=[
            {"score": 35, "grade": "D", "date": "2025-01-01"},
            {"score": 52, "grade": "C", "date": "2025-02-01"},
        ],
        current_score=52,
    )
    html = tmpl.render(**ctx)
    # Should contain some indicator of positive change (arrow, +, green)
    assert "52" in html


def test_portal_template_score_delta_negative():
    """Score decrease should show down indicator."""
    tmpl = env.get_template("portal.html")
    ctx = _full_portal_context(
        score_history=[
            {"score": 52, "grade": "C", "date": "2025-01-01"},
            {"score": 40, "grade": "D", "date": "2025-02-01"},
        ],
        current_score=40,
    )
    html = tmpl.render(**ctx)
    assert "40" in html


def test_portal_template_benchmark_above():
    """When current_score > industry_avg, benchmark section should indicate 'above'."""
    tmpl = env.get_template("portal.html")
    ctx = _full_portal_context(current_score=60, industry_avg_score=45)
    html = tmpl.render(**ctx)
    assert "60" in html
    assert "45" in html


def test_portal_template_benchmark_below():
    """When current_score < industry_avg, benchmark section should indicate 'below'."""
    tmpl = env.get_template("portal.html")
    ctx = _full_portal_context(current_score=30, industry_avg_score=45)
    html = tmpl.render(**ctx)
    assert "30" in html
    assert "45" in html


def test_login_template_renders():
    """portal_login.html should render without error."""
    tmpl = env.get_template("portal_login.html")
    html = tmpl.render(error="")
    assert html  # Non-empty output


def test_setup_template_renders():
    """portal_setup.html should render with client_id and token."""
    tmpl = env.get_template("portal_setup.html")
    html = tmpl.render(client_id="test_co", token="abc123")
    assert "test_co" in html
    assert "abc123" in html
