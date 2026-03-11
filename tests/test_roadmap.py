"""Tests for 90-day roadmap generation."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_build_roadmap_basic():
    from agents.report_generator import build_roadmap
    findings = [
        {"title": "Missing DMARC record", "severity": "CRITICAL", "category": "email_security",
         "description": "No DMARC", "fix": "Add DMARC", "points": -10},
        {"title": "Add HSTS header", "severity": "HIGH", "category": "security_headers",
         "description": "Missing HSTS", "fix": "Add header", "points": -5},
    ]
    profile = {"gaps": ["Written Information Security Plan"], "applicable_frameworks": ["NIST CSF"]}
    result = build_roadmap(findings, profile, shadow_data=None, current_score=45)
    assert "week_1_2" in result
    assert "week_3_4" in result
    assert "month_2" in result
    assert "month_3" in result
    assert result["current_score"] == 45
    assert result["projected_score"] >= 45
    assert result["projected_score"] <= 100


def test_build_roadmap_category_caps():
    from agents.report_generator import build_roadmap
    findings = [
        {"title": f"Email issue {i}", "severity": "HIGH", "category": "email_security",
         "description": "Issue", "fix": "Fix", "points": -10}
        for i in range(5)
    ]
    result = build_roadmap(findings, {"gaps": [], "applicable_frameworks": []},
                          shadow_data=None, current_score=20)
    assert result["projected_score"] <= 55  # 20 + max 35 email cap


def test_categorize_task():
    from agents.report_generator import categorize_task
    effort, owner = categorize_task("Enable MFA for all users")
    assert effort == "quick"
    effort, owner = categorize_task("Add HSTS header")
    assert effort == "it_task"
    effort, owner = categorize_task("Deploy endpoint protection solution")
    assert effort == "project"
    effort, owner = categorize_task("Written Information Security Plan")
    assert effort == "we_provide"
