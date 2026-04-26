"""Advisory-grade report tests.

Proves:
  - All 12 spec sections present in payload + rendered HTML
  - Disclaimers always include 'no legal advice' and 'no breach prevention'
  - Tone gates: no alarmist phrases anywhere in composer output
  - Advisor-recommendations section gates on real review metadata
  - "What changed" reflects score history correctly
  - Compliance implications language depends on framework %
  - Auth: route requires portal auth + cross-client blocked
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _build(**overrides):
    if "advisory_report" in sys.modules: del sys.modules["advisory_report"]
    import advisory_report as ar
    base = dict(
        client={"company_name": "Acme Corp", "domain": "acme.com",
                 "industry": "cpa"},
        current_score=72, grade="B-",
        score_history=[{"score": 68, "date": "2026-03-15"},
                        {"score": 72, "date": "2026-04-15"}],
        open_tasks=[
            {"title": "Enable DMARC reject", "severity": "HIGH",
             "fix": "Set p=reject after 30 days at quarantine.",
             "owner": "Client", "due_date": "2026-05-15"},
            {"title": "Patch SMB", "severity": "CRITICAL",
             "fix": "Apply KB-...", "owner": "Client",
             "due_date": "2026-04-25"},
            {"title": "Update banner", "severity": "LOW",
             "fix": "Hide server banner."},
        ],
        resolved_tasks=[],
        findings=[
            {"title": "DMARC quarantine, not reject", "severity": "HIGH",
             "description": "Domain at p=quarantine.",
             "fix": "Set p=reject after monitoring."},
            {"title": "SSL: weak cipher", "severity": "MEDIUM",
             "description": "TLS 1.2 supports CBC suites."},
        ],
        scan_categories=[
            {"name": "Email Auth", "score": 12, "max": 20},
        ],
        scan_data={
            "scan_date": "2026-04-15",
            "domain": "acme.com",
            "score": {"breakdown": {
                "email_auth": {"score": 12, "max": 20},
                "ssl_tls":    {"score": 18, "max": 20},
            }},
            "findings": [{"title": "DMARC", "severity": "HIGH"}],
        },
        frameworks=["IRS 4557", "SOC 2"],
        compliance_frameworks=[
            {"id": "irs_4557", "name": "IRS 4557", "pct": 78,
             "met": 8, "partial": 1, "not_met": 1},
            {"id": "soc2", "name": "SOC 2", "pct": 42,
             "met": 4, "partial": 2, "not_met": 4},
        ],
        reports=[{"filename": "monthly_2026-04.pdf", "date": "2026-04-15"}],
        policies=[{"filename": "wisp.pdf", "date": "2026-01-15"}],
        scans=[{"filename": "2026-04-15-monthly.json", "date": "2026-04-15"}],
        pending_setup=[
            {"item": "Dark-web monitoring",
             "note": "Provide a HaveIBeenPwned API key"},
        ],
        this_month_handled=["External scan completed", "2 alerts triaged"],
        value_summary={"advisor_actions": 4, "client_actions": 1},
        advisor_review_record=None,
        prior_findings_count=3,
    )
    base.update(overrides)
    return ar.build_advisory_report(**base)


# ─── Structure ───────────────────────────────────────────────


def test_all_twelve_sections_present():
    p = _build()
    expected = [
        "executive_summary", "business_risk_impact", "technical_findings",
        "compliance_implications", "remediation_roadmap", "evidence_collected",
        "advisor_recommendations", "what_changed", "client_actions",
        "provider_handled", "appendix", "disclaimers",
    ]
    for k in expected:
        assert k in p, f"missing section: {k}"


def test_disclaimers_include_legal_and_breach_prevention():
    p = _build()
    titles = [d["title"] for d in p["disclaimers"]]
    assert "No legal advice" in titles
    assert "No breach-prevention guarantee" in titles


def test_executive_summary_carries_required_fields():
    p = _build()
    es = p["executive_summary"]
    for k in ("headline", "score", "grade", "delta", "risk_label",
              "summary", "advisor_recommendation",
              "critical_count", "high_count"):
        assert k in es


def test_remediation_roadmap_orders_by_severity_and_assigns_window():
    p = _build()
    items = p["remediation_roadmap"]["items"]
    # Critical comes first.
    assert items[0]["severity"] == "CRITICAL"
    assert items[0]["window"].startswith("Within 7")
    # High is "Within 30 days".
    high = next(i for i in items if i["severity"] == "HIGH")
    assert high["window"].startswith("Within 30")
    # Low is "Within 90 days".
    low = next(i for i in items if i["severity"] == "LOW")
    assert low["window"].startswith("Within 90")


def test_compliance_implication_language_depends_on_pct():
    p = _build(compliance_frameworks=[
        {"id": "irs_4557", "name": "IRS 4557", "pct": 88,
         "met": 9, "partial": 1, "not_met": 0},
        {"id": "soc2", "name": "SOC 2", "pct": 65,
         "met": 5, "partial": 2, "not_met": 3},
        {"id": "gdpr", "name": "GDPR", "pct": 30,
         "met": 2, "partial": 1, "not_met": 7},
    ])
    rows = {r["name"]: r for r in p["compliance_implications"]["rows"]}
    assert "On track" in rows["IRS 4557"]["implication"]   # ≥80
    assert "Remediation in progress" in rows["SOC 2"]["implication"]  # 50-79
    assert "Material gaps" in rows["GDPR"]["implication"]   # <50


def test_what_changed_reports_score_delta():
    p = _build()
    items = p["what_changed"]["items"]
    # Score went 68 → 72.
    assert any("68" in s and "72" in s for s in items)


def test_provider_handled_includes_summary_when_actions_present():
    p = _build()
    assert "advisor / system action" in p["provider_handled"]["summary"]
    assert p["provider_handled"]["bullets"]


def test_evidence_collected_summary_counts():
    p = _build()
    s = p["evidence_collected"]["summary"]
    assert "1 report" in s
    assert "1 policy" in s
    assert "1 scan" in s


def test_appendix_includes_raw_scan_details():
    p = _build()
    a = p["appendix"]
    assert a["scan_date"] == "2026-04-15"
    assert a["domain"] == "acme.com"
    assert "email_auth" in a["score_breakdown"]


# ─── Tone gates ──────────────────────────────────────────────


_ALARMIST = ["panic", "danger", "catastrophic", "you are hacked",
             "imminent attack", "act now or", "all clear",
             "all systems normal", "you are safe"]


def _walk_strings(obj):
    """Yield every string value found in the payload."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)


def test_no_alarmist_phrases_in_composer_output():
    for tier in ((20, "F"), (50, "C"), (78, "B"), (95, "A")):
        p = _build(current_score=tier[0], grade=tier[1])
        for s in _walk_strings(p):
            low = (s or "").lower()
            for forbidden in _ALARMIST:
                assert forbidden not in low, (
                    f"alarmist phrase '{forbidden}' leaked into payload: {s!r}"
                )


def test_no_safety_or_clean_claims_anywhere():
    p = _build(current_score=92, grade="A")
    for s in _walk_strings(p):
        low = (s or "").lower()
        assert "credentials are clean" not in low
        assert "no threats whatsoever" not in low
        assert "you are safe" not in low


# ─── Advisor recommendations gating ──────────────────────────


def test_advisor_recommendation_signed_off_when_record_present():
    rec = {
        "review_status": "approved",
        "reviewed_by": "Alice",
        "reviewed_on": "2026-04-15",
        "sign_off_timestamp": "2026-04-15T12:00:00+00:00",
        "reviewer_credential": "CISSP",
        "client_facing_recommendation": "Move DMARC to p=reject.",
        "advisor_notes": "Monitored 30 days at quarantine.",
    }
    p = _build(advisor_review_record=rec)
    a = p["advisor_recommendations"]
    assert a["is_signed_off"] is True
    assert a["advisor"] == "Alice"
    assert a["credential"] == "CISSP"
    assert "DMARC" in a["primary"]
    # Executive-summary recommendation also flows through.
    assert "DMARC" in p["executive_summary"]["advisor_recommendation"]


def test_advisor_recommendation_falls_back_when_not_signed_off():
    p = _build(advisor_review_record=None)
    a = p["advisor_recommendations"]
    assert a["is_signed_off"] is False
    assert a["advisor"] == ""
    # We still generate guidance, but mark it composer-generated.
    assert a["primary"]


def test_advisor_recommendation_for_critical_findings_prioritizes():
    p = _build(findings=[
        {"title": "Open S3 bucket", "severity": "CRITICAL"},
        {"title": "Verbose error", "severity": "LOW"},
    ])
    primary = p["advisor_recommendations"]["primary"]
    assert "critical" in primary.lower() or "critical-severity" in primary.lower()


def test_advisor_recommendation_for_strong_score_recommends_maintain():
    p = _build(current_score=85, grade="A-",
               findings=[{"title": "Banner version", "severity": "LOW"}])
    primary = p["advisor_recommendations"]["primary"]
    assert "maintain" in primary.lower() or "no structural changes" in primary.lower()


# ─── Risk-label boundaries ───────────────────────────────────


def test_risk_label_boundaries():
    if "advisory_report" in sys.modules: del sys.modules["advisory_report"]
    import advisory_report as ar
    assert ar._risk_label(0)[0] == "Awaiting first review"
    assert "low" in ar._risk_label(85)[0].lower()
    assert "moderate" in ar._risk_label(65)[0].lower()
    assert "elevated" in ar._risk_label(45)[0].lower()
    assert "high" in ar._risk_label(25)[0].lower()


def test_business_risk_intro_calm_for_strong_posture():
    p = _build(current_score=82, findings=[])
    intro = p["business_risk_impact"]["intro"]
    assert "strong" in intro.lower()
    assert "panic" not in intro.lower()


# ─── Route + render ──────────────────────────────────────────


def _login(test_client, fresh_client_manager, cid="c1"):
    cm = fresh_client_manager
    cm.create_client(cid, "Acme Corp", "acme.com",
                      tier="essentials", industry="cpa")
    cm.set_portal_password(cid, "Pass123!")
    token = cm.create_jwt(cid)
    test_client.cookies.set("portal_token", token)
    return cm


def test_advisory_report_route_requires_auth(test_client):
    resp = test_client.get("/portal/c1/advisory-report")
    assert resp.status_code == 200
    # Auth-failing path returns the redirect script.
    assert "window.location" in resp.text


def test_advisory_report_route_renders_all_section_titles(test_client, fresh_client_manager):
    cm = _login(test_client, fresh_client_manager)
    cm.add_score("c1", 72, "B-")
    cm.add_task("c1", "Enable DMARC reject", "HIGH", "Email")
    resp = test_client.get("/portal/c1/advisory-report")
    assert resp.status_code == 200
    body = resp.text
    for h in ["Executive summary",
              "Business risk impact",
              "Technical findings",
              "Compliance implications",
              "Priority remediation roadmap",
              "Evidence collected",
              "Advisor recommendations",
              "What changed since last report",
              "What you need to do",
              "What CyberComply handled",
              "Appendix",
              "Disclaimers"]:
        assert h in body, f"section not rendered: {h}"


def test_advisory_report_renders_disclaimer_text(test_client, fresh_client_manager):
    cm = _login(test_client, fresh_client_manager)
    resp = test_client.get("/portal/c1/advisory-report")
    body = resp.text
    assert "No legal advice" in body
    assert "No breach-prevention guarantee" in body
    assert "does not guarantee certification" in body.lower() \
        or "does not guarantee" in body.lower()


def test_advisory_report_cross_client_blocked(test_app, fresh_client_manager):
    from starlette.testclient import TestClient
    cm = fresh_client_manager
    cm.create_client("c_a", "A", "a.com", tier="essentials")
    cm.create_client("c_b", "B", "b.com", tier="essentials")
    token_a = cm.create_jwt("c_a")
    c = TestClient(test_app, raise_server_exceptions=False)
    c.cookies.set("portal_token", token_a)
    resp = c.get("/portal/c_b/advisory-report")
    # Falls through to the unauth redirect HTML.
    assert "window.location" in resp.text


def test_advisory_report_renders_advisor_signed_off_recommendation(
    test_client, fresh_client_manager,
):
    cm = _login(test_client, fresh_client_manager)
    cm.add_score("c1", 75, "B")
    import advisor_review as ar
    ar.set_review(
        "c1", ar.report_key("monthly_security"),
        prepared_by="System",
        reviewed_by="Alice", reviewed_on="2026-04-15",
        review_status=ar.REVIEW_APPROVED,
        sign_off_timestamp="2026-04-15T12:00:00+00:00",
        reviewer_credential="CISSP",
        client_facing_recommendation="Maintain current cadence; no structural changes.",
    )
    resp = test_client.get("/portal/c1/advisory-report")
    body = resp.text
    assert "Alice" in body
    assert "CISSP" in body
    assert "Maintain current cadence" in body
