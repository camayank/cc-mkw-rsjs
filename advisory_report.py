"""
Advisory-grade customer report composer.

Produces a structured payload that the advisory-report template renders
into 12 named sections per the product spec:

  1. Executive summary
  2. Business risk impact
  3. Technical findings
  4. Compliance implications
  5. Priority remediation roadmap
  6. Evidence collected
  7. Advisor recommendations
  8. What changed since last report
  9. What client needs to do
 10. What CyberComply (DigComply / CA4CPA) handled this cycle
 11. Appendix — raw scan details
 12. Disclaimers — no legal advice, no breach-prevention guarantee

Tone rules enforced by the composer (the template does no rewriting):
  - Non-alarmist phrasing: never "panic", "danger", "catastrophic", etc.
  - Quantified, calm language ("X items at HIGH severity", not "exposed!")
  - No clean / safe / all clear claims (handled at the alert layer)
  - Disclaimer block always present, verbatim
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Optional


# ─── Disclaimer text (verbatim, never edited from caller) ────

LEGAL_ENTITY_NAME = "DigComply Solutions Private Limited"
LEGAL_ENTITY_ASSOCIATION = "in association with CA4CPA Global LLC"
LEGAL_ENTITY_FULL = f"{LEGAL_ENTITY_NAME} ({LEGAL_ENTITY_ASSOCIATION})"

DISCLAIMERS = [
    {
        "title": "Issuing entity",
        "body": (
            f"This report is issued by {LEGAL_ENTITY_FULL} under the "
            "engagement agreement signed with the customer. The CyberComply "
            "platform is the technology used to deliver the service."
        ),
    },
    {
        "title": "No legal advice",
        "body": (
            "This report is provided for security and compliance program "
            "purposes only. It is not legal advice and does not constitute "
            "an attorney-client relationship. Consult qualified legal counsel "
            "for matters that may carry legal exposure, including breach "
            "notification, regulatory filings, and contract obligations."
        ),
    },
    {
        "title": "No breach-prevention guarantee",
        "body": (
            "CyberComply does not guarantee the prevention of security "
            "incidents, regulatory enforcement, or insurance outcomes. Our "
            "engagement reduces the likelihood and impact of common attacks "
            "and produces audit-ready documentation, but it does not eliminate "
            "risk. Real-world security depends on continued operational "
            "discipline by the customer."
        ),
    },
    {
        "title": "External assessment scope",
        "body": (
            "Findings reflect what is observable from outside your "
            "environment plus the data you have shared with us. Active "
            "security validation only runs under a separately signed "
            "engagement scope. This report is not an authorized penetration "
            "test unless explicitly stated."
        ),
    },
    {
        "title": "Point-in-time observation",
        "body": (
            "Conditions captured here reflect a specific point in time. "
            "Continuous changes in your environment, in vendor systems, "
            "and in the threat landscape can shift your posture between "
            "review cycles."
        ),
    },
]


# ─── Tone vocabulary guards ───────────────────────────────────

_FORBIDDEN_ALARMIST = (
    "panic", "danger", "danger!", "danger.", "catastrophic", "catastrophe",
    "you are hacked", "you have been breached", "act now or",
    "imminent attack", "exposed!", "vulnerable!", "compromised!",
    "you must immediately", "all clear", "all systems normal",
    "you are safe", "no threats whatsoever",
)


def _scrub(text: str) -> str:
    """Remove obviously alarmist phrases from any narrative we emit. The
    advisor's own notes pass through unchanged — this is for our composer."""
    if not text:
        return ""
    out = text
    for phrase in _FORBIDDEN_ALARMIST:
        out = out.replace(phrase, "").replace(phrase.capitalize(), "")
    return out


# ─── Helpers ──────────────────────────────────────────────────

def _parse_date(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        s = s.replace("Z", "+00:00")
        d = datetime.fromisoformat(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d
    except Exception:
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _within(iso: str, days: int, now: datetime) -> bool:
    d = _parse_date(iso)
    if not d:
        return False
    return (now - d) <= timedelta(days=days)


def _count_severity(items: list, key: str = "severity") -> dict[str, int]:
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for it in items or []:
        sev = (it.get(key, "") or "").upper()
        if sev in out:
            out[sev] += 1
    return out


def _risk_label(score: int) -> tuple[str, str]:
    """Return (risk_label, calm_one_liner). Never alarmist."""
    if score == 0:
        return ("Awaiting first review", "Your first review cycle is in progress.")
    if score >= 80:
        return ("Low residual risk",
                "Posture is strong; remaining items are maintenance-grade.")
    if score >= 60:
        return ("Moderate residual risk",
                "Posture is broadly healthy with a small set of items to address.")
    if score >= 40:
        return ("Elevated residual risk",
                "Posture has notable gaps; advisor is prioritizing closure.")
    return ("High residual risk",
            "Posture requires focused remediation; advisor is leading closure.")


# ─── Section composers ────────────────────────────────────────

def _section_executive_summary(*, client, current_score, grade, prior_score,
                               critical, high, frameworks, advisor_recommendation):
    risk_label, sentence = _risk_label(current_score or 0)
    delta = (current_score or 0) - (prior_score or 0) if prior_score else 0
    delta_text = ""
    if prior_score:
        if delta > 0:
            delta_text = f"Score improved by {delta} since the previous cycle."
        elif delta < 0:
            delta_text = f"Score declined by {abs(delta)} since the previous cycle."
        else:
            delta_text = "Score unchanged from the previous cycle."
    headline = f"{client.get('company_name','your organization')} — {risk_label}"
    summary = sentence
    if frameworks:
        summary += (" Compliance work this cycle covered "
                    + ", ".join(frameworks[:4]) + ".")
    if delta_text:
        summary += " " + delta_text
    return {
        "headline": headline,
        "score": current_score or 0,
        "grade": grade or "—",
        "delta": delta,
        "risk_label": risk_label,
        "summary": _scrub(summary),
        "advisor_recommendation": _scrub(advisor_recommendation or ""),
        "critical_count": critical,
        "high_count": high,
    }


def _section_business_risk_impact(*, score, critical, high, exposures,
                                  frameworks_with_gaps):
    """Plain-English business impact, owner-friendly."""
    bullets = []
    if critical > 0:
        bullets.append(
            f"{critical} CRITICAL finding(s) materially increase the "
            "likelihood of customer-data exposure or regulatory reporting "
            "obligations until remediated."
        )
    if high > 0:
        bullets.append(
            f"{high} HIGH-severity finding(s) raise the risk of audit "
            "exceptions and may affect cyber-insurance underwriting."
        )
    if exposures > 0:
        bullets.append(
            f"{exposures} credential exposure(s) detected on monitored "
            "breach corpora. Affected accounts should be password-rotated "
            "and protected by MFA."
        )
    if frameworks_with_gaps:
        bullets.append(
            "Open gaps in {fw} may surface in upcoming audit cycles or "
            "third-party due diligence."
            .format(fw=", ".join(frameworks_with_gaps[:3]))
        )
    if not bullets:
        bullets.append(
            "No material business-risk items identified this cycle that "
            "require immediate ownership decisions."
        )
    headline = "Business impact this cycle"
    if score and score >= 75:
        intro = (
            "Posture is strong. The items below describe residual risks "
            "that the program is actively managing — none are emergencies."
        )
    elif score and score >= 50:
        intro = (
            "The items below describe risks that warrant attention this "
            "cycle. Your advisor has prioritized them by business impact."
        )
    else:
        intro = (
            "The items below describe risks that the program is closing "
            "as a priority. Your advisor is coordinating remediation."
        )
    return {"headline": headline,
            "intro": _scrub(intro),
            "bullets": [_scrub(b) for b in bullets]}


def _section_technical_findings(scan_categories, findings):
    """Categorized findings + a flat list. Severity-sorted."""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "": 9}
    sorted_findings = sorted(
        findings or [], key=lambda f: sev_order.get((f.get("severity") or "").upper(), 9)
    )
    return {
        "categories": scan_categories or [],
        "findings": sorted_findings,
        "counts": _count_severity(findings or []),
    }


def _section_compliance_implications(frameworks):
    """Per-framework implication line. frameworks: list of dicts with
    name + pct + met/partial/not_met."""
    rows = []
    overall = []
    for fw in frameworks or []:
        if isinstance(fw, str):
            name = fw
            pct = 0
            not_met = 0
        else:
            name = fw.get("name") or fw.get("id", "")
            pct = fw.get("pct", 0) or 0
            not_met = fw.get("not_met", 0) or 0
        if pct is None:
            pct = 0
        if pct >= 80:
            implication = (
                "On track. Documentation supports a clean audit response."
            )
        elif pct >= 50:
            implication = (
                "Remediation in progress. Audit response will reference open "
                "items with documented owners and dates."
            )
        else:
            implication = (
                "Material gaps remain. Advisor is coordinating remediation "
                "to bring this framework to audit-ready status."
            )
        rows.append({"name": str(name), "pct": pct, "not_met": not_met,
                     "implication": _scrub(implication)})
        overall.append(pct)
    avg = (sum(overall) // max(len(overall), 1)) if overall else 0
    return {"rows": rows, "overall_pct": avg}


def _section_remediation_roadmap(open_tasks):
    """Top items grouped by severity → priority. Customer-friendly text."""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_tasks = sorted(
        open_tasks or [], key=lambda t: sev_order.get((t.get("severity") or "").upper(), 9)
    )
    horizon = []
    for t in sorted_tasks[:10]:
        sev = (t.get("severity") or "MEDIUM").upper()
        if sev == "CRITICAL":
            window = "Within 7 days"
        elif sev == "HIGH":
            window = "Within 30 days"
        elif sev == "MEDIUM":
            window = "Within 60 days"
        else:
            window = "Within 90 days"
        horizon.append({
            "title": t.get("title", ""),
            "severity": sev,
            "window": window,
            "fix": (t.get("fix") or "")[:240],
            "owner": t.get("owner", "Client"),
            "due_date": t.get("due_date", ""),
        })
    return {"items": horizon, "more_count": max(len(sorted_tasks) - 10, 0)}


def _section_evidence_collected(reports, policies, scans):
    items = []
    for p in (policies or []):
        items.append({"label": p.get("filename", "Policy"),
                       "type": "Policy", "date": p.get("date", "")})
    for r in (reports or []):
        items.append({"label": r.get("filename", "Report"),
                       "type": "Report", "date": r.get("date", "")})
    for s in (scans or []):
        items.append({"label": s.get("filename", "Scan artifact"),
                       "type": "Scan artifact", "date": s.get("date", "")})
    return {"items": items[:30],
             "total": len(items),
             "summary":
                 f"{len(reports or [])} report(s), "
                 f"{len(policies or [])} policy document(s), "
                 f"{len(scans or [])} scan artifact(s) collected this cycle."}


def _section_advisor_recommendations(advisor_record, current_score, critical):
    """Pull the advisor's own recommendation when present; otherwise produce
    a calm default that does NOT make safety claims."""
    if advisor_record and advisor_record.get("client_facing_recommendation"):
        return {
            "advisor": advisor_record.get("reviewed_by", ""),
            "credential": advisor_record.get("reviewer_credential", ""),
            "reviewed_on": (advisor_record.get("reviewed_on", "") or "")[:10],
            "primary": _scrub(advisor_record["client_facing_recommendation"]),
            "supporting": _scrub(advisor_record.get("advisor_notes", "") or ""),
            "is_signed_off": True,
        }
    if critical > 0:
        primary = ("Prioritize the critical-severity items in section 5; "
                   "schedule a remediation working session with your advisor "
                   "this week.")
    elif (current_score or 0) >= 75:
        primary = ("Maintain cadence. No structural changes recommended; "
                   "your advisor will continue the program as scheduled.")
    else:
        primary = ("Work through the priority roadmap with your advisor on "
                   "the next monthly call.")
    return {"advisor": "", "credential": "", "reviewed_on": "",
             "primary": _scrub(primary), "supporting": "",
             "is_signed_off": False}


def _section_what_changed(score_history, prior_findings_count, current_findings_count):
    """Calm, factual diff line. No alarm tones."""
    items = []
    if score_history and len(score_history) >= 2:
        prior = score_history[-2].get("score", 0)
        cur = score_history[-1].get("score", 0)
        if cur > prior:
            items.append(f"Security score: {prior} → {cur} (+{cur-prior}).")
        elif cur < prior:
            items.append(f"Security score: {prior} → {cur} ({cur-prior}).")
        else:
            items.append(f"Security score unchanged at {cur}.")
    if prior_findings_count is not None:
        delta = current_findings_count - prior_findings_count
        if delta < 0:
            items.append(f"Open findings reduced by {abs(delta)} this cycle.")
        elif delta > 0:
            items.append(f"Open findings increased by {delta} this cycle.")
        else:
            items.append("Open-finding count unchanged from the previous cycle.")
    if not items:
        items.append("This is your first cycle; baseline established.")
    return {"items": [_scrub(x) for x in items]}


def _section_client_actions(open_tasks, pending_setup):
    """Concise list of what needs the customer's attention."""
    actions = []
    for t in (open_tasks or [])[:5]:
        actions.append({
            "title": t.get("title", ""),
            "severity": (t.get("severity") or "").upper(),
            "by": t.get("due_date", ""),
            "summary": (t.get("fix") or t.get("description") or "")[:160],
        })
    setup = []
    for p in (pending_setup or [])[:6]:
        setup.append({"item": p.get("item", ""), "note": p.get("note", "")})
    intro = (
        "Items below benefit from your sign-off, attestation, or input. "
        "Your advisor handles everything else in the background."
    )
    return {"intro": _scrub(intro), "tasks": actions, "pending_setup": setup}


def _section_provider_handled(this_month_handled, value_summary):
    """What CyberComply (DigComply/CA4CPA) handled on the customer's behalf."""
    bullets = list(this_month_handled or [])
    summary = ""
    if value_summary:
        summary = (
            f"This cycle: {value_summary.get('advisor_actions', 0)} "
            "advisor / system action(s) completed on your behalf, alongside "
            f"{value_summary.get('client_actions', 0)} client action(s) closed."
        )
    if not bullets:
        bullets = ["Onboarding cycle in progress. Your first review will appear here."]
    return {"summary": _scrub(summary), "bullets": [_scrub(b) for b in bullets]}


def _section_appendix(scan_data):
    """Raw scan details for auditors / technical reviewers. Customer-safe."""
    return {
        "scan_date": scan_data.get("scan_date", "") if scan_data else "",
        "domain": scan_data.get("domain", "") if scan_data else "",
        "score_breakdown": (scan_data.get("score", {}) or {}).get("breakdown", {})
                            if scan_data else {},
        "raw_findings": (scan_data or {}).get("findings", []),
        "categories": (scan_data or {}).get("categories", []),
    }


# ─── Public entry point ───────────────────────────────────────

def build_advisory_report(
    *,
    client: dict,
    current_score: int,
    grade: str,
    score_history: list,
    open_tasks: list,
    resolved_tasks: list,
    findings: list,
    scan_categories: list,
    scan_data: dict,
    frameworks: list,
    compliance_frameworks: list,
    reports: list,
    policies: list,
    scans: list,
    pending_setup: list,
    this_month_handled: list,
    value_summary: dict,
    advisor_review_record: Optional[dict] = None,
    prior_findings_count: Optional[int] = None,
    report_date: Optional[str] = None,
) -> dict[str, Any]:
    """Return a fully composed advisory-grade report payload."""
    sev_counts = _count_severity(findings or [])
    critical = sev_counts.get("CRITICAL", 0)
    high = sev_counts.get("HIGH", 0)
    prior_score = (score_history[-2].get("score", 0)
                   if score_history and len(score_history) >= 2 else 0)
    frameworks_with_gaps = []
    for fw in (compliance_frameworks or []):
        if isinstance(fw, dict) and (fw.get("pct") or 0) < 80:
            frameworks_with_gaps.append(fw.get("name") or fw.get("id", ""))

    advisor_recommendation = ""
    if advisor_review_record:
        advisor_recommendation = (
            advisor_review_record.get("client_facing_recommendation", "") or ""
        )

    payload = {
        "client": client,
        "report_date": report_date or datetime.now(timezone.utc).strftime("%Y-%m-%d"),

        "executive_summary":
            _section_executive_summary(
                client=client, current_score=current_score, grade=grade,
                prior_score=prior_score, critical=critical, high=high,
                frameworks=[(f.get("name") if isinstance(f, dict) else f)
                             for f in (frameworks or [])],
                advisor_recommendation=advisor_recommendation,
            ),

        "business_risk_impact":
            _section_business_risk_impact(
                score=current_score, critical=critical, high=high,
                exposures=client.get("dark_web_exposures", 0) or 0,
                frameworks_with_gaps=frameworks_with_gaps,
            ),

        "technical_findings":
            _section_technical_findings(scan_categories, findings),

        "compliance_implications":
            _section_compliance_implications(compliance_frameworks),

        "remediation_roadmap":
            _section_remediation_roadmap(open_tasks),

        "evidence_collected":
            _section_evidence_collected(reports, policies, scans),

        "advisor_recommendations":
            _section_advisor_recommendations(
                advisor_review_record, current_score, critical),

        "what_changed":
            _section_what_changed(
                score_history, prior_findings_count, len(findings or [])),

        "client_actions":
            _section_client_actions(open_tasks, pending_setup),

        "provider_handled":
            _section_provider_handled(this_month_handled, value_summary),

        "appendix":
            _section_appendix(scan_data),

        "disclaimers": DISCLAIMERS,
    }
    return payload
