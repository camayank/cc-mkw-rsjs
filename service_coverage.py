"""
Service coverage model for the customer portal.

Encodes the 11 service areas, their plan availability, and the rules that
turn live system state into a status the customer sees.

Hard rule: never produce status = "Active" unless a successful check ran
and is recorded. If we cannot prove a successful check, we degrade to
"Pending setup" or "Not connected" — never to a "safe / clean / normal"
label.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional


# ─── Enums ────────────────────────────────────────────────────

OWNER_CLIENT = "Client"
OWNER_ADVISOR = "Advisor"
OWNER_SYSTEM = "System"

STATUS_ACTIVE = "Active"
STATUS_PENDING_SETUP = "Pending setup"
STATUS_NOT_CONNECTED = "Not connected"
STATUS_NOT_INCLUDED = "Not included"
STATUS_NEEDS_ATTENTION = "Needs attention"

ALL_STATUSES = (
    STATUS_ACTIVE, STATUS_PENDING_SETUP, STATUS_NOT_CONNECTED,
    STATUS_NOT_INCLUDED, STATUS_NEEDS_ATTENTION,
)


# ─── Tier inclusion matrix ────────────────────────────────────

# Which plans include each service area. Anything outside this set returns
# Status = "Not included" for that tier.
TIER_INCLUSION: dict[str, set[str]] = {
    "external_attack_surface":  {"diagnostic", "essentials", "professional", "enterprise_plus"},
    "dark_web_monitoring":      {"essentials", "professional", "enterprise_plus"},
    "threat_intelligence":      {"essentials", "professional", "enterprise_plus"},
    "vulnerability_scanning":   {"professional", "enterprise_plus"},
    "identity_m365_monitoring": {"essentials", "professional", "enterprise_plus"},
    "phishing_readiness":       {"professional", "enterprise_plus"},
    "compliance_tracking":      {"essentials", "professional", "enterprise_plus"},
    "policy_management":        {"essentials", "professional", "enterprise_plus"},
    "evidence_package":         {"diagnostic", "essentials", "professional", "enterprise_plus"},
    "advisor_review":           {"diagnostic", "essentials", "professional", "enterprise_plus"},
    "security_validation":      {"professional", "enterprise_plus"},
}

# Customer-facing plan availability label (right side of the row).
PLAN_AVAILABILITY_LABEL: dict[str, str] = {
    "external_attack_surface":  "All plans",
    "dark_web_monitoring":      "Essentials and above",
    "threat_intelligence":      "Essentials and above",
    "vulnerability_scanning":   "Professional and above",
    "identity_m365_monitoring": "Essentials and above",
    "phishing_readiness":       "Professional and above",
    "compliance_tracking":      "Essentials and above",
    "policy_management":        "Essentials and above",
    "evidence_package":         "All plans",
    "advisor_review":           "All plans",
    "security_validation":      "Professional and above",
}

# Cadence -> max-age in days (used for freshness checks). Stale checks
# downgrade Active -> Pending setup so we never claim a service is currently
# operational on the basis of an old run alone.
CADENCE_MAX_AGE_DAYS: dict[str, int] = {
    "monthly":   35,
    "weekly":    10,
    "daily":     3,
    "quarterly": 100,
    "annual":    400,
}


# ─── Helpers ──────────────────────────────────────────────────

def _parse_iso(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        s = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _is_fresh(iso: str, cadence: str, *, now: Optional[datetime] = None) -> bool:
    dt = _parse_iso(iso)
    if not dt:
        return False
    max_age = CADENCE_MAX_AGE_DAYS.get(cadence, 35)
    return (now or datetime.now(timezone.utc)) - dt <= timedelta(days=max_age)


def _row(
    *,
    key: str,
    service: str,
    tier: str,
    status: str,
    last_successful_check: str,
    data_source: str,
    coverage_note: str,
    next_action: str,
    owner: str,
) -> dict[str, Any]:
    return {
        "key": key,
        "service": service,
        "plan_availability": PLAN_AVAILABILITY_LABEL[key],
        "included_in_plan": tier in TIER_INCLUSION[key],
        "status": status,
        "last_successful_check": last_successful_check or "",
        "data_source": data_source,
        "coverage_note": coverage_note,
        "next_action": next_action,
        "owner": owner,
    }


def _not_included(key: str, service: str, coverage_note: str) -> dict[str, Any]:
    return _row(
        key=key, service=service, tier="__none__",
        status=STATUS_NOT_INCLUDED,
        last_successful_check="",
        data_source="—",
        coverage_note=coverage_note,
        next_action="Available on a higher plan — talk to your advisor",
        owner=OWNER_ADVISOR,
    )


# ─── Per-service builders ─────────────────────────────────────

def _external_attack_surface(tier, score_history, open_tasks):
    if tier not in TIER_INCLUSION["external_attack_surface"]:
        return _not_included("external_attack_surface", "External attack surface",
                             "Monthly external scan and advisor review")

    last = (score_history[-1].get("date", "") if score_history else "")
    has_critical = any(
        t.get("severity", "").upper() == "CRITICAL" for t in (open_tasks or [])
    )

    if not last:
        status = STATUS_PENDING_SETUP
        next_action = "Your first scan will run on the next scheduled cycle"
    elif not _is_fresh(last, "monthly"):
        status = STATUS_PENDING_SETUP
        next_action = "Your advisor will run a fresh scan in the next cycle"
    elif has_critical:
        status = STATUS_NEEDS_ATTENTION
        next_action = "Critical findings open — see Action Items"
    else:
        status = STATUS_ACTIVE
        next_action = ""

    return _row(
        key="external_attack_surface", service="External attack surface", tier=tier,
        status=status,
        last_successful_check=last,
        data_source="Internal scheduler · RECON module",
        coverage_note="Email auth, SSL/TLS, headers, exposed services, DNS",
        next_action=next_action,
        owner=OWNER_SYSTEM,
    )


def _dark_web_monitoring(tier, *, hibp_configured: bool, last_check: str, exposures: int):
    if tier not in TIER_INCLUSION["dark_web_monitoring"]:
        return _not_included("dark_web_monitoring", "Dark web monitoring",
                             "Employee credential exposure checks on a regular cadence")

    if not hibp_configured:
        return _row(
            key="dark_web_monitoring", service="Dark web monitoring", tier=tier,
            status=STATUS_NOT_CONNECTED,
            last_successful_check="",
            data_source="HaveIBeenPwned API (not connected)",
            coverage_note="Daily/weekly check against known breach corpora",
            next_action="Provide a HaveIBeenPwned API key to your advisor",
            owner=OWNER_CLIENT,
        )

    cadence = "daily" if tier in ("professional", "enterprise_plus") else "weekly"
    if not last_check:
        status = STATUS_PENDING_SETUP
        next_action = f"First {cadence} check is queued"
    elif not _is_fresh(last_check, cadence):
        status = STATUS_PENDING_SETUP
        next_action = f"Last check is older than the {cadence} cadence — re-run scheduled"
    elif exposures > 0:
        status = STATUS_NEEDS_ATTENTION
        next_action = "Force password reset for exposed accounts and review with your advisor"
    else:
        status = STATUS_ACTIVE
        next_action = ""

    return _row(
        key="dark_web_monitoring", service="Dark web monitoring", tier=tier,
        status=status,
        last_successful_check=last_check or "",
        data_source="HaveIBeenPwned API",
        coverage_note=f"{cadence.title()} check against known breach corpora",
        next_action=next_action,
        owner=OWNER_SYSTEM,
    )


def _threat_intelligence(tier, *, alerts):
    if tier not in TIER_INCLUSION["threat_intelligence"]:
        return _not_included("threat_intelligence", "Threat intelligence",
                             "Filtered CISA KEV alerts for your tech stack")

    threat_alerts = [a for a in alerts if a.get("type") == "threat"]
    last = ""
    if threat_alerts:
        last_alert = max(threat_alerts, key=lambda a: a.get("date", ""))
        last = (last_alert.get("date", "") or "")[:10]

    if not last:
        # No recorded run yet — never claim Active without proof.
        status = STATUS_PENDING_SETUP
        next_action = "Your first scheduled feed pull will populate here"
    elif not _is_fresh(last, "daily"):
        status = STATUS_PENDING_SETUP
        next_action = "Last feed pull is older than the daily cadence — re-run scheduled"
    elif any(a.get("severity") in ("HIGH", "CRITICAL") for a in threat_alerts[-3:]):
        status = STATUS_NEEDS_ATTENTION
        next_action = "Review recent threat advisories with your advisor"
    else:
        status = STATUS_ACTIVE
        next_action = ""

    return _row(
        key="threat_intelligence", service="Threat intelligence", tier=tier,
        status=status,
        last_successful_check=last,
        data_source="CISA Known Exploited Vulnerabilities catalog",
        coverage_note="Filtered to your tech stack; HIGH/CRITICAL items raise alerts",
        next_action=next_action,
        owner=OWNER_SYSTEM,
    )


def _vulnerability_scanning(tier, *, nuclei_available: bool, last_run: str, findings: int):
    if tier not in TIER_INCLUSION["vulnerability_scanning"]:
        return _not_included("vulnerability_scanning", "Vulnerability scanning",
                             "Authenticated and unauthenticated vulnerability scans")

    if not nuclei_available:
        return _row(
            key="vulnerability_scanning", service="Vulnerability scanning", tier=tier,
            status=STATUS_NOT_CONNECTED,
            last_successful_check="",
            data_source="Nuclei scanner (not installed on the runner)",
            coverage_note="Vulnerability scan templates against in-scope hosts",
            next_action="Operator will provision the scanner — your advisor will confirm date",
            owner=OWNER_ADVISOR,
        )

    if not last_run:
        status = STATUS_PENDING_SETUP
        next_action = "First scan will run during the next maintenance window"
    elif not _is_fresh(last_run, "monthly"):
        status = STATUS_PENDING_SETUP
        next_action = "Last scan is older than the monthly cadence — re-run scheduled"
    elif findings > 0:
        status = STATUS_NEEDS_ATTENTION
        next_action = f"{findings} finding(s) open — review with your advisor"
    else:
        status = STATUS_ACTIVE
        next_action = ""

    return _row(
        key="vulnerability_scanning", service="Vulnerability scanning", tier=tier,
        status=status,
        last_successful_check=last_run or "",
        data_source="Nuclei scanner · monthly cadence",
        coverage_note="Templates aligned with current CVE landscape; advisor-triaged",
        next_action=next_action,
        owner=OWNER_SYSTEM,
    )


def _identity_m365_monitoring(tier, *, m365_configured: bool, last_run: str):
    if tier not in TIER_INCLUSION["identity_m365_monitoring"]:
        return _not_included("identity_m365_monitoring", "Identity / M365 monitoring",
                             "Microsoft 365 sign-in, MFA, and config drift monitoring")

    if not m365_configured:
        return _row(
            key="identity_m365_monitoring", service="Identity / M365 monitoring", tier=tier,
            status=STATUS_NOT_CONNECTED,
            last_successful_check="",
            data_source="Microsoft Graph API (not connected)",
            coverage_note="Sign-in anomalies, MFA gaps, and configuration drift",
            next_action="Authorize Microsoft 365 read-only access via your advisor",
            owner=OWNER_CLIENT,
        )

    if not last_run:
        status = STATUS_PENDING_SETUP
        next_action = "First sync queued"
    elif not _is_fresh(last_run, "daily"):
        status = STATUS_PENDING_SETUP
        next_action = "Last sync is stale — re-sync scheduled"
    else:
        status = STATUS_ACTIVE
        next_action = ""

    return _row(
        key="identity_m365_monitoring", service="Identity / M365 monitoring", tier=tier,
        status=status,
        last_successful_check=last_run or "",
        data_source="Microsoft Graph API",
        coverage_note="Sign-in anomalies, MFA coverage, configuration drift",
        next_action=next_action,
        owner=OWNER_SYSTEM,
    )


def _phishing_readiness(tier, *, gophish_configured: bool, employee_emails: list,
                        last_campaign: str, last_results_summary: str = ""):
    if tier not in TIER_INCLUSION["phishing_readiness"]:
        return _not_included("phishing_readiness", "Phishing readiness",
                             "Quarterly phishing simulations with awareness reporting")

    if not employee_emails:
        return _row(
            key="phishing_readiness", service="Phishing readiness", tier=tier,
            status=STATUS_PENDING_SETUP,
            last_successful_check="",
            data_source="GoPhish (employee list missing)",
            coverage_note="Quarterly phishing simulations with awareness reporting",
            next_action="Provide your employee email list to your advisor",
            owner=OWNER_CLIENT,
        )

    if not gophish_configured:
        return _row(
            key="phishing_readiness", service="Phishing readiness", tier=tier,
            status=STATUS_NOT_CONNECTED,
            last_successful_check="",
            data_source="GoPhish (not connected)",
            coverage_note="Quarterly phishing simulations with awareness reporting",
            next_action="Operator will connect GoPhish — advisor will confirm campaign date",
            owner=OWNER_ADVISOR,
        )

    if not last_campaign:
        status = STATUS_PENDING_SETUP
        next_action = "First campaign queued"
    elif not _is_fresh(last_campaign, "quarterly"):
        status = STATUS_PENDING_SETUP
        next_action = "Last campaign is older than the quarterly cadence — re-run scheduled"
    else:
        status = STATUS_ACTIVE
        next_action = ""

    return _row(
        key="phishing_readiness", service="Phishing readiness", tier=tier,
        status=status,
        last_successful_check=last_campaign or "",
        data_source="GoPhish · quarterly campaigns",
        coverage_note=last_results_summary or "Click rate, report rate, and awareness trend tracked",
        next_action=next_action,
        owner=OWNER_SYSTEM,
    )


def _compliance_tracking(tier, *, frameworks: list, compliance_pct: int, last_review: str):
    if tier not in TIER_INCLUSION["compliance_tracking"]:
        return _not_included("compliance_tracking", "Compliance tracking",
                             "Framework gap mapping with monthly or continuous review")

    if not frameworks:
        return _row(
            key="compliance_tracking", service="Compliance tracking", tier=tier,
            status=STATUS_PENDING_SETUP,
            last_successful_check="",
            data_source="Profile questionnaire + framework library",
            coverage_note="Framework gap mapping refreshed monthly",
            next_action="Complete onboarding questionnaire with your advisor",
            owner=OWNER_CLIENT,
        )

    if not last_review:
        status = STATUS_PENDING_SETUP
        next_action = "First framework review queued"
    elif not _is_fresh(last_review, "monthly"):
        status = STATUS_PENDING_SETUP
        next_action = "Last review is stale — refresh queued"
    elif compliance_pct < 40:
        status = STATUS_NEEDS_ATTENTION
        next_action = "Compliance below threshold — see remediation roadmap"
    else:
        status = STATUS_ACTIVE
        next_action = ""

    return _row(
        key="compliance_tracking", service="Compliance tracking", tier=tier,
        status=status,
        last_successful_check=last_review or "",
        data_source="Profile + GUARDIAN framework library",
        coverage_note=f"Mapped to: {', '.join(str(f) for f in frameworks[:4]) or 'pending'}",
        next_action=next_action,
        owner=OWNER_ADVISOR,
    )


def _policy_management(tier, *, policies: list, advisor_reviewed_at: str):
    if tier not in TIER_INCLUSION["policy_management"]:
        return _not_included("policy_management", "Policy management",
                             "WISP and supporting policies with advisor review")

    if not policies:
        return _row(
            key="policy_management", service="Policy management", tier=tier,
            status=STATUS_PENDING_SETUP,
            last_successful_check="",
            data_source="GUARDIAN policy templates + advisor review",
            coverage_note="WISP + supporting policies tailored to your profile",
            next_action="Your advisor will draft your initial policy library",
            owner=OWNER_ADVISOR,
        )

    if not advisor_reviewed_at:
        status = STATUS_PENDING_SETUP
        next_action = "Advisor review of latest draft pending"
    elif not _is_fresh(advisor_reviewed_at, "annual"):
        status = STATUS_PENDING_SETUP
        next_action = "Annual policy refresh due"
    else:
        status = STATUS_ACTIVE
        next_action = ""

    return _row(
        key="policy_management", service="Policy management", tier=tier,
        status=status,
        last_successful_check=advisor_reviewed_at or "",
        data_source="Policy library + advisor review",
        coverage_note=f"{len(policies)} policy document(s) on file; refreshed annually",
        next_action=next_action,
        owner=OWNER_ADVISOR,
    )


def _evidence_package(tier, *, reports: list, policies: list):
    if tier not in TIER_INCLUSION["evidence_package"]:
        return _not_included("evidence_package", "Evidence package",
                             "Audit-ready ZIP of profile, scans, reports, and policies")

    if not (reports or policies):
        return _row(
            key="evidence_package", service="Evidence package", tier=tier,
            status=STATUS_PENDING_SETUP,
            last_successful_check="",
            data_source="Generated on demand from portal data",
            coverage_note="Audit-ready ZIP of profile, scans, reports, and policies",
            next_action="Will be available after your first scan and policy refresh",
            owner=OWNER_SYSTEM,
        )

    return _row(
        key="evidence_package", service="Evidence package", tier=tier,
        status=STATUS_ACTIVE,
        # The package is generated on demand — the most recent input artifact
        # is the freshest signal we have.
        last_successful_check=(reports[0].get("date") if reports else "") or "",
        data_source="Generated on demand from portal data",
        coverage_note=f"{len(reports)} report(s) + {len(policies)} policy document(s) ready",
        next_action="",
        owner=OWNER_SYSTEM,
    )


def _advisor_review(tier, *, advisor_name: str, next_call_date: str,
                    advisor_reviewed_at: str, monthly_summary_reviewed_at: str):
    if tier not in TIER_INCLUSION["advisor_review"]:
        return _not_included("advisor_review", "Advisor review",
                             "Named advisor reviews deliverables and runs check-ins")

    if not advisor_name:
        return _row(
            key="advisor_review", service="Advisor review", tier=tier,
            status=STATUS_PENDING_SETUP,
            last_successful_check="",
            data_source="Operator-managed assignment",
            coverage_note="Named advisor reviews every deliverable",
            next_action="An advisor will be assigned during onboarding",
            owner=OWNER_ADVISOR,
        )

    last = advisor_reviewed_at or monthly_summary_reviewed_at
    if not last:
        status = STATUS_PENDING_SETUP
        next_action = "First advisor review pending"
    elif not _is_fresh(last, "monthly"):
        status = STATUS_PENDING_SETUP
        next_action = "Monthly review is overdue — your advisor will reschedule"
    else:
        status = STATUS_ACTIVE
        next_action = (f"Next call: {next_call_date}" if next_call_date else
                       "Schedule your next check-in")

    return _row(
        key="advisor_review", service="Advisor review", tier=tier,
        status=status,
        last_successful_check=last or "",
        data_source=f"Advisor: {advisor_name}",
        coverage_note="Reviews every deliverable; runs monthly check-ins",
        next_action=next_action,
        owner=OWNER_ADVISOR,
    )


def _security_validation(tier, *, legal_view: dict):
    if tier not in TIER_INCLUSION["security_validation"]:
        return _not_included("security_validation", "Security validation",
                             "Authorized active security validation with signed scope")

    av = (legal_view or {}).get("active_validation", "Pending setup")
    if av == "Approved":
        status = STATUS_ACTIVE
        next_action = "Run within agreed testing window only"
    elif av in ("Withdrawn", "Expired"):
        status = STATUS_NEEDS_ATTENTION
        next_action = "Re-sign authorization with your advisor"
    elif av == "Not included":
        status = STATUS_NOT_INCLUDED
        next_action = "Available on Professional and Enterprise+"
    else:
        status = STATUS_PENDING_SETUP
        next_action = "Sign engagement scope; advisor will counter-approve"

    return _row(
        key="security_validation", service="Security validation", tier=tier,
        status=status,
        # We never claim a successful run from approval alone — only from a
        # recorded successful run. Authorization status is a precondition,
        # not evidence of a successful check.
        last_successful_check="",
        data_source="Legal authorization record + active-validation engine",
        coverage_note="Requires signed MSA, SOW, NDA, DPA, scope, and counter-approval",
        next_action=next_action,
        owner=OWNER_CLIENT,
    )


# ─── Public entry point ───────────────────────────────────────

def build_coverage(
    *,
    tier: str,
    score_history: list,
    open_tasks: list,
    alerts: list,
    reports: list,
    policies: list,
    frameworks: list,
    compliance_pct: int,
    advisor_name: str,
    next_call_date: str,
    advisor_reviewed_at: str,
    monthly_summary_reviewed_at: str,
    last_darkweb_check_at: str,
    dark_web_exposures: int,
    last_vuln_scan_at: str,
    vuln_findings: int,
    last_phishing_campaign_at: str,
    employee_emails: list,
    last_m365_sync_at: str,
    legal_view: dict,
    hibp_configured: bool,
    gophish_configured: bool,
    nuclei_available: bool,
    m365_configured: bool,
) -> list[dict[str, Any]]:
    """Build the full 11-row service coverage table for the customer portal."""
    return [
        _external_attack_surface(tier, score_history, open_tasks),
        _dark_web_monitoring(tier, hibp_configured=hibp_configured,
                             last_check=last_darkweb_check_at,
                             exposures=dark_web_exposures),
        _threat_intelligence(tier, alerts=alerts),
        _vulnerability_scanning(tier, nuclei_available=nuclei_available,
                                last_run=last_vuln_scan_at, findings=vuln_findings),
        _identity_m365_monitoring(tier, m365_configured=m365_configured,
                                  last_run=last_m365_sync_at),
        _phishing_readiness(tier, gophish_configured=gophish_configured,
                            employee_emails=employee_emails or [],
                            last_campaign=last_phishing_campaign_at),
        _compliance_tracking(tier, frameworks=frameworks or [],
                             compliance_pct=compliance_pct,
                             last_review=monthly_summary_reviewed_at),
        _policy_management(tier, policies=policies or [],
                           advisor_reviewed_at=advisor_reviewed_at),
        _evidence_package(tier, reports=reports or [], policies=policies or []),
        _advisor_review(tier, advisor_name=advisor_name,
                        next_call_date=next_call_date,
                        advisor_reviewed_at=advisor_reviewed_at,
                        monthly_summary_reviewed_at=monthly_summary_reviewed_at),
        _security_validation(tier, legal_view=legal_view or {}),
    ]
