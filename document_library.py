"""
Document library — canonical reports and policies for the customer portal.

Eight reports and eight policies are listed *every time* — even when the
artifact has not yet been generated — so a customer always sees the full
deliverable surface and the lifecycle state of each item.

Status vocabulary (matches Evidence Vault):
  Draft, Ready, Review pending, Advisor reviewed, Expired

Each document carries:
  business_title, kind ("report"|"policy"), type, generated_date, version,
  review_status, reviewed_by, reviewed_on, review_due_date, framework_mapping,
  download_url, present (bool)
"""
from __future__ import annotations

import re
from datetime import datetime, date, timedelta, timezone
from typing import Any, Optional


STATUS_DRAFT = "Draft"
STATUS_READY = "Ready"
STATUS_REVIEW_PENDING = "Review pending"
STATUS_ADVISOR_REVIEWED = "Advisor reviewed"
STATUS_EXPIRED = "Expired"

ALL_STATUSES = (STATUS_DRAFT, STATUS_READY, STATUS_REVIEW_PENDING,
                STATUS_ADVISOR_REVIEWED, STATUS_EXPIRED)


# ─── Canonical reports ─────────────────────────────────────────

REPORT_TEMPLATES: list[dict[str, Any]] = [
    {
        "key": "paid_diagnostic",
        "business_title": "Paid Diagnostic Report",
        "type": "Diagnostic engagement",
        "filename_patterns": [
            r"diagnostic", r"readiness[-_ ]?review", r"diagnostic[-_ ]?report",
        ],
        "frameworks_default": ["NIST CSF 2.0"],
        "review_cadence_days": None,             # one-time
        "frequency_label": "One-time engagement",
        "available_tiers": ("diagnostic", "essentials", "professional", "enterprise_plus"),
    },
    {
        "key": "security_assessment",
        "business_title": "Security Assessment Report",
        "type": "Assessment",
        "filename_patterns": [
            r"^assessment", r"security[-_ ]?assessment", r"^report[-_ ]\d",
        ],
        "frameworks_default": ["NIST CSF 2.0", "SOC 2"],
        "review_cadence_days": 365,
        "frequency_label": "Annual",
        "available_tiers": ("essentials", "professional", "enterprise_plus"),
    },
    {
        "key": "monthly_security",
        "business_title": "Monthly Security Report",
        "type": "Monthly report",
        "filename_patterns": [r"monthly"],
        "frameworks_default": ["NIST CSF 2.0"],
        "review_cadence_days": 30,
        "frequency_label": "Monthly",
        "available_tiers": ("essentials", "professional", "enterprise_plus"),
    },
    {
        "key": "compliance_progress",
        "business_title": "Compliance Progress Summary",
        "type": "Compliance summary",
        "filename_patterns": [r"compliance[-_ ]?progress", r"compliance[-_ ]?summary"],
        "frameworks_default": [],
        "review_cadence_days": 30,
        "frequency_label": "Monthly",
        "available_tiers": ("essentials", "professional", "enterprise_plus"),
    },
    {
        "key": "advisor_call_agenda",
        "business_title": "Advisor Call Agenda",
        "type": "Meeting agenda",
        "filename_patterns": [r"agenda", r"call[-_ ]?agenda"],
        "frameworks_default": [],
        "review_cadence_days": 30,
        "frequency_label": "Before each advisor call",
        "available_tiers": ("essentials", "professional", "enterprise_plus"),
    },
    {
        "key": "audit_evidence_package",
        "business_title": "Audit Evidence Package",
        "type": "Evidence bundle (ZIP)",
        "filename_patterns": [r"audit[-_ ]?package"],
        "frameworks_default": [],
        "review_cadence_days": 30,
        "frequency_label": "On demand",
        "available_tiers": ("diagnostic", "essentials", "professional", "enterprise_plus"),
    },
    {
        "key": "security_validation",
        "business_title": "Security Validation Report",
        "type": "Validation report",
        "filename_patterns": [r"validation[-_ ]?report", r"pentest[-_ ]?report"],
        "frameworks_default": ["NIST CSF 2.0", "SOC 2"],
        "review_cadence_days": 90,
        "frequency_label": "Per authorized run",
        "available_tiers": ("professional", "enterprise_plus"),
    },
    {
        "key": "qbr",
        "business_title": "Quarterly Business Review",
        "type": "Executive review",
        "filename_patterns": [r"\bqbr\b", r"quarterly[-_ ]?review", r"quarterly[-_ ]?business"],
        "frameworks_default": [],
        "review_cadence_days": 90,
        "frequency_label": "Quarterly",
        "available_tiers": ("professional", "enterprise_plus"),
    },
]


# ─── Canonical policies ────────────────────────────────────────

POLICY_TEMPLATES: list[dict[str, Any]] = [
    {
        "key": "wisp",
        "business_title": "Written Information Security Plan",
        "type": "Information security plan",
        "filename_patterns": [r"wisp", r"written[-_ ]?information[-_ ]?security"],
        "frameworks_default": ["IRS 4557", "FTC Safeguards", "NIST CSF 2.0", "GLBA"],
    },
    {
        "key": "incident_response_plan",
        "business_title": "Incident Response Plan",
        "type": "Response plan",
        "filename_patterns": [r"incident[-_ ]?response", r"\birp\b", r"ir[-_ ]?plan"],
        "frameworks_default": ["NIST CSF 2.0", "HIPAA Security Rule", "SOC 2"],
    },
    {
        "key": "access_control_policy",
        "business_title": "Access Control Policy",
        "type": "Policy",
        "filename_patterns": [r"access[-_ ]?control", r"password|\biam\b"],
        "frameworks_default": ["NIST CSF 2.0", "ISO 27001", "SOC 2", "HIPAA Security Rule"],
    },
    {
        "key": "vendor_management_policy",
        "business_title": "Vendor Management Policy",
        "type": "Policy",
        "filename_patterns": [r"vendor", r"third[-_ ]?party", r"supplier"],
        "frameworks_default": ["FTC Safeguards", "SOC 2", "ISO 27001"],
    },
    {
        "key": "data_classification_policy",
        "business_title": "Data Classification Policy",
        "type": "Policy",
        "filename_patterns": [r"data[-_ ]?classification", r"data[-_ ]?handling"],
        "frameworks_default": ["HIPAA Security Rule", "ISO 27001", "SOC 2", "GDPR"],
    },
    {
        "key": "ai_acceptable_use_policy",
        "business_title": "AI Acceptable Use Policy",
        "type": "Policy",
        "filename_patterns": [r"ai[-_ ]?acceptable", r"ai[-_ ]?use", r"ai[-_ ]?policy"],
        "frameworks_default": ["NIST AI RMF", "ISO 27001", "EU AI Act"],
    },
    {
        "key": "security_awareness_policy",
        "business_title": "Security Awareness Policy",
        "type": "Policy",
        "filename_patterns": [r"awareness", r"training"],
        "frameworks_default": ["FTC Safeguards", "HIPAA Security Rule", "NIST CSF 2.0"],
    },
    {
        "key": "business_continuity_plan",
        "business_title": "Business Continuity Plan",
        "type": "Continuity plan",
        "filename_patterns": [r"business[-_ ]?continuity", r"\bbcp\b",
                              r"disaster[-_ ]?recovery", r"\bdr[-_ ]?plan\b"],
        "frameworks_default": ["NIST CSF 2.0", "ISO 27001", "SOC 2"],
    },
]


# ─── Helpers ───────────────────────────────────────────────────

def _today() -> date:
    return date.today()


def _parse_date(s: str) -> Optional[date]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except Exception:
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d").date()
        except Exception:
            return None


def _detect_version(filename: str, fallback_date: str = "") -> str:
    if filename:
        m = re.search(r"v(\d+(?:\.\d+)*)", filename, re.I)
        if m:
            return f"v{m.group(1)}"
    if fallback_date:
        d = _parse_date(fallback_date)
        if d:
            return f"Cycle {d.strftime('%m/%Y')}"
    return "v1.0"


def _match(filename: str, patterns: list[str]) -> bool:
    name = (filename or "").lower()
    for p in patterns:
        if re.search(p, name, re.I):
            return True
    return False


def _resolve_review_status(
    *, present: bool,
    advisor_reviewed_at: str = "",
    review_due_date: Optional[date] = None,
    cadence_days: Optional[int] = None,
) -> str:
    today = _today()
    # Expiry/review-due always wins.
    if review_due_date and today > review_due_date:
        return STATUS_EXPIRED
    if not present:
        return STATUS_DRAFT
    if advisor_reviewed_at:
        # Advisor sign-off recorded — but if it's older than the cadence, the
        # next review is overdue and the document falls back to Review pending.
        d = _parse_date(advisor_reviewed_at)
        if d and cadence_days and (today - d).days > cadence_days:
            return STATUS_REVIEW_PENDING
        return STATUS_ADVISOR_REVIEWED
    return STATUS_REVIEW_PENDING


def _compute_review_due_date(
    *, generated_date: str, advisor_reviewed_at: str,
    cadence_days: Optional[int],
) -> Optional[date]:
    if cadence_days is None:
        return None
    base = _parse_date(advisor_reviewed_at) or _parse_date(generated_date)
    if not base:
        return None
    return base + timedelta(days=cadence_days)


# ─── Builders ──────────────────────────────────────────────────

def _doc(
    *, kind: str, key: str, business_title: str, type_: str,
    generated_date: str, version: str, review_status: str,
    reviewed_by: str, reviewed_on: str,
    review_due_date: Optional[date], frequency_label: str,
    framework_mapping: list, download_url: str, present: bool,
    available_in_plan: bool = True, filename: str = "",
) -> dict[str, Any]:
    return {
        "kind": kind,
        "key": key,
        "business_title": business_title,
        "type": type_,
        "generated_date": generated_date or "",
        "version": version,
        "review_status": review_status,
        "reviewed_by": reviewed_by,
        "reviewed_on": reviewed_on,
        "review_due_date": review_due_date.isoformat() if review_due_date else "",
        "frequency_label": frequency_label,
        "framework_mapping": list(framework_mapping or []),
        "download_url": download_url or "",
        "present": present,
        "available_in_plan": available_in_plan,
        "_filename": filename,
    }


def _build_report_item(template, *, client_id, reports, advisor_name,
                       monthly_summary_reviewed_at, frameworks, tier,
                       legal_view) -> dict[str, Any]:
    available = tier in template["available_tiers"]
    # Find the matching artifact, if any.
    artifact = None
    for r in reports or []:
        if _match(r.get("filename", ""), template["filename_patterns"]):
            artifact = r
            break

    filename = artifact.get("filename", "") if artifact else ""
    generated = artifact.get("date", "") if artifact else ""
    version = _detect_version(filename, generated)
    frameworks_to_use = (template["frameworks_default"]
                         or [str(f) for f in (frameworks or [])])

    # Special: compliance progress summary should reflect client frameworks.
    if template["key"] == "compliance_progress":
        frameworks_to_use = [str(f) for f in (frameworks or [])] or template["frameworks_default"]

    # Special: security validation report is only meaningful when active
    # validation is approved or has run.
    if template["key"] == "security_validation":
        av = (legal_view or {}).get("active_validation", "")
        if av not in ("Approved",):
            artifact = None
            filename = ""
            generated = ""

    review_due = _compute_review_due_date(
        generated_date=generated,
        advisor_reviewed_at=monthly_summary_reviewed_at,
        cadence_days=template["review_cadence_days"],
    )
    # For the audit-evidence package the review-due is the next monthly cycle.
    if template["key"] == "audit_evidence_package" and not review_due:
        if monthly_summary_reviewed_at:
            d = _parse_date(monthly_summary_reviewed_at)
            if d:
                review_due = d + timedelta(days=30)

    status = _resolve_review_status(
        present=bool(artifact),
        advisor_reviewed_at=monthly_summary_reviewed_at if artifact else "",
        review_due_date=review_due,
        cadence_days=template["review_cadence_days"],
    )
    if not available:
        status = STATUS_DRAFT  # rendered as "Not in plan" by the template

    download_url = ""
    if artifact and filename:
        if template["key"] == "audit_evidence_package":
            download_url = f"/portal/{client_id}/download/audit-package"
        else:
            download_url = f"/portal/{client_id}/download/reports/{filename}"

    return _doc(
        kind="report", key=template["key"],
        business_title=template["business_title"],
        type_=template["type"],
        generated_date=(generated or "")[:10],
        version=version,
        review_status=status,
        reviewed_by=advisor_name if (artifact and monthly_summary_reviewed_at) else "",
        reviewed_on=(monthly_summary_reviewed_at or "")[:10] if artifact else "",
        review_due_date=review_due,
        frequency_label=template["frequency_label"],
        framework_mapping=frameworks_to_use,
        download_url=download_url,
        present=bool(artifact),
        available_in_plan=available,
        filename=filename,
    )


def _build_policy_item(template, *, client_id, policies, advisor_name,
                       advisor_reviewed_at) -> dict[str, Any]:
    artifact = None
    for p in policies or []:
        if _match(p.get("filename", ""), template["filename_patterns"]):
            artifact = p
            break

    filename = artifact.get("filename", "") if artifact else ""
    # Generated date: use advisor_reviewed_at as a stand-in if the policy file
    # doesn't carry its own metadata. Policies are versioned by review cycle.
    generated = (artifact.get("date", "") if artifact else "") or advisor_reviewed_at
    version = _detect_version(filename, generated)

    review_due = _compute_review_due_date(
        generated_date=generated,
        advisor_reviewed_at=advisor_reviewed_at,
        cadence_days=365,
    )
    status = _resolve_review_status(
        present=bool(artifact),
        advisor_reviewed_at=advisor_reviewed_at if artifact else "",
        review_due_date=review_due,
        cadence_days=365,
    )

    download_url = ""
    if artifact and filename:
        download_url = f"/portal/{client_id}/download/policies/{filename}"

    return _doc(
        kind="policy", key=template["key"],
        business_title=template["business_title"],
        type_=template["type"],
        generated_date=(generated or "")[:10],
        version=version,
        review_status=status,
        reviewed_by=advisor_name if (artifact and advisor_reviewed_at) else "",
        reviewed_on=(advisor_reviewed_at or "")[:10] if artifact else "",
        review_due_date=review_due,
        frequency_label="Annual review",
        framework_mapping=template["frameworks_default"],
        download_url=download_url,
        present=bool(artifact),
        available_in_plan=True,
        filename=filename,
    )


# ─── Public entry point ────────────────────────────────────────

def build_library(
    *, client_id: str, tier: str,
    reports: list, policies: list,
    frameworks: list,
    advisor_name: str,
    advisor_reviewed_at: str,
    monthly_summary_reviewed_at: str,
    legal_view: dict,
    review_records: Optional[dict] = None,
) -> dict[str, Any]:
    """Return the canonical 8 reports + 8 policies, each with full lifecycle
    metadata and per-subject advisor-review metadata. Reviewed claims only
    render when a real sign-off record exists.
    """
    import advisor_review as _ar

    review_records = review_records or {}

    report_items = []
    for t in REPORT_TEMPLATES:
        item = _build_report_item(
            t, client_id=client_id, reports=reports,
            advisor_name=advisor_name,
            monthly_summary_reviewed_at=monthly_summary_reviewed_at,
            frameworks=frameworks, tier=tier,
            legal_view=legal_view,
        )
        rec = review_records.get(_ar.report_key(t["key"]), {})
        # Per-subject sign-off overrides the broad "monthly_summary_reviewed_at"
        # heuristic. If there's a real record, use its identity. If not, the
        # heuristic becomes a *pending* signal only, never a reviewed claim.
        if _ar.is_signed_off(rec):
            item["review_status"] = STATUS_ADVISOR_REVIEWED
            item["reviewed_by"] = rec["reviewed_by"]
            item["reviewed_on"] = rec["reviewed_on"]
            item["reviewer_credential"] = rec.get("reviewer_credential", "")
            item["sign_off_timestamp"] = rec.get("sign_off_timestamp", "")
            item["client_facing_recommendation"] = rec.get("client_facing_recommendation", "")
            item["advisor_notes"] = rec.get("advisor_notes", "")
            item["prepared_by"] = rec.get("prepared_by", "System")
        else:
            # Strip any heuristic-derived "reviewed" metadata when no record exists.
            item["reviewed_by"] = ""
            item["reviewed_on"] = ""
            item["reviewer_credential"] = ""
            item["sign_off_timestamp"] = ""
            item["client_facing_recommendation"] = rec.get("client_facing_recommendation", "")
            item["advisor_notes"] = rec.get("advisor_notes", "")
            item["prepared_by"] = rec.get("prepared_by", "System")
            if item["review_status"] == STATUS_ADVISOR_REVIEWED:
                item["review_status"] = STATUS_REVIEW_PENDING
        report_items.append(item)

    policy_items = []
    for t in POLICY_TEMPLATES:
        item = _build_policy_item(
            t, client_id=client_id, policies=policies,
            advisor_name=advisor_name,
            advisor_reviewed_at=advisor_reviewed_at,
        )
        rec = review_records.get(_ar.policy_key(t["key"]), {})
        if _ar.is_signed_off(rec):
            item["review_status"] = STATUS_ADVISOR_REVIEWED
            item["reviewed_by"] = rec["reviewed_by"]
            item["reviewed_on"] = rec["reviewed_on"]
            item["reviewer_credential"] = rec.get("reviewer_credential", "")
            item["sign_off_timestamp"] = rec.get("sign_off_timestamp", "")
            item["client_facing_recommendation"] = rec.get("client_facing_recommendation", "")
            item["advisor_notes"] = rec.get("advisor_notes", "")
            item["prepared_by"] = rec.get("prepared_by", "System")
        else:
            item["reviewed_by"] = ""
            item["reviewed_on"] = ""
            item["reviewer_credential"] = ""
            item["sign_off_timestamp"] = ""
            item["client_facing_recommendation"] = rec.get("client_facing_recommendation", "")
            item["advisor_notes"] = rec.get("advisor_notes", "")
            item["prepared_by"] = rec.get("prepared_by", "System")
            if item["review_status"] == STATUS_ADVISOR_REVIEWED:
                item["review_status"] = STATUS_REVIEW_PENDING
        policy_items.append(item)

    return {"reports": report_items, "policies": policy_items}
