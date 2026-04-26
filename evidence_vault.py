"""
Evidence Vault — premium audit-ready catalog for the customer portal.

Organizes everything an auditor / insurer / enterprise buyer typically asks
for into 10 named categories, each item rendered with a business title
(never a raw filename), framework mapping, status, and review metadata.

Status vocabulary (single source of truth):
  - Draft            : produced but not yet released
  - Ready            : delivered and available, no advisor review on file
  - Review pending   : delivered, advisor review in progress
  - Advisor reviewed : advisor signed off — primary trust state
  - Expired          : explicit expiry has passed
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional


# ─── Categories (display order matches the spec) ──────────────

CATEGORIES: list[tuple[str, str]] = [
    ("policies",             "Policies"),
    ("security_reports",     "Security reports"),
    ("scan_results",         "Scan results"),
    ("access_reviews",       "Access reviews"),
    ("training_phishing",    "Training & phishing records"),
    ("incident_response",    "Incident response"),
    ("vendor_compliance",    "Vendor & compliance documents"),
    ("cyber_insurance",      "Cyber insurance evidence"),
    ("security_validation",  "Security validation evidence"),
    ("legal_authorizations", "Legal authorizations"),
]

CATEGORY_ORDER = [k for k, _ in CATEGORIES]
CATEGORY_LABEL = dict(CATEGORIES)


# ─── Statuses ─────────────────────────────────────────────────

STATUS_DRAFT = "Draft"
STATUS_READY = "Ready"
STATUS_REVIEW_PENDING = "Review pending"
STATUS_ADVISOR_REVIEWED = "Advisor reviewed"
STATUS_EXPIRED = "Expired"

ALL_STATUSES = (STATUS_DRAFT, STATUS_READY, STATUS_REVIEW_PENDING,
                STATUS_ADVISOR_REVIEWED, STATUS_EXPIRED)


# ─── Title resolution: filename → business title ──────────────

_POLICY_KEYWORDS: list[tuple[re.Pattern, str, list[str]]] = [
    (re.compile(r"(?:^|[^a-z])wisp(?:[^a-z]|$)|written.information.security", re.I),
     "Written Information Security Plan",
     ["IRS 4557", "FTC Safeguards", "NIST CSF 2.0", "GLBA"]),
    (re.compile(r"(?:^|[^a-z])aup(?:[^a-z]|$)|acceptable[-_ ]?use", re.I),
     "Acceptable Use Policy",
     ["NIST CSF 2.0", "SOC 2"]),
    (re.compile(r"incident[-_ ]?response|(?:^|[^a-z])irp(?:[^a-z]|$)|ir[-_ ]?plan", re.I),
     "Incident Response Plan",
     ["NIST CSF 2.0", "HIPAA Security Rule", "SOC 2"]),
    (re.compile(r"business[-_ ]?continuity|(?:^|[^a-z])bcp(?:[^a-z]|$)|disaster[-_ ]?recovery|dr[-_ ]?plan", re.I),
     "Business Continuity & Disaster Recovery Policy",
     ["NIST CSF 2.0", "ISO 27001", "SOC 2"]),
    (re.compile(r"data[-_ ]?classification|data[-_ ]?handling", re.I),
     "Data Classification & Handling Policy",
     ["HIPAA Security Rule", "ISO 27001", "SOC 2"]),
    (re.compile(r"password|access[-_ ]?control|\biam\b", re.I),
     "Password & Access Control Policy",
     ["NIST CSF 2.0", "ISO 27001", "SOC 2"]),
    (re.compile(r"byod|mobile[-_ ]?device", re.I),
     "Mobile Device & BYOD Policy",
     ["NIST CSF 2.0", "HIPAA Security Rule"]),
    (re.compile(r"vendor|third[-_ ]?party|supplier", re.I),
     "Vendor & Third-Party Risk Policy",
     ["FTC Safeguards", "SOC 2", "ISO 27001"]),
    (re.compile(r"breach[-_ ]?notification|breach[-_ ]?response", re.I),
     "Breach Notification Policy",
     ["HIPAA Security Rule", "State Privacy Laws", "GDPR"]),
    (re.compile(r"encryption|crypto", re.I),
     "Encryption & Key Management Policy",
     ["HIPAA Security Rule", "ISO 27001", "FTC Safeguards"]),
    (re.compile(r"backup|retention", re.I),
     "Backup & Retention Policy",
     ["NIST CSF 2.0", "ISO 27001", "SOC 2"]),
    (re.compile(r"training|awareness", re.I),
     "Security Awareness Training Policy",
     ["NIST CSF 2.0", "FTC Safeguards", "HIPAA Security Rule"]),
]


def _humanize_policy(filename: str) -> tuple[str, list[str]]:
    """Map a policy filename to (business_title, framework_mapping)."""
    name = filename.lower()
    for pattern, title, frameworks in _POLICY_KEYWORDS:
        if pattern.search(name):
            return title, frameworks
    # Fallback: title-case the basename and apply general framework hint.
    base = re.sub(r"\.[a-z0-9]+$", "", filename, flags=re.I)
    base = re.sub(r"[_\-]+", " ", base).strip().title()
    return f"{base} Policy", ["NIST CSF 2.0"]


def _humanize_report(filename: str, *, scan_date_hint: str = "") -> str:
    name = filename.lower()
    if "monthly" in name:
        # Extract YYYY-MM from filename if present.
        m = re.search(r"(\d{4})[-_]?(\d{2})", name)
        if m:
            try:
                dt = datetime(int(m.group(1)), int(m.group(2)), 1)
                return f"Monthly Security Report — {dt.strftime('%B %Y')}"
            except Exception:
                pass
        return "Monthly Security Report"
    if "audit" in name and "package" in name:
        return "Audit Evidence Package"
    if "executive" in name or "exec" in name:
        return "Executive Summary"
    if "diagnostic" in name or "readiness" in name:
        return "Readiness Review Report"
    # Default
    base = re.sub(r"\.[a-z0-9]+$", "", filename, flags=re.I)
    base = re.sub(r"[_\-]+", " ", base).strip().title()
    return f"Security Assessment Report — {base}"


def _humanize_scan(filename: str) -> str:
    name = filename.lower()
    m = re.search(r"(\d{4})[-_](\d{2})[-_](\d{2})", name)
    suffix = ""
    if "initial" in name:
        suffix = "Initial"
    elif "monthly" in name:
        suffix = "Monthly cycle"
    elif "weekly" in name:
        suffix = "Weekly cycle"
    elif "vuln" in name:
        suffix = "Vulnerability scan"
    if m:
        try:
            dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            label = f"External Scan — {dt.strftime('%B %d, %Y')}"
            return f"{label} ({suffix})" if suffix else label
        except Exception:
            pass
    return f"External Scan{(' — ' + suffix) if suffix else ''}"


def _detect_version(filename: str, fallback_date: str = "") -> str:
    m = re.search(r"v(\d+(?:\.\d+)*)", filename, re.I)
    if m:
        return f"v{m.group(1)}"
    if fallback_date:
        try:
            dt = datetime.strptime(fallback_date[:10], "%Y-%m-%d")
            return f"Cycle {dt.strftime('%m/%Y')}"
        except Exception:
            pass
    return "v1.0"


# ─── Item builder ─────────────────────────────────────────────

def _item(
    *, idx: int, category: str, business_title: str, type_: str,
    date: str = "", version: str = "v1.0",
    status: str = STATUS_READY,
    framework_mapping: Optional[list] = None,
    uploaded_by: str = "System",
    reviewed_by: str = "", reviewed_on: str = "",
    download_url: str = "", filename: str = "",
) -> dict[str, Any]:
    return {
        "id": f"evp_{idx:04d}",
        "category": category,
        "category_label": CATEGORY_LABEL.get(category, category),
        "business_title": business_title,
        "type": type_,
        "date": date or "",
        "version": version,
        "status": status,
        "framework_mapping": list(framework_mapping or []),
        "uploaded_by": uploaded_by,
        "reviewed_by": reviewed_by,
        "reviewed_on": reviewed_on,
        "download_url": download_url,
        # Filename is operator metadata only — the UI must never use it as the
        # primary customer-facing label.
        "_filename": filename,
    }


def _resolve_status(
    *, advisor_reviewed_at: str,
    fallback: str = STATUS_READY,
    expires_at: str = "",
) -> str:
    if expires_at:
        try:
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                return STATUS_EXPIRED
        except Exception:
            pass
    if advisor_reviewed_at:
        return STATUS_ADVISOR_REVIEWED
    return fallback


# ─── Per-category builders ────────────────────────────────────

def _build_policies(client_id, policies, advisor_reviewed_at, advisor_name, idx_start):
    items = []
    for i, p in enumerate(policies or []):
        fname = p.get("filename", "")
        title, frameworks = _humanize_policy(fname)
        date_str = p.get("date", "") or advisor_reviewed_at[:10]
        items.append(_item(
            idx=idx_start + i, category="policies",
            business_title=title, type_="Policy",
            date=date_str[:10] if date_str else "",
            version=_detect_version(fname, date_str),
            status=_resolve_status(advisor_reviewed_at=advisor_reviewed_at,
                                   fallback=STATUS_REVIEW_PENDING),
            framework_mapping=frameworks,
            uploaded_by=f"Advisor — {advisor_name}" if advisor_name else "System",
            reviewed_by=advisor_name if advisor_reviewed_at else "",
            reviewed_on=advisor_reviewed_at[:10] if advisor_reviewed_at else "",
            download_url=f"/portal/{client_id}/download/policies/{fname}",
            filename=fname,
        ))
    return items


def _build_security_reports(client_id, reports, monthly_summary_reviewed_at,
                            advisor_name, idx_start, frameworks_for_client):
    items = []
    for i, r in enumerate(reports or []):
        fname = r.get("filename", "")
        title = _humanize_report(fname, scan_date_hint=r.get("date", ""))
        date_str = r.get("date", "")
        items.append(_item(
            idx=idx_start + i, category="security_reports",
            business_title=title, type_="Security report",
            date=(date_str or "")[:10],
            version=_detect_version(fname, date_str),
            status=_resolve_status(
                advisor_reviewed_at=monthly_summary_reviewed_at,
                fallback=STATUS_READY),
            framework_mapping=list(frameworks_for_client or []) or ["NIST CSF 2.0"],
            uploaded_by="System",
            reviewed_by=advisor_name if monthly_summary_reviewed_at else "",
            reviewed_on=monthly_summary_reviewed_at[:10]
                        if monthly_summary_reviewed_at else "",
            download_url=f"/portal/{client_id}/download/reports/{fname}",
            filename=fname,
        ))
    return items


def _build_scan_results(client_id, scans, idx_start):
    items = []
    for i, s in enumerate(scans or []):
        fname = s.get("filename", "")
        title = _humanize_scan(fname)
        date_str = s.get("date", "")
        items.append(_item(
            idx=idx_start + i, category="scan_results",
            business_title=title, type_="Scan artifact",
            date=(date_str or "")[:10],
            version=_detect_version(fname, date_str),
            status=STATUS_READY,
            framework_mapping=["NIST CSF 2.0"],
            uploaded_by="System",
            reviewed_by="", reviewed_on="",
            # Scans live in the operator-only download path — surface the
            # advisor's reviewed report instead. We still expose the artifact
            # via the audit package, never as a raw scan_data.json link.
            download_url="",
            filename=fname,
        ))
    return items


def _build_access_reviews(client_id, m365_configured, last_m365_sync_at,
                          advisor_name, idx_start):
    if not m365_configured:
        return []
    return [_item(
        idx=idx_start, category="access_reviews",
        business_title="Microsoft 365 Access Review",
        type_="Access review",
        date=(last_m365_sync_at or "")[:10],
        version=_detect_version("", last_m365_sync_at),
        status=STATUS_READY if last_m365_sync_at else STATUS_DRAFT,
        framework_mapping=["NIST CSF 2.0", "SOC 2", "HIPAA Security Rule"],
        uploaded_by="System",
        reviewed_by="", reviewed_on="",
        download_url="",
        filename="",
    )]


def _build_training_phishing(client_id, alerts, last_phishing_campaign_at,
                             advisor_name, idx_start):
    items = []
    phishing_alerts = [a for a in (alerts or []) if a.get("type") == "phishing"]
    for i, a in enumerate(phishing_alerts):
        date = (a.get("date", "") or "")[:10]
        items.append(_item(
            idx=idx_start + i, category="training_phishing",
            business_title=f"Phishing Simulation — {date}" if date else "Phishing Simulation",
            type_="Phishing campaign report",
            date=date, version=_detect_version("", date),
            status=STATUS_READY,
            framework_mapping=["FTC Safeguards", "HIPAA Security Rule",
                               "NIST CSF 2.0"],
            uploaded_by="System",
            reviewed_by=advisor_name if advisor_name else "",
            reviewed_on=date,
            download_url="",
            filename="",
        ))
    if not items and last_phishing_campaign_at:
        items.append(_item(
            idx=idx_start, category="training_phishing",
            business_title="Phishing Simulation — Most Recent Cycle",
            type_="Phishing campaign report",
            date=(last_phishing_campaign_at or "")[:10],
            version=_detect_version("", last_phishing_campaign_at),
            status=STATUS_READY,
            framework_mapping=["FTC Safeguards", "NIST CSF 2.0"],
            uploaded_by="System",
            reviewed_by="", reviewed_on="",
            download_url="",
            filename="",
        ))
    return items


def _build_incident_response(client_id, alerts, idx_start):
    """Static incident-response playbooks are always part of the deliverable
    set; we present them as evidence of preparedness even when no incidents
    have occurred."""
    items = [
        _item(idx=idx_start, category="incident_response",
              business_title="Business Email Compromise Playbook",
              type_="Runbook", date="", version="v1.0",
              status=STATUS_READY,
              framework_mapping=["NIST CSF 2.0", "FTC Safeguards"],
              uploaded_by="System", reviewed_by="", reviewed_on="",
              download_url="", filename=""),
        _item(idx=idx_start + 1, category="incident_response",
              business_title="Ransomware Response Playbook",
              type_="Runbook", date="", version="v1.0",
              status=STATUS_READY,
              framework_mapping=["NIST CSF 2.0", "HIPAA Security Rule"],
              uploaded_by="System", reviewed_by="", reviewed_on="",
              download_url="", filename=""),
        _item(idx=idx_start + 2, category="incident_response",
              business_title="Data Breach Notification Playbook",
              type_="Runbook", date="", version="v1.0",
              status=STATUS_READY,
              framework_mapping=["State Privacy Laws", "HIPAA Security Rule",
                                 "GDPR"],
              uploaded_by="System", reviewed_by="", reviewed_on="",
              download_url="", filename=""),
    ]
    # Real incident records, if any.
    incidents = [a for a in (alerts or []) if a.get("type") == "incident"]
    for i, a in enumerate(incidents):
        date = (a.get("date", "") or "")[:10]
        items.append(_item(
            idx=idx_start + len(items) + i, category="incident_response",
            business_title=f"Incident Record — {a.get('title', 'Untitled')}",
            type_="Incident record",
            date=date, version=_detect_version("", date),
            status=STATUS_READY,
            framework_mapping=["NIST CSF 2.0", "HIPAA Security Rule"],
            uploaded_by="System",
            reviewed_by="", reviewed_on="",
            download_url="", filename="",
        ))
    return items


def _build_vendor_compliance(client_id, frameworks, compliance_pct,
                             monthly_summary_reviewed_at, advisor_name, idx_start):
    if not frameworks:
        return []
    items = [_item(
        idx=idx_start, category="vendor_compliance",
        business_title="Vendor Due-Diligence Response Pack",
        type_="Compliance package",
        date=(monthly_summary_reviewed_at or "")[:10],
        version=_detect_version("", monthly_summary_reviewed_at),
        status=_resolve_status(
            advisor_reviewed_at=monthly_summary_reviewed_at,
            fallback=STATUS_REVIEW_PENDING),
        framework_mapping=[str(f) for f in frameworks],
        uploaded_by="System",
        reviewed_by=advisor_name if monthly_summary_reviewed_at else "",
        reviewed_on=(monthly_summary_reviewed_at or "")[:10],
        download_url="",
        filename="",
    )]
    items.append(_item(
        idx=idx_start + 1, category="vendor_compliance",
        business_title=f"Compliance Posture Snapshot — {compliance_pct}% mapped",
        type_="Compliance snapshot",
        date=(monthly_summary_reviewed_at or "")[:10],
        version=_detect_version("", monthly_summary_reviewed_at),
        status=_resolve_status(
            advisor_reviewed_at=monthly_summary_reviewed_at,
            fallback=STATUS_READY),
        framework_mapping=[str(f) for f in frameworks],
        uploaded_by="System",
        reviewed_by=advisor_name if monthly_summary_reviewed_at else "",
        reviewed_on=(monthly_summary_reviewed_at or "")[:10],
        download_url="",
        filename="",
    ))
    return items


def _build_cyber_insurance(client_id, reports, policies, advisor_name,
                           advisor_reviewed_at, idx_start):
    items = []
    has_evidence = bool(reports) and bool(policies)
    items.append(_item(
        idx=idx_start, category="cyber_insurance",
        business_title="Cyber Insurance Readiness Letter",
        type_="Insurance letter",
        date=(advisor_reviewed_at or "")[:10],
        version=_detect_version("", advisor_reviewed_at),
        status=(_resolve_status(advisor_reviewed_at=advisor_reviewed_at,
                                fallback=STATUS_READY)
                if has_evidence else STATUS_DRAFT),
        framework_mapping=["FTC Safeguards", "NIST CSF 2.0"],
        uploaded_by=f"Advisor — {advisor_name}" if advisor_name else "System",
        reviewed_by=advisor_name if advisor_reviewed_at else "",
        reviewed_on=(advisor_reviewed_at or "")[:10],
        download_url="",
        filename="",
    ))
    if has_evidence:
        items.append(_item(
            idx=idx_start + 1, category="cyber_insurance",
            business_title="Insurer Underwriting Evidence Bundle",
            type_="Insurance evidence package",
            date=(advisor_reviewed_at or "")[:10],
            version=_detect_version("", advisor_reviewed_at),
            status=_resolve_status(advisor_reviewed_at=advisor_reviewed_at,
                                   fallback=STATUS_READY),
            framework_mapping=["FTC Safeguards", "NIST CSF 2.0"],
            uploaded_by="System",
            reviewed_by=advisor_name if advisor_reviewed_at else "",
            reviewed_on=(advisor_reviewed_at or "")[:10],
            download_url=f"/portal/{client_id}/download/audit-package",
            filename="audit-package.zip",
        ))
    return items


def _build_security_validation(client_id, legal_view, authorization_audit,
                               idx_start):
    items = []
    av = (legal_view or {}).get("active_validation", "")
    if av in ("Approved", "Review pending", "Pending setup", "Withdrawn", "Expired"):
        items.append(_item(
            idx=idx_start, category="security_validation",
            business_title="Active Security Validation Authorization",
            type_="Authorization document",
            date="",
            version="v1.0",
            status=(STATUS_ADVISOR_REVIEWED if av == "Approved"
                    else STATUS_REVIEW_PENDING if av == "Review pending"
                    else STATUS_EXPIRED if av == "Expired"
                    else STATUS_DRAFT),
            framework_mapping=["NIST CSF 2.0", "SOC 2"],
            uploaded_by="Operator",
            reviewed_by="", reviewed_on="",
            download_url="", filename="",
        ))
    # Validation activity records (gate checks, runs).
    runs = [e for e in (authorization_audit or [])
            if "active_validation" in (e.get("event", "") or "")]
    for i, e in enumerate(runs[:10]):
        date = (e.get("at", "") or "")[:10]
        title_map = {
            "active_validation_started": "Validation Run Authorization Check",
            "active_validation_gate_check": "Validation Gate Check",
            "active_validation_signed_by_customer": "Customer Signature on Validation Scope",
            "active_validation_approved": "Operator Counter-Approval of Validation Scope",
            "active_validation_revoked": "Validation Authorization Revoked",
        }
        title = title_map.get(e.get("event", ""),
                              "Validation Authorization Event")
        items.append(_item(
            idx=idx_start + 1 + i, category="security_validation",
            business_title=f"{title} — {date}" if date else title,
            type_="Validation activity record",
            date=date, version="v1.0",
            status=STATUS_READY,
            framework_mapping=["NIST CSF 2.0"],
            uploaded_by="System",
            reviewed_by="", reviewed_on="",
            download_url="", filename="",
        ))
    return items


def _build_legal_authorizations(client_id, legal_view, idx_start):
    docs = (legal_view or {}).get("documents", {}) or {}
    label_map = {
        "msa": "Master Services Agreement",
        "sow": "Statement of Work",
        "nda": "Mutual Non-Disclosure Agreement",
        "dpa": "Data Processing Agreement",
    }
    items = []
    for i, (key, label) in enumerate(label_map.items()):
        state = docs.get(key, "Pending setup")
        if state == "Signed":
            status = STATUS_ADVISOR_REVIEWED
        elif state in ("Review pending",):
            status = STATUS_REVIEW_PENDING
        elif state == "Expired":
            status = STATUS_EXPIRED
        elif state == "Withdrawn":
            status = STATUS_EXPIRED
        else:
            status = STATUS_DRAFT
        items.append(_item(
            idx=idx_start + i, category="legal_authorizations",
            business_title=label,
            type_="Legal agreement",
            date="",
            version="v1.0",
            status=status,
            framework_mapping=[],
            uploaded_by="Operator",
            reviewed_by="", reviewed_on="",
            download_url="", filename="",
        ))
    # Authorized representative + ownership confirmations
    if (legal_view or {}).get("authorized_representative_recorded"):
        items.append(_item(
            idx=idx_start + len(items), category="legal_authorizations",
            business_title="Authorized Representative on File",
            type_="Authorization record",
            date="", version="v1.0",
            status=STATUS_READY,
            framework_mapping=[],
            uploaded_by="Operator",
            reviewed_by="", reviewed_on="",
            download_url="", filename="",
        ))
    if (legal_view or {}).get("ownership_confirmed"):
        items.append(_item(
            idx=idx_start + len(items), category="legal_authorizations",
            business_title="Domain & System Ownership Confirmation",
            type_="Authorization record",
            date="", version="v1.0",
            status=STATUS_READY,
            framework_mapping=[],
            uploaded_by="Operator",
            reviewed_by="", reviewed_on="",
            download_url="", filename="",
        ))
    return items


# ─── Public entry point ───────────────────────────────────────

def build_vault(
    *,
    client_id: str,
    policies: list,
    reports: list,
    scans: list,
    alerts: list,
    frameworks: list,
    compliance_pct: int,
    advisor_name: str,
    advisor_reviewed_at: str,
    monthly_summary_reviewed_at: str,
    last_phishing_campaign_at: str,
    last_m365_sync_at: str,
    m365_configured: bool,
    legal_view: dict,
    authorization_audit: list,
    review_records: Optional[dict] = None,
) -> dict[str, Any]:
    """Return the categorized evidence catalog plus a flat lookup table.

    Shape:
      {
        "categories": [
            {"key": ..., "label": ..., "items": [...], "count": N,
             "empty_state": "..." or ""},
            ... 10 entries in display order ...
        ],
        "by_id": {evp_id: item},
      }
    """
    idx = 1
    # Build per category, tracking the running index for stable IDs.
    cat_items: dict[str, list] = {k: [] for k, _ in CATEGORIES}

    cat_items["policies"] = _build_policies(
        client_id, policies, advisor_reviewed_at, advisor_name, idx)
    idx += len(cat_items["policies"])

    cat_items["security_reports"] = _build_security_reports(
        client_id, reports, monthly_summary_reviewed_at, advisor_name, idx,
        frameworks)
    idx += len(cat_items["security_reports"])

    cat_items["scan_results"] = _build_scan_results(client_id, scans, idx)
    idx += len(cat_items["scan_results"])

    cat_items["access_reviews"] = _build_access_reviews(
        client_id, m365_configured, last_m365_sync_at, advisor_name, idx)
    idx += len(cat_items["access_reviews"])

    cat_items["training_phishing"] = _build_training_phishing(
        client_id, alerts, last_phishing_campaign_at, advisor_name, idx)
    idx += len(cat_items["training_phishing"])

    cat_items["incident_response"] = _build_incident_response(
        client_id, alerts, idx)
    idx += len(cat_items["incident_response"])

    cat_items["vendor_compliance"] = _build_vendor_compliance(
        client_id, frameworks, compliance_pct, monthly_summary_reviewed_at,
        advisor_name, idx)
    idx += len(cat_items["vendor_compliance"])

    cat_items["cyber_insurance"] = _build_cyber_insurance(
        client_id, reports, policies, advisor_name, advisor_reviewed_at, idx)
    idx += len(cat_items["cyber_insurance"])

    cat_items["security_validation"] = _build_security_validation(
        client_id, legal_view, authorization_audit, idx)
    idx += len(cat_items["security_validation"])

    cat_items["legal_authorizations"] = _build_legal_authorizations(
        client_id, legal_view, idx)
    idx += len(cat_items["legal_authorizations"])

    empty_states = {
        "policies":             "Your policy library is being assembled — your advisor is drafting now.",
        "security_reports":     "Your first security report will appear after the next scheduled scan.",
        "scan_results":         "Scan artifacts will appear here after the next scheduled cycle.",
        "access_reviews":       "Connect Microsoft 365 to enable access reviews.",
        "training_phishing":    "Phishing simulations are part of Professional and above.",
        "incident_response":    "Standard playbooks are always available — your advisor will customize on engagement.",
        "vendor_compliance":    "Complete onboarding to generate your first compliance package.",
        "cyber_insurance":      "Insurance-ready evidence is generated after your first cycle of scans and policies.",
        "security_validation":  "Active validation evidence appears after your first authorized run.",
        "legal_authorizations": "Engagement documents appear here as they are signed.",
    }

    categories_list = []
    for key, label in CATEGORIES:
        items = cat_items.get(key, [])
        categories_list.append({
            "key": key,
            "label": label,
            "items": items,
            "count": len(items),
            "empty_state": "" if items else empty_states.get(key, ""),
        })

    # Apply per-subject advisor-review records to vault items where applicable.
    # Static "Advisor reviewed" claims are removed unless a sign-off exists.
    # Categories whose status is sourced from legal_view (legal_authorizations,
    # security_validation) are NOT subject to the advisor-review override —
    # legal sign-offs are tracked separately.
    review_records = review_records or {}
    import advisor_review as _ar
    REVIEW_OVERRIDE_CATEGORIES = {
        "policies", "security_reports", "cyber_insurance",
        "training_phishing", "vendor_compliance",
    }
    for items in cat_items.values():
        for it in items:
            cat = it.get("category")
            if cat not in REVIEW_OVERRIDE_CATEGORIES:
                # Categories driven by separate authoritative sources.
                continue
            subject = None
            fname = it.get("_filename", "") or ""
            if cat == "policies":
                # Try to recover the canonical policy key from the filename.
                stem = fname.lower()
                guessed = None
                for k in ("wisp", "incident", "access", "vendor",
                          "data", "ai_", "awareness", "continuity"):
                    if k in stem:
                        guessed = {
                            "wisp": "wisp",
                            "incident": "incident_response_plan",
                            "access": "access_control_policy",
                            "vendor": "vendor_management_policy",
                            "data": "data_classification_policy",
                            "ai_": "ai_acceptable_use_policy",
                            "awareness": "security_awareness_policy",
                            "continuity": "business_continuity_plan",
                        }[k]
                        break
                if guessed:
                    subject = _ar.policy_key(guessed)
            elif cat == "security_reports":
                stem = fname.lower()
                if "monthly" in stem:
                    subject = _ar.report_key("monthly_security")
                elif "audit" in stem and "package" in stem:
                    subject = _ar.report_key("audit_evidence_package")
                elif "qbr" in stem or "quarterly" in stem:
                    subject = _ar.report_key("qbr")
                elif "validation" in stem:
                    subject = _ar.report_key("security_validation")
            elif cat == "cyber_insurance" and "audit-package" in fname.lower():
                subject = _ar.report_key("audit_evidence_package")

            rec = review_records.get(subject, {}) if subject else {}
            if _ar.is_signed_off(rec):
                it["status"] = STATUS_ADVISOR_REVIEWED
                it["reviewed_by"] = rec.get("reviewed_by", "")
                it["reviewed_on"] = rec.get("reviewed_on", "")
                it["reviewer_credential"] = rec.get("reviewer_credential", "")
                it["client_facing_recommendation"] = rec.get("client_facing_recommendation", "")
                it["advisor_notes"] = rec.get("advisor_notes", "")
                it["prepared_by"] = rec.get("prepared_by", it.get("uploaded_by", "System"))
            else:
                # Static reviewed claims are removed when no sign-off exists.
                if it.get("status") == STATUS_ADVISOR_REVIEWED:
                    it["status"] = STATUS_REVIEW_PENDING
                it["reviewed_by"] = ""
                it["reviewed_on"] = ""
                it["reviewer_credential"] = ""
                it["client_facing_recommendation"] = rec.get("client_facing_recommendation", "")
                it["advisor_notes"] = rec.get("advisor_notes", "")
                it["prepared_by"] = rec.get("prepared_by", it.get("uploaded_by", "System"))

    by_id = {}
    for items in cat_items.values():
        for it in items:
            by_id[it["id"]] = it

    return {"categories": categories_list, "by_id": by_id}
