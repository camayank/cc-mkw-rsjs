"""
Operator delivery console.

Aggregates 14 per-client signals into a single row + classifies each row
into the seven filter buckets. Backs the premium operator dashboard.

Signals per client:
  - tier / annual_value / is_high_value
  - is_qualified  (from qualification.py records)
  - authorization_status  (from legal_authorization)
  - setup_completeness_pct + setup_missing list
  - pending_advisor_reviews count
  - open_critical_risks count
  - reports_due count
  - evidence_packages_due count
  - security_validations_due count
  - payment_status
  - next_call_date
  - last_client_activity
  - health_score (0-100) + health_label

Filter buckets:
  needs_attention | review_pending | setup_incomplete |
  high_risk | renewal_risk | high_value_client | authorization_missing
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

import legal_authorization as _legal


def _cm():
    """Lazy-resolve client_manager so we always pick up the currently-imported
    instance (test fixtures rebind CLIENTS_DIR per-test)."""
    import client_manager as _client_manager
    return _client_manager


# ─── Helpers ──────────────────────────────────────────────────

def _data_root() -> Path:
    return Path(os.getenv("DATA_DIR", ".")) / "clients"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(s: str) -> Optional[datetime]:
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
            d = datetime.strptime(s[:10], "%Y-%m-%d")
            return d.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _days_since(s: str) -> Optional[int]:
    d = _parse(s)
    if not d:
        return None
    return (_now() - d).days


# ─── Per-signal extractors ───────────────────────────────────

def _qualified(client_id: str, profile: dict) -> bool:
    """A client is qualified when a qualification.py record with
    status='qualified' exists. Operator-managed clients without a
    qualification submission default to True (they were qualified manually)."""
    qroot = Path(os.getenv("DATA_DIR", ".")) / "qualifications"
    if not qroot.exists():
        return True
    domain = (profile.get("domain") or "").lower()
    for f in qroot.glob("*.json"):
        try:
            rec = json.loads(f.read_text())
            sub = rec.get("submission") or {}
            if (sub.get("domain", "") or "").lower() == domain:
                return rec.get("result", {}).get("status") == "qualified"
        except Exception:
            continue
    return True


def _authorization_state(client_id: str, tier_cfg: dict) -> tuple[str, bool]:
    """Returns (status_label, missing).

    "missing" means: the tier expects an active-validation authorization
    AND the customer's authorization is not yet approved. Diagnostic and
    Essentials tiers do not include active validation, so an absent record
    is correct — not "missing" — for them."""
    requires_active = bool(tier_cfg.get("active_validation_included"))
    raw = _cm().get_legal_authorization(client_id)
    if not raw:
        return ("Not scoped", requires_active)
    record = _legal.from_dict(raw)
    av = record.active_validation
    status_map = {
        "not_required": "Not required",
        "draft": "Draft",
        "pending_customer_signature": "Pending customer signature",
        "pending_operator_review": "Pending operator review",
        "approved": "Approved",
        "expired": "Expired",
        "withdrawn": "Withdrawn",
        "rejected": "Rejected",
    }
    label = status_map.get(av.status, av.status)
    if requires_active:
        missing = av.status != "approved"
    else:
        missing = av.status not in ("approved", "not_required")
    return (label, missing)


def _setup_completeness(profile: dict) -> tuple[int, list[str]]:
    """Score 0-100 across integrations + onboarding metadata."""
    items: list[tuple[str, bool]] = [
        ("HIBP key", bool(os.getenv("HIBP_API_KEY"))),
        ("GoPhish", bool(os.getenv("GOPHISH_API_KEY") and os.getenv("GOPHISH_URL"))),
        ("Vulnerability scanner", _which("nuclei")),
        ("M365 credentials", bool(os.getenv("MS_TENANT_ID") and os.getenv("MS_CLIENT_ID")
                                   and os.getenv("MS_CLIENT_SECRET"))),
        ("Frameworks selected", bool(profile.get("frameworks"))),
        ("Tech stack profile", bool(profile.get("tech_stack"))),
        ("Employee email list", bool(profile.get("employee_emails"))),
        ("Named advisor assigned", bool(profile.get("advisor_name"))),
    ]
    pct = round(100 * sum(1 for _, ok in items if ok) / max(len(items), 1))
    missing = [name for name, ok in items if not ok]
    return (pct, missing)


def _which(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None


def _pending_advisor_reviews(client_id: str) -> int:
    """Count subjects where a draft/in_review record exists OR where an
    artifact is on disk but no signed-off review record exists."""
    try:
        import advisor_review as _ar
    except Exception:
        return 0
    reviews = _ar.list_reviews(client_id)
    pending = 0
    for rec in reviews.values():
        if not _ar.is_signed_off(rec):
            pending += 1
    return pending


def _open_critical_risks(client_id: str) -> int:
    tasks = _cm().get_tasks(client_id)
    open_critical = 0
    for t in tasks:
        if t.get("status") in (_cm().TASK_STATUS_OPEN,
                                _cm().TASK_STATUS_IN_PROGRESS,
                                _cm().TASK_STATUS_SUBMITTED):
            if (t.get("severity", "") or "").upper() == "CRITICAL":
                open_critical += 1
    return open_critical


def _reports_due(client_id: str, profile: dict) -> int:
    """Count canonical reports whose review_due_date has passed."""
    today = _now().date()
    try:
        import document_library as _dl
        import advisor_review as _ar
        reviews = _ar.list_reviews(client_id)
    except Exception:
        return 0
    legal_view = _legal.to_customer_view(_legal.from_dict(
        _cm().get_legal_authorization(client_id)
        or {"client_id": client_id}
    ))
    lib = _dl.build_library(
        client_id=client_id,
        tier=_cm().normalize_tier(profile.get("tier", "diagnostic")),
        reports=_cm().get_reports(client_id),
        policies=_cm().get_policies(client_id),
        frameworks=profile.get("frameworks", []),
        advisor_name=profile.get("advisor_name", ""),
        advisor_reviewed_at=profile.get("advisor_reviewed_at", ""),
        monthly_summary_reviewed_at=profile.get("monthly_summary_reviewed_at", ""),
        legal_view=legal_view,
        review_records=reviews,
    )
    due = 0
    for r in lib["reports"]:
        if not r.get("available_in_plan"):
            continue
        rdd = r.get("review_due_date") or ""
        if rdd:
            try:
                rdd_date = datetime.strptime(rdd[:10], "%Y-%m-%d").date()
                if rdd_date < today:
                    due += 1
            except Exception:
                pass
    return due


def _evidence_packages_due(client_id: str, profile: dict) -> int:
    """Number of monthly cycles since the last evidence package was reviewed."""
    msr = profile.get("monthly_summary_reviewed_at", "")
    if not msr:
        # No reviewed package on file → at least one due.
        return 1
    days = _days_since(msr) or 0
    if days <= 35:
        return 0
    # Roughly one missed evidence cycle per 30 days.
    return max(1, days // 30)


def _security_validations_due(client_id: str) -> int:
    """Engagements that are scheduled, running, in advisor review, or in
    remediation/retest awaiting closure — anything operator owes attention."""
    try:
        import security_validation as _sv
    except Exception:
        return 0
    engagements = _sv.list_engagements(client_id)
    open_states = {
        _sv.SCHEDULED, _sv.RUNNING, _sv.STOPPED,
        _sv.ADVISOR_REVIEW_PENDING, _sv.REMEDIATION_IN_PROGRESS,
    }
    return sum(1 for e in engagements if e.get("status") in open_states)


def _last_client_activity(client_id: str, profile: dict) -> str:
    """Most recent of: task update, alert date, score history, call notes."""
    candidates: list[str] = []
    for t in _cm().get_tasks(client_id):
        candidates.append(t.get("updated_at", ""))
        candidates.append(t.get("submitted_at", ""))
    sh = profile.get("score_history", []) or []
    if sh:
        candidates.append((sh[-1] or {}).get("date", ""))
    candidates.append(profile.get("last_login_at", ""))
    notes_path = _cm()._client_dir(client_id) / "call_notes.json"
    if notes_path.exists():
        try:
            notes = json.loads(notes_path.read_text())
            if notes:
                candidates.append((notes[-1] or {}).get("date", ""))
        except Exception:
            pass
    candidates = [c for c in candidates if c]
    if not candidates:
        return ""
    parsed = [(_parse(c), c) for c in candidates]
    parsed = [(d, raw) for d, raw in parsed if d]
    if not parsed:
        return ""
    return max(parsed, key=lambda p: p[0])[1]


def _payment_status(profile: dict) -> str:
    return (profile.get("payment_status") or "none").lower()


def _health_score(*, current_score: int, compliance_pct: int,
                   open_critical: int, advisor_pending: int,
                   payment_status: str, last_activity_iso: str) -> tuple[int, str]:
    """0-100 composite health score, anchored at 50 with adjustments."""
    score = 50.0
    # Security score: ±30 around baseline (60% weight on the deviation from 50).
    score += ((current_score or 0) - 50) * 0.6
    # Compliance: only adjusts when actually measured.
    if (compliance_pct or 0) > 0:
        score += (compliance_pct - 50) * 0.2
    # Penalties.
    score -= min(open_critical * 5, 15)
    score -= min(advisor_pending * 2, 10)
    if payment_status == "overdue":
        score -= 10
    elif payment_status == "none":
        score -= 3
    elif payment_status == "paid":
        score += 5
    days = _days_since(last_activity_iso) if last_activity_iso else None
    if days is None:
        score -= 5
    elif days > 60:
        score -= 10
    elif days > 30:
        score -= 4
    elif days <= 14:
        score += 5
    score = max(0, min(100, round(score)))
    if score >= 75:
        label = "Healthy"
    elif score >= 50:
        label = "Watch"
    elif score >= 30:
        label = "At risk"
    else:
        label = "Critical"
    return score, label


# ─── Builder ──────────────────────────────────────────────────

def build_row(client_id: str) -> Optional[dict[str, Any]]:
    profile = _cm().get_client(client_id)
    if not profile:
        return None

    tier = _cm().normalize_tier(profile.get("tier", "diagnostic"))
    tier_cfg = _cm().get_tier_config(tier)
    annual_value = _cm().annual_revenue_for_tier(tier)
    is_high_value = tier in ("professional", "enterprise_plus")

    is_qualified = _qualified(client_id, profile)
    auth_label, auth_missing = _authorization_state(client_id, tier_cfg)
    setup_pct, setup_missing = _setup_completeness(profile)
    advisor_pending = _pending_advisor_reviews(client_id)
    critical = _open_critical_risks(client_id)
    reports_due = _reports_due(client_id, profile)
    evidence_due = _evidence_packages_due(client_id, profile)
    validations_due = _security_validations_due(client_id)
    payment = _payment_status(profile)
    next_call = profile.get("next_call_date", "")
    last_activity = _last_client_activity(client_id, profile)

    # Compliance %
    compliance_pct = 0
    try:
        if profile.get("frameworks"):
            from agents.guardian_agent import GuardianAgent
            guardian = GuardianAgent()
            data = guardian.get_compliance_status({
                "applicable_frameworks": [
                    f if isinstance(f, str) else f.get("id", "") for f in profile["frameworks"]
                ],
                "industry": profile.get("industry", ""),
            })
            if data:
                pcts = [v.get("compliance_percentage", 0) for v in data.values()
                        if isinstance(v, dict)]
                compliance_pct = sum(pcts) // max(len(pcts), 1) if pcts else 0
    except Exception:
        compliance_pct = 0

    health_score, health_label = _health_score(
        current_score=profile.get("current_score", 0) or 0,
        compliance_pct=compliance_pct,
        open_critical=critical,
        advisor_pending=advisor_pending,
        payment_status=payment,
        last_activity_iso=last_activity,
    )

    # Filter classification.
    setup_incomplete = setup_pct < 100
    high_risk = health_score < 50 or critical >= 2
    last_activity_days = _days_since(last_activity)
    renewal_risk = (
        payment == "overdue"
        or (last_activity_days is not None and last_activity_days > 60)
        or health_score < 50
    )
    review_pending = advisor_pending > 0
    needs_attention = (
        review_pending or critical > 0 or reports_due > 0
        or validations_due > 0 or evidence_due > 0 or auth_missing
    )

    return {
        "client_id": client_id,
        "company_name": profile.get("company_name", client_id),
        "domain": profile.get("domain", ""),
        "tier": tier,
        "tier_label": tier_cfg.get("label", tier),
        "annual_value": annual_value,
        "is_high_value": is_high_value,
        "is_qualified": is_qualified,
        "authorization_status": auth_label,
        "authorization_missing": auth_missing,
        "setup_completeness_pct": setup_pct,
        "setup_missing": setup_missing,
        "pending_advisor_reviews": advisor_pending,
        "open_critical_risks": critical,
        "reports_due": reports_due,
        "evidence_packages_due": evidence_due,
        "security_validations_due": validations_due,
        "payment_status": payment,
        "next_call_date": next_call,
        "last_client_activity": last_activity,
        "compliance_pct": compliance_pct,
        "current_score": profile.get("current_score", 0) or 0,
        "health_score": health_score,
        "health_label": health_label,
        "filters": {
            "needs_attention": needs_attention,
            "review_pending": review_pending,
            "setup_incomplete": setup_incomplete,
            "high_risk": high_risk,
            "renewal_risk": renewal_risk,
            "high_value_client": is_high_value,
            "authorization_missing": auth_missing,
        },
    }


def build_console() -> dict[str, Any]:
    """Aggregate rows for every client and produce summary counts."""
    rows: list[dict] = []
    for client in _cm().list_all_clients():
        row = build_row(client.get("client_id", ""))
        if row:
            rows.append(row)

    summary = {
        "total": len(rows),
        "qualified": sum(1 for r in rows if r["is_qualified"]),
        "high_value": sum(1 for r in rows if r["is_high_value"]),
        "needs_attention": sum(1 for r in rows if r["filters"]["needs_attention"]),
        "review_pending": sum(1 for r in rows if r["filters"]["review_pending"]),
        "setup_incomplete": sum(1 for r in rows if r["filters"]["setup_incomplete"]),
        "high_risk": sum(1 for r in rows if r["filters"]["high_risk"]),
        "renewal_risk": sum(1 for r in rows if r["filters"]["renewal_risk"]),
        "authorization_missing": sum(1 for r in rows if r["filters"]["authorization_missing"]),
        "total_arr": sum(r["annual_value"] for r in rows),
    }
    return {"clients": rows, "summary": summary}
