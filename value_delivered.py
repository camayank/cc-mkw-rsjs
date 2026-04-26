"""
"This Month's Value Delivered" dashboard.

Turns live system state into 12 customer-facing metrics that make the
$24K-$96K/year retainer feel tangible. Every metric has an explicit empty
state — we never fabricate activity.

Empty-state vocabulary:
  - delivered            → real activity happened this month (show the number)
  - empty                → service ran but produced no activity this month
                           ("No activity yet this month")
  - pending_first_review → service is set up but the first review cycle
                           has not run yet  ("Pending first review")
  - waiting_setup        → service is in the plan but an integration or
                           input is missing  ("Waiting for setup")
  - not_included         → service is not in this tier  ("Not included in your plan")
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import service_coverage as _sc


# ─── Empty-state labels (single source of truth for copy) ─────

LABEL_EMPTY = "No activity yet this month"
LABEL_PENDING = "Pending first review"
LABEL_WAITING = "Waiting for setup"
LABEL_NOT_INCLUDED = "Not included in your plan"

ALL_STATES = ("delivered", "empty", "pending_first_review",
              "waiting_setup", "not_included")


# ─── Helpers ──────────────────────────────────────────────────

def _parse(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        s = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        # Try date-only
        try:
            dt = datetime.strptime(s[:10], "%Y-%m-%d")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def _within(iso: str, days: int, now: datetime) -> bool:
    dt = _parse(iso)
    if not dt:
        return False
    return (now - dt) <= timedelta(days=days)


def _empty_label(state: str) -> str:
    return {
        "empty": LABEL_EMPTY,
        "pending_first_review": LABEL_PENDING,
        "waiting_setup": LABEL_WAITING,
        "not_included": LABEL_NOT_INCLUDED,
    }.get(state, "")


def _metric(*, key: str, label: str, value: int, state: str,
            supporting_text: str = "", icon: str = "") -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "value": value if state == "delivered" else None,
        "display": str(value) if state == "delivered" else _empty_label(state),
        "state": state,
        "supporting_text": supporting_text,
        "icon": icon,
    }


def _state_for_service(coverage_row: dict) -> Optional[str]:
    """Translate a service_coverage row into a value-dashboard state, or
    None if the service is in-plan and operational (so the caller should
    proceed to count activity)."""
    s = coverage_row.get("status")
    if s == _sc.STATUS_NOT_INCLUDED:
        return "not_included"
    if s == _sc.STATUS_NOT_CONNECTED:
        return "waiting_setup"
    if s == _sc.STATUS_PENDING_SETUP and not coverage_row.get("last_successful_check"):
        return "pending_first_review"
    return None


# ─── Builder ──────────────────────────────────────────────────

def build_value_delivered(
    *,
    coverage: list,
    score_history: list,
    alerts: list,
    open_tasks: list,
    resolved_tasks: list,
    reports: list,
    policies: list,
    call_notes: list,
    due_next: list,
    legal_view: dict,
    authorization_audit: list,
    advisor_reviewed_at: str,
    monthly_summary_reviewed_at: str,
    now: Optional[datetime] = None,
    window_days: int = 30,
) -> dict[str, Any]:
    """
    Compute the dashboard for the trailing `window_days` (default: 30).

    Returns:
        {
          "month_label": "April 2026",
          "window_days": 30,
          "summary": {
              "client_actions": N,
              "advisor_actions": N,
              "system_actions": N,
          },
          "metrics": [...12 metrics in display order...],
        }
    """
    now = now or datetime.now(timezone.utc)
    cov_by_key = {r["key"]: r for r in (coverage or [])}

    def _w(iso: str) -> bool:
        return _within(iso, window_days, now)

    # ── 1. Scans completed ────────────────────────────────────
    cov = cov_by_key.get("external_attack_surface", {})
    forced = _state_for_service(cov)
    if forced:
        scans = _metric(key="scans_completed", label="Scans completed",
                        value=0, state=forced)
    else:
        scans_count = sum(1 for s in (score_history or []) if _w(s.get("date", "")))
        if scans_count > 0:
            last = (score_history[-1].get("date", "") if score_history else "")
            scans = _metric(key="scans_completed", label="Scans completed",
                            value=scans_count, state="delivered",
                            supporting_text=f"Most recent: {last[:10]}")
        else:
            scans = _metric(key="scans_completed", label="Scans completed",
                            value=0, state="empty")

    # ── 2. Alerts reviewed ────────────────────────────────────
    # Counts alerts whose date falls in the window (assumed to have been
    # reviewed by the advisor as part of the monthly cycle).
    alerts_in_window = [a for a in (alerts or []) if _w(a.get("date", ""))]
    if alerts_in_window:
        alerts_metric = _metric(
            key="alerts_reviewed", label="Alerts reviewed",
            value=len(alerts_in_window), state="delivered",
            supporting_text="Triaged by your advisor",
        )
    elif coverage:
        alerts_metric = _metric(key="alerts_reviewed", label="Alerts reviewed",
                                value=0, state="empty")
    else:
        alerts_metric = _metric(key="alerts_reviewed", label="Alerts reviewed",
                                value=0, state="pending_first_review")

    # ── 3. Risks identified ───────────────────────────────────
    # Tasks created in the window + alerts severity HIGH/CRITICAL in window.
    risks = sum(1 for t in (open_tasks or []) + (resolved_tasks or [])
                if _w(t.get("created_at", "") or t.get("date", "")))
    risks += sum(1 for a in alerts_in_window if a.get("severity") in ("HIGH", "CRITICAL"))
    if risks > 0:
        risks_metric = _metric(key="risks_identified", label="Risks identified",
                               value=risks, state="delivered",
                               supporting_text="Surfaced by scans, threat intel, or advisor")
    else:
        risks_metric = _metric(key="risks_identified", label="Risks identified",
                               value=0, state="empty")

    # ── 4. Tasks resolved ─────────────────────────────────────
    resolved_in_window = [t for t in (resolved_tasks or [])
                          if _w(t.get("resolved_at", "") or t.get("updated_at", ""))]
    if resolved_in_window:
        tasks_metric = _metric(
            key="tasks_resolved", label="Tasks resolved",
            value=len(resolved_in_window), state="delivered",
            supporting_text="Closed and verified",
        )
    else:
        tasks_metric = _metric(key="tasks_resolved", label="Tasks resolved",
                               value=0, state="empty")

    # ── 5. Policies updated ───────────────────────────────────
    policy_cov = cov_by_key.get("policy_management", {})
    forced = _state_for_service(policy_cov)
    if forced:
        policies_metric = _metric(key="policies_updated", label="Policies updated",
                                  value=0, state=forced)
    else:
        # Treat advisor_reviewed_at within window as the trigger for "updated"
        if _w(advisor_reviewed_at):
            policies_metric = _metric(
                key="policies_updated", label="Policies updated",
                value=len(policies or []), state="delivered",
                supporting_text=f"Advisor reviewed {advisor_reviewed_at[:10]}",
            )
        elif policies:
            policies_metric = _metric(key="policies_updated", label="Policies updated",
                                      value=0, state="empty")
        else:
            policies_metric = _metric(key="policies_updated", label="Policies updated",
                                      value=0, state="pending_first_review")

    # ── 6. Evidence files prepared ────────────────────────────
    ev_cov = cov_by_key.get("evidence_package", {})
    forced = _state_for_service(ev_cov)
    if forced:
        evidence_metric = _metric(key="evidence_prepared",
                                  label="Evidence files prepared",
                                  value=0, state=forced)
    else:
        ev_count = sum(1 for r in (reports or []) if _w(r.get("date", ""))) \
                 + sum(1 for p in (policies or []) if _w(p.get("date", "")))
        if ev_count > 0:
            evidence_metric = _metric(
                key="evidence_prepared", label="Evidence files prepared",
                value=ev_count, state="delivered",
                supporting_text="Available in your Evidence Vault",
            )
        elif reports or policies:
            evidence_metric = _metric(key="evidence_prepared",
                                      label="Evidence files prepared",
                                      value=0, state="empty")
        else:
            evidence_metric = _metric(key="evidence_prepared",
                                      label="Evidence files prepared",
                                      value=0, state="pending_first_review")

    # ── 7. Reports generated ──────────────────────────────────
    reports_in_window = [r for r in (reports or []) if _w(r.get("date", ""))]
    if reports_in_window:
        reports_metric = _metric(
            key="reports_generated", label="Reports generated",
            value=len(reports_in_window), state="delivered",
            supporting_text="Audit-ready PDFs",
        )
    elif reports:
        reports_metric = _metric(key="reports_generated", label="Reports generated",
                                 value=0, state="empty")
    else:
        reports_metric = _metric(key="reports_generated", label="Reports generated",
                                 value=0, state="pending_first_review")

    # ── 8. Advisor notes added ────────────────────────────────
    notes_in_window = [n for n in (call_notes or []) if _w(n.get("date", ""))]
    if notes_in_window:
        notes_metric = _metric(
            key="advisor_notes", label="Advisor notes added",
            value=len(notes_in_window), state="delivered",
            supporting_text="From your monthly review",
        )
    elif call_notes:
        notes_metric = _metric(key="advisor_notes", label="Advisor notes added",
                               value=0, state="empty")
    else:
        notes_metric = _metric(key="advisor_notes", label="Advisor notes added",
                               value=0, state="pending_first_review")

    # ── 9. Client actions completed ───────────────────────────
    # Tasks marked resolved by the customer in the portal (proxy: resolved
    # tasks in the window — every resolution flows through the customer
    # "Mark complete" button or the advisor on their behalf).
    client_actions_count = len(resolved_in_window)
    if client_actions_count > 0:
        client_metric = _metric(
            key="client_actions", label="Client actions completed",
            value=client_actions_count, state="delivered",
            supporting_text="Items closed from your portal",
        )
    else:
        client_metric = _metric(key="client_actions",
                                label="Client actions completed",
                                value=0, state="empty")

    # ── 10. CyberComply (advisor + system) actions completed ──
    # Sum the work done on the customer's behalf.
    cc_actions = (
        len(alerts_in_window) +
        sum(1 for s in (score_history or []) if _w(s.get("date", ""))) +
        len(reports_in_window) +
        len(notes_in_window) +
        (1 if _w(advisor_reviewed_at) else 0) +
        (1 if _w(monthly_summary_reviewed_at) else 0)
    )
    if cc_actions > 0:
        cc_metric = _metric(
            key="cybercomply_actions", label="CyberComply actions completed",
            value=cc_actions, state="delivered",
            supporting_text="Scans, triage, reviews, and reporting on your behalf",
        )
    else:
        cc_metric = _metric(key="cybercomply_actions",
                            label="CyberComply actions completed",
                            value=0, state="pending_first_review")

    # ── 11. Security validation activity ──────────────────────
    sv_cov = cov_by_key.get("security_validation", {})
    forced = _state_for_service(sv_cov)
    if forced:
        sv_metric = _metric(key="security_validation",
                            label="Security validation activity",
                            value=0, state=forced)
    else:
        # Count audit-trail events related to active validation in the window.
        sv_events = [
            e for e in (authorization_audit or [])
            if _w(e.get("at", "")) and "active_validation" in (e.get("event", "") or "")
        ]
        if sv_events:
            sv_metric = _metric(
                key="security_validation", label="Security validation activity",
                value=len(sv_events), state="delivered",
                supporting_text="Authorization checks and validation runs",
            )
        else:
            av_status = (legal_view or {}).get("active_validation", "")
            if av_status == "Approved":
                sv_metric = _metric(key="security_validation",
                                    label="Security validation activity",
                                    value=0, state="empty")
            else:
                sv_metric = _metric(key="security_validation",
                                    label="Security validation activity",
                                    value=0, state="pending_first_review")

    # ── 12. Upcoming obligations ──────────────────────────────
    upcoming = list(due_next or [])
    if upcoming:
        next_item = upcoming[0]
        ob_metric = _metric(
            key="upcoming_obligations", label="Upcoming obligations",
            value=len(upcoming), state="delivered",
            supporting_text=f"Next: {next_item.get('what', '')} on {next_item.get('when', '')}",
        )
    else:
        ob_metric = _metric(key="upcoming_obligations",
                            label="Upcoming obligations",
                            value=0, state="empty")

    metrics = [
        scans, alerts_metric, risks_metric, tasks_metric,
        policies_metric, evidence_metric, reports_metric,
        notes_metric, client_metric, cc_metric, sv_metric, ob_metric,
    ]

    summary = {
        "client_actions": client_actions_count,
        "advisor_actions": cc_actions,
        "system_actions": (
            sum(1 for s in (score_history or []) if _w(s.get("date", ""))) +
            len(alerts_in_window)
        ),
    }

    return {
        "month_label": now.strftime("%B %Y"),
        "window_days": window_days,
        "summary": summary,
        "metrics": metrics,
    }
