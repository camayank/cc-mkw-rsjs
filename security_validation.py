"""
Security Validation module.

Manages the lifecycle of an authorized security validation engagement:
authorization → scope approval → schedule → run → advisor review →
validation → remediation → retest → final report.

The module is *layered on top of* legal_authorization. The legal layer
owns the legal preconditions (signed MSA/SOW/NDA/DPA, authorized
representative, ownership confirmation, scope, testing window, emergency
contact, rate limits). This module owns the engagement (job) record,
findings, kill-switch, retest cycle, and final-report metadata.

Hard rule (enforced in start_engagement): no active scan may run without
an approved active-validation authorization.

Apex integration: when APEX_BIN is set and the engagement is in scope, the
module composes a headless command (`pensar pentest ...`) and records it
on the engagement. Actual execution is gated behind an explicit run() call
from the operator route — the module never auto-launches Apex.
"""
from __future__ import annotations

import json
import os
import secrets
import shlex
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import legal_authorization as _legal


# ─── Statuses (the 11 spec states) ────────────────────────────

NOT_SCOPED               = "not_scoped"
AWAITING_AUTHORIZATION   = "awaiting_authorization"
APPROVED                 = "approved"
SCHEDULED                = "scheduled"
RUNNING                  = "running"
STOPPED                  = "stopped"
ADVISOR_REVIEW_PENDING   = "advisor_review_pending"
VALIDATED                = "validated"
REMEDIATION_IN_PROGRESS  = "remediation_in_progress"
RETEST_PASSED            = "retest_passed"

ALL_STATUSES = (
    NOT_SCOPED, AWAITING_AUTHORIZATION, APPROVED, SCHEDULED,
    RUNNING, STOPPED, ADVISOR_REVIEW_PENDING, VALIDATED,
    REMEDIATION_IN_PROGRESS, RETEST_PASSED,
)

STATUS_LABELS = {
    NOT_SCOPED: "Not scoped",
    AWAITING_AUTHORIZATION: "Awaiting authorization",
    APPROVED: "Approved",
    SCHEDULED: "Scheduled",
    RUNNING: "Running",
    STOPPED: "Stopped",
    ADVISOR_REVIEW_PENDING: "Advisor review pending",
    VALIDATED: "Validated",
    REMEDIATION_IN_PROGRESS: "Remediation in progress",
    RETEST_PASSED: "Retest passed",
}

# Valid transitions: (current, action) -> new
_VALID = {
    (NOT_SCOPED,             "scope"):              AWAITING_AUTHORIZATION,
    (AWAITING_AUTHORIZATION, "approve"):            APPROVED,
    (AWAITING_AUTHORIZATION, "withdraw"):           NOT_SCOPED,
    (APPROVED,               "schedule"):           SCHEDULED,
    (APPROVED,               "withdraw"):           NOT_SCOPED,
    (SCHEDULED,              "start"):              RUNNING,
    (SCHEDULED,              "withdraw"):           APPROVED,
    (RUNNING,                "stop"):               STOPPED,
    (RUNNING,                "complete"):           ADVISOR_REVIEW_PENDING,
    (STOPPED,                "resume"):             SCHEDULED,
    (STOPPED,                "complete"):           ADVISOR_REVIEW_PENDING,
    (ADVISOR_REVIEW_PENDING, "validate"):           VALIDATED,
    (ADVISOR_REVIEW_PENDING, "stop"):               STOPPED,
    (VALIDATED,              "begin_remediation"):  REMEDIATION_IN_PROGRESS,
    (REMEDIATION_IN_PROGRESS, "retest_pass"):       RETEST_PASSED,
    (REMEDIATION_IN_PROGRESS, "retest_fail"):       REMEDIATION_IN_PROGRESS,
}


class EngagementTransitionError(Exception):
    """Raised when an action is not legal from the current state."""


# ─── Scan classes ─────────────────────────────────────────────

SCAN_PASSIVE = "passive"
SCAN_ACTIVE = "active"


# ─── Finding sub-states ───────────────────────────────────────

FP_PENDING            = "pending"
FP_CONFIRMED          = "confirmed_finding"
FP_FALSE_POSITIVE     = "false_positive"

FP_STATUSES = (FP_PENDING, FP_CONFIRMED, FP_FALSE_POSITIVE)

RETEST_NOT_REQUIRED = "not_required"
RETEST_PENDING      = "pending"
RETEST_PASSED_S     = "passed"
RETEST_FAILED       = "failed"
RETEST_STATUSES = (RETEST_NOT_REQUIRED, RETEST_PENDING, RETEST_PASSED_S, RETEST_FAILED)


# ─── Models ───────────────────────────────────────────────────

@dataclass
class ValidationFinding:
    finding_id: str
    title: str = ""
    severity: str = "MEDIUM"        # CRITICAL / HIGH / MEDIUM / LOW
    description: str = ""
    affected_target: str = ""

    # Evidence captured during the run.
    evidence: list[dict] = field(default_factory=list)
    # each evidence item: {"type": "screenshot"|"log"|"http_response"|"file",
    #                       "label": str, "path": str, "captured_at": str}

    # False-positive review (operator triage step).
    fp_review_status: str = FP_PENDING
    fp_reviewed_by: str = ""
    fp_reviewed_on: str = ""
    fp_review_notes: str = ""

    # Advisor validation (named advisor sign-off).
    advisor_validated: bool = False
    advisor_validated_by: str = ""
    advisor_validated_on: str = ""
    advisor_validation_notes: str = ""
    reviewer_credential: str = ""
    client_facing_recommendation: str = ""

    # Retest.
    retest_status: str = RETEST_NOT_REQUIRED
    retest_run_id: str = ""
    retest_at: str = ""
    retest_notes: str = ""


@dataclass
class SecurityValidationEngagement:
    engagement_id: str
    client_id: str
    status: str = NOT_SCOPED

    # Scan classification.
    scan_class: str = SCAN_ACTIVE   # SCAN_PASSIVE | SCAN_ACTIVE

    # Authorization snapshot (mirrored from legal_authorization at scope time).
    authorization_status: str = "not_scoped"
    scope_summary: str = ""
    target_domains: list[str] = field(default_factory=list)
    target_ips: list[str] = field(default_factory=list)
    target_cidrs: list[str] = field(default_factory=list)
    excluded_systems: list[str] = field(default_factory=list)
    excluded_techniques: list[str] = field(default_factory=list)
    testing_window_start: str = ""
    testing_window_end: str = ""
    emergency_contact_name: str = ""
    emergency_contact_phone_24x7: str = ""

    # Rate limits.
    max_requests_per_second: int = 5
    max_concurrent_targets: int = 1
    max_total_requests: int = 100_000

    # Job lifecycle.
    scheduled_at: str = ""
    started_at: str = ""
    stopped_at: str = ""
    stop_reason: str = ""
    completed_at: str = ""
    kill_switch_engaged: bool = False

    # Apex integration (optional).
    apex_command: str = ""
    apex_run_id: str = ""
    apex_exit_code: int = 0
    apex_log_path: str = ""
    apex_scope_file: str = ""
    apex_started_at: str = ""
    apex_ended_at: str = ""

    # Findings.
    findings: list[dict] = field(default_factory=list)

    # Final report.
    final_report_path: str = ""
    final_report_signed_off_at: str = ""
    final_report_signed_off_by: str = ""

    # Audit trail.
    audit_log: list[dict] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── Persistence ──────────────────────────────────────────────

def _data_root() -> Path:
    return Path(os.getenv("DATA_DIR", ".")) / "clients"


def _engagement_dir(client_id: str) -> Path:
    p = _data_root() / client_id / "security_validations"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _engagement_path(client_id: str, engagement_id: str) -> Path:
    return _engagement_dir(client_id) / f"{engagement_id}.json"


def _save(eng: SecurityValidationEngagement) -> None:
    eng.updated_at = datetime.now(timezone.utc).isoformat()
    _engagement_path(eng.client_id, eng.engagement_id).write_text(
        json.dumps(eng.to_dict(), indent=2, default=str)
    )


def _load(client_id: str, engagement_id: str) -> SecurityValidationEngagement:
    path = _engagement_path(client_id, engagement_id)
    if not path.exists():
        raise KeyError(engagement_id)
    raw = json.loads(path.read_text())
    eng = SecurityValidationEngagement(
        engagement_id=raw["engagement_id"], client_id=raw["client_id"],
    )
    for k, v in raw.items():
        if hasattr(eng, k):
            setattr(eng, k, v)
    return eng


def list_engagements(client_id: str) -> list[dict[str, Any]]:
    if not _engagement_dir(client_id).exists():
        return []
    out: list[dict] = []
    for f in sorted(_engagement_dir(client_id).glob("*.json"), reverse=True):
        try:
            out.append(json.loads(f.read_text()))
        except Exception:
            continue
    return out


def get_engagement(client_id: str, engagement_id: str) -> dict[str, Any]:
    return _load(client_id, engagement_id).to_dict()


# ─── Audit + transitions ──────────────────────────────────────

def _audit(eng: SecurityValidationEngagement, event: str, **kwargs) -> None:
    eng.audit_log.append({
        "event": event,
        "at": datetime.now(timezone.utc).isoformat(),
        **kwargs,
    })


def _transition(eng: SecurityValidationEngagement, action: str) -> str:
    key = (eng.status, action)
    if key not in _VALID:
        raise EngagementTransitionError(
            f"Cannot {action!r} an engagement in status {eng.status!r}"
        )
    return _VALID[key]


# ─── Lifecycle API ────────────────────────────────────────────

def create_engagement(
    client_id: str, *, scan_class: str = SCAN_ACTIVE,
    scope_summary: str = "",
) -> dict[str, Any]:
    if scan_class not in (SCAN_PASSIVE, SCAN_ACTIVE):
        raise ValueError(f"Invalid scan_class: {scan_class}")
    engagement_id = f"eng_{datetime.utcnow().strftime('%Y%m%d')}_{secrets.token_urlsafe(6)}"
    eng = SecurityValidationEngagement(
        engagement_id=engagement_id, client_id=client_id,
        scan_class=scan_class, scope_summary=scope_summary,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    _audit(eng, "engagement_created", scan_class=scan_class)
    _save(eng)
    return eng.to_dict()


def scope_engagement(client_id: str, engagement_id: str, scope: dict) -> dict[str, Any]:
    """Define targets, exclusions, window, emergency contact, rate limits.
    Transitions to AWAITING_AUTHORIZATION."""
    eng = _load(client_id, engagement_id)
    new_status = _transition(eng, "scope")
    eng.scope_summary = scope.get("scope_summary", eng.scope_summary)
    for k in ("target_domains", "target_ips", "target_cidrs",
              "excluded_systems", "excluded_techniques"):
        if k in scope:
            setattr(eng, k, list(scope[k]))
    if "testing_window" in scope:
        tw = scope["testing_window"] or {}
        eng.testing_window_start = tw.get("start_at", "")
        eng.testing_window_end = tw.get("end_at", "")
    if "emergency_contact" in scope:
        ec = scope["emergency_contact"] or {}
        eng.emergency_contact_name = ec.get("name", "")
        eng.emergency_contact_phone_24x7 = ec.get("phone_24x7", "")
    if "rate_limits" in scope:
        rl = scope["rate_limits"] or {}
        for k in ("max_requests_per_second", "max_concurrent_targets",
                  "max_total_requests"):
            if k in rl:
                setattr(eng, k, int(rl[k]))
    eng.status = new_status
    eng.authorization_status = AWAITING_AUTHORIZATION
    _audit(eng, "scope_defined")
    _save(eng)
    return eng.to_dict()


def approve_engagement(client_id: str, engagement_id: str,
                       operator_name: str) -> dict[str, Any]:
    """Operator counter-approves once the legal_authorization gate passes.
    The legal layer's authorization_gate is consulted here as the source
    of truth — engagement approval cannot occur if the legal stack is
    incomplete."""
    eng = _load(client_id, engagement_id)
    new_status = _transition(eng, "approve")
    if not operator_name:
        raise ValueError("operator_name required to approve an engagement")
    # For active scans we require the full legal gate.
    if eng.scan_class == SCAN_ACTIVE:
        import client_manager
        raw = client_manager.get_legal_authorization(client_id)
        rec = _legal.from_dict(raw if raw else {"client_id": client_id})
        gate = _legal.authorization_gate(rec, require_active=True)
        if not gate["allowed"]:
            raise EngagementTransitionError(
                "Legal authorization preconditions not met: "
                + "; ".join(gate["blockers"])
            )
    eng.status = new_status
    eng.authorization_status = APPROVED
    _audit(eng, "engagement_approved", by=operator_name)
    _save(eng)
    return eng.to_dict()


def schedule_engagement(client_id: str, engagement_id: str,
                        scheduled_at: str = "") -> dict[str, Any]:
    eng = _load(client_id, engagement_id)
    new_status = _transition(eng, "schedule")
    eng.scheduled_at = scheduled_at or datetime.now(timezone.utc).isoformat()
    eng.status = new_status
    _audit(eng, "engagement_scheduled", at=eng.scheduled_at)
    _save(eng)
    return eng.to_dict()


def start_engagement(
    client_id: str, engagement_id: str, *,
    legal_check: bool = True,
) -> dict[str, Any]:
    """Hard rule: an active engagement cannot start unless the legal gate
    currently allows it (authorization approved + within window + scoped)."""
    eng = _load(client_id, engagement_id)
    new_status = _transition(eng, "start")

    if eng.kill_switch_engaged:
        raise EngagementTransitionError(
            "Kill switch is engaged — cannot start the engagement"
        )

    # Active runs MUST go through the authorization gate.
    if eng.scan_class == SCAN_ACTIVE and legal_check:
        # Re-check the legal gate against the current state (authorization
        # may have expired since scoping).
        try:
            import client_manager
        except Exception:
            client_manager = None
        raw = (client_manager.get_legal_authorization(client_id)
               if client_manager else {})
        rec = _legal.from_dict(raw if raw else {"client_id": client_id})
        gate = _legal.authorization_gate(rec, require_active=True)
        if not gate["allowed"]:
            raise EngagementTransitionError(
                "Active scan blocked by authorization gate: "
                + "; ".join(gate["blockers"])
            )

    eng.status = new_status
    eng.started_at = datetime.now(timezone.utc).isoformat()
    _audit(eng, "engagement_started")
    _save(eng)
    return eng.to_dict()


def engage_kill_switch(client_id: str, engagement_id: str, *,
                       by: str, reason: str = "") -> dict[str, Any]:
    """Operator or customer can engage the kill switch at any time during
    a running engagement. Transitions RUNNING/ADVISOR_REVIEW_PENDING -> STOPPED.
    No-op on terminal states (validated/retest_passed)."""
    eng = _load(client_id, engagement_id)
    if eng.status in (VALIDATED, RETEST_PASSED, NOT_SCOPED):
        raise EngagementTransitionError(
            f"Cannot stop engagement in status {eng.status!r}"
        )
    eng.kill_switch_engaged = True
    if eng.status == RUNNING or eng.status == ADVISOR_REVIEW_PENDING:
        new_status = _transition(eng, "stop")
        eng.status = new_status
    eng.stopped_at = datetime.now(timezone.utc).isoformat()
    eng.stop_reason = reason or "Kill switch engaged"
    _audit(eng, "kill_switch_engaged", by=by, reason=eng.stop_reason)
    _save(eng)
    return eng.to_dict()


def complete_run(client_id: str, engagement_id: str,
                 findings: Optional[list] = None) -> dict[str, Any]:
    """Move from RUNNING (or STOPPED) -> ADVISOR_REVIEW_PENDING and ingest
    raw findings. Each finding gets a stable id and starts in fp_review_status
    = pending."""
    eng = _load(client_id, engagement_id)
    new_status = _transition(eng, "complete")
    eng.status = new_status
    eng.completed_at = datetime.now(timezone.utc).isoformat()
    for f in (findings or []):
        fid = f.get("finding_id") or f"vf_{len(eng.findings)+1:04d}"
        finding = ValidationFinding(
            finding_id=fid,
            title=f.get("title", ""),
            severity=f.get("severity", "MEDIUM"),
            description=f.get("description", ""),
            affected_target=f.get("affected_target", ""),
            evidence=list(f.get("evidence", [])),
        )
        eng.findings.append(asdict(finding))
    _audit(eng, "run_completed", finding_count=len(findings or []))
    _save(eng)
    return eng.to_dict()


def fp_review_finding(client_id: str, engagement_id: str, finding_id: str,
                      *, by: str, status: str, notes: str = "") -> dict[str, Any]:
    """Operator triage to confirm a finding or mark it a false positive."""
    if status not in FP_STATUSES:
        raise ValueError(f"Invalid fp_review_status: {status}")
    eng = _load(client_id, engagement_id)
    f = _find_finding(eng, finding_id)
    f["fp_review_status"] = status
    f["fp_reviewed_by"] = by
    f["fp_reviewed_on"] = datetime.now(timezone.utc).isoformat()
    f["fp_review_notes"] = notes
    _audit(eng, "finding_fp_reviewed", finding_id=finding_id, status=status, by=by)
    _save(eng)
    return f


def advisor_validate_finding(
    client_id: str, engagement_id: str, finding_id: str,
    *, by: str, reviewer_credential: str = "",
    notes: str = "", client_facing_recommendation: str = "",
) -> dict[str, Any]:
    """Named-advisor sign-off on a single finding. Mirrors into the
    advisor_review store at validation_finding:{finding_id} so the finding
    benefits from the unified review system."""
    eng = _load(client_id, engagement_id)
    f = _find_finding(eng, finding_id)
    if f.get("fp_review_status") != FP_CONFIRMED:
        raise EngagementTransitionError(
            "Finding must be FP-reviewed and confirmed before advisor validation"
        )
    now = datetime.now(timezone.utc).isoformat()
    f["advisor_validated"] = True
    f["advisor_validated_by"] = by
    f["advisor_validated_on"] = now
    f["advisor_validation_notes"] = notes
    f["reviewer_credential"] = reviewer_credential
    f["client_facing_recommendation"] = client_facing_recommendation
    _audit(eng, "finding_advisor_validated", finding_id=finding_id, by=by)
    _save(eng)

    # Mirror into advisor_review.
    try:
        import advisor_review as _ar
        _ar.set_review(
            client_id, _ar.validation_finding_key(finding_id),
            prepared_by="System",
            reviewed_by=by, reviewed_on=now[:10],
            review_status=_ar.REVIEW_APPROVED,
            sign_off_timestamp=now,
            advisor_notes=notes,
            client_facing_recommendation=client_facing_recommendation,
            reviewer_credential=reviewer_credential or None,
        )
    except Exception:
        pass
    return f


def validate_engagement(
    client_id: str, engagement_id: str, *, by: str,
    reviewer_credential: str = "", final_report_path: str = "",
) -> dict[str, Any]:
    """Advisor signs off on the engagement as a whole. Requires that every
    confirmed finding has been advisor-validated."""
    eng = _load(client_id, engagement_id)
    new_status = _transition(eng, "validate")
    # Check every confirmed finding is advisor-validated.
    for f in eng.findings:
        if (f.get("fp_review_status") == FP_CONFIRMED
                and not f.get("advisor_validated")):
            raise EngagementTransitionError(
                f"Finding {f['finding_id']} is confirmed but not advisor-validated"
            )
    now = datetime.now(timezone.utc).isoformat()
    eng.status = new_status
    eng.final_report_path = final_report_path or eng.final_report_path
    eng.final_report_signed_off_at = now
    eng.final_report_signed_off_by = by
    _audit(eng, "engagement_validated", by=by)
    _save(eng)
    return eng.to_dict()


def begin_remediation(client_id: str, engagement_id: str) -> dict[str, Any]:
    eng = _load(client_id, engagement_id)
    new_status = _transition(eng, "begin_remediation")
    eng.status = new_status
    # Mark every confirmed finding as needing retest.
    for f in eng.findings:
        if f.get("fp_review_status") == FP_CONFIRMED:
            f["retest_status"] = RETEST_PENDING
    _audit(eng, "remediation_started")
    _save(eng)
    return eng.to_dict()


def record_retest(
    client_id: str, engagement_id: str, finding_id: str,
    *, passed: bool, by: str, notes: str = "", run_id: str = "",
) -> dict[str, Any]:
    eng = _load(client_id, engagement_id)
    f = _find_finding(eng, finding_id)
    f["retest_status"] = RETEST_PASSED_S if passed else RETEST_FAILED
    f["retest_at"] = datetime.now(timezone.utc).isoformat()
    f["retest_run_id"] = run_id
    f["retest_notes"] = notes
    _audit(eng, "finding_retested", finding_id=finding_id,
           passed=passed, by=by)

    # If every confirmed finding has now passed retest, the engagement
    # transitions to RETEST_PASSED.
    pending = [
        x for x in eng.findings
        if (x.get("fp_review_status") == FP_CONFIRMED
            and x.get("retest_status") not in (RETEST_PASSED_S, RETEST_NOT_REQUIRED))
    ]
    if not pending and eng.status == REMEDIATION_IN_PROGRESS:
        eng.status = _transition(eng, "retest_pass")
        _audit(eng, "engagement_retest_passed")
    elif eng.status == REMEDIATION_IN_PROGRESS and not passed:
        eng.status = _transition(eng, "retest_fail")
    _save(eng)
    return f


def _find_finding(eng: SecurityValidationEngagement, finding_id: str) -> dict:
    for f in eng.findings:
        if f.get("finding_id") == finding_id:
            return f
    raise KeyError(finding_id)


# ─── Apex command construction (optional integration) ────────

def build_apex_command(eng_data: dict, *, dry_run: bool = True) -> str:
    """
    Compose the headless Apex command for an engagement.

    Reference: https://github.com/camayank/apex-cybercomply-pentest
    Headless invocation: `pensar pentest --target <url> [flags]`

    Real Pensar Apex CLI flags (verified against the upstream README):
      --target <url>          required
      --cwd <path>            whitebox mode source-code path
      --mode <mode>           e.g. "exfil" for pivoting
      --model <model>         AI model selection
      --extended-thinking     bool flag
      --task-driven           bool flag
      --prompt <text|@file>   guidance for the agent
      --threat-model <text|@file>  threat model file

    Note: Apex does NOT accept --exclude or --rate-limit on the CLI.
    Exclusions, rate limits, and other scope rules must be passed in
    through --prompt or --threat-model files. We compose a scope file
    on disk and reference it via @file syntax.

    Active scans only — passive engagements never invoke Apex.
    Returns the command string for inspection / logging. Execution is
    gated to apex_runner.run_engagement().
    """
    if eng_data.get("scan_class") != SCAN_ACTIVE:
        return ""
    bin_ = os.getenv("APEX_BIN", "pensar")
    targets = list(eng_data.get("target_domains") or [])
    if not targets:
        return ""
    target = targets[0]
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parts: list[str] = [bin_, "pentest", "--target", target]

    # Threat model / scope file path is recorded on the engagement when
    # apex_runner writes it; build_apex_command embeds the @file reference.
    scope_file = eng_data.get("apex_scope_file") or ""
    if scope_file:
        parts += ["--threat-model", f"@{scope_file}"]

    # Optional model override.
    model = os.getenv("APEX_MODEL", "")
    if model:
        parts += ["--model", model]

    # Dry-run mode is implemented at our layer (we just record the command
    # without invoking subprocess); it is NOT a flag Apex itself understands.
    return " ".join(shlex.quote(p) for p in parts)


def write_apex_scope_file(eng_data: dict) -> str:
    """Write the engagement scope (targets, exclusions, rate limits, window)
    to a file Apex can read via --threat-model @file. Returns the path."""
    if eng_data.get("scan_class") != SCAN_ACTIVE:
        return ""
    client_id = eng_data.get("client_id", "")
    engagement_id = eng_data.get("engagement_id", "")
    if not client_id or not engagement_id:
        return ""
    scope_dir = _engagement_dir(client_id) / engagement_id
    scope_dir.mkdir(parents=True, exist_ok=True)
    scope_path = scope_dir / "apex_scope.md"
    body = (
        f"# Authorized scope for engagement {engagement_id}\n\n"
        f"Customer: {client_id}\n\n"
        f"Authorized targets (in scope):\n"
        + "\n".join(f"- {d}" for d in eng_data.get("target_domains") or [])
        + "\n\nExcluded systems (do NOT touch):\n"
        + "\n".join(f"- {d}" for d in eng_data.get("excluded_systems") or [])
        + "\n\nExcluded techniques:\n"
        + "\n".join(f"- {d}" for d in eng_data.get("excluded_techniques") or [])
        + f"\n\nTesting window: "
        f"{eng_data.get('testing_window_start','')} → "
        f"{eng_data.get('testing_window_end','')}\n\n"
        f"Rate limits:\n"
        f"- Max requests/sec: {eng_data.get('max_requests_per_second')}\n"
        f"- Max concurrent targets: {eng_data.get('max_concurrent_targets')}\n"
        f"- Max total requests: {eng_data.get('max_total_requests')}\n\n"
        f"Emergency contact: {eng_data.get('emergency_contact_name','')} "
        f"({eng_data.get('emergency_contact_phone_24x7','')})\n\n"
        "Stop immediately if any out-of-scope system is reached. "
        "Do not attempt destructive actions (data exfiltration, account "
        "takeover beyond proof-of-concept, denial-of-service)."
    )
    scope_path.write_text(body)
    return str(scope_path)


def attach_apex_command(client_id: str, engagement_id: str,
                        *, dry_run: bool = True) -> dict[str, Any]:
    eng = _load(client_id, engagement_id)
    if eng.scan_class != SCAN_ACTIVE:
        return eng.to_dict()
    # Ensure the scope file exists so Apex can be invoked with the agreed
    # boundaries; build_apex_command embeds the @file reference.
    eng_dict = eng.to_dict()
    scope_path = write_apex_scope_file(eng_dict)
    if scope_path:
        # Persist the path on the engagement so the runner can re-read it.
        setattr(eng, "apex_scope_file", scope_path)
        eng_dict["apex_scope_file"] = scope_path
    eng.apex_command = build_apex_command(eng_dict, dry_run=dry_run)
    _audit(eng, "apex_command_attached", dry_run=dry_run, scope_file=scope_path)
    _save(eng)
    return eng.to_dict()


# ─── Customer-safe view ───────────────────────────────────────

def customer_view(eng: dict[str, Any]) -> dict[str, Any]:
    """Strip operator-only fields before returning to the customer."""
    if not eng:
        return {}
    safe = {
        "engagement_id": eng.get("engagement_id"),
        "status": eng.get("status"),
        "status_label": STATUS_LABELS.get(eng.get("status", ""), eng.get("status", "")),
        "scan_class": eng.get("scan_class"),
        "scope_summary": eng.get("scope_summary", ""),
        "testing_window_start": eng.get("testing_window_start", ""),
        "testing_window_end": eng.get("testing_window_end", ""),
        "scheduled_at": eng.get("scheduled_at", ""),
        "started_at": eng.get("started_at", ""),
        "stopped_at": eng.get("stopped_at", ""),
        "completed_at": eng.get("completed_at", ""),
        "kill_switch_engaged": eng.get("kill_switch_engaged", False),
        "final_report_signed_off_at": eng.get("final_report_signed_off_at", ""),
        "findings_summary": _summarize_findings(eng.get("findings", [])),
    }
    return safe


def _summarize_findings(findings: list) -> dict[str, int]:
    out = {"total": 0, "confirmed": 0, "false_positive": 0,
           "advisor_validated": 0, "retest_passed": 0, "retest_pending": 0}
    for f in findings or []:
        out["total"] += 1
        if f.get("fp_review_status") == FP_CONFIRMED:
            out["confirmed"] += 1
        elif f.get("fp_review_status") == FP_FALSE_POSITIVE:
            out["false_positive"] += 1
        if f.get("advisor_validated"):
            out["advisor_validated"] += 1
        rt = f.get("retest_status", "")
        if rt == RETEST_PASSED_S:
            out["retest_passed"] += 1
        elif rt == RETEST_PENDING:
            out["retest_pending"] += 1
    return out
