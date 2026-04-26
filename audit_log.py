"""
Audit log — append-only, queryable, exportable.

Records every privileged action across the product with the fields a
compliance reviewer expects: actor, role, client_id, action, timestamp,
IP, user agent, and before/after deltas where applicable.

Storage layout:
  clients/{cid}/audit.json          # per-client events
  audit/global.json                 # cross-client / unattributed events
  audit/secret_pepper.txt           # one-time pepper used to derive the
                                     # event-id prefix (so ids are stable
                                     # across processes but unguessable)

Reads are unindexed (line-oriented JSON arrays). For now we expect O(<1k)
events per client per month, well within scan-and-filter range. If volume
grows, swap to JSONL + per-month rotation; the read API is already
filter-aware so callers won't have to change.
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterable, Optional


# ─── Roles ────────────────────────────────────────────────────

ROLE_OPERATOR = "Operator"
ROLE_CUSTOMER = "Customer"
ROLE_ANONYMOUS = "Anonymous"
ROLE_SYSTEM = "System"

ALL_ROLES = (ROLE_OPERATOR, ROLE_CUSTOMER, ROLE_ANONYMOUS, ROLE_SYSTEM)


# ─── Recognized actions (catalog only — record() accepts any string) ─

# Auth
ACTION_LOGIN              = "login"
ACTION_LOGOUT             = "logout"
ACTION_FAILED_LOGIN       = "failed_login"
ACTION_OPERATOR_LOGIN     = "operator_login"
ACTION_OPERATOR_LOGOUT    = "operator_logout"

# Downloads / uploads
ACTION_DOCUMENT_DOWNLOAD  = "document_download"
ACTION_AUDIT_PACKAGE_DOWNLOAD = "audit_package_download"
ACTION_EVIDENCE_UPLOAD    = "evidence_upload"

# Tasks
ACTION_TASK_STATUS_CHANGE = "task_status_change"
ACTION_TASK_VERIFY        = "task_verified"
ACTION_TASK_REJECT        = "task_rejected"
ACTION_TASK_DEFER         = "task_deferred"

# Reviews / authorizations
ACTION_ADVISOR_REVIEW     = "advisor_review"
ACTION_AUTHORIZATION_APPROVED = "authorization_approved"
ACTION_AUTHORIZATION_REVOKED  = "authorization_revoked"

# Scans / validations
ACTION_SCAN_START         = "scan_start"
ACTION_SCAN_STOP          = "scan_stop"
ACTION_VALIDATION_START   = "security_validation_start"
ACTION_VALIDATION_STOP    = "security_validation_stop"
ACTION_VALIDATION_COMPLETE = "security_validation_complete"

# Billing
ACTION_INVOICE_CREATE     = "invoice_create"
ACTION_PLAN_CHANGE        = "plan_change"

# Operator profile
ACTION_OPERATOR_PROFILE_UPDATE = "operator_profile_update"
ACTION_CLIENT_PROFILE_UPDATE = "client_profile_update"

ALL_ACTIONS = {
    ACTION_LOGIN, ACTION_LOGOUT, ACTION_FAILED_LOGIN,
    ACTION_OPERATOR_LOGIN, ACTION_OPERATOR_LOGOUT,
    ACTION_DOCUMENT_DOWNLOAD, ACTION_AUDIT_PACKAGE_DOWNLOAD,
    ACTION_EVIDENCE_UPLOAD,
    ACTION_TASK_STATUS_CHANGE, ACTION_TASK_VERIFY,
    ACTION_TASK_REJECT, ACTION_TASK_DEFER,
    ACTION_ADVISOR_REVIEW,
    ACTION_AUTHORIZATION_APPROVED, ACTION_AUTHORIZATION_REVOKED,
    ACTION_SCAN_START, ACTION_SCAN_STOP,
    ACTION_VALIDATION_START, ACTION_VALIDATION_STOP, ACTION_VALIDATION_COMPLETE,
    ACTION_INVOICE_CREATE, ACTION_PLAN_CHANGE,
    ACTION_OPERATOR_PROFILE_UPDATE, ACTION_CLIENT_PROFILE_UPDATE,
}


# ─── Storage paths ────────────────────────────────────────────

def _data_root() -> Path:
    return Path(os.getenv("DATA_DIR", "."))


def _client_audit_path(client_id: str) -> Path:
    p = _data_root() / "clients" / client_id
    p.mkdir(parents=True, exist_ok=True)
    return p / "audit.json"


def _global_audit_path() -> Path:
    p = _data_root() / "audit"
    p.mkdir(parents=True, exist_ok=True)
    return p / "global.json"


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def _save(path: Path, events: list[dict]) -> None:
    path.write_text(json.dumps(events, indent=2, default=str))


# ─── Request-metadata extraction ──────────────────────────────

def extract_request_meta(request: Any) -> dict[str, str]:
    """Pull IP and User-Agent from a Starlette/FastAPI Request. Tolerant of
    None and missing headers. Honors X-Forwarded-For when set, falling back
    to the direct client IP."""
    if request is None:
        return {"ip": "", "user_agent": ""}
    try:
        ua = request.headers.get("user-agent", "") or ""
        xff = request.headers.get("x-forwarded-for", "") or ""
        ip = xff.split(",")[0].strip() if xff else ""
        if not ip and getattr(request, "client", None):
            ip = (request.client.host if request.client else "") or ""
        return {"ip": ip[:64], "user_agent": ua[:256]}
    except Exception:
        return {"ip": "", "user_agent": ""}


# ─── Diff helper for before/after ─────────────────────────────

def _diff(before: Optional[dict], after: Optional[dict]) -> Optional[dict]:
    """Capture a small before/after delta. Operators can read the full
    snapshots; we still return both fields so reviewers can see context.
    Caller controls what goes in — pass small/relevant subsets only."""
    if before is None and after is None:
        return None
    return {"before": before or {}, "after": after or {}}


# ─── Recording ────────────────────────────────────────────────

def record(
    *,
    action: str,
    actor: str = "",
    role: str = ROLE_SYSTEM,
    client_id: str = "",
    request: Any = None,
    before: Optional[dict] = None,
    after: Optional[dict] = None,
    **metadata,
) -> dict[str, Any]:
    """Append a single audit event. Always returns the event dict so callers
    can chain or attach the id to a response."""
    if role not in ALL_ROLES:
        role = ROLE_SYSTEM
    rmeta = extract_request_meta(request)
    event = {
        "id": "ev_" + secrets.token_urlsafe(10),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": (actor or "")[:128],
        "role": role,
        "client_id": (client_id or "")[:128],
        "action": (action or "")[:64],
        "ip": rmeta["ip"],
        "user_agent": rmeta["user_agent"],
        "delta": _diff(before, after),
        "metadata": metadata or {},
    }

    # Per-client + global storage. Per-client when client_id present;
    # always also append to the global stream so cross-tenant audits are
    # possible (operator view).
    if client_id:
        path = _client_audit_path(client_id)
        events = _load(path)
        events.append(event)
        _save(path, events)
    g_path = _global_audit_path()
    g_events = _load(g_path)
    g_events.append(event)
    # Cap global file at 50k events to bound size; rotate older to a daily
    # archive when exceeded. (Soft cap — doesn't block writes.)
    if len(g_events) > 50_000:
        archive = g_path.parent / f"global_{datetime.utcnow():%Y%m%d}.json"
        _save(archive, g_events[:25_000])
        g_events = g_events[25_000:]
    _save(g_path, g_events)
    return event


# ─── Reading ──────────────────────────────────────────────────

def list_events(
    client_id: Optional[str] = None,
    *,
    action: Optional[str] = None,
    role: Optional[str] = None,
    actor: Optional[str] = None,
    since: Optional[str] = None,           # ISO date or datetime
    until: Optional[str] = None,
    limit: int = 1000,
) -> list[dict]:
    """Filtered query over the appropriate event stream."""
    if client_id:
        events = _load(_client_audit_path(client_id))
    else:
        events = _load(_global_audit_path())

    out = []
    since_dt = _parse(since) if since else None
    until_dt = _parse(until) if until else None
    for e in events:
        if action and e.get("action") != action:
            continue
        if role and e.get("role") != role:
            continue
        if actor and e.get("actor") != actor:
            continue
        ts = _parse(e.get("timestamp", ""))
        if since_dt and (not ts or ts < since_dt):
            continue
        if until_dt and (not ts or ts > until_dt):
            continue
        out.append(e)
    out.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return out[:limit]


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


# ─── Exports ──────────────────────────────────────────────────

def export_json(client_id: Optional[str] = None) -> str:
    return json.dumps(list_events(client_id, limit=50_000), indent=2, default=str)


def export_csv(client_id: Optional[str] = None) -> str:
    """Compact CSV suitable for inclusion in the audit package."""
    import csv, io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "timestamp", "actor", "role", "client_id", "action",
        "ip", "user_agent", "before", "after", "metadata", "id",
    ])
    for e in list_events(client_id, limit=50_000):
        delta = e.get("delta") or {}
        writer.writerow([
            e.get("timestamp", ""),
            e.get("actor", ""),
            e.get("role", ""),
            e.get("client_id", ""),
            e.get("action", ""),
            e.get("ip", ""),
            (e.get("user_agent", "") or "")[:200],
            json.dumps(delta.get("before") or {}, default=str),
            json.dumps(delta.get("after") or {}, default=str),
            json.dumps(e.get("metadata") or {}, default=str),
            e.get("id", ""),
        ])
    return buf.getvalue()
