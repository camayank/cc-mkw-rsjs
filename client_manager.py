"""Client management: auth, profiles, tiers, and data access."""
import os
import json
import secrets
import bcrypt
import jwt
from pathlib import Path
from datetime import datetime, date, timedelta
from typing import Optional

DATA_DIR = Path(os.getenv("DATA_DIR", "."))
CLIENTS_DIR = DATA_DIR / "clients"
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_EXPIRY_DAYS = 30

# Commercial tier ladder.
# - "diagnostic" is a one-time engagement (no recurring ARR, no self-serve portal).
# - "essentials", "professional", "enterprise_plus" are annual prepaid retainers
#   with full portal access and named-advisor review of deliverables.
# Pricing strings (annual_price_label) are presentation-only; no monthly billing.
TIERS = {
    "diagnostic": {
        "label": "Paid Diagnostic / Readiness Review",
        "billing_model": "one_time",
        "annual_price_min": 5_000,
        "annual_price_max": 10_000,
        "annual_price_label": "$5,000–$10,000",
        "portal_access": False,
        "portal_days": 30,
        "monthly_rescan": False,
        "dark_web": None,
        "threat_feed": "cisa_kev",
        "phishing": False,
        "tasks": False,
        "compliance_tracking": "snapshot",
        "advisor_review": "deliverable_only",
        "monthly_call": None,
        "board_report": False,
        "active_validation_included": False,
        "included_services": [
            "External readiness scan",
            "Compliance gap snapshot mapped to your primary framework",
            "90-day remediation roadmap",
            "Executive summary with named advisor sign-off",
            "Read-only deliverable hand-off (PDF + audit ZIP)",
        ],
    },
    "essentials": {
        "label": "Essentials",
        "billing_model": "annual_prepaid",
        "annual_price": 24_000,
        "annual_price_label": "$24,000 / year",
        "portal_access": True,
        "portal_days": None,
        "monthly_rescan": True,
        "dark_web": "weekly",
        "threat_feed": "cisa_kev",
        "phishing": False,
        "tasks": True,
        "compliance_tracking": "monthly",
        "advisor_review": "monthly",
        "monthly_call": 30,
        "board_report": False,
        "active_validation_included": False,
        "included_services": [
            "Customer portal with score, tasks, and audit-ready evidence",
            "Monthly external scan + advisor-reviewed report",
            "Compliance mapping kept current to your primary framework",
            "Weekly dark-web check (with HIBP key)",
            "CISA threat-intel alerts filtered to your stack",
            "WISP + 8 supporting policies with annual refresh",
            "30-minute monthly advisor review call",
        ],
    },
    "professional": {
        "label": "Professional",
        "billing_model": "annual_prepaid",
        "annual_price": 48_000,
        "annual_price_label": "$48,000 / year",
        "portal_access": True,
        "portal_days": None,
        "monthly_rescan": True,
        "dark_web": "daily",
        "threat_feed": "full",
        "phishing": True,
        "tasks": True,
        "compliance_tracking": "continuous",
        "advisor_review": "continuous",
        "monthly_call": 60,
        "board_report": True,
        "active_validation_included": True,
        "included_services": [
            "Everything in Essentials",
            "Daily dark-web monitoring (with HIBP key)",
            "Quarterly authorized active security validation (scope + signed authorization required)",
            "Quarterly phishing simulation (GoPhish required)",
            "Continuous compliance tracking across applicable frameworks",
            "60-minute monthly advisor review call",
            "Quarterly board-ready report",
            "Incident response coordination + named advisor on call",
        ],
    },
    "enterprise_plus": {
        "label": "Enterprise+",
        "billing_model": "annual_prepaid",
        "annual_price_min": 96_000,
        "annual_price_label": "From $96,000 / year (custom)",
        "portal_access": True,
        "portal_days": None,
        "monthly_rescan": True,
        "dark_web": "daily",
        "threat_feed": "full",
        "phishing": True,
        "tasks": True,
        "compliance_tracking": "continuous",
        "advisor_review": "continuous",
        "monthly_call": 60,
        "board_report": True,
        "active_validation_included": True,
        "included_services": [
            "Everything in Professional",
            "Multi-framework continuous compliance (SOC 2 + HIPAA + ISO 27001 + NIS2/DORA where applicable)",
            "Unlimited authorized active security validation within agreed scope",
            "Dedicated named advisor + 4-hour response SLA",
            "Custom data residency (US / EU / UK / IN / AU)",
            "BYOK / SSO (SAML or OIDC) on the customer portal",
            "Branded trust-center page",
            "Annual on-site visit",
        ],
    },
}

# Backwards-compatible aliases for any legacy data on disk.
TIER_ALIASES = {
    "assessment": "diagnostic",
    "basic": "essentials",
    "pro": "professional",
}


def normalize_tier(tier: str) -> str:
    return TIER_ALIASES.get(tier, tier) if tier in TIER_ALIASES else tier


def annual_revenue_for_tier(tier: str) -> int:
    """ARR contribution for a given tier. Diagnostic is one-time → 0 ARR."""
    cfg = TIERS.get(normalize_tier(tier))
    if not cfg:
        return 0
    if cfg.get("billing_model") != "annual_prepaid":
        return 0
    return cfg.get("annual_price") or cfg.get("annual_price_min") or 0


def is_paid_tier(tier: str) -> bool:
    """Diagnostic and the three retainers are all 'paid'. Anything else is not."""
    return normalize_tier(tier) in TIERS


def has_portal_access(tier: str) -> bool:
    cfg = TIERS.get(normalize_tier(tier))
    return bool(cfg and cfg.get("portal_access"))


def _client_dir(client_id: str) -> Path:
    d = CLIENTS_DIR / client_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_profile(client_id: str) -> dict:
    p = _client_dir(client_id) / "profile.json"
    if p.exists():
        return json.loads(p.read_text())
    return {}


def _save_profile(client_id: str, profile: dict):
    p = _client_dir(client_id) / "profile.json"
    p.write_text(json.dumps(profile, indent=2, default=str))


def create_client(client_id: str, company_name: str, domain: str,
                  industry: str = "general", tier: str = "diagnostic",
                  contact_name: str = "", contact_email: str = "",
                  contact_title: str = "") -> dict:
    tier = normalize_tier(tier)
    profile = _load_profile(client_id)
    profile.update({
        "client_id": client_id,
        "company_name": company_name,
        "domain": domain,
        "industry": industry,
        "tier": tier,
        "contact_name": contact_name,
        "contact_email": contact_email,
        "contact_title": contact_title,
        "created_at": profile.get("created_at", datetime.utcnow().isoformat()),
        "score_history": profile.get("score_history", []),
        "frameworks": profile.get("frameworks", []),
        "tech_stack": profile.get("tech_stack", []),
        "stripe_customer_id": profile.get("stripe_customer_id", ""),
        "stripe_subscription_id": profile.get("stripe_subscription_id", ""),
        "stripe_invoice_id": profile.get("stripe_invoice_id", ""),
        "payment_status": profile.get("payment_status", "none"),
        "paid_at": profile.get("paid_at", ""),
    })
    _save_profile(client_id, profile)
    for sub in ["scans", "reports", "policies", "alerts"]:
        (_client_dir(client_id) / sub).mkdir(exist_ok=True)
    return profile


def set_portal_password(client_id: str, password: str, *, enforce_policy: bool = True):
    """Set/replace the customer portal password. Enforces the strength policy
    by default. Pass enforce_policy=False to bypass (e.g., legacy migrations);
    don't do that for new customer-supplied passwords."""
    # The test harness sets BYPASS_PASSWORD_POLICY=1 so legacy short fixtures
    # don't have to be rewritten. Never set this in production.
    if enforce_policy and os.getenv("BYPASS_PASSWORD_POLICY", "").lower() not in ("1", "true", "yes"):
        try:
            import auth_security as _as
            _as.validate_password(password)
        except Exception as e:
            raise
    profile = _load_profile(client_id)
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    profile["auth"] = {
        "password_hash": hashed,
        "created_at": datetime.utcnow().isoformat(),
        "last_password_set_at": datetime.utcnow().isoformat(),
    }
    # Invalidate any outstanding reset nonce on success.
    profile.pop("reset_token_nonce", None)
    profile.pop("reset_token_expiry", None)
    # MFA placeholder for the customer roadmap. Never claim enabled until built.
    profile.setdefault("mfa_enabled", False)
    profile.setdefault("mfa_method", "")
    _save_profile(client_id, profile)


def store_reset_token_nonce(client_id: str, nonce: str, expiry_epoch: int):
    profile = _load_profile(client_id)
    profile["reset_token_nonce"] = nonce
    profile["reset_token_expiry"] = expiry_epoch
    _save_profile(client_id, profile)


def consume_reset_token_nonce(client_id: str, nonce: str) -> bool:
    """Single-use semantics: the stored nonce must match. Returns True iff
    the nonce was the live one. The caller should set a new password
    immediately on success — set_portal_password() clears the nonce."""
    profile = _load_profile(client_id)
    stored = profile.get("reset_token_nonce", "")
    if not stored or stored != nonce:
        return False
    return True


def verify_password(client_id: str, password: str) -> bool:
    profile = _load_profile(client_id)
    auth = profile.get("auth", {})
    stored = auth.get("password_hash", "")
    if not stored:
        return False
    return bcrypt.checkpw(password.encode(), stored.encode())


def generate_magic_link(client_id: str) -> str:
    token = secrets.token_urlsafe(48)
    profile = _load_profile(client_id)
    profile["magic_token"] = token
    profile["magic_token_expires"] = (datetime.utcnow() + timedelta(days=7)).isoformat()
    _save_profile(client_id, profile)
    return token


def verify_magic_token(client_id: str, token: str) -> bool:
    profile = _load_profile(client_id)
    stored = profile.get("magic_token", "")
    expires = profile.get("magic_token_expires", "")
    if not stored or stored != token:
        return False
    if expires and datetime.fromisoformat(expires) < datetime.utcnow():
        return False
    # Auto-extend if close to expiry (within 2 days)
    if expires:
        exp_dt = datetime.fromisoformat(expires)
        if (exp_dt - datetime.utcnow()).days < 2:
            profile["magic_token_expires"] = (datetime.utcnow() + timedelta(days=7)).isoformat()
            _save_profile(client_id, profile)
    return True


def create_jwt(client_id: str) -> str:
    payload = {
        "client_id": client_id,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRY_DAYS),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_jwt(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("client_id")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def get_client(client_id: str) -> Optional[dict]:
    profile = _load_profile(client_id)
    return profile if profile.get("client_id") else None


def update_field(client_id: str, field: str, value) -> bool:
    """Update a single field in client profile."""
    profile = _load_profile(client_id)
    if not profile.get("client_id"):
        return False
    profile[field] = value
    _save_profile(client_id, profile)
    return True


def find_by_domain(domain: str) -> Optional[dict]:
    """Find a client by their domain. Returns profile or None."""
    if not CLIENTS_DIR.exists():
        return None
    for d in CLIENTS_DIR.iterdir():
        if d.is_dir() and (d / "profile.json").exists():
            profile = json.loads((d / "profile.json").read_text())
            if profile.get("domain") == domain:
                return profile
    return None


def save_call_notes(client_id: str, notes: str, call_date: str = None):
    """Save notes from a monthly call."""
    client_dir = _client_dir(client_id)
    notes_file = client_dir / "call_notes.json"
    existing = json.loads(notes_file.read_text()) if notes_file.exists() else []
    existing.append({
        "date": call_date or datetime.utcnow().strftime("%Y-%m-%d"),
        "notes": notes,
    })
    notes_file.write_text(json.dumps(existing[-12:], indent=2))


def get_latest_call_notes(client_id: str) -> str:
    """Get notes from last month's call for agenda carry-forward."""
    client_dir = _client_dir(client_id)
    notes_file = client_dir / "call_notes.json"
    if not notes_file.exists():
        return "First month — no previous call notes."
    notes = json.loads(notes_file.read_text())
    return notes[-1]["notes"] if notes else "First month — no previous call notes."


def log_communication(client_id: str, comm_type: str, subject: str, recipient: str):
    """Log every email/alert sent to client for audit trail."""
    log_dir = _client_dir(client_id) / "communications"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "log.jsonl"
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": comm_type,
        "subject": subject,
        "recipient": recipient,
    }
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")


def get_tier_config(tier: str) -> dict:
    return TIERS.get(normalize_tier(tier), TIERS["diagnostic"])


def list_active_clients(tier_filter: Optional[str] = None) -> list:
    if not CLIENTS_DIR.exists():
        return []
    clients = []
    for d in CLIENTS_DIR.iterdir():
        if d.is_dir() and (d / "profile.json").exists():
            profile = json.loads((d / "profile.json").read_text())
            if tier_filter and profile.get("tier") != tier_filter:
                continue
            if profile.get("tier") in ("basic", "pro"):
                clients.append(profile)
    return clients


def list_all_clients() -> list:
    if not CLIENTS_DIR.exists():
        return []
    clients = []
    for d in CLIENTS_DIR.iterdir():
        if d.is_dir() and (d / "profile.json").exists():
            profile = json.loads((d / "profile.json").read_text())
            if profile.get("client_id"):
                clients.append(profile)
    return clients


def add_score(client_id: str, score: int, grade: str):
    profile = _load_profile(client_id)
    history = profile.get("score_history", [])
    history.append({
        "score": score,
        "grade": grade,
        "date": date.today().isoformat(),
    })
    profile["score_history"] = history[-12:]
    profile["current_score"] = score
    profile["current_grade"] = grade
    _save_profile(client_id, profile)


def get_tasks(client_id: str) -> list:
    f = _client_dir(client_id) / "tasks.json"
    if f.exists():
        return json.loads(f.read_text())
    return []


def save_tasks(client_id: str, tasks: list):
    f = _client_dir(client_id) / "tasks.json"
    f.write_text(json.dumps(tasks, indent=2, default=str))


# ─── Compliance task workflow ─────────────────────────────────
#
# State machine (only the transitions on this list are valid):
#
#   open ──[customer/system: start]──> in_progress
#   open ──[customer: submit]────────> submitted_for_review
#   in_progress ──[customer: submit]─> submitted_for_review
#   submitted_for_review ──[advisor: verify]──> verified        ← only path to verified
#   submitted_for_review ──[advisor: reject]──> in_progress
#   any non-terminal ──[advisor/customer: defer]──> deferred
#   deferred ──[advisor: reopen]──> open
#
# Customers can NEVER mark a task verified. Verification is restricted to the
# advisor / system endpoints in main.py.

TASK_STATUS_OPEN = "open"
TASK_STATUS_IN_PROGRESS = "in_progress"
TASK_STATUS_SUBMITTED = "submitted_for_review"
TASK_STATUS_VERIFIED = "verified"
TASK_STATUS_DEFERRED = "deferred"

TASK_STATUSES = (
    TASK_STATUS_OPEN, TASK_STATUS_IN_PROGRESS, TASK_STATUS_SUBMITTED,
    TASK_STATUS_VERIFIED, TASK_STATUS_DEFERRED,
)

# Customer-safe display labels.
TASK_STATUS_LABELS = {
    TASK_STATUS_OPEN: "Open",
    TASK_STATUS_IN_PROGRESS: "In progress",
    TASK_STATUS_SUBMITTED: "Submitted for review",
    TASK_STATUS_VERIFIED: "Verified",
    TASK_STATUS_DEFERRED: "Deferred",
}

TASK_OWNER_CLIENT = "Client"
TASK_OWNER_ADVISOR = "Advisor"
TASK_OWNER_SYSTEM = "System"

TASK_VERIFICATION_METHODS = (
    "self_attestation",
    "document_review",
    "screenshot",
    "configuration_check",
    "rescan",
    "advisor_inspection",
)


def _new_task_id(tasks: list) -> str:
    return f"task_{len(tasks)+1:03d}"


def _default_evidence_required(severity: str, category: str) -> list[str]:
    """Heuristic: seed evidence requirements based on severity + category.
    Operators can override per-task via update_task_fields()."""
    evidence: list[str] = []
    s = (severity or "").upper()
    c = (category or "").lower()
    if s in ("CRITICAL", "HIGH"):
        evidence.append("Configuration screenshot or screen recording showing the fix")
        evidence.append("Date the fix was applied")
    if "policy" in c or "wisp" in c:
        evidence.append("Signed policy acknowledgment")
    if "email" in c or "spf" in c or "dmarc" in c or "dkim" in c:
        evidence.append("DNS record screenshot post-change")
    if "ssl" in c or "tls" in c or "cert" in c:
        evidence.append("Certificate detail showing valid expiry")
    if not evidence:
        evidence.append("Brief written attestation that the fix is in place")
    return evidence


def _default_verification_method(severity: str, category: str) -> str:
    s = (severity or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return "advisor_inspection"
    c = (category or "").lower()
    if "email" in c or "ssl" in c or "tls" in c or "dns" in c:
        return "rescan"
    if "config" in c:
        return "configuration_check"
    return "self_attestation"


def add_task(
    client_id: str,
    title: str,
    severity: str,
    category: str,
    description: str = "",
    fix: str = "",
    verifiable: str = "auto",
    *,
    business_impact: str = "",
    owner: str = TASK_OWNER_CLIENT,
    due_days: int = 30,
    evidence_required: Optional[list] = None,
    verification_method: str = "",
) -> dict:
    """Create a remediation task. Severity drives sensible defaults for
    `evidence_required` and `verification_method` if not supplied."""
    tasks = get_tasks(client_id)
    task = {
        "id": _new_task_id(tasks),
        "title": title,
        "severity": severity,
        "business_impact": business_impact or _default_business_impact(severity),
        "category": category,
        "description": description,
        "fix": fix,
        "verifiable": verifiable,                # legacy field, retained
        "owner": owner,
        "status": TASK_STATUS_OPEN,
        "created_at": date.today().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "due_date": (date.today() + timedelta(days=due_days)).isoformat(),
        "evidence_required": list(evidence_required) if evidence_required is not None
                             else _default_evidence_required(severity, category),
        "evidence_attached": [],                 # list of {filename, uploaded_at, uploaded_by}
        "customer_notes": [],                    # list of {note, at, by}
        "advisor_notes": [],                     # list of {note, at, by}
        "verification_method": verification_method or
                               _default_verification_method(severity, category),
        "submitted_at": None,
        "submitted_by": "",
        "verified_at": None,
        "verified_by": "",
        "deferred_until": None,
        "deferral_reason": "",
        "resolved_at": None,                     # legacy field — set when verified
    }
    tasks.append(task)
    save_tasks(client_id, tasks)
    return task


def _default_business_impact(severity: str) -> str:
    return {
        "CRITICAL": "May expose customer data or trigger regulatory reporting if not fixed.",
        "HIGH": "Material risk to security posture and audit findings.",
        "MEDIUM": "Increases attack surface; recommended fix during the next cycle.",
        "LOW": "Hygiene item; resolve when convenient.",
    }.get((severity or "").upper(), "Reduces overall security posture.")


def _find_task(tasks: list, task_id: str) -> Optional[dict]:
    for t in tasks:
        if t.get("id") == task_id:
            return t
    return None


# Allowed transitions for safety. A row maps (current_status, action) -> new_status.
_VALID_TRANSITIONS = {
    ("open", "start"):                 TASK_STATUS_IN_PROGRESS,
    ("open", "submit"):                TASK_STATUS_SUBMITTED,
    ("in_progress", "submit"):         TASK_STATUS_SUBMITTED,
    ("submitted_for_review", "verify"): TASK_STATUS_VERIFIED,
    ("submitted_for_review", "reject"): TASK_STATUS_IN_PROGRESS,
    ("open", "defer"):                 TASK_STATUS_DEFERRED,
    ("in_progress", "defer"):          TASK_STATUS_DEFERRED,
    ("submitted_for_review", "defer"): TASK_STATUS_DEFERRED,
    ("deferred", "reopen"):            TASK_STATUS_OPEN,
}


class TaskTransitionError(Exception):
    """Raised when an action is not legal from the current status."""


def _apply_transition(task: dict, action: str) -> str:
    current = task.get("status", TASK_STATUS_OPEN)
    key = (current, action)
    if key not in _VALID_TRANSITIONS:
        raise TaskTransitionError(
            f"Cannot {action} task in status '{current}'"
        )
    return _VALID_TRANSITIONS[key]


def update_task_fields(client_id: str, task_id: str, fields: dict) -> dict:
    """Operator-only generic field update with an explicit allowlist."""
    allowed = {
        "title", "severity", "business_impact", "category", "description",
        "fix", "owner", "due_date", "evidence_required",
        "verification_method",
    }
    tasks = get_tasks(client_id)
    t = _find_task(tasks, task_id)
    if not t:
        raise KeyError(task_id)
    for k, v in fields.items():
        if k in allowed:
            t[k] = v
    t["updated_at"] = datetime.utcnow().isoformat()
    save_tasks(client_id, tasks)
    return t


def submit_task_for_review(
    client_id: str, task_id: str, by: str, notes: str = "",
    evidence: Optional[list] = None,
) -> dict:
    """Customer action. Transitions Open or In progress → Submitted for review.
    Never reaches Verified — that requires the advisor."""
    tasks = get_tasks(client_id)
    t = _find_task(tasks, task_id)
    if not t:
        raise KeyError(task_id)
    new_status = _apply_transition(t, "submit")
    t["status"] = new_status
    t["submitted_at"] = datetime.utcnow().isoformat()
    t["submitted_by"] = by
    t["updated_at"] = t["submitted_at"]
    if notes:
        t["customer_notes"].append({
            "note": notes,
            "at": t["submitted_at"],
            "by": by,
        })
    for ev in (evidence or []):
        t["evidence_attached"].append({
            "filename": ev,
            "uploaded_at": t["submitted_at"],
            "uploaded_by": by,
        })
    save_tasks(client_id, tasks)
    return t


def start_task(client_id: str, task_id: str, by: str) -> dict:
    tasks = get_tasks(client_id)
    t = _find_task(tasks, task_id)
    if not t:
        raise KeyError(task_id)
    t["status"] = _apply_transition(t, "start")
    t["updated_at"] = datetime.utcnow().isoformat()
    save_tasks(client_id, tasks)
    return t


def verify_task(
    client_id: str, task_id: str, by: str,
    method: str = "", note: str = "",
    reviewer_credential: str = "",
    client_facing_recommendation: str = "",
    internal_operator_notes: str = "",
) -> dict:
    """Advisor / system action only. Sole path to status='verified'.
    Caller (route layer) MUST gate this on operator authentication.

    Also writes a paired advisor-review record so task verification flows
    through the same metadata system as reports and policies.
    """
    tasks = get_tasks(client_id)
    t = _find_task(tasks, task_id)
    if not t:
        raise KeyError(task_id)
    new_status = _apply_transition(t, "verify")
    now = datetime.utcnow().isoformat()
    today = date.today().isoformat()
    t["status"] = new_status
    t["verified_at"] = now
    t["verified_by"] = by
    t["resolved_at"] = today  # legacy field
    t["updated_at"] = now
    if method:
        t["verification_method"] = method
    if note:
        t["advisor_notes"].append({"note": note, "at": now, "by": by})
    save_tasks(client_id, tasks)

    # Mirror the verification into the unified advisor-review store.
    try:
        import advisor_review as _ar
        _ar.set_review(
            client_id, _ar.task_key(task_id),
            prepared_by="System",
            reviewed_by=by, reviewed_on=today,
            review_status=_ar.REVIEW_APPROVED,
            advisor_notes=note or "",
            client_facing_recommendation=client_facing_recommendation or "",
            internal_operator_notes=internal_operator_notes or "",
            reviewer_credential=reviewer_credential or "",
            sign_off_timestamp=now,
        )
    except Exception:
        # Review store is best-effort; task verification still succeeds.
        pass
    return t


def reject_task(client_id: str, task_id: str, by: str, reason: str) -> dict:
    """Advisor sends a submitted task back to In progress with feedback."""
    tasks = get_tasks(client_id)
    t = _find_task(tasks, task_id)
    if not t:
        raise KeyError(task_id)
    t["status"] = _apply_transition(t, "reject")
    now = datetime.utcnow().isoformat()
    t["updated_at"] = now
    t["advisor_notes"].append({
        "note": f"Returned for additional work: {reason}",
        "at": now, "by": by,
    })
    save_tasks(client_id, tasks)
    return t


def defer_task(
    client_id: str, task_id: str, by: str,
    until: str = "", reason: str = "",
) -> dict:
    tasks = get_tasks(client_id)
    t = _find_task(tasks, task_id)
    if not t:
        raise KeyError(task_id)
    t["status"] = _apply_transition(t, "defer")
    now = datetime.utcnow().isoformat()
    t["deferred_until"] = until
    t["deferral_reason"] = reason
    t["updated_at"] = now
    t["advisor_notes"].append({
        "note": f"Deferred until {until or 'next cycle'}: {reason}",
        "at": now, "by": by,
    })
    save_tasks(client_id, tasks)
    return t


def reopen_task(client_id: str, task_id: str, by: str) -> dict:
    tasks = get_tasks(client_id)
    t = _find_task(tasks, task_id)
    if not t:
        raise KeyError(task_id)
    t["status"] = _apply_transition(t, "reopen")
    t["updated_at"] = datetime.utcnow().isoformat()
    save_tasks(client_id, tasks)
    return t


def add_customer_note(client_id: str, task_id: str, note: str, by: str) -> dict:
    tasks = get_tasks(client_id)
    t = _find_task(tasks, task_id)
    if not t:
        raise KeyError(task_id)
    now = datetime.utcnow().isoformat()
    t["customer_notes"].append({"note": note, "at": now, "by": by})
    t["updated_at"] = now
    save_tasks(client_id, tasks)
    return t


def add_advisor_note(client_id: str, task_id: str, note: str, by: str) -> dict:
    tasks = get_tasks(client_id)
    t = _find_task(tasks, task_id)
    if not t:
        raise KeyError(task_id)
    now = datetime.utcnow().isoformat()
    t["advisor_notes"].append({"note": note, "at": now, "by": by})
    t["updated_at"] = now
    save_tasks(client_id, tasks)
    return t


def attach_evidence(client_id: str, task_id: str, filename: str, by: str) -> dict:
    tasks = get_tasks(client_id)
    t = _find_task(tasks, task_id)
    if not t:
        raise KeyError(task_id)
    now = datetime.utcnow().isoformat()
    t["evidence_attached"].append({
        "filename": filename, "uploaded_at": now, "uploaded_by": by,
    })
    t["updated_at"] = now
    save_tasks(client_id, tasks)
    return t


def update_task_status(client_id: str, task_id: str, status: str):
    """Legacy generic status setter. Refuses to set 'verified' to preserve the
    rule that only verify_task() may mark a task verified."""
    if status == TASK_STATUS_VERIFIED:
        raise TaskTransitionError(
            "Use verify_task() (operator-only) to mark a task verified."
        )
    tasks = get_tasks(client_id)
    t = _find_task(tasks, task_id)
    if not t:
        return
    t["status"] = status
    t["updated_at"] = datetime.utcnow().isoformat()
    if status == "resolved":
        # Legacy callers that used "resolved" predate the new model; treat as
        # a customer submission.
        t["status"] = TASK_STATUS_SUBMITTED
        t["submitted_at"] = datetime.utcnow().isoformat()
        t["submitted_by"] = "legacy"
    save_tasks(client_id, tasks)


def get_alerts(client_id: str, limit: int = 10, alert_type: str = None) -> list:
    alerts_dir = _client_dir(client_id) / "alerts"
    if not alerts_dir.exists():
        return []
    files = sorted(alerts_dir.glob("*.json"), reverse=True)
    alerts = []
    for f in files:
        alert = json.loads(f.read_text())
        if alert_type and alert.get("type") != alert_type:
            continue
        alerts.append(alert)
        if len(alerts) >= limit:
            break
    return alerts


def save_alert(client_id: str, alert: dict):
    alerts_dir = _client_dir(client_id) / "alerts"
    alerts_dir.mkdir(exist_ok=True)
    alert_id = alert.get("id", f"{alert.get('type', 'alert')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
    alert["id"] = alert_id
    alert.setdefault("status", "new")
    alert.setdefault("emailed", False)
    filename = f"{alert_id}.json"
    (alerts_dir / filename).write_text(json.dumps(alert, indent=2, default=str))
    return alert_id


def get_reports(client_id: str) -> list:
    reports_dir = _client_dir(client_id) / "reports"
    if not reports_dir.exists():
        return []
    files = sorted(
        [f for f in reports_dir.iterdir() if f.suffix in (".pdf", ".json") and f.name != "INDEX.md"],
        reverse=True,
    )
    return [{"filename": f.name, "path": str(f), "date": f.stem[:10] if len(f.stem) >= 10 else ""} for f in files]


def get_policies(client_id: str) -> list:
    policies_dir = _client_dir(client_id) / "policies"
    if not policies_dir.exists():
        return []
    files = sorted(policies_dir.glob("*.*"))
    return [{"filename": f.name, "path": str(f)} for f in files]


def get_scans(client_id: str) -> list:
    scans_dir = _client_dir(client_id) / "scans"
    if not scans_dir.exists():
        return []
    files = sorted(scans_dir.glob("*.json"), reverse=True)
    return [{"filename": f.name, "path": str(f), "date": f.stem[:10] if len(f.stem) >= 10 else ""} for f in files]


# ─── Premium qualification ─────────────────────────────────────

QUALIFICATIONS_DIR = DATA_DIR / "qualifications"


def save_qualification(submission: dict, result: dict) -> str:
    """Persist a qualification submission + evaluator result. Returns the record id."""
    QUALIFICATIONS_DIR.mkdir(parents=True, exist_ok=True)
    record_id = secrets.token_urlsafe(12)
    record = {
        "id": record_id,
        "submitted_at": datetime.utcnow().isoformat(),
        "submission": submission,
        "result": result,
    }
    (QUALIFICATIONS_DIR / f"{record_id}.json").write_text(
        json.dumps(record, indent=2, default=str)
    )
    return record_id


def get_qualification(record_id: str) -> dict:
    p = QUALIFICATIONS_DIR / f"{record_id}.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text())


# ─── Legal authorization records ───────────────────────────────

def _legal_auth_path(client_id: str) -> Path:
    return _client_dir(client_id) / "legal_authorization.json"


def get_legal_authorization(client_id: str) -> dict:
    p = _legal_auth_path(client_id)
    if not p.exists():
        return {"client_id": client_id}
    return json.loads(p.read_text())


def save_legal_authorization(client_id: str, record: dict) -> dict:
    record["client_id"] = client_id
    record["updated_at"] = datetime.utcnow().isoformat()
    record.setdefault("created_at", datetime.utcnow().isoformat())
    _legal_auth_path(client_id).write_text(json.dumps(record, indent=2, default=str))
    return record


def append_authorization_audit(client_id: str, event: dict) -> None:
    """Append-only audit trail of authorization-related events."""
    p = _client_dir(client_id) / "authorization_audit.json"
    log = []
    if p.exists():
        try:
            log = json.loads(p.read_text())
        except Exception:
            log = []
    event = dict(event)
    event.setdefault("at", datetime.utcnow().isoformat())
    log.append(event)
    p.write_text(json.dumps(log, indent=2, default=str))


def list_qualifications(status: Optional[str] = None) -> list:
    if not QUALIFICATIONS_DIR.exists():
        return []
    out = []
    for f in sorted(QUALIFICATIONS_DIR.glob("*.json"), reverse=True):
        try:
            rec = json.loads(f.read_text())
            if status and rec.get("result", {}).get("status") != status:
                continue
            out.append(rec)
        except Exception:
            continue
    return out
