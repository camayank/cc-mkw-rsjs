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

TIERS = {
    "assessment": {"label": "Assessment", "portal_days": 90, "monthly_rescan": False, "dark_web": None, "threat_feed": None, "phishing": False, "tasks": False, "compliance_tracking": "snapshot", "monthly_call": None, "board_report": False},
    "basic": {"label": "vCISO Basic", "portal_days": None, "monthly_rescan": True, "dark_web": "weekly", "threat_feed": "cisa_kev", "phishing": False, "tasks": True, "compliance_tracking": "monthly", "monthly_call": 30, "board_report": False},
    "pro": {"label": "vCISO Pro", "portal_days": None, "monthly_rescan": True, "dark_web": "daily", "threat_feed": "full", "phishing": True, "tasks": True, "compliance_tracking": "continuous", "monthly_call": 60, "board_report": True},
}


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
                  industry: str = "general", tier: str = "assessment",
                  contact_name: str = "", contact_email: str = "",
                  contact_title: str = "") -> dict:
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


def set_portal_password(client_id: str, password: str):
    profile = _load_profile(client_id)
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    profile["auth"] = {
        "password_hash": hashed,
        "created_at": datetime.utcnow().isoformat(),
    }
    _save_profile(client_id, profile)


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
    return TIERS.get(tier, TIERS["assessment"])


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


def add_task(client_id: str, title: str, severity: str, category: str,
             description: str = "", fix: str = "", verifiable: str = "auto") -> dict:
    tasks = get_tasks(client_id)
    task = {
        "id": f"task_{len(tasks)+1:03d}",
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "fix": fix,
        "verifiable": verifiable,
        "status": "open",
        "created_at": date.today().isoformat(),
        "due_date": (date.today() + timedelta(days=30)).isoformat(),
        "resolved_at": None,
    }
    tasks.append(task)
    save_tasks(client_id, tasks)
    return task


def update_task_status(client_id: str, task_id: str, status: str):
    tasks = get_tasks(client_id)
    for t in tasks:
        if t["id"] == task_id:
            t["status"] = status
            if status == "resolved":
                t["resolved_at"] = date.today().isoformat()
            break
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
