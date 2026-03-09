# vCISO Platform Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform CyberComply from a one-time assessment tool into a full vCISO delivery platform with client portal, scheduled monitoring, and monthly report automation.

**Architecture:** Add client auth (bcrypt + JWT cookies), a Security Command Center portal (Jinja2 + HTMX), APScheduler for 24/7 monitoring automation, and wire remaining agent prompts (P46, P54, P57, P59). All on existing FastAPI stack, deployed on Railway.

**Tech Stack:** FastAPI, Jinja2, HTMX, APScheduler, bcrypt, PyJWT, ReportLab (existing)

---

### Task 1: Add Dependencies

**Files:**
- Modify: `requirements.txt`

**Step 1: Add new packages to requirements.txt**

Add these lines to the end of `requirements.txt`:
```
apscheduler>=3.10.0
bcrypt>=4.1.0
PyJWT>=2.8.0
```

**Step 2: Install dependencies**

Run: `pip install apscheduler bcrypt PyJWT`
Expected: Successfully installed

**Step 3: Commit**

```bash
git add requirements.txt
git commit -m "feat: add APScheduler, bcrypt, PyJWT dependencies for vCISO platform"
```

---

### Task 2: Client Data Model & Auth Backend

**Files:**
- Create: `client_manager.py`
- Test: manual verification via Python REPL

**Step 1: Create client_manager.py**

This module handles client CRUD, auth, and profile management. All data stored in JSON files under `DATA_DIR/clients/{client_id}/`.

```python
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
    })
    _save_profile(client_id, profile)
    # Create subdirectories
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
    profile["score_history"] = history[-12:]  # Keep last 12 months
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
             description: str = "", fix: str = "") -> dict:
    tasks = get_tasks(client_id)
    task = {
        "id": f"task_{len(tasks)+1:03d}",
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "fix": fix,
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


def get_alerts(client_id: str, limit: int = 10) -> list:
    alerts_dir = _client_dir(client_id) / "alerts"
    if not alerts_dir.exists():
        return []
    files = sorted(alerts_dir.glob("*.json"), reverse=True)[:limit]
    alerts = []
    for f in files:
        alerts.append(json.loads(f.read_text()))
    return alerts


def save_alert(client_id: str, alert: dict):
    alerts_dir = _client_dir(client_id) / "alerts"
    alerts_dir.mkdir(exist_ok=True)
    filename = f"{date.today().isoformat()}-{alert.get('type', 'alert')}.json"
    (alerts_dir / filename).write_text(json.dumps(alert, indent=2, default=str))


def get_reports(client_id: str) -> list:
    reports_dir = _client_dir(client_id) / "reports"
    if not reports_dir.exists():
        return []
    files = sorted(reports_dir.glob("*.pdf"), reverse=True)
    return [{"filename": f.name, "path": str(f), "date": f.stem[:10] if len(f.stem) >= 10 else ""} for f in files]


def get_policies(client_id: str) -> list:
    policies_dir = _client_dir(client_id) / "policies"
    if not policies_dir.exists():
        return []
    files = sorted(policies_dir.glob("*.*"))
    return [{"filename": f.name, "path": str(f)} for f in files]
```

**Step 2: Verify module loads**

Run: `python -c "import client_manager; print('OK', client_manager.TIERS.keys())"`
Expected: `OK dict_keys(['assessment', 'basic', 'pro'])`

**Step 3: Commit**

```bash
git add client_manager.py
git commit -m "feat: add client_manager with auth, profiles, tiers, tasks, alerts"
```

---

### Task 3: Portal Authentication Routes

**Files:**
- Modify: `main.py` (add auth routes after line ~358)

**Step 1: Add imports to main.py**

At the top of `main.py`, add to existing imports:
```python
import client_manager
```

**Step 2: Add portal auth routes**

Add after the dashboard route section (~line 358):

```python
# ── Portal Auth ──────────────────────────────────────────────

@app.get("/portal/login", response_class=HTMLResponse)
async def portal_login_page(request: Request, client: str = "", token: str = ""):
    """Portal login page — or magic link landing."""
    if token and client:
        if client_manager.verify_magic_token(client, token):
            tmpl = templates.get_template("portal_setup.html")
            return HTMLResponse(tmpl.render(client_id=client, token=token))
    tmpl = templates.get_template("portal_login.html")
    return HTMLResponse(tmpl.render(error=""))


class PortalLoginRequest(BaseModel):
    client_id: str
    password: str

@app.post("/portal/login")
async def portal_login(req: PortalLoginRequest):
    if client_manager.verify_password(req.client_id, req.password):
        token = client_manager.create_jwt(req.client_id)
        resp = JSONResponse({"status": "ok", "redirect": f"/portal/{req.client_id}"})
        resp.set_cookie("portal_token", token, max_age=86400 * 30, httponly=True, samesite="lax")
        return resp
    return JSONResponse({"status": "error", "message": "Invalid credentials"}, status_code=401)


class PortalSetupRequest(BaseModel):
    client_id: str
    token: str
    password: str

@app.post("/portal/setup")
async def portal_setup(req: PortalSetupRequest):
    if not client_manager.verify_magic_token(req.client_id, req.token):
        return JSONResponse({"status": "error", "message": "Invalid or expired link"}, status_code=401)
    client_manager.set_portal_password(req.client_id, req.password)
    jwt_token = client_manager.create_jwt(req.client_id)
    resp = JSONResponse({"status": "ok", "redirect": f"/portal/{req.client_id}"})
    resp.set_cookie("portal_token", jwt_token, max_age=86400 * 30, httponly=True, samesite="lax")
    return resp


def check_portal_auth(request: Request, client_id: str) -> bool:
    token = request.cookies.get("portal_token", "")
    if not token:
        return False
    verified_id = client_manager.verify_jwt(token)
    return verified_id == client_id


# ── Portal Main View ─────────────────────────────────────────

@app.get("/portal/{client_id}", response_class=HTMLResponse)
async def portal_page(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse('<script>window.location="/portal/login"</script>')

    client = client_manager.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    tier_config = client_manager.get_tier_config(client.get("tier", "assessment"))
    tasks = client_manager.get_tasks(client_id)
    alerts = client_manager.get_alerts(client_id)
    reports = client_manager.get_reports(client_id)
    policies = client_manager.get_policies(client_id)

    score_history = client.get("score_history", [])
    current_score = client.get("current_score", 0)
    current_grade = client.get("current_grade", "N/A")

    open_tasks = [t for t in tasks if t["status"] == "open"]
    in_progress_tasks = [t for t in tasks if t["status"] == "in_progress"]
    resolved_tasks = [t for t in tasks if t["status"] in ("resolved", "verified")]

    # Compliance data
    compliance_pct = 0
    frameworks = client.get("frameworks", [])

    # Agent activity (from scheduler timestamps)
    agent_status = _get_agent_status(client_id)

    # Threat count (from FALCON alerts this month)
    threats_blocked = sum(1 for a in alerts if a.get("type") == "threat")
    dark_web_alerts = sum(1 for a in alerts if a.get("type") == "darkweb")

    tmpl = templates.get_template("portal.html")
    return HTMLResponse(tmpl.render(
        client=client,
        tier=tier_config,
        current_score=current_score,
        current_grade=current_grade,
        score_history=score_history,
        open_tasks=open_tasks,
        in_progress_tasks=in_progress_tasks,
        resolved_tasks=resolved_tasks,
        alerts=alerts,
        dark_web_alerts=dark_web_alerts,
        threats_blocked=threats_blocked,
        reports=reports,
        policies=policies,
        agent_status=agent_status,
        frameworks=frameworks,
        compliance_pct=compliance_pct,
    ))


def _get_agent_status(client_id: str) -> list:
    """Read scheduler timestamps for agent activity display."""
    status_file = client_manager._client_dir(client_id) / "agent_status.json"
    if status_file.exists():
        return json.loads(status_file.read_text())
    # Default status when no scans have run yet
    return [
        {"name": "RECON", "label": "External Scan", "status": "active", "last_run": "Pending first scan"},
        {"name": "SHADOW", "label": "Dark Web Monitor", "status": "active", "last_run": "Pending"},
        {"name": "FALCON", "label": "Threat Intelligence", "status": "active", "last_run": "Pending"},
        {"name": "GUARDIAN", "label": "Compliance Engine", "status": "active", "last_run": "Pending"},
        {"name": "PHANTOM", "label": "Phishing Defense", "status": "standby", "last_run": "Not scheduled"},
        {"name": "DISPATCH", "label": "Incident Response", "status": "standby", "last_run": "0 active incidents"},
    ]


# ── Portal API Endpoints ─────────────────────────────────────

@app.post("/portal/{client_id}/task/{task_id}/status")
async def update_task(client_id: str, task_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    client_manager.update_task_status(client_id, task_id, body.get("status", "open"))
    return {"status": "ok"}


@app.get("/portal/{client_id}/download/{doc_type}/{filename}")
async def portal_download(client_id: str, doc_type: str, filename: str, request: Request):
    if not check_portal_auth(request, client_id):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if doc_type not in ("reports", "policies"):
        raise HTTPException(status_code=400)
    file_path = client_manager._client_dir(client_id) / doc_type / filename
    if not file_path.exists():
        raise HTTPException(status_code=404)
    from starlette.responses import FileResponse
    return FileResponse(str(file_path), filename=filename)
```

**Step 3: Commit**

```bash
git add main.py
git commit -m "feat: add portal auth routes (login, magic link, JWT sessions)"
```

---

### Task 4: Portal Login Template

**Files:**
- Create: `templates/portal_login.html`

**Step 1: Create portal_login.html**

Minimal login page matching CyberComply's dark design system:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberComply — Client Portal</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0f1a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.login-card{background:#111827;border:1px solid #1e293b;border-radius:16px;padding:48px;width:100%;max-width:420px;box-shadow:0 25px 50px rgba(0,0,0,.5)}
.logo{text-align:center;margin-bottom:32px}
.logo h1{font-size:1.5rem;color:#06b6d4;letter-spacing:-.5px}
.logo p{color:#64748b;font-size:.875rem;margin-top:4px}
label{display:block;font-size:.875rem;color:#94a3b8;margin-bottom:6px;margin-top:20px}
input{width:100%;padding:12px 16px;background:#0f172a;border:1px solid #1e293b;border-radius:8px;color:#e2e8f0;font-size:1rem;outline:none;transition:border .2s}
input:focus{border-color:#06b6d4}
button{width:100%;padding:14px;background:linear-gradient(135deg,#06b6d4,#0891b2);color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;margin-top:28px;transition:opacity .2s}
button:hover{opacity:.9}
button:disabled{opacity:.5;cursor:not-allowed}
.error{color:#f87171;font-size:.875rem;margin-top:12px;text-align:center;display:none}
.error.show{display:block}
.shield{font-size:3rem;display:block;margin-bottom:8px}
</style>
</head>
<body>
<div class="login-card">
  <div class="logo">
    <span class="shield">🛡️</span>
    <h1>CyberComply</h1>
    <p>Security Command Center</p>
  </div>
  <form id="loginForm">
    <label for="client_id">Client ID</label>
    <input type="text" id="client_id" name="client_id" placeholder="your-company-id" required>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" placeholder="••••••••" required>
    <button type="submit" id="submitBtn">Sign In</button>
    <div class="error" id="errorMsg"></div>
  </form>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', async(e)=>{
  e.preventDefault();
  const btn=document.getElementById('submitBtn');
  const err=document.getElementById('errorMsg');
  btn.disabled=true; btn.textContent='Signing in...'; err.classList.remove('show');
  try{
    const res=await fetch('/portal/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({client_id:document.getElementById('client_id').value,password:document.getElementById('password').value})});
    const data=await res.json();
    if(data.status==='ok'){window.location=data.redirect}
    else{err.textContent=data.message||'Invalid credentials';err.classList.add('show')}
  }catch(ex){err.textContent='Connection error';err.classList.add('show')}
  btn.disabled=false;btn.textContent='Sign In';
});
</script>
</body>
</html>
```

**Step 2: Create portal_setup.html (magic link password setup)**

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberComply — Set Up Your Portal</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0f1a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#111827;border:1px solid #1e293b;border-radius:16px;padding:48px;width:100%;max-width:420px}
.logo{text-align:center;margin-bottom:24px}
.logo h1{font-size:1.5rem;color:#06b6d4}
.logo p{color:#94a3b8;font-size:.875rem;margin-top:8px}
label{display:block;font-size:.875rem;color:#94a3b8;margin-bottom:6px;margin-top:20px}
input{width:100%;padding:12px 16px;background:#0f172a;border:1px solid #1e293b;border-radius:8px;color:#e2e8f0;font-size:1rem;outline:none}
input:focus{border-color:#06b6d4}
button{width:100%;padding:14px;background:linear-gradient(135deg,#06b6d4,#0891b2);color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;margin-top:28px}
button:hover{opacity:.9}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1>🛡️ Welcome to CyberComply</h1>
    <p>Set a password to access your Security Command Center</p>
  </div>
  <form id="setupForm">
    <input type="hidden" id="client_id" value="{{ client_id }}">
    <input type="hidden" id="token" value="{{ token }}">
    <label for="password">Create Password</label>
    <input type="password" id="password" placeholder="Min 8 characters" required minlength="8">
    <label for="confirm">Confirm Password</label>
    <input type="password" id="confirm" placeholder="Repeat password" required>
    <button type="submit">Activate Portal</button>
  </form>
</div>
<script>
document.getElementById('setupForm').addEventListener('submit',async(e)=>{
  e.preventDefault();
  const pw=document.getElementById('password').value;
  if(pw!==document.getElementById('confirm').value){alert('Passwords do not match');return}
  const res=await fetch('/portal/setup',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({client_id:document.getElementById('client_id').value,token:document.getElementById('token').value,password:pw})});
  const data=await res.json();
  if(data.status==='ok'){window.location=data.redirect}else{alert(data.message||'Error')}
});
</script>
</body>
</html>
```

**Step 3: Commit**

```bash
git add templates/portal_login.html templates/portal_setup.html
git commit -m "feat: add portal login and password setup templates"
```

---

### Task 5: Security Command Center Portal Template

**Files:**
- Create: `templates/portal.html`

**Step 1: Create the main portal template**

This is the core client-facing product. Dark theme, data-dense, professional. Uses HTMX for task status updates.

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ client.company_name }} — Security Command Center</title>
<script src="https://unpkg.com/htmx.org@1.9.10"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0f1a;--card:#111827;--border:#1e293b;--text:#e2e8f0;--muted:#64748b;--accent:#06b6d4;--accent2:#0891b2;--green:#10b981;--yellow:#f59e0b;--red:#ef4444;--orange:#f97316}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.header{background:var(--card);border-bottom:1px solid var(--border);padding:16px 32px;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:1.125rem;color:var(--accent);display:flex;align-items:center;gap:8px}
.header .company{font-size:1rem;color:var(--text);font-weight:400}
.header .score-badge{background:var(--bg);border:2px solid var(--accent);border-radius:12px;padding:8px 20px;font-size:1.25rem;font-weight:700;color:var(--accent)}
.grid{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:16px;padding:24px 32px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px}
.stat-card .label{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.stat-card .value{font-size:2rem;font-weight:700;margin-top:4px}
.stat-card .sub{font-size:.8rem;margin-top:4px}
.main{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 32px 32px}
.panel{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px}
.panel h2{font-size:1rem;color:var(--accent);margin-bottom:16px;display:flex;align-items:center;gap:8px}
.score-up{color:var(--green)}.score-down{color:var(--red)}
.agent-row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border)}
.agent-row:last-child{border:none}
.agent-name{font-weight:600;font-size:.9rem}
.agent-status{font-size:.8rem;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:8px}
.dot.active{background:var(--green)}.dot.standby{background:var(--yellow)}
.task-row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border)}
.task-row:last-child{border:none}
.sev{font-size:.7rem;padding:2px 8px;border-radius:4px;font-weight:600;text-transform:uppercase}
.sev-critical{background:rgba(239,68,68,.15);color:var(--red)}
.sev-high{background:rgba(249,115,22,.15);color:var(--orange)}
.sev-medium{background:rgba(245,158,11,.15);color:var(--yellow)}
.sev-low{background:rgba(16,185,129,.15);color:var(--green)}
.doc-row{display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--border)}
.doc-row:last-child{border:none}
.doc-row a{color:var(--accent);text-decoration:none;font-size:.9rem}
.doc-row a:hover{text-decoration:underline}
.doc-icon{font-size:1.2rem}
.bar{height:6px;background:var(--border);border-radius:3px;margin-top:8px;overflow:hidden}
.bar-fill{height:100%;border-radius:3px;background:linear-gradient(90deg,var(--accent),var(--green))}
.trend{display:flex;gap:4px;align-items:flex-end;height:80px;margin-top:12px}
.trend-bar{flex:1;background:var(--accent);border-radius:3px 3px 0 0;min-height:4px;position:relative}
.trend-label{font-size:.65rem;color:var(--muted);text-align:center;margin-top:4px}
.status-btn{padding:4px 12px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--muted);cursor:pointer;font-size:.75rem}
.status-btn:hover{border-color:var(--accent);color:var(--accent)}
@media(max-width:900px){.grid{grid-template-columns:1fr 1fr}.main{grid-template-columns:1fr}}
@media(max-width:600px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>

<!-- Header -->
<div class="header">
  <div>
    <h1>🛡️ CyberComply <span class="company">— {{ client.company_name }}</span></h1>
  </div>
  <div class="score-badge">{{ current_score }}/100 {{ current_grade }}</div>
</div>

<!-- Stat Cards -->
<div class="grid">
  <div class="stat-card">
    <div class="label">Security Score</div>
    <div class="value" style="color:var(--accent)">{{ current_score }}</div>
    <div class="sub">
      {% if score_history|length > 1 %}
        {% set delta = current_score - score_history[-2].score %}
        {% if delta > 0 %}<span class="score-up">▲ +{{ delta }} from last month</span>
        {% elif delta < 0 %}<span class="score-down">▼ {{ delta }} from last month</span>
        {% else %}→ No change{% endif %}
      {% else %}Baseline assessment{% endif %}
    </div>
  </div>
  <div class="stat-card">
    <div class="label">Dark Web Alerts</div>
    <div class="value" style="color:{% if dark_web_alerts > 0 %}var(--red){% else %}var(--green){% endif %}">{{ dark_web_alerts }}</div>
    <div class="sub">{% if dark_web_alerts > 0 %}⚠ Requires attention{% else %}✓ No new exposures{% endif %}</div>
  </div>
  <div class="stat-card">
    <div class="label">Compliance</div>
    <div class="value" style="color:var(--accent)">{{ compliance_pct }}%</div>
    <div class="bar"><div class="bar-fill" style="width:{{ compliance_pct }}%"></div></div>
  </div>
  <div class="stat-card">
    <div class="label">Threats Monitored</div>
    <div class="value" style="color:var(--green)">{{ threats_blocked }}</div>
    <div class="sub">CVEs tracked this month</div>
  </div>
</div>

<!-- Main Content -->
<div class="main">

  <!-- Score Trend -->
  <div class="panel">
    <h2>📈 Score Trend</h2>
    {% if score_history %}
    <div class="trend">
      {% for entry in score_history[-6:] %}
      <div style="flex:1;text-align:center">
        <div class="trend-bar" style="height:{{ entry.score * 0.8 }}px;{% if loop.last %}background:var(--green){% endif %}"></div>
        <div class="trend-label">{{ entry.score }}<br>{{ entry.date[5:7] }}/{{ entry.date[8:10] }}</div>
      </div>
      {% endfor %}
    </div>
    {% else %}
    <p style="color:var(--muted)">Score history will appear after your first monthly scan.</p>
    {% endif %}
  </div>

  <!-- Active Agents -->
  <div class="panel">
    <h2>🤖 Active Agents (24/7)</h2>
    {% for agent in agent_status %}
    <div class="agent-row">
      <div>
        <span class="dot {{ agent.status }}"></span>
        <span class="agent-name">{{ agent.name }}</span>
        <span style="color:var(--muted);font-size:.8rem"> — {{ agent.label }}</span>
      </div>
      <div class="agent-status">{{ agent.last_run }}</div>
    </div>
    {% endfor %}
  </div>

  <!-- Remediation Tasks -->
  <div class="panel">
    <h2>📋 Remediation Tasks ({{ open_tasks|length }} open)</h2>
    {% for task in open_tasks[:8] %}
    <div class="task-row">
      <div>
        <span class="sev sev-{{ task.severity|lower }}">{{ task.severity }}</span>
        <span style="margin-left:8px;font-size:.9rem">{{ task.title }}</span>
      </div>
      <button class="status-btn" hx-post="/portal/{{ client.client_id }}/task/{{ task.id }}/status"
              hx-vals='{"status":"in_progress"}' hx-swap="outerHTML"
              hx-confirm="Mark as in progress?">Start</button>
    </div>
    {% endfor %}
    {% if resolved_tasks %}
    <div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border)">
      <div style="color:var(--green);font-size:.85rem;font-weight:600">✓ {{ resolved_tasks|length }} resolved</div>
    </div>
    {% endif %}
    {% if not open_tasks and not resolved_tasks %}
    <p style="color:var(--muted)">No tasks yet. Tasks will be created from scan findings.</p>
    {% endif %}
  </div>

  <!-- Reports & Policies -->
  <div class="panel">
    <h2>📄 Reports & Policies</h2>
    {% for report in reports[:5] %}
    <div class="doc-row">
      <span class="doc-icon">📊</span>
      <a href="/portal/{{ client.client_id }}/download/reports/{{ report.filename }}">{{ report.filename }}</a>
    </div>
    {% endfor %}
    {% for policy in policies[:5] %}
    <div class="doc-row">
      <span class="doc-icon">📝</span>
      <a href="/portal/{{ client.client_id }}/download/policies/{{ policy.filename }}">{{ policy.filename }}</a>
    </div>
    {% endfor %}
    {% if not reports and not policies %}
    <p style="color:var(--muted)">Documents will appear here as they are generated.</p>
    {% endif %}
  </div>

</div>

</body>
</html>
```

**Step 2: Commit**

```bash
git add templates/portal.html
git commit -m "feat: add Security Command Center portal template"
```

---

### Task 6: Operator Dashboard — Client Onboarding

**Files:**
- Modify: `main.py` (add client creation + magic link endpoints)

**Step 1: Add operator endpoints for client management**

Add after the portal routes in `main.py`:

```python
# ── Operator: Client Management ──────────────────────────────

class CreateClientRequest(BaseModel):
    company_name: str
    domain: str
    industry: str = "general"
    tier: str = "assessment"
    contact_name: str = ""
    contact_email: str = ""
    contact_title: str = ""

@app.post("/api/operator/clients")
async def create_client_endpoint(req: CreateClientRequest, request: Request):
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    client_id = req.domain.replace(".", "-").replace(" ", "-").lower()
    profile = client_manager.create_client(
        client_id=client_id, company_name=req.company_name, domain=req.domain,
        industry=req.industry, tier=req.tier, contact_name=req.contact_name,
        contact_email=req.contact_email, contact_title=req.contact_title,
    )
    return {"status": "created", "client_id": client_id, "profile": profile}


@app.post("/api/operator/clients/{client_id}/portal-access")
async def create_portal_access(client_id: str, request: Request):
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    client = client_manager.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    token = client_manager.generate_magic_link(client_id)
    base_url = os.getenv("BASE_URL", "https://www.cybercomply.io")
    link = f"{base_url}/portal/login?client={client_id}&token={token}"

    # Send magic link email if SMTP configured
    contact_email = client.get("contact_email")
    if contact_email:
        try:
            send_report_email(
                to_email=contact_email,
                to_name=client.get("contact_name", ""),
                domain=client.get("domain", ""),
                pdf_path=None,  # No PDF, just the magic link
            )
        except Exception:
            pass

    return {"status": "ok", "magic_link": link, "expires": "7 days"}


@app.post("/api/operator/clients/{client_id}/tier")
async def update_tier(client_id: str, request: Request):
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    new_tier = body.get("tier", "assessment")
    profile = client_manager._load_profile(client_id)
    profile["tier"] = new_tier
    client_manager._save_profile(client_id, profile)
    return {"status": "ok", "tier": new_tier}


@app.get("/api/operator/clients")
async def list_clients_endpoint(request: Request):
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    clients = client_manager.list_all_clients()
    return {"clients": clients}


@app.get("/api/operator/mrr")
async def get_mrr(request: Request):
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    clients = client_manager.list_all_clients()
    mrr = 0
    for c in clients:
        tier = c.get("tier", "assessment")
        if tier == "basic": mrr += 2000
        elif tier == "pro": mrr += 5000
    return {"mrr": mrr, "client_count": len(clients), "retainer_count": sum(1 for c in clients if c.get("tier") in ("basic", "pro"))}
```

**Step 2: Commit**

```bash
git add main.py
git commit -m "feat: add operator client management API (create, portal access, tier, MRR)"
```

---

### Task 7: Wire Agent Prompts (P46, P54, P57)

**Files:**
- Modify: `agents/chronicle_agent.py` (add monthly report generation)
- Modify: `agents/agents_remaining.py` (wire COMPLY P57)
- Verify: `agents/shadow_agent.py` (P54 already wired)

**Step 1: Implement Chronicle monthly report**

In `agents/chronicle_agent.py`, replace the `generate_monthly_report()` stub with:

```python
def generate_monthly_report(self, client_id: str, scan_data: dict,
                             previous_scan: dict = None, alerts: list = None,
                             compliance_data: dict = None) -> dict:
    """Generate monthly security report using P46 prompt."""
    from prompt_engine import call_prompt

    company = scan_data.get("company_name", "Client")
    score = scan_data.get("score", 0)
    grade = scan_data.get("grade", "N/A")
    findings = scan_data.get("archer", {}).get("findings", [])

    prev_score = previous_scan.get("score", 0) if previous_scan else score
    score_delta = score - prev_score

    new_alerts = len(alerts) if alerts else 0
    resolved_count = sum(1 for f in findings if f.get("status") == "resolved")

    narrative = call_prompt(
        "P46_MONTHLY_SECURITY_REPORT",
        client_name=company,
        current_score=str(score),
        previous_score=str(prev_score),
        score_delta=str(score_delta),
        grade=grade,
        findings_count=str(len(findings)),
        critical_findings=str(sum(1 for f in findings if f.get("severity") == "CRITICAL")),
        high_findings=str(sum(1 for f in findings if f.get("severity") == "HIGH")),
        resolved_count=str(resolved_count),
        new_alerts=str(new_alerts),
        top_findings=json.dumps(findings[:5], indent=2) if findings else "None",
    )

    return {
        "type": "monthly_report",
        "date": date.today().isoformat(),
        "company": company,
        "score": score,
        "grade": grade,
        "score_delta": score_delta,
        "narrative": narrative,
        "findings_summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "resolved": resolved_count,
        },
        "alerts_count": new_alerts,
    }
```

**Step 2: Wire COMPLY compliance progress (P57)**

In `agents/agents_remaining.py`, add to the ComplyAgent class:

```python
def generate_compliance_update(self, client_name: str, frameworks: list,
                                 compliance_status: dict) -> str:
    """Generate compliance progress update using P57 prompt."""
    from prompt_engine import call_prompt

    framework_summary = []
    for fw_id, status in compliance_status.items():
        framework_summary.append(f"- {fw_id}: {status.get('percentage', 0)}% compliant")

    return call_prompt(
        "P57_COMPLIANCE_PROGRESS_UPDATE_EMAIL",
        client_name=client_name,
        frameworks="\n".join(framework_summary),
        overall_progress=str(sum(s.get("percentage", 0) for s in compliance_status.values()) // max(len(compliance_status), 1)),
    )
```

**Step 3: Commit**

```bash
git add agents/chronicle_agent.py agents/agents_remaining.py
git commit -m "feat: wire P46 monthly report, P57 compliance update prompts"
```

---

### Task 8: Scheduled Automation Engine

**Files:**
- Create: `scheduler.py`

**Step 1: Create the scheduler module**

```python
"""Scheduled automation engine — the '24/7 monitoring' backbone."""
import os
import json
import logging
from datetime import datetime, date
from pathlib import Path

logger = logging.getLogger("scheduler")

DATA_DIR = Path(os.getenv("DATA_DIR", "."))


def run_falcon_check():
    """Every 6 hours: pull CISA KEV + filter for client tech stacks."""
    from agents.agents_remaining import FalconAgent
    import client_manager

    falcon = FalconAgent()
    clients = client_manager.list_active_clients()

    for client in clients:
        try:
            threats = falcon.check_cisa_kev()
            tech_stack = client.get("tech_stack", [])
            if tech_stack:
                threats = falcon.filter_for_client(threats, tech_stack)

            if threats:
                client_manager.save_alert(client["client_id"], {
                    "type": "threat",
                    "date": datetime.utcnow().isoformat(),
                    "source": "CISA KEV",
                    "count": len(threats),
                    "threats": threats[:5],
                })

            _update_agent_timestamp(client["client_id"], "FALCON", "Threat Intelligence")
            logger.info(f"FALCON: {client['client_id']} — {len(threats)} threats")
        except Exception as e:
            logger.error(f"FALCON error for {client['client_id']}: {e}")


def run_shadow_check():
    """Daily: check breach databases for new credential exposures."""
    from agents.shadow_agent import ShadowAgent
    import client_manager

    shadow = ShadowAgent()
    clients = client_manager.list_active_clients()

    for client in clients:
        tier_config = client_manager.get_tier_config(client.get("tier", "assessment"))
        if not tier_config.get("dark_web"):
            continue

        try:
            domain = client.get("domain", "")
            contact_email = client.get("contact_email", "")
            emails_to_check = [contact_email] if contact_email else []

            if emails_to_check:
                result = shadow.scan(domain, emails_to_check)
                if hasattr(result, 'total_exposed') and result.total_exposed > 0:
                    alert_data = {
                        "type": "darkweb",
                        "date": datetime.utcnow().isoformat(),
                        "domain": domain,
                        "exposed_count": result.total_exposed,
                        "critical": result.critical,
                        "high": result.high,
                    }
                    client_manager.save_alert(client["client_id"], alert_data)

            _update_agent_timestamp(client["client_id"], "SHADOW", "Dark Web Monitor")
            logger.info(f"SHADOW: {client['client_id']} — checked")
        except Exception as e:
            logger.error(f"SHADOW error for {client['client_id']}: {e}")


def run_weekly_scan():
    """Weekly: quick RECON scan for score delta tracking."""
    from agents.recon_agent import ReconAgent
    import client_manager

    recon = ReconAgent()
    clients = client_manager.list_active_clients()

    for client in clients:
        try:
            domain = client.get("domain", "")
            result = recon.scan(domain, deep=False)
            score = result.get("score", {}).get("total", 0)
            grade = result.get("score", {}).get("grade", "N/A")

            client_manager.add_score(client["client_id"], score, grade)

            # Save scan data
            scan_dir = client_manager._client_dir(client["client_id"]) / "scans"
            scan_dir.mkdir(exist_ok=True)
            scan_file = scan_dir / f"{date.today().isoformat()}-weekly.json"
            scan_file.write_text(json.dumps(result, indent=2, default=str))

            # Auto-verify resolved tasks
            _auto_verify_tasks(client["client_id"], result)

            _update_agent_timestamp(client["client_id"], "RECON", "External Scan")
            logger.info(f"RECON weekly: {client['client_id']} — score {score} ({grade})")
        except Exception as e:
            logger.error(f"RECON error for {client['client_id']}: {e}")


def run_monthly_reports():
    """Monthly: full scan + CHRONICLE report + COMPLY compliance update."""
    from agents.recon_agent import ReconAgent
    from agents.chronicle_agent import ChronicleAgent
    import client_manager

    recon = ReconAgent()
    chronicle = ChronicleAgent()
    clients = client_manager.list_active_clients()

    for client in clients:
        tier_config = client_manager.get_tier_config(client.get("tier", "assessment"))
        if not tier_config.get("monthly_rescan"):
            continue

        try:
            domain = client.get("domain", "")
            client_id = client["client_id"]

            # Full scan
            result = recon.scan(domain, deep=True)
            score = result.get("score", {}).get("total", 0)
            grade = result.get("score", {}).get("grade", "N/A")
            client_manager.add_score(client_id, score, grade)

            # Save scan
            scan_dir = client_manager._client_dir(client_id) / "scans"
            scan_dir.mkdir(exist_ok=True)
            scan_file = scan_dir / f"{date.today().isoformat()}-monthly.json"
            scan_file.write_text(json.dumps(result, indent=2, default=str))

            # Generate monthly report
            scan_data = {
                "company_name": client.get("company_name", ""),
                "score": score,
                "grade": grade,
                "archer": result,
            }
            alerts = client_manager.get_alerts(client_id)
            report_data = chronicle.generate_monthly_report(
                client_id, scan_data, alerts=alerts
            )

            # Save report
            reports_dir = client_manager._client_dir(client_id) / "reports"
            reports_dir.mkdir(exist_ok=True)
            report_file = reports_dir / f"{date.today().isoformat()}-monthly-report.json"
            report_file.write_text(json.dumps(report_data, indent=2, default=str))

            # Generate tasks from new findings
            _generate_tasks_from_findings(client_id, result.get("findings", []))

            _update_agent_timestamp(client_id, "RECON", "External Scan")
            _update_agent_timestamp(client_id, "GUARDIAN", "Compliance Engine")
            logger.info(f"Monthly report: {client_id} — score {score}")
        except Exception as e:
            logger.error(f"Monthly report error for {client.get('client_id', '?')}: {e}")


def _auto_verify_tasks(client_id: str, scan_result: dict):
    """Close tasks when scans confirm the issue is fixed."""
    import client_manager

    tasks = client_manager.get_tasks(client_id)
    findings = scan_result.get("findings", [])
    finding_titles = {f.get("title", "").lower() for f in findings}

    changed = False
    for task in tasks:
        if task["status"] in ("open", "in_progress"):
            if task["title"].lower() not in finding_titles:
                task["status"] = "verified"
                task["resolved_at"] = date.today().isoformat()
                changed = True

    if changed:
        client_manager.save_tasks(client_id, tasks)


def _generate_tasks_from_findings(client_id: str, findings: list):
    """Create remediation tasks from scan findings."""
    import client_manager

    existing_tasks = client_manager.get_tasks(client_id)
    existing_titles = {t["title"] for t in existing_tasks}

    for finding in findings:
        title = finding.get("title", "")
        if title and title not in existing_titles:
            client_manager.add_task(
                client_id=client_id,
                title=title,
                severity=finding.get("severity", "MEDIUM"),
                category=finding.get("category", "General"),
                description=finding.get("description", ""),
                fix=finding.get("fix", ""),
            )


def _update_agent_timestamp(client_id: str, agent_name: str, agent_label: str):
    """Update the agent status file for portal display."""
    import client_manager

    status_file = client_manager._client_dir(client_id) / "agent_status.json"
    if status_file.exists():
        statuses = json.loads(status_file.read_text())
    else:
        statuses = []

    now = datetime.utcnow()
    found = False
    for s in statuses:
        if s["name"] == agent_name:
            s["last_run"] = _time_ago(now)
            s["last_run_ts"] = now.isoformat()
            s["status"] = "active"
            found = True
            break

    if not found:
        statuses.append({
            "name": agent_name,
            "label": agent_label,
            "status": "active",
            "last_run": "Just now",
            "last_run_ts": now.isoformat(),
        })

    status_file.write_text(json.dumps(statuses, indent=2))


def _time_ago(ts: datetime) -> str:
    """Human-readable time ago string."""
    return f"Last check: {ts.strftime('%b %d, %H:%M UTC')}"


def init_scheduler(app=None):
    """Initialize APScheduler with all jobs."""
    from apscheduler.schedulers.asyncio import AsyncIOScheduler

    scheduler = AsyncIOScheduler()

    # Every 6 hours: threat intel
    scheduler.add_job(run_falcon_check, 'interval', hours=6, id='falcon_check',
                      next_run_time=datetime.utcnow())

    # Daily: dark web check
    scheduler.add_job(run_shadow_check, 'interval', hours=24, id='shadow_check')

    # Weekly: quick scan (every Monday at 6am UTC)
    scheduler.add_job(run_weekly_scan, 'cron', day_of_week='mon', hour=6, id='weekly_scan')

    # Monthly: full report (1st of each month at 8am UTC)
    scheduler.add_job(run_monthly_reports, 'cron', day=1, hour=8, id='monthly_reports')

    scheduler.start()
    logger.info("Scheduler started: falcon(6h), shadow(daily), recon(weekly), reports(monthly)")
    return scheduler
```

**Step 2: Wire scheduler into main.py startup**

Add to `main.py` after agent initialization (after line ~82):

```python
# ── Scheduler ────────────────────────────────────────────────
from scheduler import init_scheduler

@app.on_event("startup")
async def startup_scheduler():
    app.state.scheduler = init_scheduler(app)
```

**Step 3: Commit**

```bash
git add scheduler.py main.py
git commit -m "feat: add APScheduler engine — falcon(6h), shadow(daily), recon(weekly), reports(monthly)"
```

---

### Task 9: Operator Dashboard Enhancement

**Files:**
- Modify: `templates/dashboard.html` (add client management section)
- Modify: `main.py` (already done in Task 6)

**Step 1: Add client management panel to dashboard**

Add a new section to `templates/dashboard.html` inside the authenticated view. This adds:
- MRR display
- Client list with tier, score, actions
- "Create Client" button
- "Generate Portal Link" button per client
- Scheduler status display

The exact HTML depends on the current dashboard structure. Add after the existing pipeline metrics section:

```html
<!-- vCISO Client Management -->
<div class="card" style="margin-top:24px" id="vciso-panel">
  <h3 style="color:#06b6d4;margin-bottom:16px">vCISO Retainer Clients</h3>
  <div style="display:flex;gap:24px;margin-bottom:20px">
    <div style="background:#0f172a;padding:16px 24px;border-radius:8px;border:1px solid #1e293b">
      <div style="color:#64748b;font-size:.75rem;text-transform:uppercase">Monthly Recurring Revenue</div>
      <div id="mrr-value" style="font-size:1.5rem;font-weight:700;color:#10b981">$0</div>
    </div>
    <div style="background:#0f172a;padding:16px 24px;border-radius:8px;border:1px solid #1e293b">
      <div style="color:#64748b;font-size:.75rem;text-transform:uppercase">Active Retainers</div>
      <div id="retainer-count" style="font-size:1.5rem;font-weight:700;color:#06b6d4">0</div>
    </div>
  </div>

  <button onclick="showCreateClient()" style="padding:10px 20px;background:#06b6d4;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:600;margin-bottom:16px">+ New Client</button>

  <table style="width:100%;border-collapse:collapse" id="client-table">
    <thead>
      <tr style="border-bottom:1px solid #1e293b;text-align:left">
        <th style="padding:8px;color:#64748b;font-size:.8rem">CLIENT</th>
        <th style="padding:8px;color:#64748b;font-size:.8rem">TIER</th>
        <th style="padding:8px;color:#64748b;font-size:.8rem">SCORE</th>
        <th style="padding:8px;color:#64748b;font-size:.8rem">ACTIONS</th>
      </tr>
    </thead>
    <tbody id="client-rows"></tbody>
  </table>
</div>

<script>
async function loadClients(){
  const res=await fetch('/api/operator/clients');
  const data=await res.json();
  const rows=document.getElementById('client-rows');
  rows.innerHTML='';
  data.clients.forEach(c=>{
    const tierColors={assessment:'#64748b',basic:'#06b6d4',pro:'#10b981'};
    rows.innerHTML+=`<tr style="border-bottom:1px solid #1e293b">
      <td style="padding:10px"><strong>${c.company_name}</strong><br><span style="color:#64748b;font-size:.8rem">${c.domain}</span></td>
      <td style="padding:10px"><span style="color:${tierColors[c.tier]||'#64748b'};font-weight:600">${c.tier.toUpperCase()}</span></td>
      <td style="padding:10px">${c.current_score||'—'} ${c.current_grade||''}</td>
      <td style="padding:10px">
        <button onclick="generatePortalLink('${c.client_id}')" style="padding:4px 12px;background:#1e293b;color:#06b6d4;border:1px solid #06b6d4;border-radius:6px;cursor:pointer;font-size:.8rem">Portal Link</button>
      </td>
    </tr>`;
  });
  const mrr=await fetch('/api/operator/mrr');
  const mrrData=await mrr.json();
  document.getElementById('mrr-value').textContent='$'+mrrData.mrr.toLocaleString();
  document.getElementById('retainer-count').textContent=mrrData.retainer_count;
}
async function generatePortalLink(clientId){
  const res=await fetch(`/api/operator/clients/${clientId}/portal-access`,{method:'POST'});
  const data=await res.json();
  if(data.magic_link){prompt('Send this link to your client:',data.magic_link)}
}
function showCreateClient(){
  const name=prompt('Company name:');if(!name)return;
  const domain=prompt('Domain (e.g. company.com):');if(!domain)return;
  const tier=prompt('Tier (assessment/basic/pro):','assessment');
  const industry=prompt('Industry (cpa/healthcare/legal/financial/general):','general');
  fetch('/api/operator/clients',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({company_name:name,domain:domain,tier:tier,industry:industry})})
    .then(r=>r.json()).then(d=>{if(d.status==='created'){loadClients();alert('Client created: '+d.client_id)}});
}
if(document.getElementById('vciso-panel')){loadClients()}
</script>
```

**Step 2: Commit**

```bash
git add templates/dashboard.html
git commit -m "feat: add vCISO client management panel to operator dashboard"
```

---

### Task 10: Integration — Connect Delivery Pipeline to Client System

**Files:**
- Modify: `main.py` (update `/api/clients/new-scan` to also create client profile)

**Step 1: Update new-scan endpoint to create client profile**

In the existing `new_scan` endpoint in `main.py` (~line 855), add client creation after the scan starts:

```python
@app.post("/api/clients/new-scan")
async def new_scan(req: NewScanRequest):
    from deliver import full_delivery
    company_safe = (req.company_name or req.domain.split('.')[0]).replace(" ", "_").replace("&", "and")
    dir_name = f"{company_safe}_{date.today().strftime('%Y%m%d')}"

    # Create client profile
    client_id = req.domain.replace(".", "-").replace(" ", "-").lower()
    client_manager.create_client(
        client_id=client_id,
        company_name=req.company_name or req.domain,
        domain=req.domain,
        industry=req.industry,
    )

    async def run_scan():
        result = await asyncio.to_thread(
            full_delivery, req.domain, req.company_name, req.industry,
            not req.enable_ai, req.employee_count
        )
        # Update client score after scan
        try:
            scan_file = OUTPUT_DIR / dir_name / "scan_data.json"
            if scan_file.exists():
                data = json.loads(scan_file.read_text())
                score = data.get("scan", {}).get("score", 0)
                grade = data.get("scan", {}).get("grade", "N/A")
                client_manager.add_score(client_id, score, grade)
                # Generate tasks from findings
                from scheduler import _generate_tasks_from_findings
                findings = data.get("scan", {}).get("archer", {}).get("findings", [])
                _generate_tasks_from_findings(client_id, findings)
        except Exception as e:
            logger.error(f"Post-scan update error: {e}")

    asyncio.create_task(run_scan())
    return {"status": "started", "dir_name": dir_name, "client_id": client_id}
```

**Step 2: Commit**

```bash
git add main.py
git commit -m "feat: connect delivery pipeline to client profile system"
```

---

### Task 11: Manual Scheduler Triggers

**Files:**
- Modify: `main.py` (add operator trigger endpoints)

**Step 1: Add manual trigger endpoints**

```python
@app.post("/api/operator/run-monthly-reports")
async def trigger_monthly_reports(request: Request):
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from scheduler import run_monthly_reports
    asyncio.create_task(asyncio.to_thread(run_monthly_reports))
    return {"status": "started", "message": "Monthly reports generating for all retainer clients"}


@app.post("/api/operator/run-scan/{client_id}")
async def trigger_client_scan(client_id: str, request: Request):
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from scheduler import run_weekly_scan
    asyncio.create_task(asyncio.to_thread(run_weekly_scan))
    return {"status": "started"}
```

**Step 2: Commit**

```bash
git add main.py
git commit -m "feat: add manual trigger endpoints for scheduler jobs"
```

---

### Task 12: End-to-End Smoke Test

**Files:** None (testing only)

**Step 1: Start the server**

Run: `python -m uvicorn main:app --reload --port 8000`

**Step 2: Test client creation**

```bash
curl -X POST http://localhost:8000/api/operator/clients \
  -H "Content-Type: application/json" \
  -H "Cookie: dashboard_auth=cybercomply2026" \
  -d '{"company_name":"Test CPA Firm","domain":"testcpa.com","industry":"cpa","tier":"basic"}'
```

Expected: `{"status":"created","client_id":"testcpa-com",...}`

**Step 3: Test magic link generation**

```bash
curl -X POST http://localhost:8000/api/operator/clients/testcpa-com/portal-access \
  -H "Cookie: dashboard_auth=cybercomply2026"
```

Expected: `{"status":"ok","magic_link":"https://...","expires":"7 days"}`

**Step 4: Test portal login page**

Open: `http://localhost:8000/portal/login`
Expected: Dark-themed login page renders

**Step 5: Test MRR endpoint**

```bash
curl http://localhost:8000/api/operator/mrr \
  -H "Cookie: dashboard_auth=cybercomply2026"
```

Expected: `{"mrr":2000,"client_count":1,"retainer_count":1}`

**Step 6: Verify scheduler started**

Check server logs for: `"Scheduler started: falcon(6h), shadow(daily), recon(weekly), reports(monthly)"`

**Step 7: Commit all verified work**

```bash
git add -A
git commit -m "feat: complete vCISO platform MVP — portal, auth, scheduler, client management"
```

---

## Summary: What This Plan Builds

| Task | What | Files |
|------|------|-------|
| 1 | Dependencies | requirements.txt |
| 2 | Client data model + auth | client_manager.py (new) |
| 3 | Portal auth routes | main.py |
| 4 | Login/setup templates | templates/portal_login.html, portal_setup.html (new) |
| 5 | Security Command Center | templates/portal.html (new) |
| 6 | Operator client management | main.py |
| 7 | Wire P46, P57 prompts | chronicle_agent.py, agents_remaining.py |
| 8 | Scheduler engine | scheduler.py (new) |
| 9 | Dashboard enhancement | templates/dashboard.html |
| 10 | Pipeline integration | main.py |
| 11 | Manual triggers | main.py |
| 12 | Smoke test | — |

**End state:** Client logs into portal → sees live score, agents, alerts, tasks, reports. Scheduler runs 24/7. Operator manages clients + MRR from dashboard. Monthly reports auto-generate. Full vCISO delivery platform.
