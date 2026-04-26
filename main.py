"""
CYBERCOMPLY — API Server
Connects all 11 AI agents into one unified API.

Run: uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import json
import os
import time
import asyncio
import zipfile
import tempfile
import secrets
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from datetime import datetime, date
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger("cybercomply.api")

# Import all agents
import client_manager
from agents.shadow_agent import ShadowAgent
from agents.recon_agent import ReconAgent
from agents.guardian_agent import GuardianAgent
from agents.phantom_agent import PhantomAgent
from agents.chronicle_agent import ChronicleAgent
from agents.agents_remaining import (
    VigilAgent, ComplyAgent, BreachAgent,
    DispatchAgent, FalconAgent, VanguardAgent
)

# ─── APP SETUP ────────────────────────────────────────────────

app = FastAPI(
    title="CyberComply API",
    description="11 AI Agents. Always On. Always Watching.",
    version="2.0.0"
)

_allowed_origins = os.getenv("ALLOWED_ORIGINS", "").split(",") if os.getenv("ALLOWED_ORIGINS") else [
    "https://www.cybercomply.io",
    "https://cybercomply.io",
    "http://localhost:8000",
]
_allowed_origins = [o.strip() for o in _allowed_origins if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Content-Type", "Authorization"],
)

# ─── RATE LIMITING ────────────────────────────────────────
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── JINJA2 SETUP ────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

templates = Environment(loader=FileSystemLoader("templates"), autoescape=True)

DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "cybercomply2026")
_dashboard_sessions = set()  # In-memory session tokens (cleared on restart)
CALENDLY_LINK = os.getenv("CALENDAR_LINK", "https://calendly.com/security-cybercomply/30min")


def safe_path_component(value: str) -> str:
    """Reject directory traversal attempts in any path component."""
    name = Path(value).name
    if name != value or ".." in value:
        raise HTTPException(status_code=400, detail="Invalid path")
    return name
DATA_DIR = Path(os.getenv("DATA_DIR", "."))
OUTPUT_DIR = DATA_DIR / "client-deliverables"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Initialize agents
shadow = ShadowAgent()
recon = ReconAgent()
guardian = GuardianAgent()
phantom = PhantomAgent()
vigil = VigilAgent()
comply = ComplyAgent()
breach = BreachAgent()
dispatch = DispatchAgent()
falcon = FalconAgent()
vanguard = VanguardAgent()
chronicle = ChronicleAgent()

# Initialize scheduler
from scheduler import init_scheduler

@app.on_event("startup")
async def startup_scheduler():
    if not os.getenv("JWT_SECRET"):
        logger.warning("JWT_SECRET not set — using random secret. Portal sessions will be lost on restart. Set JWT_SECRET env var for persistence.")
    app.state.scheduler = init_scheduler(app)

# ─── MODELS ───────────────────────────────────────────────────

class DomainScanRequest(BaseModel):
    domain: str
    emails: Optional[list] = []
    deep: Optional[bool] = False

class QuestionnaireSubmission(BaseModel):
    answers: dict

class PhishingCampaignRequest(BaseModel):
    template_key: str
    employee_emails: list
    campaign_name: Optional[str] = None

class EmailBreachRequest(BaseModel):
    emails: list  # List of email addresses to check

class IncidentRequest(BaseModel):
    incident_type: str
    details: Optional[dict] = {}

# ─── HEALTH CHECK ─────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def landing_page():
    tmpl = templates.get_template("landing.html")
    return HTMLResponse(tmpl.render(calendly_link=CALENDLY_LINK))

@app.get("/api/health")
async def health_check():
    return {
        "name": "CyberComply",
        "version": "2.0.0",
        "agents": {
            "RECON": {"status": "active", "tagline": recon.AGENT_TAGLINE},
            "SHADOW": {"status": "active", "tagline": shadow.AGENT_TAGLINE},
            "GUARDIAN": {"status": "active", "tagline": guardian.AGENT_TAGLINE},
            "COMPLY": {"status": "active", "tagline": comply.AGENT_TAGLINE},
            "PHANTOM": {"status": "active", "tagline": phantom.AGENT_TAGLINE},
            "VIGIL": {"status": "active", "tagline": vigil.AGENT_TAGLINE},
            "SENTINEL": {"status": "planned", "tagline": "I vet every vendor so you don't have to."},
            "DISPATCH": {"status": "standby", "tagline": dispatch.AGENT_TAGLINE},
            "FALCON": {"status": "active", "tagline": falcon.AGENT_TAGLINE},
            "VANGUARD": {"status": "active", "tagline": vanguard.AGENT_TAGLINE},
            "CHRONICLE": {"status": "active", "tagline": chronicle.AGENT_TAGLINE},
        }
    }

# ─── STAGE 0: FREE SCAN (Lead Magnet) ────────────────────────

def _validate_public_scan_target(domain: str) -> str:
    """SSRF guard for the public free-scan endpoints.

    The public endpoints accept a customer-supplied hostname and perform DNS
    lookups + TCP/HTTP probes against it. Without this guard, an attacker
    could submit `metadata.google.internal`, `localhost`, an internal hostname,
    or any name that resolves to a private/loopback/link-local IP and use the
    server as an internal-network oracle.

    Returns the cleaned domain. Raises HTTPException 400 on rejected input.
    """
    import ipaddress, socket, re as _re
    if not domain:
        raise HTTPException(status_code=400, detail="Domain required")
    cleaned = domain.strip().lower()
    cleaned = _re.sub(r"^https?://", "", cleaned)
    cleaned = cleaned.split("/", 1)[0].split("?", 1)[0]
    # Strict hostname syntax — labels of [a-z0-9-], dots between, no underscores,
    # no spaces, no colons (port stripping not supported here).
    if not _re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", cleaned):
        raise HTTPException(status_code=400, detail="Invalid domain")
    # Reject literal IPs, loopback names, and obvious internal suffixes.
    bad_suffixes = (".local", ".internal", ".lan", ".intranet", ".corp",
                     ".home", ".localhost", ".test", ".invalid", ".example",
                     ".onion")
    if cleaned in ("localhost", "broadcasthost") or cleaned.endswith(bad_suffixes):
        raise HTTPException(status_code=400, detail="Domain not eligible for scanning")
    # Resolve and reject private / loopback / link-local / multicast / reserved.
    try:
        infos = socket.getaddrinfo(cleaned, None)
    except Exception:
        raise HTTPException(status_code=400, detail="Domain could not be resolved")
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            raise HTTPException(
                status_code=400,
                detail="Domain resolves to a non-public address and cannot be scanned",
            )
    return cleaned


@app.post("/api/scan/free")
@limiter.limit("10/minute")
async def free_scan(request: Request, scan_request: DomainScanRequest):
    """
    Stage 0: Free domain scan — the lead magnet.
    Runs SHADOW + RECON quick scan. Returns teaser results.
    """
    scan_request.domain = _validate_public_scan_target(scan_request.domain)
    results = {
        "domain": scan_request.domain,
        "scan_date": datetime.utcnow().isoformat() + "Z",
        "agents_used": ["SHADOW", "RECON"],
    }

    # RECON: Quick external scan
    recon_results = recon.scan(scan_request.domain)
    results["security_score"] = recon_results.get("score", {})
    results["findings_count"] = len(recon_results.get("findings", []))
    results["top_findings"] = recon_results.get("findings", [])[:3]  # Show top 3 only

    # SHADOW: Password check (teaser — full scan behind paywall)
    if scan_request.emails:
        results["emails_to_check"] = len(scan_request.emails)
        results["shadow_note"] = "Full dark web scan available in detailed report"

    # Gate the full results
    results["full_report_available"] = True
    results["message"] = f"Security Score: {recon_results.get('score', {}).get('total', 0)}/100. Full 9-page report available — enter your details to receive it."

    return results

# ─── STAGE 1: FULL ASSESSMENT ────────────────────────────────

@app.post("/api/scan/full")
async def full_scan(scan_req: DomainScanRequest, request: Request):
    """
    Stage 1: Full assessment — SHADOW + RECON deep scan.
    Generates complete results for the 9-page PDF report.
    Operator-only: this is a paid scan that triggers AI + HIBP usage.
    """
    require_operator(request)
    results = {
        "domain": scan_req.domain,
        "scan_date": datetime.utcnow().isoformat() + "Z",
    }

    results["archer"] = recon.scan(scan_req.domain, deep=scan_req.deep)

    if scan_req.emails:
        results["spectre"] = shadow.to_dict(
            shadow.scan(scan_req.domain, scan_req.emails)
        )

    return results

# ─── STAGE 3: ONBOARDING ─────────────────────────────────────

@app.get("/api/onboarding/questionnaire")
async def get_questionnaire(request: Request):
    """Get the smart onboarding questionnaire."""
    require_operator(request)
    return guardian.get_questionnaire()

@app.post("/api/onboarding/process")
async def process_onboarding(submission: QuestionnaireSubmission, request: Request):
    """
    Process onboarding questionnaire.
    Returns: client profile, risk score, applicable frameworks,
    required policies, compliance status, risk register.
    """
    require_operator(request)
    # Process questionnaire
    profile = guardian.process_questionnaire(submission.answers)
    
    # Generate risk register
    risk_register = guardian.generate_risk_register(profile)
    
    # Get compliance status
    compliance = guardian.get_compliance_status(profile)
    
    # Get required policies
    policies = guardian.get_required_policies(profile)
    
    # Get cross-framework mapping
    cross_map = comply.cross_map_controls(profile.get("applicable_frameworks", []))
    
    return {
        "profile": profile,
        "risk_register": risk_register,
        "compliance_status": compliance,
        "required_policies": policies,
        "cross_framework_mapping": cross_map,
        "next_steps": [
            "Connect Microsoft 365 or Google Workspace (SENTINEL)",
            "Review and approve generated policies (GUARDIAN)",
            "Schedule first phishing test (PHANTOM)",
            "Review dark web findings (SHADOW)",
            "Address critical vulnerabilities (RECON)"
        ]
    }

# ─── AGENT ENDPOINTS ─────────────────────────────────────────

# GUARDIAN
@app.get("/api/guardian/policy-prompt/{policy_key}")
async def get_policy_prompt(policy_key: str, request: Request,
                             company_name: str = "Test Company",
                             industry: str = "Accounting / CPA"):
    """Get Claude API prompt for generating a specific policy."""
    require_operator(request)
    profile = {"company_name": company_name, "industry": industry,
               "employee_count": "11-25", "email_provider": "Microsoft 365",
               "data_types": ["Social Security Numbers", "Tax Returns (FTI)"],
               "applicable_frameworks": ["irs_4557", "nist_csf_2"],
               "cloud_services": ["Microsoft 365", "QuickBooks Online"],
               "mfa_status": "Yes — for some users",
               "remote_work": "Hybrid"}
    prompt = guardian.generate_policy_prompt(policy_key, profile)
    return {"policy_key": policy_key, "prompt": prompt,
            "note": "Send this prompt to Claude API to generate the actual policy document"}

# PHANTOM
@app.get("/api/phantom/templates/{industry}")
async def get_phishing_templates(industry: str, request: Request):
    """Get phishing templates for an industry."""
    require_operator(request)
    return phantom.get_templates_for_industry(industry)

@app.post("/api/phantom/campaign")
async def create_phishing_campaign(campaign_req: PhishingCampaignRequest, request: Request):
    """Create a phishing simulation campaign. Operator-only: real email send."""
    require_operator(request)
    return phantom.create_campaign(
        campaign_req.campaign_name or f"Campaign-{datetime.utcnow().strftime('%Y%m%d')}",
        campaign_req.template_key,
        campaign_req.employee_emails
    )

# SHADOW — Standalone email breach check (no domain required)
@app.post("/api/shadow/email-check")
async def check_email_breaches(breach_req: EmailBreachRequest, request: Request):
    """
    Standalone dark web breach check — works without a domain/website.
    Accepts a list of email addresses and checks each against HIBP.
    Operator-only: paid HIBP usage and PII handling.
    """
    require_operator(request)
    if not breach_req.emails:
        raise HTTPException(status_code=400, detail="At least one email address is required")
    if len(breach_req.emails) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 emails per request")

    results = []
    total_breaches = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for email in breach_req.emails:
        email = email.strip().lower()
        breaches = shadow.check_email_breaches(email)
        time.sleep(shadow.rate_limit_delay)

        email_result = {"email": email, "breaches_found": len(breaches), "breaches": []}
        for b in breaches:
            sev, reason = shadow._assess_severity(email, b)
            severity_counts[sev] += 1
            total_breaches += 1
            email_result["breaches"].append({
                "name": b.get("Name", "Unknown"),
                "date": b.get("BreachDate", "Unknown"),
                "data_exposed": b.get("DataClasses", []),
                "severity": sev,
                "severity_reason": reason,
            })
        results.append(email_result)

    exposed_emails = [r for r in results if r["breaches_found"] > 0]

    return {
        "scan_date": datetime.utcnow().isoformat() + "Z",
        "total_emails_checked": len(breach_req.emails),
        "total_exposed": len(exposed_emails),
        "total_breaches": total_breaches,
        "severity_summary": severity_counts,
        "exposure_rate": f"{len(exposed_emails)/max(len(breach_req.emails),1)*100:.0f}%",
        "results": results,
        "note": "HIBP-powered dark web intelligence. No website required.",
    }

# DISPATCH
@app.get("/api/dispatch/playbooks")
async def list_playbooks(request: Request):
    """List all incident response playbooks."""
    require_operator(request)
    return dispatch.list_playbooks()

@app.get("/api/dispatch/playbook/{incident_type}")
async def get_playbook(incident_type: str, request: Request):
    """Get a specific incident response playbook."""
    require_operator(request)
    return dispatch.get_playbook(incident_type)

# FALCON
@app.get("/api/falcon/threats")
async def get_threats(request: Request):
    """Get latest threat intelligence from CISA."""
    require_operator(request)
    return falcon.check_cisa_kev()

# COMPLY
@app.get("/api/comply/crossmap")
async def get_crossmap(request: Request, frameworks: str = "irs_4557,nist_csf_2"):
    """Cross-map controls across frameworks."""
    require_operator(request)
    fw_list = [f.strip() for f in frameworks.split(",")]
    return comply.cross_map_controls(fw_list)

@app.get("/api/comply/evidence/{framework_id}")
async def get_evidence_checklist(framework_id: str, request: Request):
    """Get evidence collection checklist for a framework."""
    require_operator(request)
    return comply.get_evidence_checklist(framework_id)

# VANGUARD
@app.get("/api/vanguard/workflows")
async def list_workflows(request: Request):
    """List all orchestration workflows."""
    require_operator(request)
    return vanguard.list_workflows()

@app.post("/api/vanguard/execute/{workflow_name}")
async def execute_workflow(workflow_name: str, request: Request):
    """Execute an orchestration workflow."""
    require_operator(request)
    return vanguard.execute_workflow(workflow_name, {})

# BREACH
@app.get("/api/breach/scope-template")
async def get_pentest_scope(request: Request):
    """Get penetration test scope of work template."""
    require_operator(request)
    return breach.get_pentest_scope_template()


# ─── DASHBOARD DATA ──────────────────────────────────────────

@app.get("/api/dashboard/{client_id}")
async def get_dashboard(client_id: str, request: Request):
    """Get complete dashboard data for a client."""
    require_operator(request)
    return {
        "client_id": client_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "security_score": {"total": 0, "grade": "F", "label": "NOT ASSESSED",
                          "note": "Run a scan to get your security score"},
        "agents": {
            "SENTINEL": {"status": "pending_setup", "message": "Connect M365 to activate"},
            "GUARDIAN": {"status": "pending_setup", "message": "Complete questionnaire to activate"},
            "SHADOW": {"status": "ready", "message": "Ready to scan"},
            "RECON": {"status": "ready", "message": "Ready to scan"},
            "PHANTOM": {"status": "pending_setup", "message": "Upload employee list to activate"},
            "COMPLY": {"status": "pending_setup", "message": "Complete questionnaire to activate"},
            "BREACH": {"status": "available", "message": "Available on-demand"},
            "DISPATCH": {"status": "standby", "message": "On standby — no incidents"},
            "FALCON": {"status": "active", "message": "Monitoring threat feeds"},
            "VANGUARD": {"status": "active", "message": "Orchestration ready"},
        }
    }


# ─── TEMPLATE ROUTES ─────────────────────────────────────

@app.get("/scan", response_class=HTMLResponse)
async def scan_page():
    tmpl = templates.get_template("scan.html")
    return HTMLResponse(tmpl.render(calendly_link=CALENDLY_LINK))

_dashboard_mfa_passed: set = set()  # session tokens that have completed MFA


def check_dashboard_auth(request: Request):
    """Operator authentication. When operator MFA is enabled, both the
    password AND a verified TOTP code are required. The query-password
    path is preserved as a backwards-compatible loophole for environments
    without MFA configured (and for tests via OPERATOR_MFA_DISABLED=1)."""
    import auth_security as _as
    # Existing session token covers password + (when applicable) MFA.
    token = request.cookies.get("dashboard_auth")
    if token and token in _dashboard_sessions:
        if _as.operator_mfa_required() and token not in _dashboard_mfa_passed:
            return False
        return True
    # Initial password check via query parameter (test + first-login path).
    password = request.query_params.get("password")
    if password == DASHBOARD_PASSWORD:
        if _as.operator_mfa_required():
            mfa_code = (request.query_params.get("mfa")
                        or request.headers.get("x-operator-mfa", ""))
            if not _as.verify_operator_mfa(mfa_code):
                return False
        return True
    return False

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    if not check_dashboard_auth(request):
        tmpl = templates.get_template("dashboard.html")
        return HTMLResponse(tmpl.render(authenticated=False))

    tmpl = templates.get_template("dashboard.html")
    resp = HTMLResponse(tmpl.render(authenticated=True, calendly_link=CALENDLY_LINK))

    # Only mint a new session token if authenticated via password (not existing token)
    existing_token = request.cookies.get("dashboard_auth")
    if not (existing_token and existing_token in _dashboard_sessions):
        import audit_log as _al
        import auth_security as _as
        _al.record(action=_al.ACTION_OPERATOR_LOGIN, actor="operator",
                   role=_al.ROLE_OPERATOR, request=request)
        session_token = secrets.token_hex(32)
        _dashboard_sessions.add(session_token)
        # If MFA was satisfied during this request, mark the session as
        # MFA-passed so subsequent calls accept the cookie alone.
        if _as.operator_mfa_required():
            mfa_code = (request.query_params.get("mfa")
                        or request.headers.get("x-operator-mfa", ""))
            if _as.verify_operator_mfa(mfa_code):
                _dashboard_mfa_passed.add(session_token)
        else:
            # MFA not configured → session is "passed" by default but the UI
            # banners the operator about MFA setup.
            _dashboard_mfa_passed.add(session_token)
        # Cap sessions to prevent unbounded growth (single-operator dashboard)
        if len(_dashboard_sessions) > 100:
            _dashboard_sessions.clear()
            _dashboard_sessions.add(session_token)
        resp.set_cookie("dashboard_auth", session_token, max_age=86400,
                         httponly=True, secure=True, samesite="lax")
    return resp

# ─── DIAGNOSTIC REPORT ──────────────────────────────────

@app.get("/report/{client_dir}", response_class=HTMLResponse)
async def diagnostic_report(client_dir: str, request: Request):
    """Full 7-section diagnostic report for a client."""
    client_dir = safe_path_component(client_dir)
    client_path = OUTPUT_DIR / client_dir
    scan_file = client_path / "scan_data.json"
    if not scan_file.exists():
        raise HTTPException(status_code=404, detail="Client not found")

    with open(scan_file) as f:
        data = json.load(f)

    scan = data.get("scan", {})
    forge = data.get("forge", {})
    archer = scan.get("archer", {})
    profile = forge.get("profile", {})
    compliance_data = forge.get("compliance", {})
    score_data = archer.get("score", {})
    findings_raw = archer.get("findings", [])
    breakdown = score_data.get("breakdown", {})

    total_score = score_data.get("total", 0)

    # Score color
    if total_score >= 80: score_color, score_color_dim = "#34d399", "rgba(52,211,153,0.12)"
    elif total_score >= 60: score_color, score_color_dim = "#a3e635", "rgba(163,230,53,0.12)"
    elif total_score >= 40: score_color, score_color_dim = "#fbbf24", "rgba(251,191,36,0.12)"
    elif total_score >= 20: score_color, score_color_dim = "#f97316", "rgba(249,115,22,0.12)"
    else: score_color, score_color_dim = "#ef4444", "rgba(239,68,68,0.12)"

    # Arc math (semicircle, r=85 → circumference/2 ≈ 267)
    arc_total = 267
    arc_offset = arc_total * (1 - total_score / 100)

    # Scan categories
    cat_map = {
        "email_security": ("Email Security", "SPF, DKIM, DMARC verification"),
        "ssl_tls": ("SSL / TLS", "Certificate validity, protocol strength"),
        "security_headers": ("Security Headers", "HSTS, CSP, X-Frame-Options, and more"),
        "network_exposure": ("Network Exposure", "Open ports and services"),
        "technology": ("Technology Stack", "Server, CDN, CMS detection"),
        "dns_security": ("DNS Security", "DNSSEC, CAA records"),
    }
    scan_categories = []
    for key, (name, desc) in cat_map.items():
        bd = breakdown.get(key, {})
        s, mx = bd.get("score", 0), bd.get("max", 1)
        pct = round(s / mx * 100) if mx > 0 else 0
        if pct >= 80: color, status, scls = "#34d399", "PASS", "status-pass"
        elif pct >= 40: color, status, scls = "#fbbf24", "PARTIAL", "status-partial"
        else: color, status, scls = "#ef4444", "FAIL", "status-fail"
        scan_categories.append(dict(name=name, description=desc, score=s, max=mx, pct=pct, color=color, status=status, status_class=scls))

    # Findings
    findings = []
    critical_count = high_count = 0
    for f in findings_raw:
        sev = f.get("severity", "INFO").upper()
        if sev == "CRITICAL": critical_count += 1
        elif sev == "HIGH": high_count += 1
        findings.append(dict(
            severity=sev, title=f.get("title", ""),
            description=f.get("description", ""), fix=f.get("fix", ""),
            effort=f.get("effort", "—"), cost=f.get("cost", "—"),
            category=f.get("category", "General"),
        ))

    # Compliance frameworks
    compliance_frameworks = []
    avg_compliance = 0
    for fw_key, fw_data in compliance_data.items():
        met = fw_data.get("met", 0)
        partial = fw_data.get("partial", 0)
        not_met = fw_data.get("not_met", 0)
        total = fw_data.get("total_controls", met + partial + not_met)
        pct = fw_data.get("compliance_percentage", 0)
        controls = []
        for c in fw_data.get("controls", []):
            controls.append(dict(id=c.get("id", ""), name=c.get("name", ""), category=c.get("category", ""), status=c.get("status", "not_met")))
        compliance_frameworks.append(dict(
            key=fw_key, name=fw_data.get("framework_name", fw_key),
            met=met, partial=partial, not_met=not_met, total=total, pct=pct, controls=controls,
        ))
    if compliance_frameworks:
        avg_compliance = round(sum(f["pct"] for f in compliance_frameworks) / len(compliance_frameworks))

    # Risk items from questionnaire
    risk_items = []
    risk_score = profile.get("risk_score", {})
    for finding in risk_score.get("findings", []):
        # Classify severity based on keywords
        fl = finding.lower()
        if any(k in fl for k in ["no backup", "no wisp", "no incident", "no endpoint"]): sev = "CRITICAL"
        elif any(k in fl for k in ["mfa not", "no firewall", "no cyber insurance", "no recent"]): sev = "HIGH"
        elif any(k in fl for k in ["no training", "not properly"]): sev = "MEDIUM"
        else: sev = "LOW"
        risk_items.append(dict(finding=finding, severity=sev))

    # Policies status
    policy_dir = client_path / "policies"
    all_policies = [
        ("WISP", "Written Information Security Plan"),
        ("IRP", "Incident Response Plan"),
        ("AUP", "Acceptable Use Policy"),
        ("ENCRYPTION", "Encryption & Data Protection"),
        ("REMOTE_WORK", "Remote Work Security"),
        ("VENDOR_MGMT", "Vendor Management"),
        ("DATA_CLASS", "Data Classification & Handling"),
        ("PASSWORD", "Password & Authentication"),
        ("TRAINING", "Security Awareness Training"),
        ("CHANGE_MGMT", "Change Management"),
        ("BCP", "Business Continuity Plan"),
        ("PHYSICAL", "Physical Security"),
        ("MDM", "Mobile Device Management"),
        ("CLOUD", "Cloud Security"),
        ("RETENTION", "Data Retention & Destruction"),
        ("SOCIAL_MEDIA", "Social Media & Communications"),
    ]
    policies = []
    policies_generated = 0
    for key, name in all_policies:
        exists = (policy_dir / f"{key}.txt").exists() if policy_dir.exists() else False
        if exists: policies_generated += 1
        policies.append(dict(key=key, name=name, generated=exists))

    # Deliverables
    deliverables = [
        dict(name="Security Assessment PDF", file=f"{client_dir.split('_2')[0]}_Security_Assessment_*.pdf", ready=(len(list(client_path.glob("*.pdf"))) > 0)),
        dict(name="Proposal Email", file="PROPOSAL_EMAIL.txt", ready=(client_path / "PROPOSAL_EMAIL.txt").exists()),
        dict(name="Policy Documents", file=f"policies/ ({policies_generated} files)", ready=policies_generated > 0),
        dict(name="Raw Scan Data", file="scan_data.json", ready=True),
        dict(name="AI Finding Narratives", file="cold_email_1.txt", ready=(client_path / "cold_email_1.txt").exists()),
        dict(name="Dark Web Breach Report", file="shadow_alerts/", ready=(client_path / "shadow_alerts").exists()),
    ]

    # Upsells based on profile
    upsells = []
    if profile.get("cyber_insurance") == "No":
        upsells.append(dict(name="Cyber Insurance Readiness", why="No current coverage — handles sensitive FTI/PII", price="$1,500"))
    if profile.get("training") == "No":
        upsells.append(dict(name="Security Training Program", why="No awareness training — #1 breach cause", price="$1,000"))
    upsells.append(dict(name="Vendor Risk Assessment", why="FTC/IRS requires vendor oversight", price="$500/vendor"))
    if total_score < 70:
        upsells.append(dict(name="Penetration Test Coordination", why=f"Score {total_score}/100 — validate external findings", price="$2,500"))

    # Client info
    scan_date = archer.get("scan_date", "")
    if scan_date:
        try:
            dt = datetime.fromisoformat(scan_date.replace("Z", "+00:00"))
            scan_date = dt.strftime("%B %d, %Y")
        except Exception:
            pass

    client_info = dict(
        company_name=scan.get("company_name", client_dir),
        domain=scan.get("domain", ""),
        industry=profile.get("industry", "General"),
        size=profile.get("employee_count", "Unknown"),
        email_platform=profile.get("email_provider", "Unknown"),
        scan_date=scan_date,
        report_date=date.today().strftime("%B %d, %Y"),
        frameworks=[fw["name"] for fw in compliance_frameworks],
        data_types=profile.get("data_types", []),
    )

    tmpl = templates.get_template("report.html")
    return HTMLResponse(tmpl.render(
        client=client_info,
        score=score_data,
        score_color=score_color,
        score_color_dim=score_color_dim,
        arc_total=round(arc_total),
        arc_offset=round(arc_offset),
        scan_categories=scan_categories,
        findings=findings,
        findings_count=len(findings),
        critical_count=critical_count,
        high_count=high_count,
        shadow_status="not_run",
        shadow_data={},
        compliance_frameworks=compliance_frameworks,
        avg_compliance=avg_compliance,
        risk_items=risk_items,
        risk_findings=len(risk_items),
        policies=policies,
        policies_generated=policies_generated,
        deliverables=deliverables,
        upsells=upsells,
        calendly_link=CALENDLY_LINK,
        current_year=date.today().year,
    ))


# ─── SSE SCAN ENDPOINT ──────────────────────────────────

@app.get("/api/scan/free/stream")
@limiter.limit("10/minute")
async def free_scan_stream(request: Request, domain: str):
    """SSE endpoint for real-time scan progress."""
    domain = _validate_public_scan_target(domain)

    async def event_generator():
        results = {"domain": domain, "scan_date": datetime.utcnow().isoformat() + "Z"}

        steps = [
            ("email_security", "Checking SPF/DKIM/DMARC...", recon.scan_email_security),
            ("ssl", "Checking SSL certificate...", recon.scan_ssl),
            ("headers", "Scanning HTTP security headers...", recon.scan_security_headers),
            ("ports", "Checking open ports...", recon.scan_common_ports),
            ("dns", "Checking DNS security...", recon.scan_dns),
            ("technology", "Detecting technology stack...", recon.detect_technology),
        ]

        for i, (key, message, func) in enumerate(steps):
            yield f"data: {json.dumps({'type': 'progress', 'step': i+1, 'total': len(steps)+1, 'message': message})}\n\n"
            try:
                result = await asyncio.to_thread(func, domain)
                results[key] = result
            except Exception as e:
                results[key] = {"status": "FAIL", "issue": str(e), "points": 0}

        yield f"data: {json.dumps({'type': 'progress', 'step': len(steps)+1, 'total': len(steps)+1, 'message': 'Calculating security score...'})}\n\n"
        score = recon.calculate_score(results)
        findings = recon.generate_findings(results)
        results["score"] = score
        results["findings"] = findings

        yield f"data: {json.dumps({'type': 'complete', 'score': score, 'findings': findings[:5], 'domain': domain})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ─── LEAD CAPTURE ────────────────────────────────────────

class LeadCapture(BaseModel):
    name: str = ""
    email: str = ""
    phone: str = ""
    domain: str = ""
    score: Optional[int] = None

def send_report_email(to_email: str, to_name: str, domain: str, pdf_path: str):
    """Send the PDF report via SendGrid (preferred) or SMTP fallback."""
    from_email = os.getenv("SMTP_FROM", os.getenv("SENDER_EMAIL", "security@cybercomply.io"))
    from_name = os.getenv("SENDER_NAME", "CyberComply")
    subject = f"Your Security Assessment Report — {domain}"

    body = f"""Hi {to_name or 'there'},

Thank you for running a security scan on {domain} with CyberComply.

Attached is your Security Assessment Report with:
- Your security score and grade
- All findings ranked by severity
- Specific remediation steps for each issue
- Compliance gap analysis

Want to discuss the findings? Book a free 15-minute review call:
{CALENDLY_LINK}

Best,
{from_name}
CyberComply — 11 AI Agents. Always On. Always Watching.
"""

    # Read PDF attachment if exists
    attachments = []
    if pdf_path and Path(pdf_path).exists():
        with open(pdf_path, "rb") as f:
            attachments.append(("application/pdf", Path(pdf_path).name, f.read()))

    # Try SendGrid first
    sendgrid_key = os.getenv("SENDGRID_API_KEY")
    if sendgrid_key:
        try:
            import sendgrid
            from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition
            import base64
            sg = sendgrid.SendGridAPIClient(api_key=sendgrid_key)
            message = Mail(from_email=from_email, to_emails=to_email, subject=subject, plain_text_content=body)
            for mime_type, filename, data in attachments:
                att = Attachment(FileContent(base64.b64encode(data).decode()), FileName(filename), FileType(mime_type), Disposition("attachment"))
                message.add_attachment(att)
            sg.send(message)
            logger.info(f"Report emailed via SendGrid to {to_email}")
            return True
        except Exception as e:
            logger.error(f"SendGrid failed for {to_email}: {e}")

    # Fallback to SMTP
    smtp_host = os.getenv("SMTP_HOST")
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    if smtp_host and smtp_user and smtp_pass:
        try:
            msg = MIMEMultipart()
            msg["From"] = f"{from_name} <{from_email}>"
            msg["To"] = to_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            for mime_type, filename, data in attachments:
                part = MIMEBase("application", "pdf")
                part.set_payload(data)
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={filename}")
                msg.attach(part)
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            logger.info(f"Report emailed via SMTP to {to_email}")
            return True
        except Exception as e:
            logger.error(f"SMTP failed for {to_email}: {e}")

    logger.warning(f"No email transport configured — report not sent to {to_email}")
    return False


def notify_operator_new_lead(lead_name: str, lead_email: str, domain: str, score: int = None):
    """Send operator a notification when a new lead comes in."""
    operator_email = os.getenv("SMTP_FROM", os.getenv("SENDER_EMAIL", "security@cybercomply.io"))
    sendgrid_key = os.getenv("SENDGRID_API_KEY")
    if not sendgrid_key:
        return

    try:
        import sendgrid
        from sendgrid.helpers.mail import Mail
        sg = sendgrid.SendGridAPIClient(api_key=sendgrid_key)
        score_text = f"Score: {score}" if score else "Score: pending"
        body = f"""New lead captured on CyberComply!

Name: {lead_name or 'Not provided'}
Email: {lead_email}
Domain: {domain}
{score_text}
Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

View in dashboard: https://www.cybercomply.io/dashboard
"""
        message = Mail(
            from_email=operator_email,
            to_emails=operator_email,
            subject=f"New Lead: {domain} — {lead_name or lead_email}",
            plain_text_content=body,
        )
        sg.send(message)
        logger.info(f"Operator notified of new lead: {domain}")
    except Exception as e:
        logger.error(f"Failed to notify operator of lead: {e}")


# ─── PREMIUM QUALIFICATION ───────────────────────────────────

import qualification as _qual
import legal_authorization as _legal


def _operator_authed(request: Request) -> bool:
    """Operator is authed if dashboard cookie is valid OR query password is correct
    (mirrors check_dashboard_auth so every operator endpoint uses one rule)."""
    return check_dashboard_auth(request)


def require_operator(request: Request) -> None:
    """Single operator gate. Raises HTTP 401 when caller is not an operator."""
    if not check_dashboard_auth(request):
        raise HTTPException(status_code=401, detail="Unauthorized")


def require_active_validation_authorization(client_id: str, target_hint: Optional[str] = None) -> dict:
    """
    Hard gate: call before starting any active security validation run
    (Apex pentest, authenticated scan, exploit verification, intrusive scan).
    Raises HTTP 403 if authorization is not Approved + within window + scoped.

    Returns the gate result dict on success; the caller should record it.
    """
    raw = client_manager.get_legal_authorization(client_id)
    record = _legal.from_dict(raw)
    gate = _legal.authorization_gate(record, require_active=True, target_hint=target_hint)
    # Always audit the attempt (allowed or denied).
    client_manager.append_authorization_audit(client_id, {
        "event": "active_validation_gate_check",
        "target": target_hint or "",
        "allowed": gate["allowed"],
        "blockers": gate["blockers"],
    })
    if not gate["allowed"]:
        # Operator-facing detail; never show to unauthenticated callers.
        raise HTTPException(
            status_code=403,
            detail={
                "error": "active_validation_not_authorized",
                "message": "Active security validation cannot start: authorization is not approved.",
                "blockers": gate["blockers"],
            },
        )
    return gate


@app.get("/qualify", response_class=HTMLResponse)
async def qualify_form(request: Request, ref: str = ""):
    tmpl = templates.get_template("qualify.html")
    return HTMLResponse(tmpl.render(
        calendly_link=CALENDLY_LINK,
        countries_supported=sorted(_qual.SUPPORTED_COUNTRIES),
        ref=ref,
    ))


@app.post("/api/qualify")
@limiter.limit("6/minute")
async def qualify_submit(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Coerce booleans coming from form posts.
    for bool_field in ("has_internal_ciso", "domain_ownership_confirmed", "prohibited_self_attest"):
        v = body.get(bool_field)
        if isinstance(v, str):
            body[bool_field] = v.lower() in ("true", "1", "yes", "on")

    result = _qual.evaluate(body)
    record_id = client_manager.save_qualification(submission=body, result=result)

    # Operator notification (best-effort).
    try:
        op_email = os.getenv("OPERATOR_NOTIFY_EMAIL")
        if op_email:
            notify_operator_new_lead(
                name=body.get("legal_name", ""),
                email=body.get("contact_email", ""),
                domain=body.get("domain", ""),
                score=result.get("score", 0),
            )
    except Exception:
        pass

    # Customer-safe payload only — never leak flags / reasons / score.
    return JSONResponse({
        "record_id": record_id,
        "status": result["status"],
        "headline": result["headline"],
        "message": result["customer_message"],
        "next_step": result["next_step"],
        "calendly_link": CALENDLY_LINK if result["next_step"] in ("schedule_intro_call", "proposal") else None,
    })


@app.get("/api/operator/qualifications")
async def operator_list_qualifications(request: Request, status: str = ""):
    """Operator-only: full record incl. flags + reasons. Dashboard auth required."""
    if not _operator_authed(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"qualifications": client_manager.list_qualifications(status=status or None)}


# ─── LEGAL & AUTHORIZATION ───────────────────────────────────

@app.get("/api/portal/{client_id}/legal-authorization")
async def portal_legal_status(client_id: str, request: Request):
    """Customer-safe summary using soft labels only."""
    if not check_portal_auth(request, client_id):
        raise HTTPException(status_code=401, detail="Authentication required")
    raw = client_manager.get_legal_authorization(client_id)
    record = _legal.from_dict(raw)
    return _legal.to_customer_view(record)


@app.get("/api/operator/clients/{client_id}/legal-authorization")
async def operator_get_legal_authorization(client_id: str, request: Request):
    if not _operator_authed(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return client_manager.get_legal_authorization(client_id)


@app.put("/api/operator/clients/{client_id}/legal-authorization")
async def operator_update_legal_authorization(client_id: str, request: Request):
    if not _operator_authed(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    body = await request.json()
    # Validate scope syntax up-front so bad data never reaches the gate.
    av = (body.get("active_validation") or {})
    for d in av.get("target_domains", []):
        if not _legal.validate_domain(d):
            raise HTTPException(status_code=400, detail=f"Invalid domain: {d}")
    for ip in av.get("target_ips", []):
        if not _legal.validate_ip(ip):
            raise HTTPException(status_code=400, detail=f"Invalid IP: {ip}")
    for cidr in av.get("target_cidrs", []):
        if not _legal.validate_cidr(cidr):
            raise HTTPException(status_code=400, detail=f"Invalid CIDR: {cidr}")
    saved = client_manager.save_legal_authorization(client_id, body)
    client_manager.append_authorization_audit(client_id, {
        "event": "legal_authorization_updated",
        "by": "operator",
    })
    return saved


@app.post("/api/operator/clients/{client_id}/legal-authorization/approve-active")
async def operator_approve_active(client_id: str, request: Request):
    """Operator counter-approval for active validation. Customer signature must
    already be present; we never auto-approve without it."""
    if not _operator_authed(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    body = await request.json()
    operator_name = (body.get("operator_name") or "").strip()
    if not operator_name:
        raise HTTPException(status_code=400, detail="operator_name required")

    raw = client_manager.get_legal_authorization(client_id)
    if not raw or not raw.get("active_validation"):
        raise HTTPException(status_code=400, detail="Active validation record not found")

    av = raw["active_validation"]
    if not av.get("authorized_at") or not av.get("authorized_by_name"):
        raise HTTPException(status_code=400, detail="Customer signature missing — cannot approve")

    av["operator_approved_at"] = datetime.utcnow().isoformat()
    av["operator_approved_by"] = operator_name
    av["status"] = "approved"
    raw["active_validation"] = av

    # Final integrity check via gate (without target_hint).
    record = _legal.from_dict(raw)
    gate = _legal.authorization_gate(record, require_active=True)
    if not gate["allowed"]:
        raise HTTPException(
            status_code=400,
            detail={"error": "preconditions_not_met", "blockers": gate["blockers"]},
        )

    client_manager.save_legal_authorization(client_id, raw)
    client_manager.append_authorization_audit(client_id, {
        "event": "active_validation_approved",
        "by": operator_name,
    })
    import audit_log as _al
    _al.record(action=_al.ACTION_AUTHORIZATION_APPROVED, actor=operator_name,
               role=_al.ROLE_OPERATOR, client_id=client_id, request=request,
               after={"authorization_status": "approved"})
    return {"status": "approved", "approved_at": av["operator_approved_at"]}


@app.post("/api/operator/clients/{client_id}/legal-authorization/revoke-active")
async def operator_revoke_active(client_id: str, request: Request):
    if not _operator_authed(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    body = await request.json()
    reason = (body.get("reason") or "").strip() or "Revoked by operator"
    raw = client_manager.get_legal_authorization(client_id)
    if not raw.get("active_validation"):
        raise HTTPException(status_code=400, detail="No active authorization on file")
    raw["active_validation"]["status"] = "withdrawn"
    raw["active_validation"]["revoked_at"] = datetime.utcnow().isoformat()
    raw["active_validation"]["revocation_reason"] = reason
    client_manager.save_legal_authorization(client_id, raw)
    client_manager.append_authorization_audit(client_id, {
        "event": "active_validation_revoked",
        "reason": reason,
    })
    import audit_log as _al
    _al.record(action=_al.ACTION_AUTHORIZATION_REVOKED, actor="operator",
               role=_al.ROLE_OPERATOR, client_id=client_id, request=request,
               after={"authorization_status": "withdrawn"},
               reason=reason)
    return {"status": "withdrawn", "reason": reason}


@app.post("/api/portal/{client_id}/legal-authorization/sign-active")
async def portal_sign_active(client_id: str, request: Request):
    """Customer-side signature on active authorization. Does NOT approve the
    run on its own — operator counter-approval is still required."""
    if not check_portal_auth(request, client_id):
        raise HTTPException(status_code=401, detail="Authentication required")
    body = await request.json()
    name = (body.get("authorized_by_name") or "").strip()
    title = (body.get("authorized_by_title") or "").strip()
    email = (body.get("authorized_by_email") or "").strip()
    if not (name and title and email):
        raise HTTPException(status_code=400, detail="Signer name, title, and email required")

    raw = client_manager.get_legal_authorization(client_id)
    if not raw.get("active_validation"):
        raise HTTPException(status_code=400, detail="No active validation request to sign")

    if not raw.get("acknowledgments", {}).get("client_responsibility") or \
       not raw.get("acknowledgments", {}).get("no_legal_advice") or \
       not raw.get("acknowledgments", {}).get("no_breach_prevention_guarantee"):
        raise HTTPException(status_code=400, detail="Required acknowledgments missing")

    raw["active_validation"].update({
        "authorized_at": datetime.utcnow().isoformat(),
        "authorized_by_name": name,
        "authorized_by_title": title,
        "authorized_by_email": email,
        "status": "pending_operator_review",
    })
    client_manager.save_legal_authorization(client_id, raw)
    client_manager.append_authorization_audit(client_id, {
        "event": "active_validation_signed_by_customer",
        "signer": name,
    })
    return {"status": "pending_operator_review"}


@app.get("/api/operator/clients/{client_id}/legal-authorization/audit")
async def operator_authorization_audit(client_id: str, request: Request):
    if not _operator_authed(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    p = client_manager._client_dir(client_id) / "authorization_audit.json"
    return {"audit": json.loads(p.read_text()) if p.exists() else []}


@app.post("/api/operator/clients/{client_id}/active-validation/start")
async def operator_start_active_validation(client_id: str, request: Request):
    """
    Single entry point for kicking off any active security validation run
    (Apex / authenticated scan / exploit verification). The hard gate runs
    here — no agent should run active classes without going through this.
    """
    if not _operator_authed(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    body = await request.json()
    target_hint = (body.get("target") or "").strip()
    run_class = (body.get("run_class") or "active_validation").strip()

    gate = require_active_validation_authorization(client_id, target_hint=target_hint or None)

    # Authorization is good. Caller is responsible for invoking the actual
    # validation engine (Apex wrapper, etc.). This endpoint records intent
    # and returns the green-light token.
    client_manager.append_authorization_audit(client_id, {
        "event": "active_validation_started",
        "run_class": run_class,
        "target": target_hint,
    })
    return {
        "allowed": True,
        "run_class": run_class,
        "target": target_hint,
        "checked_at": gate["checked_at"],
    }


@app.post("/api/lead/capture")
@limiter.limit("10/minute")
async def capture_lead(request: Request, lead: LeadCapture):
    leads_file = DATA_DIR / "leads.json"
    leads = []
    if leads_file.exists():
        try:
            leads = json.loads(leads_file.read_text())
        except Exception:
            leads = []
    leads.append({
        "name": lead.name,
        "email": lead.email,
        "phone": lead.phone,
        "domain": lead.domain,
        "score": lead.score,
        "captured_at": datetime.utcnow().isoformat() + "Z",
    })
    leads_file.write_text(json.dumps(leads, indent=2))

    # Notify operator of new lead
    try:
        notify_operator_new_lead(lead.name, lead.email, lead.domain, lead.score)
    except Exception:
        pass

    # Background: generate full report + email it
    if lead.email and lead.domain:
        async def generate_and_email():
            try:
                from deliver import run_scan, run_questionnaire, generate_pdf_report
                scan_data = await asyncio.to_thread(run_scan, lead.domain)
                forge_data = await asyncio.to_thread(run_questionnaire, scan_data["company_name"])

                company_safe = scan_data["company_name"].replace(" ", "_").replace("&", "and")
                client_dir = OUTPUT_DIR / f"{company_safe}_{date.today().strftime('%Y%m%d')}"
                client_dir.mkdir(exist_ok=True)

                pdf_path = await asyncio.to_thread(generate_pdf_report, scan_data, forge_data, client_dir)

                # Save scan data
                raw_file = client_dir / "scan_data.json"
                raw_file.write_text(json.dumps({
                    "scan": scan_data,
                    "forge": {"profile": forge_data["profile"], "compliance": forge_data["compliance"]},
                }, indent=2, default=str))

                # Email the PDF
                await asyncio.to_thread(send_report_email, lead.email, lead.name, lead.domain, pdf_path)
                logger.info(f"Lead pipeline complete for {lead.domain} -> {lead.email}")
            except Exception as e:
                logger.error(f"Lead pipeline failed for {lead.domain}: {e}")

        asyncio.create_task(generate_and_email())

    return {"status": "captured", "count": len(leads)}

# ─── CLIENT LIST ENDPOINT ───────────────────────────────

@app.get("/api/clients")
async def list_clients(request: Request):
    require_operator(request)
    clients = []
    if not OUTPUT_DIR.exists():
        return {"clients": []}

    outreach_schedule = {}
    outreach_file = DATA_DIR / "outreach_schedule.json"
    if outreach_file.exists():
        try:
            outreach_schedule = json.loads(outreach_file.read_text())
        except Exception:
            pass

    for d in sorted(OUTPUT_DIR.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        scan_file = d / "scan_data.json"
        if not scan_file.exists():
            continue
        try:
            data = json.loads(scan_file.read_text())
            scan = data.get("scan", {})
            clients.append({
                "dir_name": d.name,
                "company": scan.get("company_name", d.name),
                "domain": scan.get("domain", ""),
                "score": scan.get("score", 0),
                "grade": scan.get("grade", "F"),
                "scan_date": scan.get("scan_date", ""),
                "has_pdf": any(f.suffix == ".pdf" for f in d.iterdir()),
                "has_proposal": (d / "PROPOSAL_EMAIL.txt").exists(),
                "has_policies": (d / "policies").is_dir() and any((d / "policies").iterdir()),
                "has_emails": False,  # updated below after company_safe is known
                "email_status": "not_started",
                "last_email_sent": None,
                "next_email_due": None,
            })

            # Check outreach schedule for email status
            company_name = scan.get("company_name", d.name)
            company_safe = company_name.replace(" ", "_").replace("&", "and")
            email_dir = DATA_DIR / "outreach_emails" / company_safe
            clients[-1]["has_emails"] = email_dir.is_dir() and any(email_dir.glob("*.txt"))
            _day_offsets = {0: "0", 1: "3", 2: "7", 3: "14", 4: "21"}
            if company_safe in outreach_schedule:
                outreach = outreach_schedule[company_safe]
                emails = outreach.get("emails", [])
                sent_emails = [e for e in emails if e.get("status") == "sent"]
                pending_emails = [e for e in emails if e.get("status") != "sent"]
                if len(sent_emails) == len(emails) and emails:
                    clients[-1]["email_status"] = "sequence_complete"
                elif sent_emails:
                    last_idx = len(sent_emails) - 1
                    day_label = _day_offsets.get(last_idx, str(last_idx))
                    clients[-1]["email_status"] = f"day_{day_label}_sent"
                    last = sent_emails[-1]
                    clients[-1]["last_email_sent"] = last.get("sent_at") or last.get("send_date")
                if pending_emails:
                    clients[-1]["next_email_due"] = pending_emails[0].get("send_date")

        except Exception:
            continue
    return {"clients": clients}

# ─── CLIENT DOWNLOAD ENDPOINT ───────────────────────────

@app.get("/api/clients/{dir_name}/download/{file_type}")
async def download_client_file(dir_name: str, file_type: str, request: Request):
    require_operator(request)
    import audit_log as _al
    _al.record(action=_al.ACTION_DOCUMENT_DOWNLOAD, actor="operator",
               role=_al.ROLE_OPERATOR, request=request,
               dir_name=dir_name, file_type=file_type)
    dir_name = safe_path_component(dir_name)
    client_dir = OUTPUT_DIR / dir_name
    if not client_dir.exists() or not client_dir.is_dir():
        raise HTTPException(status_code=404, detail="Client not found")

    if file_type == "pdf":
        pdfs = list(client_dir.glob("*.pdf"))
        if not pdfs:
            raise HTTPException(status_code=404, detail="No PDF found")
        return FileResponse(str(pdfs[0]), filename=pdfs[0].name, media_type="application/pdf")
    elif file_type == "proposal":
        f = client_dir / "PROPOSAL_EMAIL.txt"
        if not f.exists():
            raise HTTPException(status_code=404, detail="No proposal found")
        return FileResponse(str(f), filename="PROPOSAL_EMAIL.txt")
    elif file_type == "scan_data":
        f = client_dir / "scan_data.json"
        if not f.exists():
            raise HTTPException(status_code=404, detail="No scan data found")
        return FileResponse(str(f), filename="scan_data.json")
    elif file_type == "policies":
        policy_dirs = list(client_dir.glob("policies_*"))
        if not policy_dirs:
            raise HTTPException(status_code=404, detail="No policies found")
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        with zipfile.ZipFile(tmp.name, "w") as zf:
            for pd in policy_dirs:
                for pf in pd.iterdir():
                    zf.write(str(pf), pf.name)
        return FileResponse(tmp.name, filename=f"{dir_name}_policies.zip", media_type="application/zip")
    else:
        raise HTTPException(status_code=400, detail=f"Unknown file type: {file_type}")

# ─── CLIENT DETAIL ENDPOINT ─────────────────────────────

@app.get("/api/clients/{dir_name}/detail", response_class=HTMLResponse)
async def client_detail(dir_name: str, request: Request):
    if not check_dashboard_auth(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    dir_name = safe_path_component(dir_name)
    client_dir = OUTPUT_DIR / dir_name
    if not client_dir.exists():
        raise HTTPException(status_code=404, detail="Client not found")
    scan_file = client_dir / "scan_data.json"
    if not scan_file.exists():
        raise HTTPException(status_code=404, detail="No scan data")
    data = json.loads(scan_file.read_text())
    scan = data.get("scan", {})
    forge = data.get("forge", {})
    tmpl = templates.get_template("partials/client_detail.html")
    return HTMLResponse(tmpl.render(
        dir_name=dir_name, scan=scan, forge=forge,
        has_pdf=any(f.suffix == ".pdf" for f in client_dir.iterdir()),
        has_proposal=(client_dir / "PROPOSAL_EMAIL.txt").exists(),
        has_policies=(client_dir / "policies").is_dir() and any((client_dir / "policies").iterdir()),
    ))

# ─── PIPELINE ENDPOINT ──────────────────────────────────

@app.get("/api/pipeline")
async def get_pipeline(request: Request):
    require_operator(request)
    scanned = 0
    proposed = 0
    has_policies = 0
    has_emails = 0
    total_value = 0

    if OUTPUT_DIR.exists():
        for d in OUTPUT_DIR.iterdir():
            if not d.is_dir():
                continue
            if (d / "scan_data.json").exists():
                scanned += 1
                total_value += 2500
            if (d / "PROPOSAL_EMAIL.txt").exists():
                proposed += 1
                total_value += 2500
            if (d / "policies").is_dir() and any((d / "policies").iterdir()):
                has_policies += 1
            # Check outreach_emails dir for this company
            try:
                scan_data = json.loads((d / "scan_data.json").read_text()) if (d / "scan_data.json").exists() else {}
                co_name = scan_data.get("scan", {}).get("company_name", d.name)
                co_safe = co_name.replace(" ", "_").replace("&", "and")
                email_dir = DATA_DIR / "outreach_emails" / co_safe
                if email_dir.is_dir() and any(email_dir.glob("*.txt")):
                    has_emails += 1
            except Exception:
                pass

    leads_count = 0
    leads_file = DATA_DIR / "leads.json"
    if leads_file.exists():
        try:
            leads_count = len(json.loads(leads_file.read_text()))
        except Exception:
            pass

    ai_cost = 0.0
    log_file = DATA_DIR / "prompt_log.jsonl"
    if log_file.exists():
        try:
            for line in log_file.read_text().strip().split("\n"):
                if line.strip():
                    entry = json.loads(line)
                    ai_cost += entry.get("cost", 0)
        except Exception:
            pass

    # Outreach stats from email scheduler
    email_stats = {"total_scheduled": 0, "sent": 0, "pending": 0, "next_batch": None}
    outreach_schedule_file = DATA_DIR / "outreach_schedule.json"
    if outreach_schedule_file.exists():
        try:
            outreach_data = json.loads(outreach_schedule_file.read_text())
            for company_key, data in outreach_data.items():
                for email in data.get("emails", []):
                    email_stats["total_scheduled"] += 1
                    if email.get("status") == "sent":
                        email_stats["sent"] += 1
                    else:
                        email_stats["pending"] += 1
                        send_date = email.get("send_date", "")
                        if send_date:
                            if not email_stats["next_batch"] or send_date < email_stats["next_batch"]:
                                email_stats["next_batch"] = send_date
        except Exception:
            pass

    return {
        "leads": leads_count,
        "scanned": scanned,
        "proposed": proposed,
        "has_policies": has_policies,
        "has_emails": has_emails,
        "emailed": has_emails,
        "total_value": total_value,
        "ai_cost": round(ai_cost, 4),
        "email_stats": email_stats,
    }

# ─── NEW SCAN ENDPOINT ──────────────────────────────────

class NewScanRequest(BaseModel):
    domain: str
    company_name: Optional[str] = None
    industry: str = "cpa"
    employee_count: int = 15
    enable_ai: bool = False

@app.post("/api/clients/new-scan")
async def new_scan(req: NewScanRequest, request: Request):
    require_operator(request)
    from deliver import full_delivery
    company_safe = (req.company_name or req.domain.split('.')[0]).replace(" ", "_").replace("&", "and")
    dir_name = f"{company_safe}_{date.today().strftime('%Y%m%d')}"

    # Create client profile for portal system
    client_id = req.domain.replace(".", "-").replace(" ", "-").lower()
    client_manager.create_client(
        client_id=client_id,
        company_name=req.company_name or req.domain,
        domain=req.domain,
        industry=req.industry,
    )

    async def run_scan():
        await asyncio.to_thread(
            full_delivery, req.domain, req.company_name, req.industry,
            not req.enable_ai, req.employee_count  # no_ai is inverse of enable_ai
        )
        # Update client score after scan
        try:
            scan_file = OUTPUT_DIR / dir_name / "scan_data.json"
            if scan_file.exists():
                data = json.loads(scan_file.read_text())
                score = data.get("scan", {}).get("score", 0)
                grade = data.get("scan", {}).get("grade", "N/A")
                client_manager.add_score(client_id, score, grade)
                from scheduler import _generate_tasks_from_findings
                findings = data.get("scan", {}).get("archer", {}).get("findings", [])
                _generate_tasks_from_findings(client_id, findings)
                # Persist scan to clients/{id}/scans/ for audit trail
                scans_dir = client_manager._client_dir(client_id) / "scans"
                scans_dir.mkdir(exist_ok=True)
                scan_date = data.get("scan", {}).get("date", time.strftime("%Y-%m-%d"))
                (scans_dir / f"{scan_date}-initial.json").write_text(json.dumps(data.get("scan", {}), indent=2, default=str))
                # Copy PDF to portal reports/ so it shows in client portal
                import shutil
                portal_reports = client_manager._client_dir(client_id) / "reports"
                portal_reports.mkdir(exist_ok=True)
                for pdf in (OUTPUT_DIR / dir_name).glob("*.pdf"):
                    shutil.copy2(str(pdf), str(portal_reports / pdf.name))
        except Exception as e:
            logger.error(f"Post-scan update error: {e}")

    asyncio.create_task(run_scan())
    mode = "with AI narratives" if req.enable_ai else "quick mode (no AI)"
    return {"status": "started", "dir_name": dir_name, "client_id": client_id, "message": f"Scan started — {mode}"}

# ─── GENERATE POLICIES ENDPOINT ──────────────────────────

@app.post("/api/clients/{dir_name}/generate-policies")
async def generate_policies_for_client(dir_name: str, request: Request):
    require_operator(request)
    dir_name = safe_path_component(dir_name)
    client_dir = OUTPUT_DIR / dir_name
    scan_file = client_dir / "scan_data.json"
    if not scan_file.exists():
        raise HTTPException(status_code=404, detail="No scan data found")

    data = json.loads(scan_file.read_text())
    scan = data.get("scan", {})
    forge = data.get("forge", {})

    async def run_policies():
        from policy_engine import generate_core_policies, save_policies, build_client_profile
        client_profile = build_client_profile(scan, forge)
        policy_docs = await asyncio.to_thread(generate_core_policies, client_profile)
        if policy_docs:
            await asyncio.to_thread(save_policies, scan.get("company_name", dir_name), policy_docs, client_dir)

    asyncio.create_task(run_policies())
    return {"status": "started", "message": "Generating 9 core policies in background. Refresh in ~3 minutes."}

# ─── GENERATE EMAILS ENDPOINT ───────────────────────────

@app.post("/api/clients/{dir_name}/generate-emails")
async def generate_emails_for_client(dir_name: str, request: Request):
    require_operator(request)
    dir_name = safe_path_component(dir_name)
    client_dir = OUTPUT_DIR / dir_name
    scan_file = client_dir / "scan_data.json"
    if not scan_file.exists():
        raise HTTPException(status_code=404, detail="No scan data found")

    data = json.loads(scan_file.read_text())
    scan = data.get("scan", {})

    async def run_emails():
        from email_scheduler import generate_sequence
        await asyncio.to_thread(
            generate_sequence,
            domain=scan.get("domain", ""),
            company_name=scan.get("company_name", dir_name),
            scan_data=data,
        )

    asyncio.create_task(run_emails())
    return {"status": "started", "message": "Generating 5-email outreach sequence in background."}

# ─── LEADS LIST ENDPOINT ────────────────────────────────

@app.get("/api/leads")
async def list_leads(request: Request):
    require_operator(request)
    leads_file = DATA_DIR / "leads.json"
    if not leads_file.exists():
        return {"leads": []}
    try:
        return {"leads": json.loads(leads_file.read_text())}
    except Exception:
        return {"leads": []}

# ─── PORTAL AUTH ─────────────────────────────────────────────

@app.get("/portal/login", response_class=HTMLResponse)
async def portal_login_page(request: Request, client: str = "", token: str = ""):
    company = ""
    if client:
        c = client_manager.get_client(client)
        if c:
            company = c.get("company_name", "")
    if token and client:
        if client_manager.verify_magic_token(client, token):
            tmpl = templates.get_template("portal_setup.html")
            return HTMLResponse(tmpl.render(
                client_id=client, token=token, company=company,
                min_password_length=12,
            ))
    tmpl = templates.get_template("portal_login.html")
    return HTMLResponse(tmpl.render(
        error="", client_id=client, company=company,
        support_email=os.getenv("SUPPORT_EMAIL", "support@cybercomply.io"),
        calendly_link=CALENDLY_LINK,
    ))


class PortalLoginRequest(BaseModel):
    client_id: str
    password: str

@app.post("/portal/login")
@limiter.limit("5/minute")
async def portal_login(request: Request, req: PortalLoginRequest):
    import audit_log as _al
    if client_manager.verify_password(req.client_id, req.password):
        token = client_manager.create_jwt(req.client_id)
        _al.record(action=_al.ACTION_LOGIN, actor=req.client_id,
                   role=_al.ROLE_CUSTOMER, client_id=req.client_id,
                   request=request)
        resp = JSONResponse({"status": "ok", "redirect": f"/portal/{req.client_id}"})
        resp.set_cookie("portal_token", token, max_age=86400 * 30, httponly=True, samesite="lax")
        return resp
    _al.record(action=_al.ACTION_FAILED_LOGIN, actor=req.client_id,
               role=_al.ROLE_ANONYMOUS, client_id=req.client_id,
               request=request)
    return JSONResponse({"status": "error", "message": "Invalid credentials"}, status_code=401)


@app.post("/portal/logout")
async def portal_logout(request: Request):
    import audit_log as _al
    token = request.cookies.get("portal_token", "")
    cid = client_manager.verify_jwt(token) if token else ""
    _al.record(action=_al.ACTION_LOGOUT, actor=cid or "unknown",
               role=_al.ROLE_CUSTOMER, client_id=cid or "",
               request=request)
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie("portal_token")
    return resp


# ─── OPERATOR MFA SETUP ──────────────────────────────────────

@app.get("/api/operator/mfa/status")
async def operator_mfa_status(request: Request):
    """Reports whether operator MFA is configured. Public-safe: returns no
    secret material."""
    import auth_security as _as
    return {
        "mfa_required": _as.operator_mfa_required(),
        "configured": bool(_as.operator_mfa_secret()),
    }


@app.post("/api/operator/mfa/setup-secret")
async def operator_mfa_setup_secret(request: Request):
    """Generate a new TOTP secret + otpauth URI for the operator to add to
    their authenticator. The secret is returned ONCE — the operator must
    save it to OPERATOR_MFA_SECRET before MFA becomes effective."""
    # Gate by password only (since MFA isn't yet configured at this point).
    password = request.query_params.get("password")
    if password != DASHBOARD_PASSWORD:
        raise HTTPException(status_code=401, detail="Unauthorized")
    import auth_security as _as
    secret = _as.generate_totp_secret()
    return {
        "secret": secret,
        "otpauth_uri": _as.otpauth_uri(secret=secret, account="operator"),
        "instructions": (
            "Add this secret to your authenticator app, then save it to the "
            "OPERATOR_MFA_SECRET environment variable. Restart the service "
            "to enforce MFA on the next operator login."
        ),
    }


@app.post("/api/operator/mfa/verify-test")
async def operator_mfa_verify_test(request: Request):
    """Used during setup to confirm the operator entered the secret correctly
    in their authenticator before they save it to env. Pass the candidate
    secret + a TOTP code; we do NOT persist anything here."""
    password = request.query_params.get("password")
    if password != DASHBOARD_PASSWORD:
        raise HTTPException(status_code=401, detail="Unauthorized")
    body = await request.json()
    candidate = (body.get("secret") or "").strip()
    code = (body.get("code") or "").strip()
    import auth_security as _as
    return {"ok": _as.verify_totp(candidate, code)}


@app.post("/dashboard/logout")
async def dashboard_logout(request: Request):
    import audit_log as _al
    _al.record(action=_al.ACTION_OPERATOR_LOGOUT, actor="operator",
               role=_al.ROLE_OPERATOR, request=request)
    token = request.cookies.get("dashboard_auth", "")
    if token in _dashboard_sessions:
        _dashboard_sessions.discard(token)
    if token in _dashboard_mfa_passed:
        _dashboard_mfa_passed.discard(token)
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie("dashboard_auth")
    return resp


# ─── PORTAL: advisory-grade report ──────────────────────────

@app.get("/portal/{client_id}/advisory-report", response_class=HTMLResponse)
async def portal_advisory_report(client_id: str, request: Request):
    """Render the advisor-grade 12-section report for the customer portal."""
    if not check_portal_auth(request, client_id):
        return HTMLResponse('<script>window.location="/portal/login"</script>')
    client = client_manager.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    import advisory_report as _ar
    import advisor_review as _arev
    tasks = client_manager.get_tasks(client_id)
    open_tasks = [t for t in tasks if t.get("status") in (
        client_manager.TASK_STATUS_OPEN,
        client_manager.TASK_STATUS_IN_PROGRESS,
    )]
    resolved_tasks = [t for t in tasks if t.get("status") == client_manager.TASK_STATUS_VERIFIED]

    score_history = client.get("score_history", []) or []
    current_score = client.get("current_score", 0) or 0
    grade = client.get("current_grade", "—")
    frameworks = client.get("frameworks", []) or []

    # Pull latest scan + findings if available.
    latest_scan = {}
    findings = []
    scan_categories = []
    scans_dir = client_manager._client_dir(client_id) / "scans"
    scan_files = sorted(scans_dir.glob("*.json"), reverse=True) if scans_dir.exists() else []
    if scan_files:
        try:
            latest_scan = json.loads(scan_files[0].read_text())
            archer = latest_scan.get("archer", {}) or {}
            findings = archer.get("findings", []) or []
            scan_categories = archer.get("categories", []) or []
        except Exception:
            pass

    reports = client_manager.get_reports(client_id)
    policies = client_manager.get_policies(client_id)
    scans_listing = [{"filename": f.name,
                       "date": f.stem[:10] if len(f.stem) >= 10 else ""}
                      for f in scan_files]

    # Compliance frameworks with met/partial/not-met counts.
    compliance_frameworks = []
    try:
        if frameworks:
            from agents.guardian_agent import GuardianAgent
            guardian = GuardianAgent()
            guardian_profile = {
                "applicable_frameworks": [
                    f if isinstance(f, str) else f.get("id", "") for f in frameworks
                ],
                "industry": client.get("industry", ""),
            }
            data = guardian.get_compliance_status(guardian_profile)
            for fw_id, fw in (data or {}).items():
                if not isinstance(fw, dict):
                    continue
                compliance_frameworks.append({
                    "id": fw_id,
                    "name": fw.get("name", fw_id),
                    "pct": fw.get("compliance_percentage", 0) or 0,
                    "met": fw.get("met_count", 0),
                    "partial": fw.get("partial_count", 0),
                    "not_met": fw.get("not_met_count", 0),
                })
    except Exception:
        pass

    # Pending setup heuristic for the "what client needs to do" section.
    pending_setup = []
    if not os.getenv("HIBP_API_KEY"):
        pending_setup.append({"item": "Dark-web monitoring",
                              "note": "Provide a HaveIBeenPwned API key"})
    if not (os.getenv("GOPHISH_API_KEY") and os.getenv("GOPHISH_URL")):
        pending_setup.append({"item": "Phishing simulation",
                              "note": "Connect GoPhish to enable campaigns"})
    if not client.get("employee_emails"):
        pending_setup.append({"item": "Employee email list",
                              "note": "Share for phishing tests"})

    # This-month-handled bullets.
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=30)
    def _w(iso):
        try:
            return datetime.fromisoformat((iso or "").replace("Z", "")) >= cutoff
        except Exception:
            return False
    handled = []
    if score_history and _w(score_history[-1].get("date", "")):
        handled.append("External scan completed and reviewed")
    alerts = client_manager.get_alerts(client_id) or []
    handled_alerts = sum(1 for a in alerts if _w(a.get("date", "")))
    if handled_alerts:
        handled.append(f"{handled_alerts} alert(s) triaged by your advisor")
    handled_resolved = sum(1 for t in resolved_tasks
                           if _w(t.get("verified_at", "") or t.get("resolved_at", "")))
    if handled_resolved:
        handled.append(f"{handled_resolved} remediation task(s) verified")

    # Advisor review on the monthly summary.
    yyyymm = datetime.utcnow().strftime("%Y-%m")
    advisor_record = _arev.get_review(client_id, _arev.monthly_summary_key(yyyymm))
    if not _arev.is_signed_off(advisor_record):
        # Try the explicit report subject.
        advisor_record = _arev.get_review(client_id, _arev.report_key("monthly_security"))
    if not _arev.is_signed_off(advisor_record):
        advisor_record = None

    payload = _ar.build_advisory_report(
        client=client,
        current_score=current_score,
        grade=grade,
        score_history=score_history,
        open_tasks=open_tasks,
        resolved_tasks=resolved_tasks,
        findings=findings,
        scan_categories=scan_categories,
        scan_data=latest_scan,
        frameworks=frameworks,
        compliance_frameworks=compliance_frameworks,
        reports=reports,
        policies=policies,
        scans=scans_listing,
        pending_setup=pending_setup,
        this_month_handled=handled,
        value_summary={
            "advisor_actions": handled_alerts + (1 if score_history and _w(score_history[-1].get("date","")) else 0),
            "client_actions": handled_resolved,
        },
        advisor_review_record=advisor_record,
        prior_findings_count=None,
    )

    return HTMLResponse(templates.get_template("advisory_report.html").render(**payload))


# ─── PORTAL: forgot / reset ─────────────────────────────────

class PortalForgotRequest(BaseModel):
    client_id: str
    email: str = ""


@app.post("/portal/forgot")
@limiter.limit("5/minute")
async def portal_forgot(request: Request, req: PortalForgotRequest):
    """Begin password-reset flow. Returns a generic success regardless of
    whether the client_id exists, to avoid account enumeration. When email
    is configured the reset link is delivered out-of-band."""
    import auth_security as _as
    import audit_log as _al
    client = client_manager.get_client(req.client_id)
    base_url = os.getenv("BASE_URL", "https://www.cybercomply.io")
    if client:
        token = _as.create_reset_token(req.client_id)
        # Persist the nonce so /portal/reset can enforce single-use.
        try:
            parts = token.split(".")
            client_manager.store_reset_token_nonce(
                req.client_id, parts[1], int(parts[2])
            )
        except Exception:
            pass
        link = f"{base_url}/portal/reset?client={req.client_id}&token={token}"
        contact = (req.email or client.get("contact_email", "")).strip()
        try:
            if contact:
                _send_password_reset_email(contact, client.get("company_name", ""), link)
        except Exception as e:
            logger.error(f"Reset email failed for {req.client_id}: {e}")
        _al.record(action="password_reset_requested", actor=req.client_id,
                   role=_al.ROLE_ANONYMOUS, client_id=req.client_id,
                   request=request)
    return {"status": "ok",
            "message": "If an account exists, a reset link has been sent."}


def _send_password_reset_email(to: str, company: str, link: str) -> None:
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    smtp_host = os.getenv("SMTP_HOST")
    if not smtp_host:
        return
    msg = MIMEMultipart()
    msg["From"] = os.getenv("SMTP_FROM", os.getenv("SMTP_USERNAME", ""))
    msg["To"] = to
    msg["Subject"] = "Reset your CyberComply portal password"
    body = (
        f"Hi {company or 'there'},\n\n"
        f"A password reset was requested for your CyberComply portal. "
        f"Open the link below within 30 minutes to set a new password:\n\n"
        f"{link}\n\n"
        f"If you did not request this, you can ignore this email — your "
        f"current password remains unchanged.\n\n"
        f"Need help? Reply to this email or contact support@cybercomply.io.\n\n"
        f"— CyberComply Security"
    )
    msg.attach(MIMEText(body, "plain"))
    server = smtplib.SMTP(smtp_host, int(os.getenv("SMTP_PORT", "587")))
    server.starttls()
    user = os.getenv("SMTP_USERNAME", "")
    pw = os.getenv("SMTP_PASSWORD", "")
    if user and pw:
        server.login(user, pw)
    server.sendmail(msg["From"], [to], msg.as_string())
    server.quit()


class PortalResetRequest(BaseModel):
    client_id: str
    token: str
    new_password: str


@app.post("/portal/reset")
@limiter.limit("10/minute")
async def portal_reset(request: Request, req: PortalResetRequest):
    import auth_security as _as
    import audit_log as _al
    valid, nonce = _as.verify_reset_token(req.token, req.client_id)
    if not valid or not client_manager.consume_reset_token_nonce(req.client_id, nonce):
        return JSONResponse(
            {"status": "error",
             "message": "Reset link is invalid or has expired. Request a new one."},
            status_code=400,
        )
    try:
        client_manager.set_portal_password(req.client_id, req.new_password)
    except _as.PasswordPolicyError as e:
        return JSONResponse(
            {"status": "error", "message": str(e)},
            status_code=400,
        )
    _al.record(action="password_reset_completed", actor=req.client_id,
               role=_al.ROLE_CUSTOMER, client_id=req.client_id, request=request)
    jwt_token = client_manager.create_jwt(req.client_id)
    resp = JSONResponse({"status": "ok",
                          "redirect": f"/portal/{req.client_id}"})
    resp.set_cookie("portal_token", jwt_token, max_age=86400 * 30,
                     httponly=True, samesite="lax")
    return resp


@app.get("/portal/forgot", response_class=HTMLResponse)
async def portal_forgot_page(request: Request):
    return HTMLResponse(templates.get_template("portal_forgot.html").render(
        company="", error="",
    ))


@app.get("/portal/reset", response_class=HTMLResponse)
async def portal_reset_page(request: Request,
                             client: str = "", token: str = ""):
    company = ""
    if client:
        c = client_manager.get_client(client)
        company = c.get("company_name", "") if c else ""
    return HTMLResponse(templates.get_template("portal_reset.html").render(
        client_id=client, token=token, company=company,
        min_password_length=12, error="",
    ))


class PortalSetupRequest(BaseModel):
    client_id: str
    token: str
    password: str

@app.post("/portal/setup")
async def portal_setup(req: PortalSetupRequest):
    if not client_manager.verify_magic_token(req.client_id, req.token):
        return JSONResponse({"status": "error", "message": "Invalid or expired link"}, status_code=401)
    import auth_security as _as
    try:
        client_manager.set_portal_password(req.client_id, req.password)
    except _as.PasswordPolicyError as e:
        return JSONResponse({"status": "error", "message": str(e)},
                             status_code=400)
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


# ─── PORTAL MAIN VIEW ───────────────────────────────────────

@app.get("/portal/{client_id}", response_class=HTMLResponse)
async def portal_page(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse('<script>window.location="/portal/login"</script>')

    client = client_manager.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    tier = client_manager.normalize_tier(client.get("tier", "diagnostic"))
    tier_config = client_manager.get_tier_config(tier)
    # Gate self-serve portal on paid plans only. Diagnostic engagements are
    # operator-managed deliverables, not a self-serve portal.
    if not tier_config.get("portal_access"):
        return HTMLResponse(
            "<h2>Portal access is part of paid plans</h2>"
            "<p>Your engagement is a one-time diagnostic. Your advisor will deliver "
            "your readiness report and recommendations directly. To access the live "
            "customer portal, ask about the Essentials, Professional, or Enterprise+ plan.</p>"
            f"<p><a href=\"{CALENDLY_LINK}\">Schedule a call &rarr;</a></p>",
            status_code=200,
        )
    tasks = client_manager.get_tasks(client_id)
    alerts = client_manager.get_alerts(client_id)
    reports = client_manager.get_reports(client_id)
    policies = client_manager.get_policies(client_id)

    score_history = client.get("score_history", [])
    current_score = client.get("current_score", 0)
    current_grade = client.get("current_grade", "N/A")

    # Annotate each task with a customer-safe status label.
    for _t in tasks:
        _t["status_label"] = client_manager.TASK_STATUS_LABELS.get(
            _t.get("status", "open"), _t.get("status", "open")
        )

    # Tasks the customer can still act on (Open, In progress, Submitted for review).
    open_tasks = [t for t in tasks if t["status"] in (
        client_manager.TASK_STATUS_OPEN,
        client_manager.TASK_STATUS_IN_PROGRESS,
        client_manager.TASK_STATUS_SUBMITTED,
    )]
    in_progress_tasks = [t for t in tasks
                         if t["status"] == client_manager.TASK_STATUS_IN_PROGRESS]
    resolved_tasks = [t for t in tasks if t["status"] in (
        client_manager.TASK_STATUS_VERIFIED, "resolved",
    )]

    # Calculate real compliance from GUARDIAN data
    compliance_pct = 0
    frameworks = client.get("frameworks", [])
    try:
        if frameworks:
            # Normalize frameworks to list of strings (IDs)
            fw_list = []
            for fw in frameworks:
                if isinstance(fw, str):
                    fw_list.append(fw)
                elif isinstance(fw, dict):
                    fw_list.append(fw.get("id", fw.get("name", "")))
            fw_list = [f for f in fw_list if f]

            if fw_list:
                from agents.guardian_agent import GuardianAgent
                guardian = GuardianAgent()
                guardian_profile = {"applicable_frameworks": fw_list}
                # Map client fields to what _check_control expects
                guardian_profile["mfa_status"] = client.get("mfa_status", "")
                guardian_profile["training"] = client.get("training_frequency", client.get("training", ""))
                guardian_profile["has_wisp"] = client.get("has_wisp", "")
                guardian_profile["has_irp"] = client.get("has_irp", "")
                guardian_profile["industry"] = client.get("industry", "")
                compliance_data = guardian.get_compliance_status(guardian_profile)
                if compliance_data:
                    percentages = [fw.get("compliance_percentage", 0) for fw in compliance_data.values() if isinstance(fw, dict)]
                    compliance_pct = sum(percentages) // max(len(percentages), 1) if percentages else 0
    except Exception:
        compliance_pct = 0

    agent_status = _get_agent_status(client_id)
    threats_blocked = sum(1 for a in alerts if a.get("type") == "threat")
    dark_web_alerts = sum(1 for a in alerts if a.get("type") == "darkweb")
    vuln_findings = sum(1 for a in alerts if a.get("type") == "vulnscan")
    phishing_tests = sum(1 for a in alerts if a.get("type") == "phishing")
    monitoring_alerts = sum(1 for a in alerts if a.get("type") == "monitoring")

    # Load call notes for portal display
    call_notes_file = client_manager._client_dir(client_id) / "call_notes.json"
    call_notes = json.loads(call_notes_file.read_text()) if call_notes_file.exists() else []

    # Industry benchmark
    industry_avg_score = None
    try:
        from prompt_library import INDUSTRY_CONTEXT
        industry_key = client.get("industry", "").lower().strip()
        if industry_key and industry_key in INDUSTRY_CONTEXT:
            industry_avg_score = INDUSTRY_CONTEXT[industry_key].get("industry_avg_score")
    except Exception:
        pass

    # Monthly narrative from latest report
    monthly_narrative = None
    try:
        reports_dir = client_manager._client_dir(client_id) / "reports"
        monthly_files = sorted(reports_dir.glob("*monthly*"), reverse=True) if reports_dir.exists() else []
        if monthly_files:
            report_data = json.loads(monthly_files[0].read_text())
            monthly_narrative = report_data.get("narrative", "")
    except Exception:
        pass

    # Advisor info
    advisor_name = client.get("advisor_name", "CyberComply Security Team")
    next_call_date = client.get("next_call_date", "")

    # Truth-gate flags for portal copy: only show "Active" / "All clear" when integration is connected.
    import shutil as _shutil
    client["hibp_configured"] = bool(os.getenv("HIBP_API_KEY"))
    client["gophish_configured"] = bool(os.getenv("GOPHISH_API_KEY") and os.getenv("GOPHISH_URL"))
    client["nuclei_available"] = _shutil.which("nuclei") is not None
    client.setdefault("advisor_reviewed_at", "")
    client.setdefault("monthly_summary_reviewed_at", "")
    client.setdefault("last_darkweb_check_at", "")

    # ── Legal authorization customer-safe view (must come before coverage) ──
    raw_legal = client_manager.get_legal_authorization(client_id)
    legal_view = _legal.to_customer_view(
        _legal.from_dict(raw_legal if raw_legal else {"client_id": client_id})
    )

    # ── Service coverage (rich model) ──
    import service_coverage as _sc
    m365_configured = bool(
        os.getenv("MS_TENANT_ID") and os.getenv("MS_CLIENT_ID") and os.getenv("MS_CLIENT_SECRET")
    )
    coverage = _sc.build_coverage(
        tier=tier,
        score_history=score_history,
        open_tasks=open_tasks,
        alerts=alerts,
        reports=reports,
        policies=policies,
        frameworks=frameworks,
        compliance_pct=compliance_pct,
        advisor_name=advisor_name,
        next_call_date=next_call_date,
        advisor_reviewed_at=client.get("advisor_reviewed_at", ""),
        monthly_summary_reviewed_at=client.get("monthly_summary_reviewed_at", ""),
        last_darkweb_check_at=client.get("last_darkweb_check_at", ""),
        dark_web_exposures=dark_web_alerts,
        last_vuln_scan_at=client.get("last_vuln_scan_at", ""),
        vuln_findings=vuln_findings,
        last_phishing_campaign_at=client.get("last_phishing_campaign_at", ""),
        employee_emails=client.get("employee_emails", []),
        last_m365_sync_at=client.get("last_m365_sync_at", ""),
        legal_view=legal_view,
        hibp_configured=client["hibp_configured"],
        gophish_configured=client["gophish_configured"],
        nuclei_available=client["nuclei_available"],
        m365_configured=m365_configured,
    )

    # ── This month: what we handled (executive summary) ──
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=30)
    def _within_30d(iso):
        try:
            return datetime.fromisoformat(iso.replace("Z", "")) >= cutoff
        except Exception:
            return False
    handled_alerts = sum(1 for a in alerts if _within_30d(a.get("date", "")))
    handled_tasks = sum(1 for t in resolved_tasks if _within_30d(t.get("resolved_at", "")))
    handled_scans = 1 if score_history and _within_30d(score_history[-1].get("date", "")) else 0
    this_month_handled = []
    if handled_scans:
        this_month_handled.append(f"{handled_scans} external scan completed and reviewed")
    if handled_alerts:
        this_month_handled.append(f"{handled_alerts} alert(s) triaged by your advisor")
    if handled_tasks:
        this_month_handled.append(f"{handled_tasks} remediation task(s) closed")
    if monthly_narrative:
        this_month_handled.append("Monthly executive summary prepared")
    if not this_month_handled:
        this_month_handled.append("Onboarding in progress — your first review cycle is being scheduled")

    # ── Pending setup (integrations / metadata not yet connected) ──
    pending_setup = []
    if tier_config.get("dark_web") and not client["hibp_configured"]:
        pending_setup.append({"item": "Dark-web monitoring",
                              "note": "Connect a HaveIBeenPwned API key to enable scheduled checks"})
    if tier_config.get("phishing") and not client["gophish_configured"]:
        pending_setup.append({"item": "Phishing simulation",
                              "note": "Connect GoPhish to launch employee tests"})
    if not tier_config.get("active_validation_included"):
        pass
    elif tier_config.get("active_validation_included"):
        pending_setup.append({"item": "Active security validation authorization",
                              "note": "Sign the engagement scope to enable quarterly authorized validation"})
    if not next_call_date and tier_config.get("monthly_call"):
        pending_setup.append({"item": "Advisor review call",
                              "note": "Schedule your next check-in"})
    if not client.get("advisor_reviewed_at") and policies:
        pending_setup.append({"item": "Policy advisor review",
                              "note": "Your advisor will sign off on the latest policy refresh"})

    # ── Due next (timeline of upcoming events) ──
    due_next = []
    if next_call_date:
        due_next.append({"when": next_call_date, "what": "Advisor review call"})
    # Tasks with a due_date
    for t in open_tasks:
        if t.get("due_date"):
            due_next.append({"when": t["due_date"], "what": t.get("title", "Remediation task")})
    due_next.sort(key=lambda r: r["when"])
    due_next = due_next[:5]

    # ── Risk narrative (single executive sentence) ──
    if current_score == 0:
        risk_narrative = "Your first assessment is being prepared. Once complete, your business risk picture will appear here."
        risk_label = "Awaiting first scan"
    elif current_score >= 80:
        risk_narrative = f"Your external security posture is strong (score {current_score}/100). Continue with maintenance — no urgent gaps detected."
        risk_label = "Low risk"
    elif current_score >= 60:
        risk_narrative = f"Your posture is moderate (score {current_score}/100). A small number of items need attention this month."
        risk_label = "Moderate risk"
    elif current_score >= 40:
        risk_narrative = f"Your posture has notable gaps (score {current_score}/100). Your advisor is prioritizing remediation."
        risk_label = "Elevated risk"
    else:
        risk_narrative = f"Your posture requires immediate attention (score {current_score}/100). Critical items are being actioned now."
        risk_label = "High risk"

    # ── Reduce open_tasks to the 3 highest-priority "needs attention" items ──
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    needs_attention = sorted(open_tasks, key=lambda t: severity_order.get(t.get("severity", "LOW"), 9))[:3]

    # ── Authorization audit + scans (used by value dashboard + vault) ──
    auth_audit_path = client_manager._client_dir(client_id) / "authorization_audit.json"
    authorization_audit = json.loads(auth_audit_path.read_text()) if auth_audit_path.exists() else []
    scans_dir = client_manager._client_dir(client_id) / "scans"
    scans_listing = []
    if scans_dir.exists():
        for f in sorted(scans_dir.glob("*.json"), reverse=True):
            scans_listing.append({
                "filename": f.name,
                "date": f.stem[:10] if len(f.stem) >= 10 else "",
            })

    # ── Advisor review records (per subject) ──
    import advisor_review as _ar
    review_records = _ar.list_reviews(client_id)

    # ── Document library (8 reports + 8 policies) ──
    import document_library as _doclib
    document_library = _doclib.build_library(
        client_id=client_id, tier=tier,
        reports=reports, policies=policies,
        frameworks=frameworks,
        advisor_name=advisor_name,
        advisor_reviewed_at=client.get("advisor_reviewed_at", ""),
        monthly_summary_reviewed_at=client.get("monthly_summary_reviewed_at", ""),
        legal_view=legal_view,
        review_records=review_records,
    )

    # ── Evidence Vault catalog (10 categories) ──
    import evidence_vault as _ev
    vault = _ev.build_vault(
        client_id=client_id,
        policies=policies,
        reports=reports,
        scans=scans_listing,
        alerts=alerts,
        frameworks=frameworks,
        compliance_pct=compliance_pct,
        advisor_name=advisor_name,
        advisor_reviewed_at=client.get("advisor_reviewed_at", ""),
        monthly_summary_reviewed_at=client.get("monthly_summary_reviewed_at", ""),
        last_phishing_campaign_at=client.get("last_phishing_campaign_at", ""),
        last_m365_sync_at=client.get("last_m365_sync_at", ""),
        m365_configured=m365_configured,
        legal_view=legal_view,
        authorization_audit=authorization_audit,
        review_records=review_records,
    )

    # Compute monthly_summary review record for the current YYYY-MM (used by
    # the portal monthly-summary card so its badge respects review metadata).
    _today_yyyymm = datetime.utcnow().strftime("%Y-%m")
    monthly_summary_review = review_records.get(
        _ar.monthly_summary_key(_today_yyyymm), {}
    )
    if not _ar.is_signed_off(monthly_summary_review):
        # Walk back up to 6 months to find the most recent signed-off summary
        for i in range(1, 7):
            from datetime import timedelta as _td
            ymd = (datetime.utcnow() - _td(days=30 * i)).strftime("%Y-%m")
            r = review_records.get(_ar.monthly_summary_key(ymd), {})
            if _ar.is_signed_off(r):
                monthly_summary_review = r
                break

    # ── This Month's Value Delivered ──
    import value_delivered as _vd
    value_dashboard = _vd.build_value_delivered(
        coverage=coverage,
        score_history=score_history,
        alerts=alerts,
        open_tasks=open_tasks,
        resolved_tasks=resolved_tasks,
        reports=reports,
        policies=policies,
        call_notes=call_notes,
        due_next=due_next,
        legal_view=legal_view,
        authorization_audit=authorization_audit,
        advisor_reviewed_at=client.get("advisor_reviewed_at", ""),
        monthly_summary_reviewed_at=client.get("monthly_summary_reviewed_at", ""),
    )

    tmpl = templates.get_template("portal.html")
    return HTMLResponse(tmpl.render(
        client=client, tier=tier_config,
        current_score=current_score, current_grade=current_grade,
        score_history=score_history,
        open_tasks=open_tasks, in_progress_tasks=in_progress_tasks,
        resolved_tasks=resolved_tasks,
        alerts=alerts, dark_web_alerts=dark_web_alerts,
        threats_blocked=threats_blocked,
        coverage=coverage,
        this_month_handled=this_month_handled,
        pending_setup=pending_setup,
        due_next=due_next,
        legal_view=legal_view,
        risk_narrative=risk_narrative,
        risk_label=risk_label,
        needs_attention=needs_attention,
        value_dashboard=value_dashboard,
        vault=vault,
        document_library=document_library,
        monthly_summary_review=_ar.customer_view(monthly_summary_review),
        monthly_summary_signed_off=_ar.is_signed_off(monthly_summary_review),
        vuln_findings=vuln_findings, phishing_tests=phishing_tests,
        monitoring_alerts=monitoring_alerts,
        reports=reports, policies=policies,
        agent_status=agent_status, frameworks=frameworks,
        compliance_pct=compliance_pct,
        call_notes=call_notes,
        industry_avg_score=industry_avg_score,
        monthly_narrative=monthly_narrative,
        advisor_name=advisor_name,
        next_call_date=next_call_date,
        calendly_link=CALENDLY_LINK,
    ))


def _get_agent_status(client_id: str) -> list:
    status_file = client_manager._client_dir(client_id) / "agent_status.json"
    if status_file.exists():
        return json.loads(status_file.read_text())
    return [
        {"name": "RECON", "label": "External Scan", "status": "active", "last_run": "Pending first scan"},
        {"name": "SHADOW", "label": "Dark Web Monitor", "status": "active", "last_run": "Pending"},
        {"name": "FALCON", "label": "Threat Intelligence", "status": "active", "last_run": "Pending"},
        {"name": "GUARDIAN", "label": "Compliance Engine", "status": "active", "last_run": "Pending"},
        {"name": "PHANTOM", "label": "Phishing Defense", "status": "standby", "last_run": "Not scheduled"},
        {"name": "DISPATCH", "label": "Incident Response", "status": "standby", "last_run": "0 active incidents"},
    ]


@app.post("/portal/{client_id}/task/{task_id}/status")
async def update_task(client_id: str, task_id: str, request: Request):
    """Customer-side status nudge (e.g. Open → In progress).
    Verification is gated to operators only — see /api/operator/.../verify."""
    if not check_portal_auth(request, client_id):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    requested = (body.get("status") or "").strip()
    # Reject any attempt to mark a task verified from the customer portal.
    if requested == client_manager.TASK_STATUS_VERIFIED:
        raise HTTPException(
            status_code=403,
            detail="Verification is performed by your advisor.",
        )
    before = next((t for t in client_manager.get_tasks(client_id) if t.get("id") == task_id), None)
    try:
        if requested == client_manager.TASK_STATUS_IN_PROGRESS:
            client_manager.start_task(client_id, task_id, by="customer")
        else:
            client_manager.update_task_status(client_id, task_id, requested)
    except client_manager.TaskTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    after = next((t for t in client_manager.get_tasks(client_id) if t.get("id") == task_id), None)
    import audit_log as _al
    _al.record(action=_al.ACTION_TASK_STATUS_CHANGE, actor=client_id,
               role=_al.ROLE_CUSTOMER, client_id=client_id, request=request,
               before={"status": (before or {}).get("status", "")},
               after={"status": (after or {}).get("status", "")},
               task_id=task_id)
    return {"status": "ok"}


@app.post("/portal/{client_id}/task/{task_id}/submit")
async def submit_portal_task(client_id: str, task_id: str, request: Request):
    """Customer submits a task for advisor review. This is the path that used
    to be 'Done' — but it never marks the task verified."""
    token = request.query_params.get("token")
    jwt_cookie = request.cookies.get("portal_token")

    authenticated = False
    if token:
        authenticated = client_manager.verify_magic_token(client_id, token)
    elif jwt_cookie:
        jwt_client = client_manager.verify_jwt(jwt_cookie)
        authenticated = (jwt_client == client_id)

    if not authenticated:
        raise HTTPException(
            status_code=403,
            detail="Authentication required. Use magic link or log in to portal.",
        )

    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    notes = (body.get("notes") or "").strip()
    evidence = body.get("evidence") or []
    if not isinstance(evidence, list):
        evidence = []

    try:
        client_manager.submit_task_for_review(
            client_id, task_id, by="customer",
            notes=notes, evidence=evidence,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Task not found")
    except client_manager.TaskTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return HTMLResponse(
        '<span class="status-pill status-Submittedforreview">Submitted for review</span>'
        '<div style="font-size:11.5px;color:var(--muted);margin-top:6px">'
        'Awaiting advisor verification.'
        '</div>'
    )


# Backwards-compatible alias: the old "resolve" path now submits for review.
# It does NOT mark the task verified.
@app.post("/portal/{client_id}/task/{task_id}/resolve")
async def resolve_portal_task_legacy(client_id: str, task_id: str, request: Request):
    return await submit_portal_task(client_id, task_id, request)


@app.post("/portal/{client_id}/task/{task_id}/note")
async def portal_task_add_note(client_id: str, task_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    note = (body.get("note") or "").strip()
    if not note:
        raise HTTPException(status_code=400, detail="Note text required")
    try:
        client_manager.add_customer_note(client_id, task_id, note, by="customer")
    except KeyError:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"status": "ok"}


@app.post("/portal/{client_id}/task/{task_id}/evidence")
async def portal_task_attach_evidence(client_id: str, task_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    filename = safe_path_component((body.get("filename") or "").strip())
    if not filename:
        raise HTTPException(status_code=400, detail="filename required")
    try:
        client_manager.attach_evidence(client_id, task_id, filename, by="customer")
    except KeyError:
        raise HTTPException(status_code=404, detail="Task not found")
    import audit_log as _al
    _al.record(action=_al.ACTION_EVIDENCE_UPLOAD, actor=client_id,
               role=_al.ROLE_CUSTOMER, client_id=client_id, request=request,
               task_id=task_id, filename=filename)
    return {"status": "ok"}


# ─── OPERATOR: Task verification ────────────────────────────────

@app.post("/api/operator/clients/{client_id}/tasks/{task_id}/verify")
async def operator_verify_task(client_id: str, task_id: str, request: Request):
    """Sole path to status='verified'. Refuses unless the task is currently
    in 'submitted_for_review' (enforced by the state machine)."""
    require_operator(request)
    body = await request.json()
    operator_name = (body.get("operator_name") or "").strip()
    if not operator_name:
        raise HTTPException(status_code=400, detail="operator_name required")
    method = (body.get("method") or "").strip()
    if method and method not in client_manager.TASK_VERIFICATION_METHODS:
        raise HTTPException(status_code=400, detail=f"Invalid method: {method}")
    note = (body.get("note") or "").strip()
    try:
        task = client_manager.verify_task(
            client_id, task_id, by=operator_name,
            method=method, note=note,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Task not found")
    except client_manager.TaskTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    import audit_log as _al
    _al.record(action=_al.ACTION_TASK_VERIFY, actor=operator_name,
               role=_al.ROLE_OPERATOR, client_id=client_id, request=request,
               after={"status": task.get("status"),
                       "verified_by": task.get("verified_by")},
               task_id=task_id, method=method)
    return {"status": "verified", "task": task}


@app.post("/api/operator/clients/{client_id}/tasks/{task_id}/reject")
async def operator_reject_task(client_id: str, task_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    operator_name = (body.get("operator_name") or "").strip()
    reason = (body.get("reason") or "").strip()
    if not operator_name or not reason:
        raise HTTPException(status_code=400,
                            detail="operator_name and reason required")
    try:
        task = client_manager.reject_task(client_id, task_id,
                                          by=operator_name, reason=reason)
    except KeyError:
        raise HTTPException(status_code=404, detail="Task not found")
    except client_manager.TaskTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "in_progress", "task": task}


@app.post("/api/operator/clients/{client_id}/tasks/{task_id}/defer")
async def operator_defer_task(client_id: str, task_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    operator_name = (body.get("operator_name") or "").strip()
    until = (body.get("until") or "").strip()
    reason = (body.get("reason") or "").strip()
    if not operator_name:
        raise HTTPException(status_code=400, detail="operator_name required")
    try:
        task = client_manager.defer_task(client_id, task_id,
                                         by=operator_name, until=until,
                                         reason=reason)
    except KeyError:
        raise HTTPException(status_code=404, detail="Task not found")
    except client_manager.TaskTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"status": "deferred", "task": task}


@app.post("/api/operator/clients/{client_id}/tasks/{task_id}/note")
async def operator_add_advisor_note(client_id: str, task_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    note = (body.get("note") or "").strip()
    operator_name = (body.get("operator_name") or "").strip()
    if not note or not operator_name:
        raise HTTPException(status_code=400,
                            detail="note and operator_name required")
    try:
        task = client_manager.add_advisor_note(client_id, task_id, note,
                                               by=operator_name)
    except KeyError:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"status": "ok", "task": task}


@app.put("/api/operator/clients/{client_id}/tasks/{task_id}")
async def operator_update_task(client_id: str, task_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    try:
        task = client_manager.update_task_fields(client_id, task_id, body)
    except KeyError:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"status": "ok", "task": task}


# ─── OPERATOR: advisor-review records (any subject) ─────────

@app.get("/api/operator/clients/{client_id}/reviews")
async def operator_list_reviews(client_id: str, request: Request):
    """Operator view — full records including internal_operator_notes."""
    require_operator(request)
    import advisor_review as _ar
    return {"reviews": _ar.list_reviews(client_id)}


@app.get("/api/operator/clients/{client_id}/reviews/{subject_key:path}")
async def operator_get_review(client_id: str, subject_key: str, request: Request):
    require_operator(request)
    import advisor_review as _ar
    return _ar.get_review(client_id, subject_key)


@app.post("/api/operator/clients/{client_id}/reviews/{subject_key:path}")
async def operator_set_review(client_id: str, subject_key: str, request: Request):
    """Create or update a review record for any subject. Approval requires
    a complete sign-off identity (reviewed_by, reviewed_on, sign_off_timestamp);
    the module raises ValueError if the caller asks for approved without them."""
    require_operator(request)
    import advisor_review as _ar
    body = await request.json() or {}
    # If status=approved and sign_off_timestamp absent, set it server-side.
    if body.get("review_status") == _ar.REVIEW_APPROVED \
       and not body.get("sign_off_timestamp"):
        body["sign_off_timestamp"] = _ar.now_iso()
    before = _ar.get_review(client_id, subject_key)
    try:
        rec = _ar.set_review(client_id, subject_key, **body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    import audit_log as _al
    _al.record(action=_al.ACTION_ADVISOR_REVIEW, actor=rec.get("reviewed_by", ""),
               role=_al.ROLE_OPERATOR, client_id=client_id, request=request,
               before={"review_status": (before or {}).get("review_status", "")},
               after={"review_status": rec.get("review_status", ""),
                       "reviewed_by": rec.get("reviewed_by", "")},
               subject_key=subject_key)
    return {"status": "ok", "review": rec}


@app.get("/api/portal/{client_id}/reviews/{subject_key:path}")
async def portal_get_review(client_id: str, subject_key: str, request: Request):
    """Customer view — internal_operator_notes is stripped."""
    if not check_portal_auth(request, client_id):
        raise HTTPException(status_code=401, detail="Authentication required")
    import advisor_review as _ar
    rec = _ar.get_review(client_id, subject_key)
    return _ar.customer_view(rec)


# ─── SECURITY VALIDATION ────────────────────────────────────

import security_validation as _sv


def _sv_handle_error(e: Exception):
    if isinstance(e, _sv.EngagementTransitionError):
        raise HTTPException(status_code=400, detail=str(e))
    if isinstance(e, ValueError):
        raise HTTPException(status_code=400, detail=str(e))
    if isinstance(e, KeyError):
        raise HTTPException(status_code=404, detail=f"Not found: {e}")
    raise


@app.get("/api/operator/clients/{client_id}/validations")
async def operator_list_validations(client_id: str, request: Request):
    require_operator(request)
    return {"engagements": _sv.list_engagements(client_id)}


@app.post("/api/operator/clients/{client_id}/validations")
async def operator_create_validation(client_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    try:
        eng = _sv.create_engagement(
            client_id,
            scan_class=body.get("scan_class", _sv.SCAN_ACTIVE),
            scope_summary=body.get("scope_summary", ""),
        )
    except Exception as e:
        _sv_handle_error(e)
    return eng


@app.get("/api/operator/clients/{client_id}/validations/{engagement_id}")
async def operator_get_validation(client_id: str, engagement_id: str, request: Request):
    require_operator(request)
    try:
        return _sv.get_engagement(client_id, engagement_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Engagement not found")


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/scope")
async def operator_scope_validation(client_id: str, engagement_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    try:
        return _sv.scope_engagement(client_id, engagement_id, body)
    except Exception as e:
        _sv_handle_error(e)


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/approve")
async def operator_approve_validation(client_id: str, engagement_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    operator_name = (body.get("operator_name") or "").strip()
    try:
        return _sv.approve_engagement(client_id, engagement_id, operator_name)
    except Exception as e:
        _sv_handle_error(e)


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/schedule")
async def operator_schedule_validation(client_id: str, engagement_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    try:
        return _sv.schedule_engagement(
            client_id, engagement_id,
            scheduled_at=body.get("scheduled_at", ""),
        )
    except Exception as e:
        _sv_handle_error(e)


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/start")
async def operator_start_validation(client_id: str, engagement_id: str, request: Request):
    """Hard rule: active scans go through the legal authorization gate."""
    require_operator(request)
    try:
        out = _sv.start_engagement(client_id, engagement_id)
    except Exception as e:
        _sv_handle_error(e)
    import audit_log as _al
    _al.record(action=_al.ACTION_VALIDATION_START, actor="operator",
               role=_al.ROLE_OPERATOR, client_id=client_id, request=request,
               engagement_id=engagement_id,
               scan_class=out.get("scan_class"))
    # Mirror as scan_start for the unified scan log.
    _al.record(action=_al.ACTION_SCAN_START, actor="operator",
               role=_al.ROLE_OPERATOR, client_id=client_id, request=request,
               engagement_id=engagement_id, scan_class=out.get("scan_class"))
    return out


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/stop")
@app.post("/api/portal/{client_id}/validations/{engagement_id}/stop")
async def operator_or_customer_stop_validation(
    client_id: str, engagement_id: str, request: Request,
):
    """Kill switch — operator OR the authenticated customer can engage it."""
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    # Either dashboard auth OR portal auth (customer can stop their own run).
    is_operator = check_dashboard_auth(request)
    is_customer = check_portal_auth(request, client_id) if not is_operator else False
    if not (is_operator or is_customer):
        raise HTTPException(status_code=401, detail="Unauthorized")
    by = "operator" if is_operator else "customer"
    reason = (body.get("reason") or "Kill switch engaged").strip()
    try:
        out = _sv.engage_kill_switch(client_id, engagement_id,
                                      by=by, reason=reason)
    except Exception as e:
        _sv_handle_error(e)
    import audit_log as _al
    _al.record(action=_al.ACTION_VALIDATION_STOP, actor=by,
               role=_al.ROLE_OPERATOR if is_operator else _al.ROLE_CUSTOMER,
               client_id=client_id, request=request,
               engagement_id=engagement_id, reason=reason)
    _al.record(action=_al.ACTION_SCAN_STOP, actor=by,
               role=_al.ROLE_OPERATOR if is_operator else _al.ROLE_CUSTOMER,
               client_id=client_id, request=request,
               engagement_id=engagement_id, reason=reason)
    return out


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/complete")
async def operator_complete_validation(client_id: str, engagement_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    try:
        out = _sv.complete_run(client_id, engagement_id,
                                findings=body.get("findings") or [])
    except Exception as e:
        _sv_handle_error(e)
    import audit_log as _al
    _al.record(action=_al.ACTION_VALIDATION_COMPLETE, actor="operator",
               role=_al.ROLE_OPERATOR, client_id=client_id, request=request,
               engagement_id=engagement_id,
               finding_count=len(out.get("findings") or []))
    return out


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/findings/{finding_id}/fp-review")
async def operator_fp_review(client_id: str, engagement_id: str, finding_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    by = (body.get("operator_name") or "").strip()
    status = (body.get("status") or "").strip()
    if not by:
        raise HTTPException(status_code=400, detail="operator_name required")
    try:
        return _sv.fp_review_finding(client_id, engagement_id, finding_id,
                                     by=by, status=status,
                                     notes=body.get("notes", ""))
    except Exception as e:
        _sv_handle_error(e)


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/findings/{finding_id}/validate")
async def operator_validate_finding(client_id: str, engagement_id: str, finding_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    by = (body.get("operator_name") or "").strip()
    if not by:
        raise HTTPException(status_code=400, detail="operator_name required")
    try:
        return _sv.advisor_validate_finding(
            client_id, engagement_id, finding_id, by=by,
            reviewer_credential=body.get("reviewer_credential", ""),
            notes=body.get("notes", ""),
            client_facing_recommendation=body.get("client_facing_recommendation", ""),
        )
    except Exception as e:
        _sv_handle_error(e)


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/validate")
async def operator_validate_engagement(client_id: str, engagement_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    by = (body.get("operator_name") or "").strip()
    if not by:
        raise HTTPException(status_code=400, detail="operator_name required")
    try:
        return _sv.validate_engagement(
            client_id, engagement_id, by=by,
            reviewer_credential=body.get("reviewer_credential", ""),
            final_report_path=body.get("final_report_path", ""),
        )
    except Exception as e:
        _sv_handle_error(e)


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/begin-remediation")
async def operator_begin_remediation(client_id: str, engagement_id: str, request: Request):
    require_operator(request)
    try:
        return _sv.begin_remediation(client_id, engagement_id)
    except Exception as e:
        _sv_handle_error(e)


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/findings/{finding_id}/retest")
async def operator_retest_finding(client_id: str, engagement_id: str, finding_id: str, request: Request):
    require_operator(request)
    body = await request.json()
    try:
        return _sv.record_retest(
            client_id, engagement_id, finding_id,
            passed=bool(body.get("passed")),
            by=(body.get("operator_name") or "").strip(),
            notes=body.get("notes", ""),
            run_id=body.get("run_id", ""),
        )
    except Exception as e:
        _sv_handle_error(e)


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/apex-command")
async def operator_attach_apex_command(client_id: str, engagement_id: str, request: Request):
    """Compose the headless Apex command on the engagement (does NOT execute).
    Caller can choose dry_run=False to use a runnable command later."""
    require_operator(request)
    body = await request.json()
    try:
        return _sv.attach_apex_command(
            client_id, engagement_id,
            dry_run=bool(body.get("dry_run", True)),
        )
    except Exception as e:
        _sv_handle_error(e)


@app.post("/api/operator/clients/{client_id}/validations/{engagement_id}/run-apex")
async def operator_run_apex(client_id: str, engagement_id: str, request: Request):
    """Execute the engagement's Apex command on our runner host. Operator-only.

    Hard preconditions (re-checked at execution time, NOT just at approval):
      - Engagement is in 'running' state (start_engagement was called)
      - Legal authorization gate is currently open (signed MSA/SOW/NDA/DPA,
        scope, testing window, emergency contact, acknowledgments)
      - Kill switch is not engaged
      - Pensar Apex binary is on PATH on the runner host
      - APEX_ANTHROPIC_API_KEY is set (Apex requires it)

    The customer cannot reach this endpoint. The customer's only role is
    signing the scope authorization and (optionally) engaging the kill
    switch via /api/portal/{cid}/validations/{eid}/stop.
    """
    require_operator(request)
    import apex_runner as _apex
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    operator_name = (body.get("operator_name") or "operator").strip()
    timeout = int(body.get("timeout_seconds")
                   or os.getenv("APEX_TIMEOUT_SECONDS", "3600"))
    try:
        result = await asyncio.to_thread(
            _apex.run_engagement, client_id, engagement_id,
            timeout_seconds=timeout, operator_name=operator_name,
        )
    except _apex.ApexRunError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@app.get("/api/portal/{client_id}/validations")
async def portal_list_validations(client_id: str, request: Request):
    """Customer view — operator-only fields stripped."""
    if not check_portal_auth(request, client_id):
        raise HTTPException(status_code=401, detail="Authentication required")
    return {"engagements": [_sv.customer_view(e)
                             for e in _sv.list_engagements(client_id)]}


@app.get("/api/portal/{client_id}/validations/{engagement_id}")
async def portal_get_validation(client_id: str, engagement_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        return _sv.customer_view(_sv.get_engagement(client_id, engagement_id))
    except KeyError:
        raise HTTPException(status_code=404, detail="Engagement not found")


@app.get("/portal/{client_id}/download/{doc_type}/{filename}")
async def portal_download(client_id: str, doc_type: str, filename: str, request: Request):
    if not check_portal_auth(request, client_id):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    client_id = safe_path_component(client_id)
    doc_type = safe_path_component(doc_type)
    filename = safe_path_component(filename)
    if doc_type not in ("reports", "policies"):
        raise HTTPException(status_code=400)
    file_path = client_manager._client_dir(client_id) / doc_type / filename
    if not file_path.exists():
        raise HTTPException(status_code=404)
    import audit_log as _al
    _al.record(action=_al.ACTION_DOCUMENT_DOWNLOAD, actor=client_id,
               role=_al.ROLE_CUSTOMER, client_id=client_id, request=request,
               doc_type=doc_type, filename=filename)
    from starlette.responses import FileResponse
    return FileResponse(str(file_path), filename=filename)


@app.get("/portal/{client_id}/download/audit-package")
async def portal_download_audit_package(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    client_id = safe_path_component(client_id)
    client = client_manager.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    company = client.get("company_name", "Unknown").replace(" ", "_")
    today = time.strftime("%Y%m%d")
    zip_name = f"{company}_Audit_Package_{today}.zip"
    client_dir = client_manager._client_dir(client_id)

    # Sanitize profile — strip sensitive fields recursively. Caught by the
    # sell-readiness check: nested fields like client["auth"]["password_hash"]
    # were previously surviving the top-level filter.
    SENSITIVE_KEYS = {
        "password_hash", "magic_token", "magic_token_expires",
        "stripe_secret", "stripe_secret_key", "stripe_api_key",
        "reset_token_nonce", "reset_token_expiry",
        "OPERATOR_MFA_SECRET", "JWT_SECRET", "RESET_TOKEN_SECRET",
        "auth",  # entire auth dict is operator-only
    }
    def _deep_strip(obj):
        if isinstance(obj, dict):
            return {k: _deep_strip(v) for k, v in obj.items()
                     if k not in SENSITIVE_KEYS}
        if isinstance(obj, list):
            return [_deep_strip(v) for v in obj]
        return obj
    profile = _deep_strip(client)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
        # Profile summary
        zf.writestr("profile_summary.json", json.dumps(profile, indent=2, default=str))

        # Score history
        score_history = client.get("score_history", [])
        zf.writestr("score_history.json", json.dumps(score_history, indent=2, default=str))

        # Scans
        scans_dir = client_dir / "scans"
        if scans_dir.exists():
            for f in sorted(scans_dir.glob("*.json")):
                zf.write(str(f), f"scans/{f.name}")

        # Reports
        reports_dir = client_dir / "reports"
        if reports_dir.exists():
            for f in sorted(f for f in reports_dir.iterdir() if f.suffix in (".pdf", ".json")):
                zf.write(str(f), f"reports/{f.name}")

        # Policies
        policies_dir = client_dir / "policies"
        if policies_dir.exists():
            for f in sorted(policies_dir.glob("*.*")):
                zf.write(str(f), f"policies/{f.name}")

        # Tasks
        tasks = client_manager.get_tasks(client_id)
        zf.writestr("tasks.json", json.dumps(tasks, indent=2, default=str))

        # Alerts — all historical
        alerts_dir = client_dir / "alerts"
        if alerts_dir.exists():
            for f in sorted(alerts_dir.glob("*.json")):
                zf.write(str(f), f"alerts/{f.name}")

        # Communications log
        comms_file = client_dir / "communications" / "log.jsonl"
        if comms_file.exists():
            zf.write(str(comms_file), "communications_log.jsonl")

        # Call notes
        call_notes_file = client_dir / "call_notes.json"
        if call_notes_file.exists():
            zf.write(str(call_notes_file), "call_notes.json")

        # Audit log (JSON + CSV) — what auditors expect to see
        import audit_log as _al
        zf.writestr("audit_log.json", _al.export_json(client_id))
        zf.writestr("audit_log.csv", _al.export_csv(client_id))

        # Record this download itself in the global audit stream
        _al.record(action=_al.ACTION_AUDIT_PACKAGE_DOWNLOAD, actor=client_id,
                   role=_al.ROLE_CUSTOMER, client_id=client_id, request=request)

        # MANIFEST
        file_list = zf.namelist()
        manifest_lines = [
            f"# Audit Evidence Package",
            f"**Company:** {client.get('company_name', 'N/A')}",
            f"**Domain:** {client.get('domain', 'N/A')}",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Total files:** {len(file_list) + 1}",
            "",
            "## Contents",
        ]
        for name in sorted(file_list):
            manifest_lines.append(f"- {name}")
        zf.writestr("MANIFEST.md", "\n".join(manifest_lines))

    return FileResponse(tmp.name, filename=zip_name, media_type="application/zip")


# ─── PORTAL: ALERT DETAIL ENDPOINTS (HTMX partials) ────────

def _alert_panel_state(connected: bool, last_checked: str, alerts: list) -> str:
    """Resolve the four-way alert panel state from real signals."""
    if not connected:
        return "not_connected"
    if not last_checked:
        return "pending_first_check"
    if alerts:
        return "success_with_findings"
    return "success_no_findings"


def _render_alert_panel(**ctx) -> HTMLResponse:
    """Render the alert panel through the autoescaping Jinja environment.
    Every alert-derived field is escaped — never trust agent-stored content."""
    tmpl = templates.get_template("partials/alert_panel.html")
    return HTMLResponse(tmpl.render(**ctx))


@app.get("/portal/{client_id}/alerts/darkweb", response_class=HTMLResponse)
async def portal_darkweb_alerts(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    client = client_manager.get_client(client_id) or {}
    connected = bool(os.getenv("HIBP_API_KEY"))
    last_checked = client.get("last_darkweb_check_at", "")
    alerts = client_manager.get_alerts(client_id, limit=10, alert_type="darkweb")
    state = _alert_panel_state(connected, last_checked, alerts)
    return _render_alert_panel(
        category_label="Dark-web exposure",
        source_label="HaveIBeenPwned API",
        cadence_label="Weekly",
        state=state,
        last_checked=last_checked,
        alerts=alerts,
        extras_kind="darkweb",
        next_action=("Force password reset for any exposed accounts; "
                     "your advisor will follow up."
                     if state == "success_with_findings"
                     else "We will continue checking on the weekly schedule."),
        setup_action="Provide a HaveIBeenPwned API key to your advisor",
    )


@app.get("/portal/{client_id}/alerts/threats", response_class=HTMLResponse)
async def portal_threat_alerts(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    alerts = client_manager.get_alerts(client_id, limit=10, alert_type="threat")
    last_checked = ""
    if alerts:
        # Most recent alert date is the proxy for last successful feed pull.
        last_checked = max((a.get("date", "") for a in alerts), default="")
    # CISA KEV is always reachable; the scheduler is the precondition.
    connected = True
    state = _alert_panel_state(connected, last_checked, alerts)
    return _render_alert_panel(
        category_label="Threat intelligence",
        source_label="CISA Known Exploited Vulnerabilities",
        cadence_label="Daily",
        state=state,
        last_checked=last_checked,
        alerts=alerts,
        extras_kind="threats",
        next_action=("Review priority CVEs with your advisor."
                     if state == "success_with_findings"
                     else "We will continue pulling CISA on the daily schedule."),
        setup_action="",
    )


@app.get("/portal/{client_id}/alerts/report", response_class=HTMLResponse)
async def portal_latest_report(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    reports_dir = client_manager._client_dir(client_id) / "reports"
    report_files = (sorted(reports_dir.glob("*monthly*"), reverse=True)
                    if reports_dir.exists() else [])
    tmpl = templates.get_template("partials/alert_report.html")
    if not report_files:
        return HTMLResponse(tmpl.render(present=False))
    try:
        data = json.loads(report_files[0].read_text())
    except Exception:
        return HTMLResponse(tmpl.render(present=False))

    findings = data.get("findings_summary", {}) or {}

    # Industry benchmark
    industry_avg = 0
    try:
        client = client_manager.get_client(client_id) or {}
        from prompt_library import INDUSTRY_CONTEXT
        ind = (client.get("industry", "") or "").lower().strip()
        if ind and ind in INDUSTRY_CONTEXT:
            industry_avg = INDUSTRY_CONTEXT[ind].get("industry_avg_score", 0) or 0
    except Exception:
        industry_avg = 0

    # Sign-off comes from the unified advisor-review store, not a static badge.
    import advisor_review as _ar
    yyyymm = datetime.utcnow().strftime("%Y-%m")
    rec = _ar.get_review(client_id, _ar.monthly_summary_key(yyyymm))
    if not _ar.is_signed_off(rec):
        # Fall back to looking at the matching report subject if present.
        rec = _ar.get_review(client_id, _ar.report_key("monthly_security"))
    signed_off = _ar.is_signed_off(rec)

    return HTMLResponse(tmpl.render(
        present=True,
        score=data.get("score", 0),
        grade=data.get("grade", "N/A"),
        delta=data.get("score_delta", 0),
        total_findings=findings.get("total", 0),
        resolved_findings=findings.get("resolved", 0),
        critical_findings=findings.get("critical", 0),
        narrative=(data.get("narrative", "") or "")[:1500],
        industry_avg=industry_avg,
        signed_off=signed_off,
        reviewed_by=rec.get("reviewed_by", "") if signed_off else "",
        reviewed_on=rec.get("reviewed_on", "") if signed_off else "",
        reviewer_credential=rec.get("reviewer_credential", "") if signed_off else "",
        client_facing_recommendation=rec.get("client_facing_recommendation", ""),
    ))


@app.get("/portal/{client_id}/alerts/vulns", response_class=HTMLResponse)
async def portal_vuln_alerts(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    import shutil as _shutil
    client = client_manager.get_client(client_id) or {}
    connected = _shutil.which("nuclei") is not None
    last_checked = client.get("last_vuln_scan_at", "")
    alerts = client_manager.get_alerts(client_id, limit=5, alert_type="vulnscan")
    if alerts and not last_checked:
        last_checked = max((a.get("date", "") for a in alerts), default="")
    state = _alert_panel_state(connected, last_checked, alerts)
    return _render_alert_panel(
        category_label="Vulnerability scanning",
        source_label="Nuclei scanner",
        cadence_label="Monthly",
        state=state,
        last_checked=last_checked,
        alerts=alerts,
        extras_kind="vulns",
        next_action=("Review prioritized findings with your advisor."
                     if state == "success_with_findings"
                     else "Your next monthly scan is scheduled."),
        setup_action="Operator will provision the scanner — your advisor will confirm date",
    )


@app.get("/portal/{client_id}/alerts/phishing", response_class=HTMLResponse)
async def portal_phishing_alerts(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    client = client_manager.get_client(client_id) or {}
    gophish_ok = bool(os.getenv("GOPHISH_API_KEY") and os.getenv("GOPHISH_URL"))
    employee_emails = client.get("employee_emails", []) or []
    connected = gophish_ok and bool(employee_emails)
    last_checked = client.get("last_phishing_campaign_at", "")
    alerts = client_manager.get_alerts(client_id, limit=5, alert_type="phishing")
    if alerts and not last_checked:
        last_checked = max((a.get("date", "") for a in alerts), default="")
    state = _alert_panel_state(connected, last_checked, alerts)
    setup = ("Provide your employee email list to your advisor"
             if not employee_emails
             else "Operator will connect GoPhish — advisor will confirm campaign date")
    return _render_alert_panel(
        category_label="Phishing readiness",
        source_label="GoPhish campaigns",
        cadence_label="Quarterly",
        state=state,
        last_checked=last_checked,
        alerts=alerts,
        extras_kind="phishing",
        next_action=("Review campaign results with your advisor."
                     if state == "success_with_findings"
                     else "Your next quarterly campaign is scheduled."),
        setup_action=setup,
    )


@app.get("/portal/{client_id}/alerts/monitoring", response_class=HTMLResponse)
async def portal_monitoring_alerts(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    client = client_manager.get_client(client_id) or {}
    m365_configured = bool(
        os.getenv("MS_TENANT_ID") and os.getenv("MS_CLIENT_ID")
        and os.getenv("MS_CLIENT_SECRET")
    )
    last_checked = client.get("last_m365_sync_at", "")
    alerts = client_manager.get_alerts(client_id, limit=10, alert_type="monitoring")
    if alerts and not last_checked:
        last_checked = max((a.get("date", "") for a in alerts), default="")
    state = _alert_panel_state(m365_configured, last_checked, alerts)
    return _render_alert_panel(
        category_label="Configuration monitoring",
        source_label="Microsoft Graph API",
        cadence_label="Daily",
        state=state,
        last_checked=last_checked,
        alerts=alerts,
        extras_kind="monitoring",
        next_action=("Review anomalies with your advisor."
                     if state == "success_with_findings"
                     else "We will continue syncing on the daily schedule."),
        setup_action="Authorize Microsoft 365 read-only access via your advisor",
    )


# ─── OPERATOR: CLIENT MANAGEMENT ────────────────────────────

class CreateClientRequest(BaseModel):
    company_name: str
    domain: str
    industry: str = "general"
    tier: str = "diagnostic"
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
    return {"status": "ok", "magic_link": link, "expires": "7 days"}


@app.post("/api/operator/clients/{client_id}/tier")
async def update_tier(client_id: str, request: Request):
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    new_tier = client_manager.normalize_tier(body.get("tier", "diagnostic"))
    if new_tier not in client_manager.TIERS:
        raise HTTPException(status_code=400, detail=f"Unknown tier: {body.get('tier')}")
    profile = client_manager._load_profile(client_id)
    old_tier = profile.get("tier", "")
    profile["tier"] = new_tier
    client_manager._save_profile(client_id, profile)
    import audit_log as _al
    _al.record(action=_al.ACTION_PLAN_CHANGE, actor="operator",
               role=_al.ROLE_OPERATOR, client_id=client_id, request=request,
               before={"tier": old_tier}, after={"tier": new_tier})
    return {"status": "ok", "tier": new_tier}


@app.get("/api/operator/clients")
async def list_clients_endpoint(request: Request):
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    clients = client_manager.list_all_clients()
    return {"clients": clients}


# ─── AUDIT LOG ────────────────────────────────────────────

@app.get("/api/operator/audit-log")
async def operator_audit_log(request: Request, client_id: str = "",
                              action: str = "", role: str = "",
                              actor: str = "", since: str = "",
                              until: str = "", limit: int = 1000,
                              format: str = "json"):
    """Operator query over the global or per-client stream. Supports JSON
    and CSV via ?format=csv."""
    require_operator(request)
    import audit_log as _al
    events = _al.list_events(
        client_id=client_id or None,
        action=action or None, role=role or None, actor=actor or None,
        since=since or None, until=until or None, limit=int(limit or 1000),
    )
    if (format or "").lower() == "csv":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(
            _al.export_csv(client_id or None),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
        )
    return {"events": events, "count": len(events)}


@app.get("/api/operator/audit-log/{client_id}/export")
async def operator_audit_log_export_client(client_id: str, request: Request,
                                           format: str = "csv"):
    require_operator(request)
    import audit_log as _al
    if (format or "").lower() == "json":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(_al.export_json(client_id),
                                 media_type="application/json")
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        _al.export_csv(client_id), media_type="text/csv",
        headers={"Content-Disposition":
                 f"attachment; filename=audit_log_{client_id}.csv"},
    )


@app.get("/api/portal/{client_id}/audit-log")
async def portal_audit_log(client_id: str, request: Request, limit: int = 200):
    """Customer view of their own audit stream — same fields, no filtering
    cross-tenant."""
    if not check_portal_auth(request, client_id):
        raise HTTPException(status_code=401, detail="Authentication required")
    import audit_log as _al
    return {"events": _al.list_events(client_id, limit=int(limit or 200))}


@app.get("/api/operator/sell-readiness")
async def operator_sell_readiness(request: Request):
    """Run the 11 sell-readiness invariants and return the classification.
    The same logic is exercised by tests/test_sell_readiness.py."""
    require_operator(request)
    import sell_readiness as _sr
    return _sr.run_checks()


@app.get("/api/operator/delivery-console")
async def operator_delivery_console(request: Request):
    """Aggregated per-client delivery view for the premium operator dashboard.
    Returns 14 signals per client + filter classification + summary counts."""
    require_operator(request)
    import delivery_console as _dc
    return _dc.build_console()


@app.get("/api/operator/mrr")
async def get_mrr(request: Request):
    """Returns ARR + derived MRR. Diagnostic engagements are one-time and do
    not contribute to recurring revenue. Tier amounts come from the canonical
    tier table — no hardcoded values here."""
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    clients = client_manager.list_all_clients()
    arr = 0
    by_tier: dict[str, int] = {}
    retainer_count = 0
    for c in clients:
        tier = client_manager.normalize_tier(c.get("tier", "diagnostic"))
        by_tier[tier] = by_tier.get(tier, 0) + 1
        contribution = client_manager.annual_revenue_for_tier(tier)
        arr += contribution
        if contribution > 0:
            retainer_count += 1
    return {
        "arr": arr,
        "mrr": round(arr / 12),
        "client_count": len(clients),
        "retainer_count": retainer_count,
        "by_tier": by_tier,
    }


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


@app.post("/api/operator/call-notes/{client_id}")
async def save_call_notes_endpoint(client_id: str, request: Request):
    """Save notes after a monthly call."""
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    notes = body.get("notes", "")
    if not notes:
        raise HTTPException(status_code=400, detail="Notes required")
    client_manager.save_call_notes(client_id, notes)
    return {"status": "saved", "client_id": client_id}


@app.put("/api/operator/client/{client_id}")
async def update_client_endpoint(client_id: str, request: Request):
    """Update client profile fields."""
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    allowed_fields = ["tier", "contact_name", "contact_email", "contact_title",
                      "industry", "tech_stack", "employee_emails", "task_email_frequency"]
    updated = []
    for field in allowed_fields:
        if field in body:
            client_manager.update_field(client_id, field, body[field])
            updated.append(field)
    if not updated:
        raise HTTPException(status_code=400, detail="No valid fields to update")
    import audit_log as _al
    _al.record(action=_al.ACTION_CLIENT_PROFILE_UPDATE, actor="operator",
               role=_al.ROLE_OPERATOR, client_id=client_id, request=request,
               updated_fields=updated)
    return {"status": "updated", "client_id": client_id, "updated_fields": updated}


@app.post("/api/operator/phishing/launch/{client_id}")
async def launch_phishing(client_id: str, request: Request):
    if not check_dashboard_auth(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    client = client_manager.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    industry = client.get("industry", "general")
    contact_email = client.get("contact_email", "")
    employee_emails = client.get("employee_emails", [contact_email] if contact_email else [])
    if not employee_emails:
        return JSONResponse({"error": "No employee emails configured"}, status_code=400)
    templates_list = phantom.get_templates_for_industry(industry)
    if not templates_list:
        return JSONResponse({"error": "No templates for industry"}, status_code=400)
    result = phantom.create_campaign(
        f"{client.get('company_name', client_id)}_manual_{date.today().isoformat()}",
        templates_list[0]["key"], employee_emails
    )
    return JSONResponse(result)


# ─── STRIPE BILLING ───────────────────────────────────────

@app.post("/api/operator/clients/{client_id}/invoice")
async def create_client_invoice(client_id: str, request: Request):
    """Create and send a Stripe invoice for a client."""
    if not check_dashboard_auth(request):
        raise HTTPException(status_code=401, detail="Unauthorized")
    import audit_log as _al

    from billing import get_or_create_customer, create_invoice

    body = await request.json()
    items = body.get("items", [])
    due_days = body.get("due_days", 7)

    if not items:
        raise HTTPException(status_code=400, detail="No items provided")

    profile = client_manager.get_client(client_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Client not found")

    try:
        customer_id = get_or_create_customer(profile)
        profile["stripe_customer_id"] = customer_id
        client_manager._save_profile(client_id, profile)

        result = create_invoice(customer_id, items, due_days)

        if result.get("invoice_id"):
            profile["stripe_invoice_id"] = result["invoice_id"]
            profile["payment_status"] = "invoiced"
        if result.get("subscription_id"):
            profile["stripe_subscription_id"] = result["subscription_id"]
        client_manager._save_profile(client_id, profile)
        _al.record(action=_al.ACTION_INVOICE_CREATE, actor="operator",
                   role=_al.ROLE_OPERATOR, client_id=client_id, request=request,
                   invoice_id=result.get("invoice_id"),
                   subscription_id=result.get("subscription_id"),
                   item_count=len(items))
        return result
    except Exception as e:
        logger.error(f"Invoice creation failed for {client_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events."""
    from billing import handle_webhook

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        result = handle_webhook(payload, sig_header)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Stripe webhook error: {e}")
        raise HTTPException(status_code=400, detail="Webhook verification failed")

    client_id = result.get("client_id")
    if not client_id:
        return {"status": "ok", "action": "no_client_id"}

    profile = client_manager.get_client(client_id)
    if not profile:
        logger.warning(f"Webhook for unknown client: {client_id}")
        return {"status": "ok", "action": "client_not_found"}

    action = result.get("action")
    details = result.get("details", {})

    if action == "update_tier":
        profile["tier"] = details["tier"]
        client_manager._save_profile(client_id, profile)
        logger.info(f"Tier updated to {details['tier']} for {client_id}")
    elif action == "downgrade_tier":
        profile["tier"] = "diagnostic"
        client_manager._save_profile(client_id, profile)
        logger.info(f"Tier downgraded to assessment for {client_id}")
    elif action == "mark_paid":
        profile["payment_status"] = "paid"
        profile["paid_at"] = datetime.utcnow().isoformat()
        client_manager._save_profile(client_id, profile)
        logger.info(f"Payment received for {client_id}")
    elif action == "mark_overdue":
        profile["payment_status"] = "overdue"
        client_manager._save_profile(client_id, profile)
        logger.warning(f"Payment failed for {client_id}")

    return {"status": "ok", "action": action}


# ─── RUN ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 60)
    print("  CYBERCOMPLY — API Server")
    print("  11 AI Agents. Always On. Always Watching.")
    print("=" * 60)
    print("\n  Starting on http://localhost:8000")
    print("  API Docs: http://localhost:8000/docs")
    print("=" * 60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
