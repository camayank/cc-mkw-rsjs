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
    allow_methods=["GET", "POST"],
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

@app.post("/api/scan/free")
@limiter.limit("10/minute")
async def free_scan(request: Request, scan_request: DomainScanRequest):
    """
    Stage 0: Free domain scan — the lead magnet.
    Runs SHADOW + RECON quick scan. Returns teaser results.
    """
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
async def full_scan(request: DomainScanRequest):
    """
    Stage 1: Full assessment — SHADOW + RECON deep scan.
    Generates complete results for the 9-page PDF report.
    """
    results = {
        "domain": request.domain,
        "scan_date": datetime.utcnow().isoformat() + "Z",
    }
    
    # Full RECON scan
    results["archer"] = recon.scan(request.domain, deep=request.deep)
    
    # Full SHADOW scan (if emails provided)
    if request.emails:
        results["spectre"] = shadow.to_dict(
            shadow.scan(request.domain, request.emails)
        )
    
    return results

# ─── STAGE 3: ONBOARDING ─────────────────────────────────────

@app.get("/api/onboarding/questionnaire")
async def get_questionnaire():
    """Get the smart onboarding questionnaire."""
    return guardian.get_questionnaire()

@app.post("/api/onboarding/process")
async def process_onboarding(submission: QuestionnaireSubmission):
    """
    Process onboarding questionnaire.
    Returns: client profile, risk score, applicable frameworks,
    required policies, compliance status, risk register.
    """
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
async def get_policy_prompt(policy_key: str, company_name: str = "Test Company",
                             industry: str = "Accounting / CPA"):
    """Get Claude API prompt for generating a specific policy."""
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
async def get_phishing_templates(industry: str):
    """Get phishing templates for an industry."""
    return phantom.get_templates_for_industry(industry)

@app.post("/api/phantom/campaign")
async def create_phishing_campaign(request: PhishingCampaignRequest):
    """Create a phishing simulation campaign."""
    return phantom.create_campaign(
        request.campaign_name or f"Campaign-{datetime.utcnow().strftime('%Y%m%d')}",
        request.template_key,
        request.employee_emails
    )

# SHADOW — Standalone email breach check (no domain required)
@app.post("/api/shadow/email-check")
async def check_email_breaches(request: EmailBreachRequest):
    """
    Standalone dark web breach check — works without a domain/website.
    Accepts a list of email addresses and checks each against HIBP.
    Perfect for clients without websites (consultants, sole practitioners).
    """
    if not request.emails:
        raise HTTPException(status_code=400, detail="At least one email address is required")
    if len(request.emails) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 emails per request")

    results = []
    total_breaches = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for email in request.emails:
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
        "total_emails_checked": len(request.emails),
        "total_exposed": len(exposed_emails),
        "total_breaches": total_breaches,
        "severity_summary": severity_counts,
        "exposure_rate": f"{len(exposed_emails)/max(len(request.emails),1)*100:.0f}%",
        "results": results,
        "note": "HIBP-powered dark web intelligence. No website required.",
    }

# DISPATCH
@app.get("/api/dispatch/playbooks")
async def list_playbooks():
    """List all incident response playbooks."""
    return dispatch.list_playbooks()

@app.get("/api/dispatch/playbook/{incident_type}")
async def get_playbook(incident_type: str):
    """Get a specific incident response playbook."""
    return dispatch.get_playbook(incident_type)

# FALCON
@app.get("/api/falcon/threats")
async def get_threats():
    """Get latest threat intelligence from CISA."""
    return falcon.check_cisa_kev()

# COMPLY
@app.get("/api/comply/crossmap")
async def get_crossmap(frameworks: str = "irs_4557,nist_csf_2"):
    """Cross-map controls across frameworks."""
    fw_list = [f.strip() for f in frameworks.split(",")]
    return comply.cross_map_controls(fw_list)

@app.get("/api/comply/evidence/{framework_id}")
async def get_evidence_checklist(framework_id: str):
    """Get evidence collection checklist for a framework."""
    return comply.get_evidence_checklist(framework_id)

# VANGUARD
@app.get("/api/vanguard/workflows")
async def list_workflows():
    """List all orchestration workflows."""
    return vanguard.list_workflows()

@app.post("/api/vanguard/execute/{workflow_name}")
async def execute_workflow(workflow_name: str):
    """Execute an orchestration workflow."""
    return vanguard.execute_workflow(workflow_name, {})

# BREACH
@app.get("/api/breach/scope-template")
async def get_pentest_scope():
    """Get penetration test scope of work template."""
    return breach.get_pentest_scope_template()


# ─── DASHBOARD DATA ──────────────────────────────────────────

@app.get("/api/dashboard/{client_id}")
async def get_dashboard(client_id: str):
    """Get complete dashboard data for a client."""
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

def check_dashboard_auth(request: Request):
    # Check session token cookie first
    token = request.cookies.get("dashboard_auth")
    if token and token in _dashboard_sessions:
        return True
    # Fall back to password for initial login
    password = request.query_params.get("password")
    if password == DASHBOARD_PASSWORD:
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
        session_token = secrets.token_hex(32)
        _dashboard_sessions.add(session_token)
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
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

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
async def list_clients():
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
                "has_policies": any(d.glob("policies_*")),
                "has_emails": (d / "cold_email_1.txt").exists(),
                "email_status": "not_started",
                "last_email_sent": None,
                "next_email_due": None,
            })

            # Check outreach schedule for email status
            company_name = scan.get("company_name", d.name)
            company_safe = company_name.replace(" ", "_").replace("&", "and")
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
async def download_client_file(dir_name: str, file_type: str):
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
async def client_detail(dir_name: str):
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
        has_policies=any(client_dir.glob("policies_*")),
    ))

# ─── PIPELINE ENDPOINT ──────────────────────────────────

@app.get("/api/pipeline")
async def get_pipeline():
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
            if any(d.glob("policies_*")):
                has_policies += 1
            if (d / "cold_email_1.txt").exists():
                has_emails += 1

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
async def new_scan(req: NewScanRequest):
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
        except Exception as e:
            logger.error(f"Post-scan update error: {e}")

    asyncio.create_task(run_scan())
    mode = "with AI narratives" if req.enable_ai else "quick mode (no AI)"
    return {"status": "started", "dir_name": dir_name, "client_id": client_id, "message": f"Scan started — {mode}"}

# ─── GENERATE POLICIES ENDPOINT ──────────────────────────

@app.post("/api/clients/{dir_name}/generate-policies")
async def generate_policies_for_client(dir_name: str):
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
async def generate_emails_for_client(dir_name: str):
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
async def list_leads():
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
@limiter.limit("5/minute")
async def portal_login(request: Request, req: PortalLoginRequest):
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


# ─── PORTAL MAIN VIEW ───────────────────────────────────────

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

    tmpl = templates.get_template("portal.html")
    return HTMLResponse(tmpl.render(
        client=client, tier=tier_config,
        current_score=current_score, current_grade=current_grade,
        score_history=score_history,
        open_tasks=open_tasks, in_progress_tasks=in_progress_tasks,
        resolved_tasks=resolved_tasks,
        alerts=alerts, dark_web_alerts=dark_web_alerts,
        threats_blocked=threats_blocked,
        vuln_findings=vuln_findings, phishing_tests=phishing_tests,
        monitoring_alerts=monitoring_alerts,
        reports=reports, policies=policies,
        agent_status=agent_status, frameworks=frameworks,
        compliance_pct=compliance_pct,
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
    if not check_portal_auth(request, client_id):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    client_manager.update_task_status(client_id, task_id, body.get("status", "open"))
    return {"status": "ok"}


@app.post("/portal/{client_id}/task/{task_id}/resolve")
async def resolve_portal_task(client_id: str, task_id: str, request: Request):
    """One-click task resolution from portal or email link."""
    token = request.query_params.get("token")
    jwt_cookie = request.cookies.get("portal_token")

    authenticated = False
    if token:
        authenticated = client_manager.verify_magic_token(client_id, token)
    elif jwt_cookie:
        jwt_client = client_manager.verify_jwt(jwt_cookie)
        authenticated = (jwt_client == client_id)

    if not authenticated:
        raise HTTPException(status_code=403, detail="Authentication required. Use magic link or log in to portal.")

    client_manager.update_task_status(client_id, task_id, "resolved")
    return HTMLResponse('<span class="badge bg-success">Resolved &#x2713;</span>')


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
    from starlette.responses import FileResponse
    return FileResponse(str(file_path), filename=filename)


# ─── PORTAL: ALERT DETAIL ENDPOINTS (HTMX partials) ────────

@app.get("/portal/{client_id}/alerts/darkweb", response_class=HTMLResponse)
async def portal_darkweb_alerts(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    alerts = client_manager.get_alerts(client_id, limit=20)
    darkweb = [a for a in alerts if a.get("type") == "darkweb"]
    rows = ""
    for a in darkweb[:10]:
        sev = a.get("severity", "MEDIUM").lower()
        sev_colors = {"critical": "var(--red)", "high": "var(--orange)", "medium": "var(--yellow)", "low": "var(--green)"}
        color = sev_colors.get(sev, "var(--muted)")
        actions_html = "".join(f'<li style="margin:4px 0">{act}</li>' for act in a.get("actions", []))
        status_badge = '<span style="color:var(--green);font-size:.75rem">&#x2713; Resolved</span>' if a.get("status") == "resolved" else ""
        rows += f'''<div style="padding:16px 0;border-bottom:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600">{a.get("severity", "MEDIUM")}</span>
            <span style="color:var(--muted);font-size:.75rem">{a.get("date", "")[:10]}</span>
            {status_badge}
          </div>
          <div style="font-weight:600;margin:8px 0">{a.get("title", "Alert")}</div>
          <div style="color:var(--muted);font-size:.85rem;line-height:1.5">{a.get("narrative", a.get("summary", ""))}</div>
          {"<ul style='margin:12px 0 0 16px;color:var(--accent);font-size:.85rem'>" + actions_html + "</ul>" if actions_html else ""}
        </div>'''
    if not rows:
        rows = '<p style="color:var(--muted);padding:16px 0">No dark web alerts detected. Your credentials are clean.</p>'
    return HTMLResponse(rows)


@app.get("/portal/{client_id}/alerts/threats", response_class=HTMLResponse)
async def portal_threat_alerts(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    alerts = client_manager.get_alerts(client_id, limit=20)
    threats = [a for a in alerts if a.get("type") == "threat"]
    rows = ""
    for a in threats[:10]:
        sev = a.get("severity", "MEDIUM").lower()
        sev_colors = {"critical": "var(--red)", "high": "var(--orange)", "medium": "var(--yellow)", "low": "var(--green)"}
        color = sev_colors.get(sev, "var(--muted)")
        actions_html = "".join(f'<li style="margin:4px 0">{act}</li>' for act in a.get("actions", []))
        threat_list = ""
        for t in a.get("threats", [])[:3]:
            cve = t.get("cve_id", t.get("cveID", ""))
            name = t.get("name", t.get("vulnerabilityName", ""))
            threat_list += f'<div style="font-size:.8rem;color:var(--muted);margin:2px 0">&#x2022; {cve}: {name}</div>'
        rows += f'''<div style="padding:16px 0;border-bottom:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600">{a.get("severity", "MEDIUM")}</span>
            <span style="color:var(--muted);font-size:.75rem">{a.get("date", "")[:10]}</span>
          </div>
          <div style="font-weight:600;margin:8px 0">{a.get("title", "Threat Alert")}</div>
          <div style="color:var(--muted);font-size:.85rem;line-height:1.5">{a.get("narrative", a.get("summary", ""))}</div>
          {threat_list}
          {"<ul style='margin:12px 0 0 16px;color:var(--accent);font-size:.85rem'>" + actions_html + "</ul>" if actions_html else ""}
        </div>'''
    if not rows:
        rows = '<p style="color:var(--muted);padding:16px 0">No relevant threats detected for your technology stack.</p>'
    return HTMLResponse(rows)


@app.get("/portal/{client_id}/alerts/report", response_class=HTMLResponse)
async def portal_latest_report(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    reports_dir = client_manager._client_dir(client_id) / "reports"
    report_files = sorted(reports_dir.glob("*monthly*"), reverse=True) if reports_dir.exists() else []
    if not report_files:
        return HTMLResponse('<p style="color:var(--muted);padding:16px 0">No monthly reports yet. First report will generate on the 1st of next month.</p>')
    latest = report_files[0]
    try:
        data = json.loads(latest.read_text())
        narrative = data.get("narrative", "Report available.")
        score = data.get("score", 0)
        grade = data.get("grade", "N/A")
        delta = data.get("score_delta", 0)
        findings = data.get("findings_summary", {})
        delta_html = f'<span style="color:var(--green)">&#x25b2; +{delta}</span>' if delta > 0 else f'<span style="color:var(--red)">&#x25bc; {delta}</span>' if delta < 0 else '&#x2192; No change'
        return HTMLResponse(f'''
          <div style="padding:16px 0">
            <div style="display:flex;gap:24px;margin-bottom:16px">
              <div><span style="font-size:2rem;font-weight:700;color:var(--accent)">{score}</span><span style="color:var(--muted)">/{grade}</span> {delta_html}</div>
              <div style="color:var(--muted);font-size:.85rem">Findings: {findings.get("total", 0)} total | {findings.get("resolved", 0)} resolved</div>
            </div>
            <div style="color:var(--text);font-size:.9rem;line-height:1.6;white-space:pre-wrap">{narrative[:1500]}</div>
          </div>''')
    except Exception:
        return HTMLResponse('<p style="color:var(--muted);padding:16px 0">Report loading...</p>')


@app.get("/portal/{client_id}/alerts/vulns", response_class=HTMLResponse)
async def portal_vuln_alerts(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    alerts = client_manager.get_alerts(client_id, limit=20)
    vulns = [a for a in alerts if a.get("type") == "vulnscan"]
    rows = ""
    for a in vulns[:5]:
        sev = a.get("severity", "MEDIUM").lower()
        sev_colors = {"critical": "var(--red)", "high": "var(--orange)", "medium": "var(--yellow)", "low": "var(--green)"}
        color = sev_colors.get(sev, "var(--muted)")
        findings_html = ""
        for f in a.get("findings", [])[:5]:
            cve = f.get("cve_id", "")
            cve_link = f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank" style="color:var(--accent)">{cve}</a>' if cve else ""
            f_sev = f.get("severity", "").lower()
            f_color = sev_colors.get(f_sev, "var(--muted)")
            findings_html += f'<div style="font-size:.8rem;padding:6px 0;border-bottom:1px solid var(--border)"><span style="background:{f_color};color:#fff;padding:1px 6px;border-radius:3px;font-size:.7rem">{f.get("severity","")}</span> {f.get("name","")} {cve_link}<div style="color:var(--muted);margin-top:2px">{f.get("matched_at","")}</div></div>'
        rows += f'''<div style="padding:16px 0;border-bottom:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600">{a.get("severity","MEDIUM")}</span>
            <span style="color:var(--muted);font-size:.75rem">{a.get("date","")[:10]}</span>
          </div>
          <div style="font-weight:600;margin:8px 0">{a.get("title","Vulnerability Scan")}</div>
          <div style="color:var(--muted);font-size:.85rem;line-height:1.5;margin-bottom:12px">{a.get("narrative", a.get("summary",""))}</div>
          <div style="font-size:.8rem;font-weight:600;color:var(--text);margin-bottom:8px">Findings ({a.get("total",0)} total):</div>
          {findings_html}
        </div>'''
    if not rows:
        rows = '<p style="color:var(--muted);padding:16px 0">No vulnerability scans yet. First scan runs on the 15th of the month.</p>'
    return HTMLResponse(rows)


@app.get("/portal/{client_id}/alerts/phishing", response_class=HTMLResponse)
async def portal_phishing_alerts(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    alerts = client_manager.get_alerts(client_id, limit=20)
    phishing = [a for a in alerts if a.get("type") == "phishing"]
    rows = ""
    for a in phishing[:5]:
        actions_html = "".join(f'<li style="margin:4px 0">{act}</li>' for act in a.get("actions", []))
        rows += f'''<div style="padding:16px 0;border-bottom:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="background:var(--accent);color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600">PHISHING TEST</span>
            <span style="color:var(--muted);font-size:.75rem">{a.get("date","")[:10]}</span>
          </div>
          <div style="font-weight:600;margin:8px 0">{a.get("title","Phishing Campaign")}</div>
          <div style="color:var(--muted);font-size:.85rem;line-height:1.5">{a.get("narrative", a.get("summary",""))}</div>
          {"<ul style='margin:12px 0 0 16px;color:var(--accent);font-size:.85rem'>" + actions_html + "</ul>" if actions_html else ""}
        </div>'''
    if not rows:
        rows = '<p style="color:var(--muted);padding:16px 0">No phishing tests yet. First campaign launches next quarter.</p>'
    return HTMLResponse(rows)


@app.get("/portal/{client_id}/alerts/monitoring", response_class=HTMLResponse)
async def portal_monitoring_alerts(client_id: str, request: Request):
    if not check_portal_auth(request, client_id):
        return HTMLResponse("", status_code=401)
    alerts = client_manager.get_alerts(client_id, limit=20)
    monitoring = [a for a in alerts if a.get("type") == "monitoring"]
    rows = ""
    for a in monitoring[:10]:
        sev = a.get("severity", "MEDIUM").lower()
        sev_colors = {"critical": "var(--red)", "high": "var(--orange)", "medium": "var(--yellow)", "low": "var(--green)"}
        color = sev_colors.get(sev, "var(--muted)")
        anomaly_html = ""
        for an in a.get("anomalies", [])[:5]:
            anomaly_html += f'<div style="font-size:.8rem;padding:4px 0;color:var(--muted)">&#x2022; {an.get("type","")}: {an.get("user","N/A")} from {an.get("location","unknown")} ({an.get("app","")})</div>'
        actions_html = "".join(f'<li style="margin:4px 0">{act}</li>' for act in a.get("actions", []))
        rows += f'''<div style="padding:16px 0;border-bottom:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600">{a.get("severity","MEDIUM")}</span>
            <span style="color:var(--muted);font-size:.75rem">{a.get("date","")[:10]}</span>
          </div>
          <div style="font-weight:600;margin:8px 0">{a.get("title","Monitoring Alert")}</div>
          <div style="color:var(--muted);font-size:.85rem;line-height:1.5;margin-bottom:8px">{a.get("narrative", a.get("summary",""))}</div>
          {anomaly_html}
          {"<ul style='margin:12px 0 0 16px;color:var(--accent);font-size:.85rem'>" + actions_html + "</ul>" if actions_html else ""}
        </div>'''
    if not rows:
        rows = '<p style="color:var(--muted);padding:16px 0">No monitoring anomalies detected. All systems normal.</p>'
    return HTMLResponse(rows)


# ─── OPERATOR: CLIENT MANAGEMENT ────────────────────────────

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
        profile["tier"] = "assessment"
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
