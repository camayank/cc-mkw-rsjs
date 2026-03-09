"""
CYBERCOMPLY — API Server
Connects all 11 AI agents into one unified API.

Run: uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import json
import os
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock down in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── JINJA2 SETUP ────────────────────────────────────────
from dotenv import load_dotenv
load_dotenv()

templates = Environment(loader=FileSystemLoader("templates"), autoescape=True)

DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "cybercomply2026")
CALENDLY_LINK = os.getenv("CALENDAR_LINK", "https://calendly.com/cybercomply/security-review")
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
async def free_scan(request: DomainScanRequest):
    """
    Stage 0: Free domain scan — the lead magnet.
    Runs SHADOW + RECON quick scan. Returns teaser results.
    """
    results = {
        "domain": request.domain,
        "scan_date": datetime.utcnow().isoformat() + "Z",
        "agents_used": ["SHADOW", "RECON"],
    }
    
    # RECON: Quick external scan
    recon_results = recon.scan(request.domain)
    results["security_score"] = recon_results.get("score", {})
    results["findings_count"] = len(recon_results.get("findings", []))
    results["top_findings"] = recon_results.get("findings", [])[:3]  # Show top 3 only
    
    # SHADOW: Password check (teaser — full scan behind paywall)
    if request.emails:
        results["emails_to_check"] = len(request.emails)
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
    auth = request.cookies.get("dashboard_auth")
    if auth == DASHBOARD_PASSWORD:
        return True
    token = request.query_params.get("password")
    if token == DASHBOARD_PASSWORD:
        return True
    return False

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    if not check_dashboard_auth(request):
        tmpl = templates.get_template("dashboard.html")
        return HTMLResponse(tmpl.render(authenticated=False))
    tmpl = templates.get_template("dashboard.html")
    resp = HTMLResponse(tmpl.render(authenticated=True, calendly_link=CALENDLY_LINK))
    resp.set_cookie("dashboard_auth", DASHBOARD_PASSWORD, max_age=86400)
    return resp

# ─── DIAGNOSTIC REPORT ──────────────────────────────────

@app.get("/report/{client_dir}", response_class=HTMLResponse)
async def diagnostic_report(client_dir: str, request: Request):
    """Full 7-section diagnostic report for a client."""
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
async def free_scan_stream(domain: str):
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
    """Send the PDF report via SMTP. Silently fails if SMTP not configured."""
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    from_email = os.getenv("SMTP_FROM", os.getenv("SENDER_EMAIL", "security@cybercomply.io"))
    from_name = os.getenv("SENDER_NAME", "CyberComply")

    if not smtp_host or not smtp_user or not smtp_pass:
        logger.info(f"SMTP not configured — skipping email to {to_email}. Set SMTP_HOST/SMTP_USER/SMTP_PASS in .env")
        return False

    msg = MIMEMultipart()
    msg["From"] = f"{from_name} <{from_email}>"
    msg["To"] = to_email
    msg["Subject"] = f"Your Security Assessment Report — {domain}"

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
    msg.attach(MIMEText(body, "plain"))

    if pdf_path and Path(pdf_path).exists():
        with open(pdf_path, "rb") as f:
            part = MIMEBase("application", "pdf")
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={Path(pdf_path).name}")
            msg.attach(part)

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        logger.info(f"Report emailed to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to email report to {to_email}: {e}")
        return False


@app.post("/api/lead/capture")
async def capture_lead(lead: LeadCapture):
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
            })
        except Exception:
            continue
    return {"clients": clients}

# ─── CLIENT DOWNLOAD ENDPOINT ───────────────────────────

@app.get("/api/clients/{dir_name}/download/{file_type}")
async def download_client_file(dir_name: str, file_type: str):
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

    return {
        "leads": leads_count,
        "scanned": scanned,
        "proposed": proposed,
        "has_policies": has_policies,
        "has_emails": has_emails,
        "total_value": total_value,
        "ai_cost": round(ai_cost, 4),
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

    async def run_scan():
        await asyncio.to_thread(
            full_delivery, req.domain, req.company_name, req.industry,
            not req.enable_ai, req.employee_count  # no_ai is inverse of enable_ai
        )

    asyncio.create_task(run_scan())
    mode = "with AI narratives" if req.enable_ai else "quick mode (no AI)"
    return {"status": "started", "dir_name": dir_name, "message": f"Scan started — {mode}"}

# ─── GENERATE POLICIES ENDPOINT ──────────────────────────

@app.post("/api/clients/{dir_name}/generate-policies")
async def generate_policies_for_client(dir_name: str):
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
