#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  CYBERCOMPLY — SERVICE DELIVERY ENGINE              ║
║                                                                  ║
║  This is NOT a SaaS platform. This is YOUR money-making tool.   ║
║                                                                  ║
║  What it does:                                                   ║
║  1. Scans any domain (RECON + SHADOW)                         ║
║  2. Runs GUARDIAN risk questionnaire                                ║
║  3. Generates Claude API prompts for policy documents            ║
║  4. Produces branded PDF report                                  ║
║  5. Creates complete deliverable package you invoice $3K-7.5K    ║
║                                                                  ║
║  Revenue model:                                                  ║
║  - Free scan (lead magnet) → 5 min your time, $0 cost           ║
║  - Full assessment report → 1 hr, invoice $2,500-5,000          ║
║  - WISP + 8 policies → 2 hrs, invoice $3,000-7,500              ║
║  - Monthly retainer → 3 hrs/month, invoice $2,000-5,000/mo      ║
║                                                                  ║
║  Your cost per client: $2-5 in Claude API calls + your time      ║
╚══════════════════════════════════════════════════════════════════╝
"""

import sys, os, json, argparse, subprocess, logging
from datetime import datetime, date
from pathlib import Path

logger = logging.getLogger("deliver")

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ═══════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════

BRAND = {
    "company": "CyberComply",
    "tagline": "11 AI Agents. Always On. Always Watching.",
    "email": "security@cybercomply.io",
    "phone": "+1-XXX-XXX-XXXX",
    "website": "https://cybercomply.io",
    "calendly": "https://calendly.com/security-cybercomply/30min",
}

# Create output directory
DATA_DIR = Path(os.getenv("DATA_DIR", "."))
OUTPUT_DIR = DATA_DIR / "client-deliverables"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════╗
║           CYBERCOMPLY — DELIVERY ENGINE                    ║
║        Scan → Assess → Invoice → Profit                   ║
╚═══════════════════════════════════════════════════════════╝
    """)


# ═══════════════════════════════════════════════════════════
# STEP 1: SCAN THE DOMAIN
# ═══════════════════════════════════════════════════════════

def run_scan(domain, company_name=None):
    """Run RECON + basic SHADOW scan on a domain."""
    from agents.recon_agent import ReconAgent
    
    company = company_name or domain.split('.')[0].replace('-', ' ').title()
    
    print(f"\n🎯 RECON scanning {domain}...")
    archer = ReconAgent()
    archer_results = archer.scan(domain)
    
    score = archer_results.get("score", {}).get("total", 0)
    grade = archer_results.get("score", {}).get("grade", "F")
    findings = archer_results.get("findings", [])
    
    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE: {company}")
    print(f"  Domain: {domain}")
    print(f"  Score: {score}/100 (Grade: {grade})")
    print(f"  Findings: {len(findings)}")
    
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    
    if critical > 0:
        print(f"  ⚠️  {critical} CRITICAL issues found!")
    if high > 0:
        print(f"  ⚠️  {high} HIGH issues found!")
    print(f"{'='*60}")
    
    return {
        "domain": domain,
        "company_name": company,
        "archer": archer_results,
        "score": score,
        "grade": grade,
        "scan_date": datetime.now().isoformat(),
    }


# ═══════════════════════════════════════════════════════════
# STEP 2: RISK QUESTIONNAIRE
# ═══════════════════════════════════════════════════════════

QUICK_PROFILES = {
    "cpa": {
        "q1": "", "q2": "Accounting / CPA", "q3": "11-25",
        "q6": "Microsoft 365", "q7": "Yes — for some users",
        "q12": ["Social Security Numbers", "Tax Returns (FTI)", "Client Financial Data"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["IRS Publication 4557", "FTC Safeguards Rule"],
        "q24": "Yes — some employees", "q25": "No", "q26": "Possibly — we don't monitor",
        "q27": ["Employees sharing client data with AI", "Compliance violations from AI use"],
    },
    "healthcare": {
        "q1": "", "q2": "Healthcare", "q3": "26-50",
        "q6": "Microsoft 365", "q7": "Yes — for some users",
        "q12": ["Protected Health Information (PHI)", "Insurance Data"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["HIPAA", "NIST CSF"],
        "q24": "Yes — some employees", "q25": "No", "q26": "Possibly — we don't monitor",
        "q27": ["Employees sharing client data with AI", "Compliance violations from AI use"],
    },
    "legal": {
        "q1": "", "q2": "Legal / Law Firm", "q3": "11-25",
        "q6": "Microsoft 365", "q7": "Yes — for some users",
        "q12": ["Attorney-Client Privileged Data", "Client Financial Data"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["ABA Formal Opinion 477R", "NIST CSF"],
        "q24": "Yes — some employees", "q25": "No", "q26": "Possibly — we don't monitor",
        "q27": ["Employees sharing client data with AI", "AI hallucinations in client work"],
    },
    "financial": {
        "q1": "", "q2": "Financial Services", "q3": "26-50",
        "q6": "Microsoft 365", "q7": "Yes — for some users",
        "q12": ["Social Security Numbers", "Bank Account Data", "Client Financial Data"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["FTC Safeguards Rule", "NIST CSF", "SOC 2"],
        "q24": "Yes — some employees", "q25": "No", "q26": "Possibly — we don't monitor",
        "q27": ["Employees sharing client data with AI", "Compliance violations from AI use"],
    },
    "saas": {
        "q1": "", "q2": "Technology / SaaS", "q3": "26-50",
        "q6": "Google Workspace", "q7": "Yes — for all users",
        "q12": ["Client Data", "Source Code"],
        "q15": "Yes", "q16": "No", "q17": "Annually", "q18": "No", "q20": "No",
        "q21": ["SOC 2", "ISO 27001"],
        "q24": "Yes — widely adopted", "q25": "Yes — informal guidelines", "q26": "Possibly — we don't monitor",
        "q27": ["Employees sharing client data with AI", "Lack of visibility into AI usage"],
    },
    "govcon": {
        "q1": "", "q2": "Government Contractor", "q3": "51-100",
        "q6": "Microsoft 365 GCC", "q7": "Yes — for all users",
        "q12": ["CUI (Controlled Unclassified Information)", "Government Data"],
        "q15": "Yes", "q16": "No", "q17": "Annually", "q18": "No", "q20": "No",
        "q21": ["CMMC Level 2", "NIST 800-171"],
        "q24": "Yes — some employees", "q25": "No", "q26": "I don't know",
        "q27": ["Compliance violations from AI use", "Employees sharing client data with AI"],
    },
    "general": {
        "q1": "", "q2": "Professional Services", "q3": "11-25",
        "q6": "Microsoft 365", "q7": "No",
        "q12": ["Client Data", "Employee PII"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["NIST CSF"],
        "q24": "Yes — some employees", "q25": "No", "q26": "I don't know",
        "q27": ["Employees sharing client data with AI"],
    },
    "nonprofit": {
        "q1": "", "q2": "Nonprofit Organization", "q3": "11-25",
        "q6": "Google Workspace", "q7": "No",
        "q12": ["Donor PII", "Employee PII"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["NIST CSF"],
        "q24": "Yes — some employees", "q25": "No", "q26": "I don't know",
        "q27": ["Employees sharing client data with AI"],
    },
    "education": {
        "q1": "", "q2": "Education", "q3": "26-50",
        "q6": "Google Workspace", "q7": "Yes — for some users",
        "q12": ["Student Records (FERPA)", "Employee PII"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["NIST CSF", "FERPA"],
        "q24": "Yes — some employees", "q25": "No", "q26": "I don't know",
        "q27": ["Employees sharing client data with AI"],
    },
    "manufacturing": {
        "q1": "", "q2": "Manufacturing", "q3": "51-100",
        "q6": "Microsoft 365", "q7": "No",
        "q12": ["Employee PII", "Trade Secrets / IP"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["NIST CSF", "CMMC"],
        "q24": "No", "q25": "No", "q26": "I don't know",
        "q27": ["Compliance violations from AI use"],
    },
    "real_estate": {
        "q1": "", "q2": "Real Estate", "q3": "11-25",
        "q6": "Google Workspace", "q7": "No",
        "q12": ["Client Financial Data", "Social Security Numbers"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["FTC Safeguards Rule", "NIST CSF"],
        "q24": "Yes — some employees", "q25": "No", "q26": "I don't know",
        "q27": ["Employees sharing client data with AI"],
    },
}


def run_questionnaire(company_name, industry="cpa", overrides=None):
    """Run GUARDIAN questionnaire with quick industry profile."""
    from agents.guardian_agent import GuardianAgent

    profile_data = QUICK_PROFILES.get(industry, QUICK_PROFILES["cpa"]).copy()
    profile_data["q1"] = company_name
    if overrides:
        profile_data.update(overrides)
    
    print(f"\n🏗  GUARDIAN processing questionnaire for {company_name} ({industry})...")
    forge = GuardianAgent()
    profile = forge.process_questionnaire(profile_data)
    compliance = forge.get_compliance_status(profile)
    
    print(f"  Risk Score: {profile.get('risk_score', 'N/A')}")
    print(f"  Frameworks: {', '.join(profile.get('applicable_frameworks', []))}")
    print(f"  Gaps Found: {len(profile.get('gaps', []))}")
    
    return {
        "profile": profile,
        "compliance": compliance,
    }


# ═══════════════════════════════════════════════════════════
# STEP 3: GENERATE CLAUDE PROMPTS FOR POLICIES
# ═══════════════════════════════════════════════════════════

def generate_policy_prompts(scan_data, forge_data):
    """
    Generate ready-to-paste Claude API prompts that produce 
    complete policy documents. Each prompt = one policy worth $500-1000.
    
    You paste these into Claude.ai or call the API.
    Total value of output: $3,000-7,500 per client.
    """
    company = scan_data["company_name"]
    domain = scan_data["domain"]
    score = scan_data["score"]
    findings = scan_data["archer"].get("findings", [])
    profile = forge_data["profile"]
    compliance = forge_data["compliance"]
    
    industry = profile.get("industry", "Professional Services")
    emp_range = profile.get("employee_range", "11-25")
    frameworks = profile.get("applicable_frameworks", [])
    gaps = profile.get("gaps", [])
    data_types = profile.get("sensitive_data", [])
    
    # Build context block used in all prompts
    context = f"""
COMPANY: {company}
DOMAIN: {domain}
INDUSTRY: {industry}
EMPLOYEES: {emp_range}
SECURITY SCORE: {score}/100
APPLICABLE FRAMEWORKS: {', '.join(frameworks)}
SENSITIVE DATA TYPES: {', '.join(data_types)}
KEY FINDINGS:
{chr(10).join(f"- [{f['severity']}] {f['title']}: {f.get('description','')[:100]}" for f in findings[:8])}
COMPLIANCE GAPS:
{chr(10).join(f"- {g}" for g in gaps[:10])}
"""

    policies = {
        "WISP": {
            "name": "Written Information Security Plan (WISP)",
            "value": "$1,500-3,000",
            "prompt": f"""You are a senior cybersecurity consultant writing a Written Information Security Plan (WISP) for a client. This is a formal compliance document that will be reviewed by auditors, cyber insurance underwriters, and regulators.

{context}

Write a complete, professional WISP document (3,000-5,000 words) that includes:

1. PURPOSE AND SCOPE
2. DESIGNATED SECURITY COORDINATOR (leave name as [NAME])
3. RISK ASSESSMENT SUMMARY (use the findings above)
4. DATA CLASSIFICATION AND INVENTORY
   - List all sensitive data types this company handles
   - Classification levels: Public, Internal, Confidential, Restricted
5. ADMINISTRATIVE SAFEGUARDS
   - Employee screening, training, access management
   - Clean desk policy, acceptable use
6. TECHNICAL SAFEGUARDS
   - Encryption, MFA, endpoint protection
   - Network security, email security (reference actual findings)
   - Patch management, vulnerability scanning
7. PHYSICAL SAFEGUARDS
   - Office security, visitor management, device disposal
8. INCIDENT RESPONSE PROCEDURES
   - Detection, containment, notification requirements
   - Specific notification requirements for {industry}
9. VENDOR MANAGEMENT
   - Third-party risk assessment process
10. POLICY REVIEW AND UPDATES
    - Annual review schedule, change management

Format as a professional document with section numbers. 
Reference specific frameworks: {', '.join(frameworks)}.
Include specific remediation items from the findings.
Use formal professional tone suitable for audit review.
Date: {date.today().strftime('%B %Y')}
"""
        },
        
        "IRP": {
            "name": "Incident Response Plan",
            "value": "$1,000-2,000",
            "prompt": f"""You are a cybersecurity incident response expert writing an Incident Response Plan for:

{context}

Write a complete Incident Response Plan (2,000-3,500 words) that includes:

1. PURPOSE AND SCOPE
2. INCIDENT RESPONSE TEAM
   - Roles: IR Lead, Technical Lead, Legal, Communications, Executive Sponsor
   - Contact information placeholders
3. INCIDENT CLASSIFICATION
   - Severity levels (P1-P4) with definitions and response times
   - Examples specific to {industry}
4. DETECTION AND ANALYSIS
   - How incidents are detected (monitoring, alerts, user reports)
   - Initial triage checklist
5. CONTAINMENT PROCEDURES
   - Short-term containment (isolate, block, disable)
   - Long-term containment (patch, rebuild, segment)
6. ERADICATION AND RECOVERY
   - Root cause analysis requirements
   - System restoration procedures
   - Verification testing
7. POST-INCIDENT ACTIVITIES
   - Lessons learned meeting (within 72 hours)
   - Documentation requirements
   - Plan updates
8. COMMUNICATION PLAN
   - Internal notification chain
   - External notification requirements specific to {industry}
   - Regulatory notification timelines
   - Client notification templates
9. SPECIFIC PLAYBOOKS
   - Ransomware attack
   - Business Email Compromise (BEC)
   - Data breach (with {', '.join(data_types)} exposure)
   - Phishing incident
10. TESTING AND TRAINING
    - Quarterly tabletop exercises
    - Annual full simulation

Include specific notification requirements for: {', '.join(frameworks)}
"""
        },

        "AUP": {
            "name": "Acceptable Use Policy",
            "value": "$500-1,000",
            "prompt": f"""Write a complete Acceptable Use Policy for:

{context}

Include: purpose, scope, acceptable/prohibited uses of company systems, email/internet use, personal device policy, social media, remote work, monitoring disclosure, consequences of violations. Keep it clear enough for non-technical employees. 2,000 words. Professional tone.
"""
        },

        "ACCESS_CONTROL": {
            "name": "Access Control Policy",
            "value": "$500-1,000",
            "prompt": f"""Write a complete Access Control Policy for:

{context}

Include: least privilege principle, role-based access, account provisioning/deprovisioning, MFA requirements, password standards, privileged access management, access review schedule (quarterly), remote access controls, third-party access procedures. 2,000 words. Reference {', '.join(frameworks)}.
"""
        },

        "DATA_CLASSIFICATION": {
            "name": "Data Classification & Handling Policy",
            "value": "$500-1,000",
            "prompt": f"""Write a complete Data Classification and Handling Policy for:

{context}

This company handles: {', '.join(data_types)}. 
Include: classification levels (Public/Internal/Confidential/Restricted), handling requirements per level, labeling standards, storage requirements, transmission requirements, disposal procedures, breach definitions per classification. 2,000 words. Specific to {industry}.
"""
        },

        "VENDOR_MGMT": {
            "name": "Vendor Risk Management Policy",
            "value": "$500-1,000",
            "prompt": f"""Write a complete Vendor Risk Management Policy for:

{context}

Include: vendor risk tiering (Critical/High/Medium/Low), due diligence requirements per tier, security questionnaire requirements, contract security clauses, ongoing monitoring, annual reassessment, incident notification requirements from vendors, termination procedures. 2,000 words.
"""
        },

        "BCP": {
            "name": "Business Continuity Plan",
            "value": "$1,000-2,000",
            "prompt": f"""Write a complete Business Continuity Plan for:

{context}

Include: business impact analysis, critical systems identification, RPO/RTO definitions, backup strategy, disaster recovery procedures, communication plan, alternate work site procedures, supply chain continuity, testing schedule (quarterly), plan maintenance. 2,500 words. Industry-specific for {industry}.
"""
        },

        "REMOTE_WORK": {
            "name": "Remote Work Security Policy",
            "value": "$500-1,000",
            "prompt": f"""Write a complete Remote Work Security Policy for:

{context}

Include: eligible roles, device requirements, VPN/encryption requirements, home network security, physical security at home, video conferencing security, document handling, monitoring and compliance, incident reporting from remote locations. 1,500 words.
"""
        },

        "RISK_REGISTER": {
            "name": "Risk Register",
            "value": "$1,000-2,000",
            "prompt": f"""Create a complete Risk Register for:

{context}

Format as a table with columns:
Risk ID | Risk Description | Likelihood (1-5) | Impact (1-5) | Risk Score | Risk Owner | Mitigation Strategy | Status | Target Date

Include 15-20 risks covering:
- Each finding from the scan results above
- Compliance gaps identified
- Industry-specific risks for {industry}
- Third-party/vendor risks
- Human risks (phishing, insider threat)
- Technical risks (ransomware, data breach)
- Regulatory risks

Sort by risk score (highest first). Be specific and actionable.
"""
        },
    }
    
    return policies


# ═══════════════════════════════════════════════════════════
# STEP 4: GENERATE PDF REPORT
# ═══════════════════════════════════════════════════════════

def generate_pdf_report(scan_data, forge_data, output_dir, executive_summary=None):
    """Generate the branded 9-page PDF assessment report."""
    from agents.report_generator import generate_report

    company_safe = scan_data["company_name"].replace(" ", "_").replace("&", "and")
    pdf_name = f"{company_safe}_Security_Assessment_{date.today().strftime('%Y%m%d')}.pdf"
    pdf_path = str(output_dir / pdf_name)

    report_data = {
        "domain": scan_data["domain"],
        "company_name": scan_data["company_name"],
        "archer": scan_data["archer"],
        "spectre": {"total_exposed": 0, "breaches": []},
        "forge_profile": forge_data["profile"],
        "compliance": forge_data["compliance"],
        "executive_summary": executive_summary,
    }

    generate_report(report_data, pdf_path)
    return pdf_path


# ═══════════════════════════════════════════════════════════
# STEP 5: CREATE PROPOSAL / INVOICE HELPER
# ═══════════════════════════════════════════════════════════

def generate_proposal(scan_data, forge_data):
    """Generate a proposal email you can send to the client."""
    company = scan_data["company_name"]
    score = scan_data["score"]
    findings = scan_data["archer"].get("findings", [])
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    frameworks = forge_data["profile"].get("applicable_frameworks", [])
    gaps = forge_data["profile"].get("gaps", [])
    
    proposal = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PROPOSAL EMAIL — Copy/paste and customize
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Subject: Security Alert — {company} scored {score}/100

Hi [NAME],

I ran a complimentary security assessment on {scan_data['domain']} 
as part of our cybersecurity advisory practice, and I wanted to 
share what we found.

Your current security score is {score} out of 100.

We identified {len(findings)} issues, including:
- {critical} CRITICAL vulnerabilities
- {high} HIGH-risk items
{"- " + findings[0]["title"] if findings else ""}
{"- " + findings[1]["title"] if len(findings) > 1 else ""}

For context, {', '.join(frameworks[:2])} {"requires" if len(frameworks) == 1 else "require"} 
specific security controls that your organization currently has 
{len(gaps)} gaps in.

I've attached a summary report. I'd like to offer a free 
15-minute call to walk through the findings and discuss 
what should be prioritized.

We can also prepare your complete compliance package — including 
your Written Information Security Plan, Incident Response Plan, 
and all required policies — which typically takes about a week.

Would [DATE] work for a quick call?

Best,
[YOUR NAME]
{BRAND['company']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRICING OPTIONS TO OFFER ON THE CALL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Option A — Security Assessment Only          $2,500
  Full report, risk register, remediation plan

Option B — Assessment + WISP + Policies      $5,000
  Everything in A + WISP + 8 policy documents
  + compliance framework mapping

Option C — Ongoing vCISO Retainer            $3,000/month
  Everything in B + monthly scanning
  + quarterly phishing tests
  + policy updates + compliance tracking
  + executive reporting

UPSELLS:
  Cyber insurance readiness package           $1,500
  Vendor risk assessment (per vendor)         $500
  Employee security training program          $1,000
  Penetration test coordination               $2,500
  SOC 2 / ISO 27001 readiness                $7,500-15,000

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    return proposal


def _generate_onboard_tasks(scan_data, forge_data):
    """Generate remediation tasks from scan findings + compliance gaps at onboarding."""
    from scheduler import _generate_tasks_from_findings
    import client_manager

    domain = scan_data.get("domain", "")
    client_id = domain.replace(".", "_")

    client = client_manager.get_client(client_id)
    if not client:
        return

    findings = scan_data.get("archer", {}).get("findings", [])
    if findings:
        _generate_tasks_from_findings(client_id, findings)

    gaps = forge_data.get("profile", {}).get("gaps", [])
    frameworks = forge_data.get("profile", {}).get("applicable_frameworks", [])
    for gap in gaps:
        client_manager.add_task(
            client_id=client_id,
            title=gap,
            severity="HIGH",
            category="Compliance",
            description=f"Required by {', '.join(frameworks[:2])}",
            fix=f"CyberComply provides this — review and adopt the {gap} document",
        )


# ═══════════════════════════════════════════════════════════
# BATCH SCAN — Run against multiple CA4CPA clients at once
# ═══════════════════════════════════════════════════════════

def batch_scan(clients_file):
    """
    Batch scan from a CSV: domain,company_name,industry[,contact_name,contact_title,email]
    Example:
      smithcpa.com,Smith & Associates CPA,cpa,John Smith,Managing Partner,john@smithcpa.com
      abclaw.com,ABC Law Firm,legal
    """
    results = []
    with open(clients_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',')
            domain = parts[0].strip()
            company = parts[1].strip() if len(parts) > 1 else None
            industry = parts[2].strip() if len(parts) > 2 else "cpa"
            contact_name = parts[3].strip() if len(parts) > 3 else None
            contact_title = parts[4].strip() if len(parts) > 4 else None
            contact_email = parts[5].strip() if len(parts) > 5 else None
            
            try:
                scan = run_scan(domain, company)
                results.append({
                    "domain": domain,
                    "company": scan["company_name"],
                    "score": scan["score"],
                    "grade": scan["grade"],
                    "critical": sum(1 for f in scan["archer"].get("findings", []) if f.get("severity") == "CRITICAL"),
                    "high": sum(1 for f in scan["archer"].get("findings", []) if f.get("severity") == "HIGH"),
                    "contact_name": contact_name,
                    "contact_title": contact_title,
                    "contact_email": contact_email,
                })
            except Exception as e:
                print(f"  ❌ Error scanning {domain}: {e}")
                results.append({"domain": domain, "company": company, "score": 0, "error": str(e)})
    
    # Print summary sorted by worst score
    print(f"\n{'='*70}")
    print(f"  BATCH SCAN RESULTS — {len(results)} domains")
    print(f"{'='*70}")
    print(f"  {'Score':<8} {'Grade':<8} {'Critical':<10} {'High':<8} {'Company'}")
    print(f"  {'─'*8} {'─'*8} {'─'*10} {'─'*8} {'─'*30}")
    
    for r in sorted(results, key=lambda x: x.get("score", 0)):
        if "error" in r:
            print(f"  {'ERR':<8} {'—':<8} {'—':<10} {'—':<8} {r['company']} (FAILED)")
        else:
            print(f"  {r['score']:<8} {r['grade']:<8} {r['critical']:<10} {r['high']:<8} {r['company']}")
    
    # Revenue opportunity
    convertible = sum(1 for r in results if r.get("score", 100) < 60)
    print(f"\n  💰 REVENUE OPPORTUNITY:")
    print(f"  {convertible} clients scored below 60 — immediate conversion targets")
    print(f"  At $5,000/assessment: ${convertible * 5000:,} one-time revenue")
    print(f"  At $3,000/mo retainer: ${convertible * 3000:,}/month recurring")
    
    return results


# ═══════════════════════════════════════════════════════════
# MAIN — THE DELIVERY WORKFLOW
# ═══════════════════════════════════════════════════════════

def _generate_ai_narratives(scan_data, forge_data, industry, employee_count, client_dir,
                            contact_name=None, contact_title=None):
    """
    Generate AI-powered narratives for findings, executive summary, and cold email.
    Returns (executive_summary, ai_cost_summary) and mutates findings in-place.
    """
    from prompt_engine import call_prompt, get_industry_context, get_total_cost

    company = scan_data["company_name"]
    findings = scan_data["archer"].get("findings", [])
    score = scan_data["score"]
    grade = scan_data["grade"]

    # Get industry context
    ctx = get_industry_context(industry)
    data_types = ctx.get("data_types", "business data")
    frameworks = ctx.get("frameworks", "NIST CSF")
    industry_avg = ctx.get("industry_avg_score", 42)

    # Count findings by severity
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")

    # 1. Generate narrative for each finding
    print(f"\n🤖 Generating AI narratives for {len(findings)} findings...")
    for i, finding in enumerate(findings):
        try:
            narrative = call_prompt(
                "P01_FINDING_NARRATIVE",
                client_name=company,
                company_name=company,
                industry=ctx.get("label", industry),
                employee_count=str(employee_count),
                data_types=data_types,
                frameworks=frameworks,
                finding_title=finding.get("title", "Unknown"),
                severity=finding.get("severity", "MEDIUM"),
                technical_detail=finding.get("description", finding.get("title", "")),
                category=finding.get("category", "Security"),
            )
            finding["narrative"] = narrative
            print(f"  [{i+1}/{len(findings)}] {finding.get('title', 'Unknown')[:50]}... done")
        except Exception as e:
            logger.warning(f"AI narrative failed for finding '{finding.get('title')}': {e}")
            print(f"  [{i+1}/{len(findings)}] {finding.get('title', 'Unknown')[:50]}... SKIPPED (API error)")

    # 2. Executive summary
    print(f"\n🤖 Generating executive summary...")
    findings_summary = "; ".join(
        f"[{f['severity']}] {f['title']}" for f in findings[:5]
    )
    breach_count = scan_data.get("archer", {}).get("spectre", {}).get("total_exposed", 0)

    try:
        executive_summary = call_prompt(
            "P02_EXECUTIVE_SUMMARY",
            client_name=company,
            company_name=company,
            industry=ctx.get("label", industry),
            employee_count=str(employee_count),
            score=str(score),
            grade=grade,
            industry_avg=str(industry_avg),
            critical_count=str(critical_count),
            high_count=str(high_count),
            medium_count=str(medium_count),
            low_count=str(low_count),
            breach_count=str(breach_count),
            latest_breach="N/A",
            findings_summary=findings_summary,
        )
        print(f"  Executive summary generated ({len(executive_summary)} chars)")
    except Exception as e:
        logger.warning(f"Executive summary generation failed: {e}")
        executive_summary = None
        print(f"  Executive summary SKIPPED (API error)")

    # 3. Cold email
    print(f"\n🤖 Generating cold outreach email...")
    from dotenv import load_dotenv
    load_dotenv()
    sender_name = os.getenv("SENDER_NAME", "[YOUR NAME]")
    sender_title = os.getenv("SENDER_TITLE", "Cybersecurity Advisor")
    calendar_link = os.getenv("CALENDAR_LINK", BRAND["calendly"])

    top_findings = [f.get("title", "Unknown") for f in findings[:3]]
    while len(top_findings) < 3:
        top_findings.append("N/A")

    try:
        cold_email = call_prompt(
            "P03_COLD_EMAIL_1",
            client_name=company,
            company_name=company,
            contact_name=contact_name or ctx.get("client_title", "Decision Maker"),
            contact_title=contact_title or ctx.get("client_title", ""),
            industry=ctx.get("label", industry),
            score=str(score),
            grade=grade,
            finding_1=top_findings[0],
            finding_2=top_findings[1],
            finding_3=top_findings[2],
            breach_count=str(breach_count),
            sender_name=sender_name,
            sender_title=sender_title,
            calendar_link=calendar_link,
        )

        # Save cold email
        email_dir = Path("outreach_emails") / company.replace(" ", "_").replace("&", "and")
        email_dir.mkdir(parents=True, exist_ok=True)
        email_path = email_dir / "cold_email_1.txt"
        email_path.write_text(cold_email)

        # Also save to client dir
        (client_dir / "cold_email_1.txt").write_text(cold_email)
        print(f"  Cold email saved to {email_path}")
    except Exception as e:
        logger.warning(f"Cold email generation failed: {e}")
        print(f"  Cold email SKIPPED (API error)")

    cost_info = get_total_cost()
    return executive_summary, cost_info


def full_delivery(domain, company_name=None, industry="cpa", no_ai=False, employee_count=15,
                  policies_mode=None, policy_single=None,
                  contact_name=None, contact_title=None, contact_email=None,
                  email_provider=None, mfa=None, has_wisp=None, has_irp=None,
                  cyber_insurance=None, no_fti=False, data_types=None):
    """
    Complete delivery workflow for one client.
    Run this, get: PDF report + policies + proposal email.
    With AI: also get AI-powered narratives, executive summary, and cold email.

    policies_mode: None (no policies), "core" (9), "all" (16), "single" (1)
    policy_single: policy key when policies_mode="single" (e.g., "P29_WISP")
    contact_name/title/email: prospect contact info for personalization
    """
    print_banner()

    # Create client output directory
    company_safe = (company_name or domain.split('.')[0]).replace(" ", "_").replace("&", "and")
    client_dir = OUTPUT_DIR / f"{company_safe}_{date.today().strftime('%Y%m%d')}"
    client_dir.mkdir(exist_ok=True)

    # Step 1: Scan
    scan_data = run_scan(domain, company_name)

    # Build overrides from arguments
    overrides = {}
    if employee_count:
        ranges = [(10, "1-10"), (25, "11-25"), (50, "26-50"), (100, "51-100"), (250, "101-250")]
        for threshold, label in ranges:
            if employee_count <= threshold:
                overrides["q3"] = label
                break
        else:
            overrides["q3"] = "250+"

    if email_provider:
        provider_map = {"microsoft": "Microsoft 365", "google": "Google Workspace", "other": "Other"}
        overrides["q6"] = provider_map.get(email_provider, email_provider)

    if mfa:
        mfa_map = {"full": "Yes — for all users", "partial": "Yes — for some users",
                   "none": "No", "unknown": "I don't know"}
        overrides["q7"] = mfa_map.get(mfa, mfa)

    if has_wisp is not None:
        overrides["q15"] = "Yes — current and reviewed annually" if has_wisp else "No"

    if has_irp is not None:
        overrides["q16"] = "Yes — tested within last 12 months" if has_irp else "No"

    if cyber_insurance is not None:
        overrides["q20"] = "Yes — active policy" if cyber_insurance else "No"

    if data_types:
        overrides["q12"] = data_types

    if no_fti:
        profile_data = QUICK_PROFILES.get(industry, QUICK_PROFILES["cpa"])
        default_types = profile_data.get("q12", [])
        overrides["q12"] = [t for t in default_types if "Tax" not in t and "FTI" not in t]

    # Step 2: Questionnaire
    forge_data = run_questionnaire(scan_data["company_name"], industry, overrides=overrides)

    # Step 2.5: AI Narratives (if enabled)
    executive_summary = None
    ai_cost_info = None
    if not no_ai:
        try:
            executive_summary, ai_cost_info = _generate_ai_narratives(
                scan_data, forge_data, industry, employee_count, client_dir,
                contact_name=contact_name, contact_title=contact_title
            )
        except Exception as e:
            print(f"\n⚠️  AI narrative generation failed: {e}")
            print(f"   Continuing with raw findings (use --no-ai to skip AI)")
    else:
        print(f"\n⏭️  Skipping AI narratives (--no-ai mode)")

    # Step 3: PDF Report (pass AI data)
    print(f"\n📄 Generating PDF report...")
    pdf_path = generate_pdf_report(scan_data, forge_data, client_dir,
                                    executive_summary=executive_summary)
    print(f"  ✅ Report: {pdf_path}")

    # Step 4: Policy documents (AI-generated via policy_engine)
    policy_dir = None
    if policies_mode and not no_ai:
        from policy_engine import (
            generate_policy, generate_core_policies, generate_all_policies,
            save_policies, build_client_profile
        )

        client_profile = build_client_profile(scan_data, forge_data, industry, employee_count,
                                              contact_name=contact_name, contact_title=contact_title,
                                              contact_email=contact_email)

        if policies_mode == "core":
            print(f"\n📝 Generating 9 core policy documents...")
            policy_docs = generate_core_policies(client_profile)
        elif policies_mode == "all":
            print(f"\n📝 Generating all 16 policy documents...")
            policy_docs = generate_all_policies(client_profile)
        elif policies_mode == "single" and policy_single:
            print(f"\n📝 Generating policy: {policy_single}...")
            try:
                doc = generate_policy(policy_single, client_profile)
                policy_docs = {policy_single: doc}
                print(f"  done ({len(doc.split())} words)")
            except Exception as e:
                logger.warning(f"Policy generation failed for {policy_single}: {e}")
                print(f"  FAILED ({e})")
                policy_docs = {}
        else:
            policy_docs = {}

        if policy_docs:
            policy_dir = save_policies(scan_data["company_name"], policy_docs, client_dir)
            print(f"  ✅ {len(policy_docs)} policy documents generated")
    elif policies_mode and no_ai:
        print(f"\n⏭️  Skipping policy generation (--no-ai mode)")
    else:
        # Legacy fallback: generate prompts file for manual workflow
        print(f"\n📝 Generating policy prompts (use --policies for auto-generation)...")
        policies = generate_policy_prompts(scan_data, forge_data)

        prompts_file = client_dir / "CLAUDE_POLICY_PROMPTS.md"
        with open(prompts_file, 'w') as f:
            f.write(f"# Policy Generation Prompts for {scan_data['company_name']}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            f.write(f"# TIP: Use --policies flag to auto-generate documents via API\n\n")
            for key, policy in policies.items():
                f.write(f"\n{'='*70}\n")
                f.write(f"## {policy['name']}\n")
                f.write(f"## Billable value: {policy['value']}\n")
                f.write(f"{'='*70}\n\n")
                f.write(policy['prompt'])
                f.write(f"\n\n")
        print(f"  ✅ Prompts: {prompts_file}")

    # Step 5: Proposal
    print(f"\n✉️  Generating proposal...")
    proposal = generate_proposal(scan_data, forge_data)

    proposal_file = client_dir / "PROPOSAL_EMAIL.txt"
    with open(proposal_file, 'w') as f:
        f.write(proposal)

    print(f"  ✅ Proposal: {proposal_file}")

    # Step 6: Save raw data
    raw_file = client_dir / "scan_data.json"
    with open(raw_file, 'w') as f:
        json.dump({
            "scan": scan_data,
            "forge": {
                "profile": forge_data["profile"],
                "compliance": {k: v for k, v in forge_data["compliance"].items()},
            },
        }, f, indent=2, default=str)

    # Step 7: Generate remediation tasks from findings
    _generate_onboard_tasks(scan_data, forge_data)

    # Summary
    ai_line = ""
    if ai_cost_info and not no_ai:
        ai_line = f"\n║  AI cost: ${ai_cost_info['total_cost']:.4f} for {ai_cost_info['total_calls']} calls ({ai_cost_info['cached_calls']} cached)"

    print(f"""
╔═══════════════════════════════════════════════════════════╗
║  DELIVERY PACKAGE COMPLETE                                ║
╠═══════════════════════════════════════════════════════════╣
║                                                           ║
║  Client:  {scan_data['company_name'][:45]:<45} ║
║  Score:   {scan_data['score']}/100 ({scan_data['grade']})                                      ║
║  Output:  {str(client_dir)[:45]:<45} ║
║                                                           ║
║  Files created:                                           ║
║  📄 PDF Security Assessment Report {'(AI-powered)' if not no_ai else '(raw)' :<20} ║
{"║  📝 Policy Documents (AI-generated)                       ║" if policy_dir else "║  📝 Claude Policy Prompts (manual workflow)                ║"}
║  ✉️  Proposal Email (ready to send)                       ║
║  💾 Raw scan data (JSON)                                  ║
{"║  📧 Cold outreach email (AI-generated)                    ║" if not no_ai else ""}
║                                                           ║{ai_line}
║                                                           ║
║  NEXT STEPS:                                              ║
║  1. Send proposal email with PDF attached                 ║
║  2. Book 15-min call via Calendly                         ║
║  3. On call: walk through findings, offer packages        ║
{"║  4. Review policy documents, add branding, deliver        ║" if policy_dir else "║  4. If they buy: use --policies to generate documents     ║"}
║  5. Invoice $5,000 (assessment + policies)                ║
║     or $3,000/month (ongoing retainer)                    ║
║                                                           ║
║  YOUR COST: ~$2-5 in API calls                            ║
║  CLIENT PAYS: $2,500-7,500                                ║
╚═══════════════════════════════════════════════════════════╝
""")

    return client_dir


def outreach_pipeline(clients_file: str):
    """Batch scan + email sequence generation in one command.
    CSV format: domain,company,industry,contact_name,contact_title,contact_email
    """
    from email_scheduler import generate_sequence

    deliverables_dir = Path(os.getenv("DATA_DIR", ".")) / "client-deliverables"

    # Step 1: Batch scan
    results = batch_scan(clients_file)

    # Step 2: Generate email sequences for qualifying prospects
    sequenced = 0
    skipped = 0
    total_emails = 0

    for result in results:
        if "error" in result:
            continue

        contact_email = result.get("contact_email")
        if not contact_email:
            print(f"  Skipping {result['company']} — no contact email")
            skipped += 1
            continue

        score = result.get("score", 100)
        if score >= 70:
            print(f"  Skipping {result['company']} — score {score}/100 (above threshold)")
            skipped += 1
            continue

        company_safe = result["company"].replace(" ", "_").replace("&", "and")
        scan_data = None
        for d in deliverables_dir.glob(f"{company_safe}_*"):
            scan_file = d / "scan_data.json"
            if scan_file.exists():
                scan_data = json.loads(scan_file.read_text())
                break

        generated = generate_sequence(
            domain=result["domain"],
            company_name=result["company"],
            industry=result.get("industry", "general"),
            contact_name=result.get("contact_name"),
            contact_title=result.get("contact_title"),
            contact_email=contact_email,
            scan_data=scan_data,
        )
        sequenced += 1
        total_emails += len(generated)

    print(f"\n{'='*60}")
    print(f"  OUTREACH PIPELINE COMPLETE")
    print(f"{'='*60}")
    print(f"  {len(results)} scanned, {sequenced} qualify, {total_emails} emails scheduled over 21 days")
    print(f"  {skipped} skipped (no email or score >= 70)")
    print(f"\n  Emails will auto-send daily at 9am UTC via scheduler.")
    print(f"  Check schedule: python email_scheduler.py list")


# ═══════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberComply Service Delivery Engine")
    subparsers = parser.add_subparsers(dest="command")
    
    # Single client scan + full delivery
    deliver = subparsers.add_parser("deliver", help="Full delivery for one client")
    deliver.add_argument("domain", help="Client domain to scan")
    deliver.add_argument("--company", "-c", help="Company name")
    deliver.add_argument("--industry", "-i", default="cpa",
                        choices=["cpa", "healthcare", "legal", "financial", "saas", "govcon",
                                 "government", "nonprofit", "education", "manufacturing", "real_estate", "general"])
    deliver.add_argument("--employees", "-e", type=int, default=15, help="Employee count (default: 15)")
    deliver.add_argument("--no-ai", action="store_true", help="Skip AI narrative generation (offline/testing mode)")
    deliver.add_argument("--contact", type=str, help="Contact person name (e.g., 'John Smith')")
    deliver.add_argument("--title", type=str, help="Contact title (e.g., 'Managing Partner')")
    deliver.add_argument("--email", type=str, help="Contact email (e.g., 'john@smithcpa.com')")
    deliver.add_argument("--policies", action="store_true", help="Generate 9 core policy documents via AI")
    deliver.add_argument("--policies-all", action="store_true", help="Generate all 16 policy documents via AI")
    deliver.add_argument("--policy", type=str, metavar="KEY", help="Generate a single policy (e.g., P29_WISP)")
    deliver.add_argument("--no-policies", action="store_true", help="Skip policy generation entirely")
    deliver.add_argument("--email-provider", choices=["microsoft", "google", "other"])
    deliver.add_argument("--mfa", choices=["full", "partial", "none", "unknown"])
    deliver.add_argument("--has-wisp", type=lambda x: x.lower() == "yes", metavar="yes/no")
    deliver.add_argument("--has-irp", type=lambda x: x.lower() == "yes", metavar="yes/no")
    deliver.add_argument("--cyber-insurance", type=lambda x: x.lower() == "yes", metavar="yes/no")
    deliver.add_argument("--no-fti", action="store_true", help="Client does not handle FTI")
    deliver.add_argument("--data-types", nargs="+", help="Override sensitive data types")

    # Quick scan only (lead magnet)
    scan = subparsers.add_parser("scan", help="Quick scan only (free lead magnet)")
    scan.add_argument("domain", help="Domain to scan")
    
    # Batch scan
    batch = subparsers.add_parser("batch", help="Batch scan from CSV file")
    batch.add_argument("file", help="CSV file: domain,company,industry")

    # Outreach: batch scan + email sequences
    outreach = subparsers.add_parser("outreach", help="Batch scan + generate email sequences")
    outreach.add_argument("file", help="CSV: domain,company,industry,contact_name,contact_title,contact_email")

    args = parser.parse_args()
    
    if args.command == "deliver":
        # Determine policy mode
        policies_mode = None
        policy_single = None
        if args.policies_all:
            policies_mode = "all"
        elif args.policies:
            policies_mode = "core"
        elif args.policy:
            policies_mode = "single"
            policy_single = args.policy.upper()
            if not policy_single.startswith("P"):
                policy_single = f"P{policy_single}"
        # --no-policies explicitly skips (policies_mode stays None)

        full_delivery(args.domain, args.company, args.industry,
                      no_ai=args.no_ai, employee_count=args.employees,
                      policies_mode=policies_mode, policy_single=policy_single,
                      contact_name=args.contact, contact_title=args.title,
                      contact_email=args.email,
                      email_provider=args.email_provider, mfa=args.mfa,
                      has_wisp=args.has_wisp, has_irp=args.has_irp,
                      cyber_insurance=args.cyber_insurance, no_fti=args.no_fti,
                      data_types=args.data_types)
    elif args.command == "scan":
        run_scan(args.domain)
    elif args.command == "batch":
        batch_scan(args.file)
    elif args.command == "outreach":
        outreach_pipeline(args.file)
    else:
        print_banner()
        print("  Usage:")
        print("    python deliver.py scan example.com              # Quick free scan")
        print("    python deliver.py deliver smithcpa.com -c 'Smith CPA' -i cpa -e 15  # Full delivery with AI")
        print("    python deliver.py deliver smithcpa.com -c 'Smith CPA' --contact 'John Smith' --title 'Managing Partner' --email john@smithcpa.com")
        print("    python deliver.py deliver smithcpa.com -c 'Smith CPA' --policies     # + 9 core policies")
        print("    python deliver.py deliver smithcpa.com -c 'Smith CPA' --policies-all # + all 16 policies")
        print("    python deliver.py deliver smithcpa.com -c 'Smith CPA' --policy P29_WISP  # Single policy")
        print("    python deliver.py deliver smithcpa.com -c 'Smith CPA' --no-ai       # Without AI (offline)")
        print("    python deliver.py batch clients.csv             # Batch scan 20 clients")
        print("")
        print("  Industries: cpa, healthcare, legal, financial, saas, govcon, government,")
        print("              nonprofit, education, manufacturing, real_estate, general")
