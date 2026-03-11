"""
GUARDIAN — AI Virtual CISO & GRC Engine
"I build your security program while you run your business."

Generates: WISP, Incident Response Plans, Security Policies, Risk Registers,
Compliance Roadmaps, Monthly Board Reports, Cyber Insurance Evidence Packages.

Uses Claude API to generate customized policies (not generic templates).
"""

import json
import os
from datetime import datetime
from typing import Optional


# ─── FRAMEWORK KNOWLEDGE BASE ────────────────────────────────
# This is YOUR competitive moat. Build this out over time.

FRAMEWORKS = {
    "irs_4557": {
        "name": "IRS Publication 4557",
        "description": "Tax Preparer Security Requirements",
        "target_industry": ["Accounting", "Tax Preparation", "CPA Firms"],
        "controls": [
            {"id": "4557-1", "name": "Written Information Security Plan (WISP)", "category": "Governance", "required": True},
            {"id": "4557-2", "name": "Designated Security Coordinator", "category": "Governance", "required": True},
            {"id": "4557-3", "name": "Risk Assessment", "category": "Risk Management", "required": True},
            {"id": "4557-4", "name": "Employee Background Checks", "category": "Personnel", "required": True},
            {"id": "4557-5", "name": "Security Awareness Training", "category": "Training", "required": True},
            {"id": "4557-6", "name": "Strong Password Policy", "category": "Access Control", "required": True},
            {"id": "4557-7", "name": "Multi-Factor Authentication", "category": "Access Control", "required": True},
            {"id": "4557-8", "name": "Encryption of FTI at Rest", "category": "Data Protection", "required": True},
            {"id": "4557-9", "name": "Encryption of FTI in Transit", "category": "Data Protection", "required": True},
            {"id": "4557-10", "name": "Firewall Protection", "category": "Network Security", "required": True},
            {"id": "4557-11", "name": "Anti-Malware Software", "category": "Endpoint Security", "required": True},
            {"id": "4557-12", "name": "Software Updates and Patching", "category": "Vulnerability Management", "required": True},
            {"id": "4557-13", "name": "Data Backup Procedures", "category": "Business Continuity", "required": True},
            {"id": "4557-14", "name": "Incident Response Plan", "category": "Incident Response", "required": True},
            {"id": "4557-15", "name": "Physical Security Controls", "category": "Physical Security", "required": True},
            {"id": "4557-16", "name": "Remote Access Security", "category": "Access Control", "required": True},
            {"id": "4557-17", "name": "Vendor Management", "category": "Third Party", "required": True},
            {"id": "4557-18", "name": "Data Disposal Procedures", "category": "Data Protection", "required": True},
            {"id": "4557-19", "name": "Monitoring and Logging", "category": "Monitoring", "required": True},
            {"id": "4557-20", "name": "Annual WISP Review", "category": "Governance", "required": True},
            {"id": "4557-21", "name": "AI Acceptable Use Policy", "category": "Governance", "required": False},
            {"id": "4557-22", "name": "AI Tool Data Input Controls (FTI prohibition)", "category": "Data Protection", "required": False},
        ]
    },
    "ftc_safeguards": {
        "name": "FTC Safeguards Rule",
        "description": "Financial Institution Information Security Requirements",
        "target_industry": ["Financial Services", "Insurance", "Lending", "Auto Dealers"],
        "controls": [
            {"id": "FTC-1", "name": "Qualified Individual Designation", "category": "Governance", "required": True},
            {"id": "FTC-2", "name": "Written Risk Assessment", "category": "Risk Management", "required": True},
            {"id": "FTC-3", "name": "Access Controls", "category": "Access Control", "required": True},
            {"id": "FTC-4", "name": "Data Inventory", "category": "Data Protection", "required": True},
            {"id": "FTC-5", "name": "Encryption", "category": "Data Protection", "required": True},
            {"id": "FTC-6", "name": "MFA for Access to Customer Info", "category": "Access Control", "required": True},
            {"id": "FTC-7", "name": "Secure Disposal", "category": "Data Protection", "required": True},
            {"id": "FTC-8", "name": "Change Management", "category": "Operations", "required": True},
            {"id": "FTC-9", "name": "Monitoring and Logging", "category": "Monitoring", "required": True},
            {"id": "FTC-10", "name": "Incident Response Plan", "category": "Incident Response", "required": True},
            {"id": "FTC-11", "name": "Periodic Security Testing", "category": "Assessment", "required": True},
            {"id": "FTC-12", "name": "Security Awareness Training", "category": "Training", "required": True},
            {"id": "FTC-13", "name": "Vendor Oversight", "category": "Third Party", "required": True},
            {"id": "FTC-14", "name": "Board Reporting", "category": "Governance", "required": True},
            {"id": "FTC-15", "name": "AI and Automated Decision-Making Risk Controls", "category": "Risk Management", "required": False},
            {"id": "FTC-16", "name": "AI Tool Data Protection (Customer Info Prohibition)", "category": "Data Protection", "required": False},
        ]
    },
    "nist_csf_2": {
        "name": "NIST Cybersecurity Framework 2.0",
        "description": "Universal Cybersecurity Best Practice Framework",
        "target_industry": ["All"],
        "controls": [
            # GOVERN
            {"id": "GV.OC-01", "name": "Organizational Context", "category": "Govern", "required": False},
            {"id": "GV.RM-01", "name": "Risk Management Strategy", "category": "Govern", "required": False},
            {"id": "GV.RR-01", "name": "Roles and Responsibilities", "category": "Govern", "required": False},
            {"id": "GV.PO-01", "name": "Cybersecurity Policy", "category": "Govern", "required": False},
            # IDENTIFY
            {"id": "ID.AM-01", "name": "Asset Inventory", "category": "Identify", "required": False},
            {"id": "ID.RA-01", "name": "Risk Assessment", "category": "Identify", "required": False},
            {"id": "ID.IM-01", "name": "Improvement", "category": "Identify", "required": False},
            # PROTECT
            {"id": "PR.AA-01", "name": "Identity and Access Management", "category": "Protect", "required": False},
            {"id": "PR.AT-01", "name": "Awareness and Training", "category": "Protect", "required": False},
            {"id": "PR.DS-01", "name": "Data Security", "category": "Protect", "required": False},
            {"id": "PR.PS-01", "name": "Platform Security", "category": "Protect", "required": False},
            {"id": "PR.IR-01", "name": "Technology Infrastructure Resilience", "category": "Protect", "required": False},
            # DETECT
            {"id": "DE.CM-01", "name": "Continuous Monitoring", "category": "Detect", "required": False},
            {"id": "DE.AE-01", "name": "Adverse Event Analysis", "category": "Detect", "required": False},
            # RESPOND
            {"id": "RS.MA-01", "name": "Incident Management", "category": "Respond", "required": False},
            {"id": "RS.AN-01", "name": "Incident Analysis", "category": "Respond", "required": False},
            {"id": "RS.CO-01", "name": "Incident Reporting & Communication", "category": "Respond", "required": False},
            {"id": "RS.MI-01", "name": "Incident Mitigation", "category": "Respond", "required": False},
            # RECOVER
            {"id": "RC.RP-01", "name": "Recovery Planning", "category": "Recover", "required": False},
            {"id": "RC.CO-01", "name": "Recovery Communication", "category": "Recover", "required": False},
            # AI GOVERNANCE (maps to NIST AI RMF alignment)
            {"id": "GV.AI-01", "name": "AI Risk Management Policy", "category": "Govern", "required": False},
            {"id": "PR.AI-01", "name": "AI Tool Inventory and Data Flow Controls", "category": "Protect", "required": False},
            {"id": "DE.AI-01", "name": "AI Usage Monitoring and Shadow AI Detection", "category": "Detect", "required": False},
        ]
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "description": "Service Organization Controls — Trust Services Criteria",
        "target_industry": ["SaaS", "Technology", "Cloud Services", "Data Processing"],
        "controls": [
            {"id": "CC1.1", "name": "Control Environment — Integrity & Ethics", "category": "Common Criteria", "required": True},
            {"id": "CC1.2", "name": "Board Oversight", "category": "Common Criteria", "required": True},
            {"id": "CC2.1", "name": "Internal & External Communication", "category": "Common Criteria", "required": True},
            {"id": "CC3.1", "name": "Risk Assessment — Objectives", "category": "Common Criteria", "required": True},
            {"id": "CC3.2", "name": "Risk Assessment — Identification & Analysis", "category": "Common Criteria", "required": True},
            {"id": "CC4.1", "name": "Monitoring Activities", "category": "Common Criteria", "required": True},
            {"id": "CC5.1", "name": "Control Selection & Development", "category": "Common Criteria", "required": True},
            {"id": "CC6.1", "name": "Logical & Physical Access", "category": "Common Criteria", "required": True},
            {"id": "CC6.2", "name": "System Access Registration", "category": "Common Criteria", "required": True},
            {"id": "CC6.3", "name": "Role-Based Access", "category": "Common Criteria", "required": True},
            {"id": "CC6.6", "name": "External Threat Protection", "category": "Common Criteria", "required": True},
            {"id": "CC6.7", "name": "Data Transmission Restriction", "category": "Common Criteria", "required": True},
            {"id": "CC6.8", "name": "Malicious Software Prevention", "category": "Common Criteria", "required": True},
            {"id": "CC7.1", "name": "Detection of Changes", "category": "Common Criteria", "required": True},
            {"id": "CC7.2", "name": "Monitoring for Anomalies", "category": "Common Criteria", "required": True},
            {"id": "CC7.3", "name": "Evaluation of Security Events", "category": "Common Criteria", "required": True},
            {"id": "CC7.4", "name": "Incident Response", "category": "Common Criteria", "required": True},
            {"id": "CC8.1", "name": "Change Management", "category": "Common Criteria", "required": True},
            {"id": "CC9.1", "name": "Risk Mitigation", "category": "Common Criteria", "required": True},
            {"id": "CC9.2", "name": "Vendor Risk Management", "category": "Common Criteria", "required": True},
            {"id": "CC9.3", "name": "AI Vendor and Model Risk Assessment", "category": "Common Criteria", "required": False},
            {"id": "CC2.2", "name": "AI Disclosure and Transparency Controls", "category": "Common Criteria", "required": False},
        ]
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "description": "Health Insurance Portability and Accountability Act",
        "target_industry": ["Healthcare", "Health IT", "Telehealth", "Medical Devices"],
        "controls": [
            {"id": "164.308(a)(1)", "name": "Security Management Process", "category": "Administrative", "required": True},
            {"id": "164.308(a)(2)", "name": "Assigned Security Responsibility", "category": "Administrative", "required": True},
            {"id": "164.308(a)(3)", "name": "Workforce Security", "category": "Administrative", "required": True},
            {"id": "164.308(a)(4)", "name": "Information Access Management", "category": "Administrative", "required": True},
            {"id": "164.308(a)(5)", "name": "Security Awareness and Training", "category": "Administrative", "required": True},
            {"id": "164.308(a)(6)", "name": "Security Incident Procedures", "category": "Administrative", "required": True},
            {"id": "164.308(a)(7)", "name": "Contingency Plan", "category": "Administrative", "required": True},
            {"id": "164.308(a)(8)", "name": "Evaluation", "category": "Administrative", "required": True},
            {"id": "164.310(a)", "name": "Facility Access Controls", "category": "Physical", "required": True},
            {"id": "164.310(b)", "name": "Workstation Use", "category": "Physical", "required": True},
            {"id": "164.310(c)", "name": "Workstation Security", "category": "Physical", "required": True},
            {"id": "164.310(d)", "name": "Device and Media Controls", "category": "Physical", "required": True},
            {"id": "164.312(a)", "name": "Access Control", "category": "Technical", "required": True},
            {"id": "164.312(b)", "name": "Audit Controls", "category": "Technical", "required": True},
            {"id": "164.312(c)", "name": "Integrity Controls", "category": "Technical", "required": True},
            {"id": "164.312(d)", "name": "Person or Entity Authentication", "category": "Technical", "required": True},
            {"id": "164.312(e)", "name": "Transmission Security", "category": "Technical", "required": True},
            {"id": "164.308(a)(9)", "name": "AI and Automated Processing of PHI Controls", "category": "Administrative", "required": False},
            {"id": "164.312(f)", "name": "AI Tool Access Restrictions for PHI Systems", "category": "Technical", "required": False},
        ]
    }
}


# ─── POLICY TEMPLATES ────────────────────────────────────────

POLICY_TEMPLATES = {
    "wisp": {
        "name": "Written Information Security Plan (WISP)",
        "frameworks": ["irs_4557", "ftc_safeguards"],
        "sections": [
            "Purpose and Scope",
            "Designated Security Coordinator",
            "Risk Assessment Summary",
            "Employee Management and Training",
            "Information Systems Security",
            "Access Control Procedures",
            "Data Protection and Encryption",
            "Network Security",
            "Incident Detection and Response",
            "Data Disposal Procedures",
            "Vendor and Third-Party Management",
            "Physical Security",
            "Monitoring and Review Schedule",
            "Plan Update and Maintenance"
        ]
    },
    "incident_response": {
        "name": "Incident Response Plan",
        "frameworks": ["irs_4557", "ftc_safeguards", "nist_csf_2", "soc2", "hipaa"],
        "sections": [
            "Purpose and Scope",
            "Incident Response Team Roles",
            "Incident Classification (Severity Levels)",
            "Detection and Identification Procedures",
            "Containment Strategy",
            "Eradication and Recovery",
            "Evidence Preservation",
            "Notification Requirements (Federal, State, Client)",
            "Communication Templates",
            "Post-Incident Review",
            "Testing and Update Schedule"
        ]
    },
    "acceptable_use": {
        "name": "Acceptable Use Policy",
        "frameworks": ["nist_csf_2", "soc2"],
        "sections": [
            "Purpose",
            "Scope — Who This Applies To",
            "Acceptable Use of Company Devices",
            "Email and Communication Standards",
            "Internet Usage",
            "Password Requirements",
            "Remote Work Security",
            "Personal Device (BYOD) Rules",
            "Social Media Guidelines",
            "Data Handling and Classification",
            "Consequences of Violation",
            "Acknowledgment Form"
        ]
    },
    "data_classification": {
        "name": "Data Classification Policy",
        "frameworks": ["nist_csf_2", "soc2", "hipaa"],
        "sections": [
            "Purpose",
            "Classification Levels (Public, Internal, Confidential, Restricted)",
            "Classification Criteria",
            "Labeling Requirements",
            "Handling Requirements per Level",
            "Storage Requirements per Level",
            "Transmission Requirements per Level",
            "Disposal Requirements per Level",
            "Roles and Responsibilities",
            "Exceptions Process"
        ]
    },
    "access_control": {
        "name": "Access Control Policy",
        "frameworks": ["irs_4557", "ftc_safeguards", "nist_csf_2", "soc2", "hipaa"],
        "sections": [
            "Purpose",
            "Principle of Least Privilege",
            "Account Provisioning (New Employees)",
            "Account Deprovisioning (Departing Employees)",
            "Password Requirements",
            "Multi-Factor Authentication Requirements",
            "Remote Access Procedures",
            "Privileged Access Management",
            "Access Review Schedule",
            "Logging and Monitoring"
        ]
    },
    "vendor_management": {
        "name": "Vendor Risk Management Policy",
        "frameworks": ["irs_4557", "ftc_safeguards", "soc2"],
        "sections": [
            "Purpose",
            "Vendor Classification (Critical, High, Medium, Low)",
            "Due Diligence Requirements per Classification",
            "Security Assessment Requirements",
            "Contractual Security Requirements",
            "Ongoing Monitoring",
            "Incident Notification Requirements",
            "Annual Review Process",
            "Approved Vendor List Management"
        ]
    },
    "remote_work": {
        "name": "Remote Work Security Policy",
        "frameworks": ["nist_csf_2", "irs_4557"],
        "sections": [
            "Purpose",
            "Eligibility and Approval",
            "Device Requirements",
            "Network Security (VPN, Wi-Fi)",
            "Physical Security of Work Area",
            "Data Handling While Remote",
            "Video Conferencing Security",
            "Printing and Document Handling",
            "Incident Reporting While Remote",
            "Compliance and Monitoring"
        ]
    },
    "business_continuity": {
        "name": "Business Continuity / Disaster Recovery Plan",
        "frameworks": ["nist_csf_2", "soc2", "hipaa"],
        "sections": [
            "Purpose and Scope",
            "Business Impact Analysis",
            "Recovery Time Objectives (RTO)",
            "Recovery Point Objectives (RPO)",
            "Critical Systems and Data Inventory",
            "Backup Procedures and Verification",
            "Recovery Procedures (Step-by-Step)",
            "Communication Plan During Disaster",
            "Alternate Work Site Procedures",
            "Testing Schedule (Annual)",
            "Plan Maintenance"
        ]
    }
}


# ─── SMART QUESTIONNAIRE ─────────────────────────────────────

ONBOARDING_QUESTIONNAIRE = {
    "sections": [
        {
            "title": "About Your Business",
            "questions": [
                {"id": "q1", "text": "What is your company name?", "type": "text"},
                {"id": "q2", "text": "What industry are you in?", "type": "select",
                 "options": ["Accounting / CPA", "Financial Services", "Healthcare", "Technology / SaaS",
                             "Manufacturing", "Legal", "Real Estate", "Retail", "Government Contractor", "Other"]},
                {"id": "q3", "text": "How many employees?", "type": "select",
                 "options": ["1-10", "11-25", "26-50", "51-100", "101-250", "251-500", "500+"]},
                {"id": "q4", "text": "How many office locations?", "type": "number"},
                {"id": "q5", "text": "Do employees work remotely?", "type": "select",
                 "options": ["No — all in-office", "Hybrid", "Mostly remote", "Fully remote"]},
            ]
        },
        {
            "title": "Your Technology",
            "questions": [
                {"id": "q6", "text": "Email provider?", "type": "select",
                 "options": ["Microsoft 365", "Google Workspace", "On-premise Exchange", "Other"]},
                {"id": "q7", "text": "Is Multi-Factor Authentication (MFA) enabled for email?", "type": "select",
                 "options": ["Yes — for everyone", "Yes — for some users", "No", "I don't know"]},
                {"id": "q8", "text": "What cloud services do you use?", "type": "multiselect",
                 "options": ["Microsoft 365", "Google Workspace", "AWS", "Azure", "Dropbox",
                             "QuickBooks Online", "Salesforce", "Slack", "Zoom", "Other"]},
                {"id": "q9", "text": "Do you have a firewall?", "type": "select",
                 "options": ["Yes — managed", "Yes — unmanaged", "No", "I don't know"]},
                {"id": "q10", "text": "Do you have antivirus/endpoint protection on all devices?", "type": "select",
                 "options": ["Yes — on all devices", "Yes — on some", "No", "I don't know"]},
                {"id": "q11", "text": "Do you back up your data?", "type": "select",
                 "options": ["Yes — automated cloud backup", "Yes — manual backup", "No", "I don't know"]},
            ]
        },
        {
            "title": "Sensitive Data",
            "questions": [
                {"id": "q12", "text": "What types of sensitive data do you handle?", "type": "multiselect",
                 "options": ["Social Security Numbers", "Tax Returns (FTI)", "Bank Account Numbers",
                             "Credit Card Numbers", "Health Records (PHI)", "Driver License Numbers",
                             "Client Financial Data", "Employee HR Data", "Intellectual Property", "None"]},
                {"id": "q13", "text": "Where is sensitive data stored?", "type": "multiselect",
                 "options": ["Cloud applications", "Company servers", "Employee laptops",
                             "External hard drives", "Paper files", "Email"]},
                {"id": "q14", "text": "Who has access to sensitive data?", "type": "select",
                 "options": ["Only specific authorized staff", "All employees", "I'm not sure"]},
            ]
        },
        {
            "title": "Current Security Posture",
            "questions": [
                {"id": "q15", "text": "Do you have a Written Information Security Plan (WISP)?", "type": "select",
                 "options": ["Yes — current", "Yes — outdated", "No", "What is a WISP?"]},
                {"id": "q16", "text": "Do you have an Incident Response Plan?", "type": "select",
                 "options": ["Yes — tested", "Yes — untested", "No"]},
                {"id": "q17", "text": "When was your last security risk assessment?", "type": "select",
                 "options": ["Within 6 months", "6-12 months ago", "Over a year ago", "Never"]},
                {"id": "q18", "text": "Do employees receive security awareness training?", "type": "select",
                 "options": ["Yes — at least annually", "Yes — at hire only", "Informal/ad-hoc", "No"]},
                {"id": "q19", "text": "Have you experienced a security incident in the past 2 years?", "type": "select",
                 "options": ["Yes", "No", "Not sure"]},
                {"id": "q20", "text": "Do you have cyber insurance?", "type": "select",
                 "options": ["Yes", "No", "Application in process", "I don't know"]},
            ]
        },
        {
            "title": "Compliance Requirements",
            "questions": [
                {"id": "q21", "text": "Which compliance frameworks apply to you?", "type": "multiselect",
                 "options": ["IRS Publication 4557", "FTC Safeguards Rule", "HIPAA", "SOC 2",
                             "PCI-DSS", "CMMC", "State Privacy Laws (CCPA etc.)", "I'm not sure", "None"]},
                {"id": "q22", "text": "Has a client or partner ever sent you a security questionnaire?", "type": "select",
                 "options": ["Yes — frequently", "Yes — occasionally", "No"]},
                {"id": "q23", "text": "Are you planning for any certifications?", "type": "multiselect",
                 "options": ["SOC 2 Type II", "ISO 27001", "CMMC", "HITRUST", "None currently"]},
            ]
        },
        {
            "title": "AI & Emerging Technology",
            "questions": [
                {"id": "q24", "text": "Do employees use AI tools (ChatGPT, Copilot, Claude, Gemini, etc.)?", "type": "select",
                 "options": ["Yes — widely adopted", "Yes — some employees", "No", "I don't know"]},
                {"id": "q25", "text": "Do you have a policy governing AI use with client/sensitive data?", "type": "select",
                 "options": ["Yes — formal written policy", "Yes — informal guidelines", "No", "What is an AI use policy?"]},
                {"id": "q26", "text": "Has client or sensitive data ever been entered into an AI tool?", "type": "select",
                 "options": ["Yes", "Possibly — we don't monitor", "No — we have controls", "I don't know"]},
                {"id": "q27", "text": "Which AI-related risks concern you most?", "type": "multiselect",
                 "options": ["Employees sharing client data with AI", "AI-generated phishing attacks",
                             "Compliance violations from AI use", "AI hallucinations in client work",
                             "Lack of visibility into AI usage", "None — not concerned"]},
            ]
        }
    ]
}


class GuardianAgent:
    """
    AI Virtual CISO — generates entire security programs.
    
    Works WITHOUT Claude API for structure/framework mapping.
    Uses Claude API (when available) for customized policy TEXT generation.
    """

    AGENT_NAME = "GUARDIAN"
    AGENT_TAGLINE = "I build your security program while you run your business."

    def __init__(self, anthropic_api_key: Optional[str] = None):
        self.api_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
        self.frameworks = FRAMEWORKS
        self.policy_templates = POLICY_TEMPLATES
        self.questionnaire = ONBOARDING_QUESTIONNAIRE

    # ─── QUESTIONNAIRE ────────────────────────────────────────

    def get_questionnaire(self) -> dict:
        """Return the onboarding questionnaire for the client portal."""
        return self.questionnaire

    def process_questionnaire(self, answers: dict) -> dict:
        """Process questionnaire answers into a client profile."""
        profile = {
            "company_name": answers.get("q1", "Unknown"),
            "industry": answers.get("q2", "Other"),
            "employee_count": answers.get("q3", "Unknown"),
            "locations": answers.get("q4", 1),
            "remote_work": answers.get("q5", "Unknown"),
            "email_provider": answers.get("q6", "Unknown"),
            "mfa_status": answers.get("q7", "Unknown"),
            "cloud_services": answers.get("q8", []),
            "firewall": answers.get("q9", "Unknown"),
            "endpoint_protection": answers.get("q10", "Unknown"),
            "backup": answers.get("q11", "Unknown"),
            "data_types": answers.get("q12", []),
            "data_storage": answers.get("q13", []),
            "data_access": answers.get("q14", "Unknown"),
            "has_wisp": answers.get("q15", "No"),
            "has_irp": answers.get("q16", "No"),
            "last_assessment": answers.get("q17", "Never"),
            "training": answers.get("q18", "No"),
            "past_incidents": answers.get("q19", "Not sure"),
            "cyber_insurance": answers.get("q20", "Unknown"),
            "compliance_frameworks": answers.get("q21", []),
            "security_questionnaires": answers.get("q22", "No"),
            "planned_certifications": answers.get("q23", []),
            "ai_tool_usage": answers.get("q24", "I don't know"),
            "ai_policy": answers.get("q25", "No"),
            "ai_data_exposure": answers.get("q26", "I don't know"),
            "ai_risk_concerns": answers.get("q27", []),
        }

        # Auto-detect applicable frameworks
        profile["applicable_frameworks"] = self._detect_frameworks(profile)

        # Generate initial risk assessment
        profile["risk_score"] = self._calculate_risk_score(profile)

        return profile

    def _detect_frameworks(self, profile: dict) -> list:
        """Auto-detect which compliance frameworks apply based on industry and data types."""
        applicable = []

        industry = profile.get("industry", "")
        data_types = profile.get("data_types", [])

        # IRS 4557 — if they handle tax data
        if industry in ["Accounting / CPA", "Tax Preparation"] or "Tax Returns (FTI)" in data_types:
            applicable.append("irs_4557")

        # FTC Safeguards — if financial services
        if industry in ["Financial Services", "Insurance", "Lending"] or "Client Financial Data" in data_types:
            applicable.append("ftc_safeguards")

        # HIPAA — if healthcare or health data
        if industry in ["Healthcare"] or "Health Records (PHI)" in data_types:
            applicable.append("hipaa")

        # SOC 2 — if SaaS/tech or clients request it
        if industry in ["Technology / SaaS"] or profile.get("security_questionnaires") == "Yes — frequently":
            applicable.append("soc2")

        # NIST CSF — always applicable as baseline
        applicable.append("nist_csf_2")

        return applicable

    def _calculate_risk_score(self, profile: dict) -> dict:
        """Calculate initial risk score from questionnaire answers."""
        score = 0
        max_score = 100
        findings = []

        # MFA (most important)
        if profile["mfa_status"] == "Yes — for everyone":
            score += 15
        elif profile["mfa_status"] == "Yes — for some users":
            score += 7
            findings.append("MFA not enabled for all users")
        else:
            findings.append("No MFA — #1 security risk")

        # WISP
        if profile["has_wisp"] in ["Yes — current"]:
            score += 10
        else:
            findings.append("No current WISP document")

        # Incident Response Plan
        if profile["has_irp"] == "Yes — tested":
            score += 10
        elif profile["has_irp"] == "Yes — untested":
            score += 5
            findings.append("Incident Response Plan exists but untested")
        else:
            findings.append("No Incident Response Plan")

        # Training
        if profile["training"] == "Yes — at least annually":
            score += 10
        elif profile["training"] in ["Yes — at hire only", "Informal/ad-hoc"]:
            score += 3
            findings.append("Security training not conducted annually")
        else:
            findings.append("No security awareness training")

        # Endpoint Protection
        if profile["endpoint_protection"] == "Yes — on all devices":
            score += 10
        elif profile["endpoint_protection"] == "Yes — on some":
            score += 4
            findings.append("Endpoint protection not on all devices")
        else:
            findings.append("No endpoint protection")

        # Firewall
        if profile["firewall"] in ["Yes — managed"]:
            score += 10
        elif profile["firewall"] == "Yes — unmanaged":
            score += 5
            findings.append("Firewall exists but is not actively managed")
        else:
            findings.append("No firewall or unknown status")

        # Backup
        if profile["backup"] == "Yes — automated cloud backup":
            score += 10
        elif profile["backup"] == "Yes — manual backup":
            score += 4
            findings.append("Backups are manual — should be automated")
        else:
            findings.append("No data backup — critical risk")

        # Data access controls
        if profile["data_access"] == "Only specific authorized staff":
            score += 10
        else:
            findings.append("Sensitive data access not properly restricted")

        # Cyber insurance
        if profile["cyber_insurance"] == "Yes":
            score += 5
        else:
            findings.append("No cyber insurance")

        # Recent assessment
        if profile["last_assessment"] == "Within 6 months":
            score += 10
        elif profile["last_assessment"] == "6-12 months ago":
            score += 5
        else:
            findings.append("No recent security assessment")

        # AI Governance (new risk category)
        ai_usage = profile.get("ai_tool_usage", "I don't know")
        ai_policy = profile.get("ai_policy", "No")
        ai_exposure = profile.get("ai_data_exposure", "I don't know")

        if ai_usage in ["Yes — widely adopted", "Yes — some employees", "I don't know"]:
            # AI is being used (or unknown = assume yes) — policy matters
            if ai_policy == "Yes — formal written policy":
                score += 10
            elif ai_policy == "Yes — informal guidelines":
                score += 4
                findings.append("AI tools in use without formal governance policy")
            else:
                findings.append("No AI acceptable use policy — employees may be exposing client data to AI tools")

            if ai_exposure in ["Yes", "Possibly — we don't monitor", "I don't know"]:
                findings.append("Client/sensitive data may have been shared with AI tools — potential compliance violation")
        else:
            # No AI usage claimed — still worth noting
            score += 5

        return {
            "questionnaire_score": min(score, max_score),
            "max_score": max_score,
            "findings": findings,
            "findings_count": len(findings)
        }

    # ─── RISK REGISTER ────────────────────────────────────────

    def generate_risk_register(self, client_profile: dict, scan_results: dict = None) -> list:
        """
        Generate a risk register combining questionnaire gaps + scan findings.
        
        Each risk has: ID, title, description, likelihood (1-5), impact (1-5),
        risk_score, category, applicable_controls, remediation, priority.
        """
        risks = []
        risk_id = 1

        # From questionnaire gaps
        for finding in client_profile.get("risk_score", {}).get("findings", []):
            likelihood, impact = self._assess_risk_level(finding)
            risks.append({
                "id": f"R-{risk_id:03d}",
                "title": finding,
                "source": "questionnaire",
                "likelihood": likelihood,
                "impact": impact,
                "risk_score": likelihood * impact,
                "priority": "CRITICAL" if likelihood * impact >= 20 else "HIGH" if likelihood * impact >= 12 else "MEDIUM" if likelihood * impact >= 6 else "LOW",
                "remediation": self._get_remediation(finding),
                "status": "open"
            })
            risk_id += 1

        # From scan results (if provided)
        if scan_results:
            for finding in scan_results.get("findings", []):
                likelihood = 5 if finding["severity"] == "CRITICAL" else 4 if finding["severity"] == "HIGH" else 3
                impact = 4 if finding["severity"] in ["CRITICAL", "HIGH"] else 3
                risks.append({
                    "id": f"R-{risk_id:03d}",
                    "title": finding["title"],
                    "source": "scan",
                    "likelihood": likelihood,
                    "impact": impact,
                    "risk_score": likelihood * impact,
                    "priority": finding["severity"],
                    "remediation": finding.get("fix", "See scan report"),
                    "status": "open"
                })
                risk_id += 1

        # Sort by risk score descending
        risks.sort(key=lambda x: x["risk_score"], reverse=True)
        return risks

    def _assess_risk_level(self, finding: str) -> tuple:
        """Map finding text to likelihood and impact scores."""
        high_risk_keywords = ["no mfa", "no wisp", "no backup", "no endpoint", "no firewall"]
        medium_risk_keywords = ["untested", "not all", "manual", "outdated", "not conducted"]

        finding_lower = finding.lower()
        if any(kw in finding_lower for kw in high_risk_keywords):
            return (5, 5)  # Very likely, very high impact
        elif any(kw in finding_lower for kw in medium_risk_keywords):
            return (3, 4)
        else:
            return (2, 3)

    def _get_remediation(self, finding: str) -> str:
        """Get remediation steps for common findings."""
        remediations = {
            "No MFA": "Enable Multi-Factor Authentication for ALL user accounts in Microsoft 365/Google Workspace. Start with admin and privileged accounts.",
            "No current WISP": "Generate WISP using GUARDIAN. Review and customize with firm leadership. Sign and distribute to all employees.",
            "No Incident Response Plan": "Generate IRP using GUARDIAN. Assign incident response roles. Test with tabletop exercise within 30 days.",
            "No security awareness training": "Deploy PHANTOM phishing simulations monthly. Assign annual security training to all employees.",
            "No endpoint protection": "Deploy Microsoft Defender for Business or equivalent on ALL company devices including personal devices used for work.",
            "No data backup": "Implement automated cloud backup (e.g., Veeam, Datto, or native M365 backup). Test restore monthly.",
            "No cyber insurance": "Obtain cyber insurance quotes. GUARDIAN can generate the evidence package needed for favorable premiums.",
        }
        for key, value in remediations.items():
            if key.lower() in finding.lower():
                return value
        return "Schedule remediation and assign to responsible party."

    # ─── COMPLIANCE MAPPING ───────────────────────────────────

    def get_compliance_status(self, client_profile: dict, scan_results: dict = None) -> dict:
        """Map client's current state to applicable framework controls."""
        status = {}
        
        for framework_id in client_profile.get("applicable_frameworks", []):
            framework = self.frameworks.get(framework_id)
            if not framework:
                continue

            controls = framework["controls"]
            met = 0
            partial = 0
            not_met = 0
            control_status = []

            for control in controls:
                ctrl_status = self._check_control(control, client_profile, scan_results)
                control_status.append({**control, "status": ctrl_status})
                if ctrl_status == "met":
                    met += 1
                elif ctrl_status == "partial":
                    partial += 1
                else:
                    not_met += 1

            total = len(controls)
            pct = int(((met + partial * 0.5) / max(total, 1)) * 100)

            status[framework_id] = {
                "framework_name": framework["name"],
                "total_controls": total,
                "met": met,
                "partial": partial,
                "not_met": not_met,
                "compliance_percentage": pct,
                "controls": control_status
            }

        return status

    def _check_control(self, control: dict, profile: dict, scan_results: dict = None) -> str:
        """Check if a specific control is met based on profile data."""
        name = control["name"].lower()

        # MFA controls
        if "multi-factor" in name or "mfa" in name:
            if profile.get("mfa_status") == "Yes — for everyone":
                return "met"
            elif profile.get("mfa_status") == "Yes — for some users":
                return "partial"
            return "not_met"

        # WISP / Security Plan
        if "security plan" in name or "wisp" in name or "security management" in name:
            if profile.get("has_wisp") == "Yes — current":
                return "met"
            elif profile.get("has_wisp") == "Yes — outdated":
                return "partial"
            return "not_met"

        # Training
        if "training" in name or "awareness" in name:
            if profile.get("training") == "Yes — at least annually":
                return "met"
            elif profile.get("training") in ["Yes — at hire only", "Informal/ad-hoc"]:
                return "partial"
            return "not_met"

        # Incident Response
        if "incident" in name:
            if profile.get("has_irp") == "Yes — tested":
                return "met"
            elif profile.get("has_irp") == "Yes — untested":
                return "partial"
            return "not_met"

        # Encryption
        if "encryption" in name or "data security" in name or "data protection" in name:
            return "partial"  # Need scan data to confirm

        # Backup
        if "backup" in name or "recovery" in name or "contingency" in name or "continuity" in name:
            if profile.get("backup") == "Yes — automated cloud backup":
                return "met"
            elif profile.get("backup") == "Yes — manual backup":
                return "partial"
            return "not_met"

        # Default
        return "not_met"

    # ─── POLICY GENERATION ────────────────────────────────────

    def get_required_policies(self, client_profile: dict) -> list:
        """Determine which policies need to be generated for this client."""
        required = []
        frameworks = client_profile.get("applicable_frameworks", [])

        for policy_key, policy in self.policy_templates.items():
            # Check if any of the client's frameworks require this policy
            if any(fw in frameworks for fw in policy["frameworks"]):
                required.append({
                    "key": policy_key,
                    "name": policy["name"],
                    "sections": policy["sections"],
                    "frameworks": [f for f in policy["frameworks"] if f in frameworks]
                })

        return required

    def generate_policy_prompt(self, policy_key: str, client_profile: dict) -> str:
        """
        Generate the Claude API prompt for a specific policy.
        This is what you send to Claude to generate the actual policy text.
        """
        template = self.policy_templates.get(policy_key)
        if not template:
            return ""

        prompt = f"""Generate a complete, professional {template['name']} for the following organization:

Company: {client_profile.get('company_name', 'Unknown')}
Industry: {client_profile.get('industry', 'Unknown')}
Employees: {client_profile.get('employee_count', 'Unknown')}
Locations: {client_profile.get('locations', 1)}
Remote Work: {client_profile.get('remote_work', 'Unknown')}
Email Provider: {client_profile.get('email_provider', 'Unknown')}
Cloud Services: {', '.join(client_profile.get('cloud_services', []))}
Sensitive Data Types: {', '.join(client_profile.get('data_types', []))}
Current MFA Status: {client_profile.get('mfa_status', 'Unknown')}
Firewall: {client_profile.get('firewall', 'Unknown')}
Endpoint Protection: {client_profile.get('endpoint_protection', 'Unknown')}
Backup: {client_profile.get('backup', 'Unknown')}
Applicable Frameworks: {', '.join(client_profile.get('applicable_frameworks', []))}

The policy MUST include these sections:
{chr(10).join(f'- {s}' for s in template['sections'])}

Requirements:
1. Write in clear, professional English that a business owner can understand
2. Be SPECIFIC to this company — reference their actual technology, data types, and industry
3. Include actual procedures, not just policy statements
4. Reference specific compliance requirements ({', '.join(template['frameworks'])})
5. Include effective dates, review schedules, and version control
6. Format as a complete, ready-to-sign document
7. Include signature block at the end

Do NOT write a generic template. This must be customized for THIS specific organization."""

        return prompt

    # ─── MONTHLY REPORT ───────────────────────────────────────

    def generate_report_data(self, client_id: str, agent_data: dict) -> dict:
        """
        Compile data from all agents into a monthly report structure.
        
        agent_data should contain outputs from: spectre, archer, mirage, sentinel, compass
        """
        report = {
            "client_id": client_id,
            "report_date": datetime.utcnow().isoformat() + "Z",
            "report_type": "monthly",
            "sections": {
                "executive_summary": {
                    "security_score_current": agent_data.get("archer", {}).get("score", {}).get("total", 0),
                    "security_score_previous": agent_data.get("previous_score", 0),
                    "incidents_this_month": agent_data.get("sentinel", {}).get("incidents", 0),
                    "vulnerabilities_fixed": agent_data.get("archer", {}).get("vulns_fixed", 0),
                    "new_vulnerabilities": agent_data.get("archer", {}).get("vulns_new", 0),
                },
                "spectre": {
                    "new_credentials_found": agent_data.get("spectre", {}).get("new_exposures", 0),
                    "total_credentials_monitored": agent_data.get("spectre", {}).get("total_monitored", 0),
                },
                "archer": {
                    "total_vulnerabilities": agent_data.get("archer", {}).get("total_vulns", 0),
                    "critical_remaining": agent_data.get("archer", {}).get("critical", 0),
                },
                "mirage": {
                    "employees_tested": agent_data.get("mirage", {}).get("tested", 0),
                    "click_rate": agent_data.get("mirage", {}).get("click_rate", 0),
                    "previous_click_rate": agent_data.get("mirage", {}).get("prev_click_rate", 0),
                },
                "compass": {
                    "compliance_status": agent_data.get("compass", {}),
                },
                "recommendations": [],
            }
        }
        return report

    # ─── EXPORT ───────────────────────────────────────────────

    def to_json(self, data) -> str:
        """Export any data as JSON."""
        return json.dumps(data, indent=2, default=str)


# ─── DEMO ────────────────────────────────────────────────────

if __name__ == "__main__":
    forge = GuardianAgent()

    # Simulate client onboarding
    print("[GUARDIAN] Demo: Processing client questionnaire...\n")

    sample_answers = {
        "q1": "Smith & Associates CPA",
        "q2": "Accounting / CPA",
        "q3": "11-25",
        "q4": 2,
        "q5": "Hybrid",
        "q6": "Microsoft 365",
        "q7": "Yes — for some users",
        "q8": ["Microsoft 365", "QuickBooks Online", "Dropbox"],
        "q9": "Yes — unmanaged",
        "q10": "Yes — on some",
        "q11": "Yes — manual backup",
        "q12": ["Social Security Numbers", "Tax Returns (FTI)", "Bank Account Numbers"],
        "q13": ["Cloud applications", "Employee laptops"],
        "q14": "All employees",
        "q15": "No",
        "q16": "No",
        "q17": "Never",
        "q18": "Informal/ad-hoc",
        "q19": "Not sure",
        "q20": "No",
        "q21": ["IRS Publication 4557"],
        "q22": "No",
        "q23": [],
    }

    # Process questionnaire
    profile = forge.process_questionnaire(sample_answers)
    print(f"Company: {profile['company_name']}")
    print(f"Industry: {profile['industry']}")
    print(f"Applicable Frameworks: {profile['applicable_frameworks']}")
    print(f"Risk Score: {profile['risk_score']['questionnaire_score']}/100")
    print(f"Findings: {profile['risk_score']['findings_count']}")
    for f in profile['risk_score']['findings']:
        print(f"  ⚠️  {f}")

    # Generate risk register
    print(f"\n[GUARDIAN] Generating Risk Register...")
    risks = forge.generate_risk_register(profile)
    print(f"Total Risks: {len(risks)}")
    for r in risks[:5]:
        print(f"  [{r['priority']}] {r['title']} (Score: {r['risk_score']})")

    # Get compliance status
    print(f"\n[GUARDIAN] Calculating Compliance Status...")
    compliance = forge.get_compliance_status(profile)
    for fw_id, status in compliance.items():
        print(f"  {status['framework_name']}: {status['compliance_percentage']}% compliant")
        print(f"    Met: {status['met']} | Partial: {status['partial']} | Not Met: {status['not_met']}")

    # List required policies
    print(f"\n[GUARDIAN] Required Policies:")
    policies = forge.get_required_policies(profile)
    for p in policies:
        print(f"  📄 {p['name']}")

    # Show policy generation prompt (for Claude API)
    print(f"\n[GUARDIAN] Sample WISP Generation Prompt (first 200 chars):")
    prompt = forge.generate_policy_prompt("wisp", profile)
    print(f"  {prompt[:200]}...")
