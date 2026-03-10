"""
VIGIL — Continuous Security Monitoring Agent
"I watch everything. I never sleep."

Integrates with Wazuh SIEM + Microsoft 365 Graph API.
Setup: docker-compose up wazuh (see wazuh-docker repo)
"""
import os, json
from datetime import datetime

class VigilAgent:
    AGENT_NAME = "VIGIL"
    AGENT_TAGLINE = "I watch everything. I never sleep."

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"
    TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    def __init__(self):
        pass

    def _get_m365_token(self, tenant_id: str, client_id: str, client_secret: str) -> str:
        """Get OAuth2 token for Microsoft Graph API."""
        import requests
        resp = requests.post(
            self.TOKEN_URL.format(tenant_id=tenant_id),
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def check_m365_signin_logs(self, tenant_id: str, client_id: str, client_secret: str) -> dict:
        """Pull risky sign-ins from Microsoft 365 Graph API."""
        import requests
        from datetime import timedelta
        try:
            token = self._get_m365_token(tenant_id, client_id, client_secret)
            headers = {"Authorization": f"Bearer {token}"}

            since = (datetime.utcnow() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
            url = f"{self.GRAPH_BASE}/auditLogs/signIns?$filter=createdDateTime ge {since} and (riskLevelDuringSignIn eq 'high' or riskLevelDuringSignIn eq 'medium' or status/errorCode ne 0)&$top=50&$orderby=createdDateTime desc"

            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            sign_ins = resp.json().get("value", [])

            anomalies = []
            for si in sign_ins:
                risk = si.get("riskLevelDuringSignIn", "none")
                error_code = si.get("status", {}).get("errorCode", 0)
                location = si.get("location", {})
                city = location.get("city", "Unknown")
                country = location.get("countryOrRegion", "Unknown")

                anomaly_type = None
                severity = "MEDIUM"

                if risk in ("high",):
                    anomaly_type = "Risky sign-in"
                    severity = "HIGH"
                elif risk in ("medium",):
                    anomaly_type = "Suspicious sign-in"
                    severity = "MEDIUM"
                elif error_code != 0:
                    anomaly_type = "Failed sign-in"
                    severity = "LOW"

                if anomaly_type:
                    anomalies.append({
                        "type": anomaly_type,
                        "severity": severity,
                        "user": si.get("userPrincipalName", "unknown"),
                        "ip": si.get("ipAddress", ""),
                        "location": f"{city}, {country}",
                        "app": si.get("appDisplayName", ""),
                        "time": si.get("createdDateTime", ""),
                        "risk_detail": si.get("riskEventTypes_v2", []),
                        "error_code": error_code,
                    })

            # Check for impossible travel
            user_locations = {}
            for a in anomalies:
                user = a["user"]
                if user not in user_locations:
                    user_locations[user] = []
                user_locations[user].append(a)

            for user, events in user_locations.items():
                countries = set(e["location"].split(", ")[-1] for e in events)
                if len(countries) > 1:
                    for e in events:
                        e["type"] = "Impossible travel detected"
                        e["severity"] = "CRITICAL"

            return {"status": "ok", "anomalies": anomalies, "total_checked": len(sign_ins)}

        except Exception as e:
            return {"status": "error", "error": str(e), "anomalies": []}

    def check_uptime(self, domain: str) -> dict:
        """Fallback monitoring: HTTP uptime + SSL check for non-M365 clients."""
        import requests
        try:
            resp = requests.get(f"https://{domain}", timeout=10, allow_redirects=True)
            ssl_ok = resp.url.startswith("https")
            return {
                "status": "up",
                "response_time_ms": int(resp.elapsed.total_seconds() * 1000),
                "status_code": resp.status_code,
                "ssl": ssl_ok,
                "domain": domain,
            }
        except requests.exceptions.SSLError:
            return {"status": "ssl_error", "domain": domain, "ssl": False}
        except requests.exceptions.ConnectionError:
            return {"status": "down", "domain": domain}
        except Exception as e:
            return {"status": "error", "domain": domain, "error": str(e)}

    def triage_alert_prompt(self, alert_data: dict, client_context: dict) -> str:
        """Generate Claude API prompt for AI alert triage."""
        return f"""You are VIGIL, CyberComply's AI SOC analyst.
Analyze this alert and provide: SEVERITY (Critical/High/Medium/Low/False Positive),
WHAT HAPPENED (plain English for a business owner), WHY IT MATTERS, RECOMMENDED ACTION.

Alert: {json.dumps(alert_data)}
Client: {client_context.get('industry')}, {client_context.get('employees')} employees
"""

    def generate_daily_digest_prompt(self, alerts: list) -> str:
        """Generate prompt for daily security digest."""
        return f"""Generate a brief daily security digest for a business owner.
Include: events monitored, threats blocked, items needing attention.
Today's alerts: {json.dumps(alerts[:20])}"""


"""
COMPLY — Compliance Framework Mapper Agent
"Fix one thing. Satisfy five frameworks."

Uses GUARDIAN's framework database for cross-mapping.
Tracks evidence collection and compliance progress.
"""

class ComplyAgent:
    AGENT_NAME = "COMPLY"
    AGENT_TAGLINE = "Fix one thing. Satisfy five frameworks."

    def __init__(self):
        from agents.guardian_agent import FRAMEWORKS
        self.frameworks = FRAMEWORKS
    
    def cross_map_controls(self, framework_ids: list) -> dict:
        """Find overlapping controls across multiple frameworks."""
        control_groups = {
            "access_control": ["mfa", "multi-factor", "access control", "authentication", "password"],
            "risk_assessment": ["risk assessment", "risk management"],
            "incident_response": ["incident", "response", "breach notification"],
            "training": ["training", "awareness", "education"],
            "encryption": ["encryption", "data protection", "data security"],
            "monitoring": ["monitoring", "logging", "audit"],
            "vendor_management": ["vendor", "third party", "service provider"],
            "backup_recovery": ["backup", "recovery", "continuity", "contingency"],
        }
        
        mapping = {}
        for group_name, keywords in control_groups.items():
            group_controls = []
            for fw_id in framework_ids:
                fw = self.frameworks.get(fw_id, {})
                for control in fw.get("controls", []):
                    if any(kw in control["name"].lower() for kw in keywords):
                        group_controls.append({"framework": fw_id, "control_id": control["id"],
                                                "control_name": control["name"]})
            if len(group_controls) > 1:  # Only include if overlaps exist
                mapping[group_name] = {
                    "description": f"Implement once, satisfy {len(group_controls)} controls",
                    "controls": group_controls,
                    "frameworks_affected": list(set(c["framework"] for c in group_controls))
                }
        return mapping

    def get_evidence_checklist(self, framework_id: str) -> list:
        """Generate evidence collection checklist for a framework."""
        evidence_map = {
            "Access Control": ["MFA configuration screenshot", "User access review log", "Password policy document"],
            "Governance": ["Signed security policy", "Board meeting minutes", "Risk assessment report"],
            "Training": ["Training completion records", "Phishing simulation results", "Training material"],
            "Monitoring": ["SIEM dashboard screenshot", "Alert log sample", "Monitoring policy"],
            "Incident Response": ["Incident response plan", "Tabletop exercise results", "Incident log"],
            "Data Protection": ["Encryption configuration", "Data classification matrix", "DLP policy"],
            "Network Security": ["Firewall rules export", "Network diagram", "Vulnerability scan report"],
            "Business Continuity": ["Backup verification report", "DR test results", "BCP document"],
            "Third Party": ["Vendor risk assessment", "Contract review", "Vendor SOC reports"],
        }
        
        fw = self.frameworks.get(framework_id, {})
        checklist = []
        for control in fw.get("controls", []):
            category = control.get("category", "General")
            evidence = evidence_map.get(category, ["Policy document", "Implementation evidence"])
            checklist.append({
                "control_id": control["id"],
                "control_name": control["name"],
                "required_evidence": evidence,
                "status": "not_started"
            })
        return checklist

    def generate_compliance_update(self, client_name: str, frameworks: list,
                                     compliance_status: dict) -> str:
        """Generate compliance progress update using P57 prompt."""
        from prompt_engine import call_prompt

        framework_summary = []
        for fw_id, status in compliance_status.items():
            pct = status.get("percentage", 0) if isinstance(status, dict) else 0
            framework_summary.append(f"- {fw_id}: {pct}% compliant")

        try:
            return call_prompt(
                "P57_COMPLIANCE_PROGRESS_UPDATE_EMAIL",
                client_name=client_name,
                frameworks="\n".join(framework_summary) if framework_summary else "No frameworks tracked",
                overall_progress=str(sum(s.get("percentage", 0) for s in compliance_status.values() if isinstance(s, dict)) // max(len(compliance_status), 1)),
            )
        except Exception:
            return f"Compliance update for {client_name}: {len(frameworks)} frameworks tracked."


"""
BREACH — AI Penetration Testing Agent
"I break in so nobody else can."

Orchestrates: OWASP ZAP (web), SQLMap (injection), Subfinder (recon).
Requires human validation for findings.
"""

class BreachAgent:
    AGENT_NAME = "BREACH"
    AGENT_TAGLINE = "I break in so nobody else can."

    INDUSTRY_TEMPLATES = {
        "cpa": ["cves", "misconfigurations", "exposed-panels", "default-logins", "takeovers"],
        "healthcare": ["cves", "misconfigurations", "exposed-panels", "default-logins"],
        "financial": ["cves", "misconfigurations", "exposed-panels", "default-logins", "takeovers"],
        "legal": ["cves", "misconfigurations", "exposed-panels", "takeovers"],
        "general": ["cves", "misconfigurations", "default-logins", "exposures"],
    }

    def run_nuclei_scan(self, target: str, industry: str = "general", severity: str = "critical,high,medium") -> dict:
        """Run Nuclei vulnerability scan against a target domain/URL."""
        import subprocess
        import tempfile

        tags = self.INDUSTRY_TEMPLATES.get(industry, self.INDUSTRY_TEMPLATES["general"])
        tags_str = ",".join(tags)

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as f:
            output_file = f.name

        try:
            cmd = [
                "nuclei", "-u", target,
                "-severity", severity,
                "-tags", tags_str,
                "-jsonl", "-o", output_file,
                "-silent", "-nc",
                "-rate-limit", "50",
                "-timeout", "10",
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            findings = []
            try:
                with open(output_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            finding = json.loads(line)
                            findings.append({
                                "template_id": finding.get("template-id", ""),
                                "name": finding.get("info", {}).get("name", "Unknown"),
                                "severity": finding.get("info", {}).get("severity", "medium").upper(),
                                "description": finding.get("info", {}).get("description", ""),
                                "matched_at": finding.get("matched-at", target),
                                "matcher_name": finding.get("matcher-name", ""),
                                "tags": finding.get("info", {}).get("tags", []),
                                "reference": finding.get("info", {}).get("reference", []),
                                "cve_id": next((r for r in finding.get("info", {}).get("classification", {}).get("cve-id", []) if r), ""),
                            })
            except Exception:
                pass
            finally:
                import os as _os
                _os.unlink(output_file)

            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            findings.sort(key=lambda f: sev_order.get(f["severity"], 5))

            return {
                "status": "complete",
                "target": target,
                "total": len(findings),
                "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
                "high": sum(1 for f in findings if f["severity"] == "HIGH"),
                "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
                "findings": findings[:50],
            }
        except FileNotFoundError:
            return {"status": "not_installed", "error": "Nuclei not installed. Runs on Railway deployment.",
                    "target": target, "total": 0, "findings": []}
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": "Scan timed out after 5 minutes",
                    "target": target, "total": 0, "findings": []}
        except Exception as e:
            return {"status": "error", "error": str(e),
                    "target": target, "total": 0, "findings": []}

    def get_pentest_scope_template(self) -> dict:
        """Return standard pentest scope document."""
        return {
            "title": "Penetration Test Scope of Work",
            "sections": {
                "external_network": ["IP ranges", "Domains", "Subdomains"],
                "web_applications": ["URLs", "Authentication type", "User roles to test"],
                "wireless": ["Office locations", "SSID names"],
                "social_engineering": ["Phishing allowed?", "Physical access test?", "Phone pretexting?"],
                "exclusions": ["Systems NOT to test", "Time restrictions", "Rate limits"],
                "rules_of_engagement": ["Testing window", "Emergency contacts", "Data handling"],
            }
        }


"""
DISPATCH — Incident Response Engine
"When something goes wrong, I take over."

Pre-built playbooks for top 7 SMB incident scenarios.
"""

class DispatchAgent:
    AGENT_NAME = "DISPATCH"
    AGENT_TAGLINE = "When something goes wrong, I take over."
    
    PLAYBOOKS = {
        "bec": {
            "name": "Business Email Compromise (BEC)",
            "severity": "CRITICAL",
            "steps": [
                "Disable compromised email account immediately",
                "Revoke all active sessions (M365 Admin → Users → Revoke sessions)",
                "Check email rules for auto-forwarding to external addresses",
                "Search sent folder for fraudulent emails sent to clients/vendors",
                "Reset password and enforce MFA",
                "Scan for unauthorized inbox rules",
                "Notify affected clients/vendors if fraudulent emails were sent",
                "Check if any wire transfers were requested/initiated",
                "Contact bank immediately if funds were transferred",
                "File FBI IC3 complaint (ic3.gov)",
                "Document everything for insurance claim",
                "Conduct post-incident review in 72 hours"
            ],
            "notification_templates": {
                "client": "We detected unauthorized access to an employee email account. We have contained the incident and are investigating. No action is needed from you at this time.",
                "insurance": "We are reporting a potential Business Email Compromise incident. Details attached. Claim number requested.",
            }
        },
        "ransomware": {
            "name": "Ransomware Attack",
            "severity": "CRITICAL",
            "steps": [
                "DISCONNECT affected systems from network IMMEDIATELY (pull ethernet, disable WiFi)",
                "DO NOT turn off infected machines (preserves forensic evidence)",
                "DO NOT pay the ransom",
                "Identify patient zero — which machine was infected first?",
                "Check if backups are intact (verify they're not encrypted too)",
                "Notify cyber insurance carrier within required timeframe",
                "Contact FBI (ic3.gov) and CISA (cisa.gov/report)",
                "Determine scope: how many systems affected?",
                "Begin restoration from clean backups",
                "Reset ALL passwords across the organization",
                "Patch the vulnerability that was exploited",
                "Conduct full incident review"
            ]
        },
        "phished_credentials": {
            "name": "Phished Credentials",
            "severity": "HIGH",
            "steps": [
                "Reset the compromised password immediately",
                "Revoke all active sessions",
                "Enable MFA if not already active",
                "Check for unauthorized access in sign-in logs",
                "Check for email forwarding rules",
                "Search for data exfiltration indicators",
                "Notify the affected employee",
                "Send targeted security training",
                "Monitor account for 30 days for suspicious activity"
            ]
        },
        "data_breach": {
            "name": "Data Breach / Unauthorized Data Access",
            "severity": "CRITICAL",
            "steps": [
                "Contain: Disable access for the source of breach",
                "Determine WHAT data was accessed/exfiltrated",
                "Determine HOW MANY individuals are affected",
                "Determine WHAT TYPE of data (SSN, financial, health)",
                "Activate legal counsel — breach notification laws vary by state",
                "Notify cyber insurance carrier",
                "Federal notification (if FTI: IRS; if PHI: HHS; if financial: FTC)",
                "State notification (varies — some require notice within 30 days)",
                "Individual notification to affected persons",
                "Offer credit monitoring if SSNs exposed",
                "Document all actions taken with timestamps",
                "Conduct root cause analysis"
            ]
        },
        "malware": {
            "name": "Malware Infection",
            "severity": "HIGH",
            "steps": [
                "Isolate infected machine from network",
                "Identify the malware type (check with endpoint protection logs)",
                "Scan all other machines on the same network segment",
                "Remove malware using endpoint protection tools",
                "Check for persistence mechanisms (startup items, scheduled tasks)",
                "Reset credentials used on the infected machine",
                "Verify no data was exfiltrated",
                "Patch the entry vector",
                "Re-image machine if unable to fully clean"
            ]
        },
        "insider_threat": {
            "name": "Insider Threat / Departing Employee",
            "severity": "HIGH",
            "steps": [
                "Preserve all access logs BEFORE revoking access",
                "Disable all accounts (email, VPN, cloud apps, physical access)",
                "Revoke OAuth tokens and API keys",
                "Check for large file downloads or USB activity in past 30 days",
                "Check for emails sent to personal accounts",
                "Review cloud storage sharing permissions",
                "Collect company devices",
                "Change shared passwords/credentials they had access to",
                "Review NDA and non-compete obligations",
                "Monitor for data appearing externally"
            ]
        },
        "lost_device": {
            "name": "Lost or Stolen Device",
            "severity": "MEDIUM",
            "steps": [
                "Remote wipe the device (M365 Admin or MDM solution)",
                "Revoke all active sessions for the user",
                "Reset passwords for all accounts accessed from that device",
                "Check if full disk encryption was enabled",
                "Determine what data was on the device",
                "If sensitive data present and unencrypted → treat as data breach",
                "File police report if stolen",
                "Notify insurance if device was company-owned",
                "Issue replacement device with encryption enforced"
            ]
        }
    }
    
    def get_playbook(self, incident_type: str) -> dict:
        """Get incident response playbook."""
        return self.PLAYBOOKS.get(incident_type, {"error": "Playbook not found"})
    
    def list_playbooks(self) -> list:
        """List all available playbooks."""
        return [{"key": k, "name": v["name"], "severity": v["severity"]} 
                for k, v in self.PLAYBOOKS.items()]
    
    def generate_incident_report_prompt(self, incident_data: dict) -> str:
        """Generate Claude API prompt for incident report."""
        return f"""Generate a formal Incident Response Report for:
Incident Type: {incident_data.get('type')}
Date Detected: {incident_data.get('detected_date')}
Affected Systems: {incident_data.get('affected_systems')}
Actions Taken: {incident_data.get('actions_taken')}
Data Impact: {incident_data.get('data_impact')}

Format as a professional report suitable for: regulators, insurance claims, and board review.
Include: Timeline, Root Cause Analysis, Impact Assessment, Remediation Steps, Lessons Learned."""


"""
FALCON — Threat Intelligence Agent
"I track threats heading your way."

Aggregates free threat feeds relevant to client's industry.
"""

class FalconAgent:
    AGENT_NAME = "FALCON"
    AGENT_TAGLINE = "I track threats heading your way."
    
    THREAT_FEEDS = {
        "cisa_kev": {
            "name": "CISA Known Exploited Vulnerabilities",
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "type": "json",
            "description": "Vulnerabilities actively being exploited in the wild"
        },
        "cisa_alerts": {
            "name": "CISA Cybersecurity Alerts",
            "url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
            "type": "web",
            "description": "Official US government cybersecurity advisories"
        },
        "abuse_ch_urlhaus": {
            "name": "URLhaus (abuse.ch)",
            "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            "type": "json",
            "description": "Recently reported malicious URLs"
        },
        "otx_alienvault": {
            "name": "AlienVault OTX",
            "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
            "type": "api",
            "description": "Community threat intelligence pulses"
        }
    }
    
    def check_cisa_kev(self) -> list:
        """Check CISA Known Exploited Vulnerabilities catalog."""
        import requests
        try:
            resp = requests.get(self.THREAT_FEEDS["cisa_kev"]["url"], timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                # Return most recent 10 KEVs
                vulns = data.get("vulnerabilities", [])[-10:]
                return [{"cve": v.get("cveID"), "vendor": v.get("vendorProject"),
                         "product": v.get("product"), "description": v.get("shortDescription"),
                         "date_added": v.get("dateAdded"), "due_date": v.get("dueDate")}
                        for v in vulns]
        except Exception as e:
            return [{"error": str(e)}]
        return []
    
    def filter_for_client(self, threats: list, client_tech_stack: list) -> list:
        """Filter threat feed for relevance to a specific client's technology."""
        relevant = []
        tech_keywords = [t.lower() for t in client_tech_stack]
        
        for threat in threats:
            desc = (threat.get("description", "") + threat.get("product", "")).lower()
            vendor = threat.get("vendor", "").lower()
            if any(kw in desc or kw in vendor for kw in tech_keywords):
                threat["relevance"] = "HIGH"
                relevant.append(threat)
        return relevant


"""
VANGUARD — Task Orchestration & Workflow Engine
"I make sure nothing falls through the cracks."

Coordinates workflows between all agents using n8n or custom Python.
Setup: docker pull n8nio/n8n && docker run -d -p 5678:5678 n8nio/n8n
"""

class VanguardAgent:
    AGENT_NAME = "VANGUARD"
    AGENT_TAGLINE = "I make sure nothing falls through the cracks."
    
    WORKFLOWS = {
        "new_credential_leak": {
            "trigger": "SHADOW detects new leaked credential",
            "actions": [
                {"agent": "VIGIL", "action": "Monitor this user account for 72 hours"},
                {"agent": "RECON", "action": "Run targeted scan on user's accessible systems"},
                {"agent": "GUARDIAN", "action": "Update risk register with new finding"},
                {"agent": "PHANTOM", "action": "Schedule targeted phishing test for this user"},
                {"agent": "VANGUARD", "action": "Send immediate alert to client"},
                {"agent": "VANGUARD", "action": "If password not changed in 24h → auto-force reset via M365 API"}
            ]
        },
        "critical_vulnerability": {
            "trigger": "RECON finds critical vulnerability",
            "actions": [
                {"agent": "FALCON", "action": "Check if this CVE is in CISA KEV (actively exploited)"},
                {"agent": "GUARDIAN", "action": "Update risk register"},
                {"agent": "COMPLY", "action": "Update compliance status"},
                {"agent": "VANGUARD", "action": "Send urgent alert if exploited in wild"},
            ]
        },
        "phishing_test_failure": {
            "trigger": "PHANTOM detects employee clicked phishing link",
            "actions": [
                {"agent": "PHANTOM", "action": "Show training page immediately"},
                {"agent": "VIGIL", "action": "Increase monitoring on this user for 48 hours"},
                {"agent": "GUARDIAN", "action": "Log training event for compliance evidence"},
            ]
        },
        "monthly_report_cycle": {
            "trigger": "Last business day of month",
            "actions": [
                {"agent": "SHADOW", "action": "Run full domain scan"},
                {"agent": "RECON", "action": "Run full vulnerability scan"},
                {"agent": "GUARDIAN", "action": "Compile data from all agents → generate monthly report"},
                {"agent": "COMPLY", "action": "Update compliance percentages"},
                {"agent": "VANGUARD", "action": "Email report to client contacts"},
            ]
        },
        "new_client_onboarding": {
            "trigger": "New client signs up",
            "actions": [
                {"agent": "GUARDIAN", "action": "Send onboarding questionnaire"},
                {"agent": "SHADOW", "action": "Run dark web scan on all employee emails"},
                {"agent": "RECON", "action": "Run full security assessment"},
                {"agent": "GUARDIAN", "action": "Process questionnaire → generate risk register"},
                {"agent": "GUARDIAN", "action": "Generate all required policies"},
                {"agent": "COMPLY", "action": "Map compliance status"},
                {"agent": "PHANTOM", "action": "Schedule first phishing test (Day 14)"},
                {"agent": "VIGIL", "action": "Connect M365/Google and start monitoring"},
                {"agent": "FALCON", "action": "Set up industry-specific threat feed"},
                {"agent": "VANGUARD", "action": "Populate client dashboard with all data"},
            ]
        }
    }
    
    def get_workflow(self, workflow_name: str) -> dict:
        return self.WORKFLOWS.get(workflow_name, {})
    
    def list_workflows(self) -> list:
        return [{"name": k, "trigger": v["trigger"], "steps": len(v["actions"])} 
                for k, v in self.WORKFLOWS.items()]
    
    def execute_workflow(self, workflow_name: str, context: dict) -> dict:
        """Execute a workflow (placeholder — connects to n8n in production)."""
        workflow = self.WORKFLOWS.get(workflow_name)
        if not workflow:
            return {"error": "Workflow not found"}
        
        execution_log = {
            "workflow": workflow_name,
            "triggered_at": datetime.utcnow().isoformat() + "Z",
            "context": context,
            "steps_executed": [],
            "status": "simulated"
        }
        
        for action in workflow["actions"]:
            execution_log["steps_executed"].append({
                "agent": action["agent"],
                "action": action["action"],
                "status": "queued"
            })
        
        return execution_log


# ─── DEMO ALL AGENTS ─────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  CYBERCOMPLY — ALL AGENTS STATUS")
    print("=" * 60)

    agents = [
        VigilAgent(), ComplyAgent(), BreachAgent(),
        DispatchAgent(), FalconAgent(), VanguardAgent()
    ]
    
    for agent in agents:
        print(f"\n  🟢 {agent.AGENT_NAME:12s} — {agent.AGENT_TAGLINE}")
    
    print("\n" + "=" * 60)
    
    # Demo: DISPATCH playbooks
    dispatch = DispatchAgent()
    print("\n[DISPATCH] Available Incident Response Playbooks:")
    for pb in dispatch.list_playbooks():
        print(f"  📋 {pb['name']} ({pb['severity']})")
    
    # Demo: VANGUARD workflows
    vanguard = VanguardAgent()
    print("\n[VANGUARD] Orchestration Workflows:")
    for wf in vanguard.list_workflows():
        print(f"  🔄 {wf['name']} — Trigger: {wf['trigger']} ({wf['steps']} steps)")
    
    # Demo: FALCON threat feed
    print("\n[FALCON] Checking CISA Known Exploited Vulnerabilities...")
    falcon = FalconAgent()
    kevs = falcon.check_cisa_kev()
    if kevs and not kevs[0].get("error"):
        for kev in kevs[:3]:
            print(f"  ⚠️  {kev.get('cve', 'N/A')} — {kev.get('vendor', 'N/A')} {kev.get('product', 'N/A')}")
    
    # Demo: COMPLY cross-mapping
    print("\n[COMPLY] Cross-Framework Control Mapping (IRS 4557 + NIST CSF):")
    compass = ComplyAgent()
    overlaps = compass.cross_map_controls(["irs_4557", "nist_csf_2"])
    for group, data in list(overlaps.items())[:4]:
        print(f"  🔗 {group}: {data['description']} ({len(data['controls'])} controls)")
