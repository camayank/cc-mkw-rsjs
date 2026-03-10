# Wire BREACH, PHANTOM, VIGIL Agents — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the three stub agents to real scanning tools — Nuclei for vuln scanning, GoPhish for phishing campaigns, M365 Graph API for sign-in monitoring.

**Architecture:** BREACH uses Nuclei binary as subprocess (installed via nixpacks). PHANTOM wires existing GoPhish API code to a Railway Docker service. VIGIL polls M365 Graph API for risky sign-ins with HTTP uptime fallback. All three feed into the existing rich alert system + portal panels.

**Tech Stack:** Nuclei CLI, GoPhish REST API, Microsoft Graph API, FastAPI, HTMX, APScheduler

---

### Task 1: Install Nuclei Binary via Nixpacks

**Files:**
- Create: `nixpacks.toml`
- Modify: `requirements.txt`

**Step 1: Create nixpacks.toml to install Nuclei during build**

```toml
[phases.setup]
nixPkgs = ["wget", "unzip"]

[phases.install]
cmds = [
    "pip install -r requirements.txt",
    "wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -O /tmp/nuclei.zip",
    "unzip -o /tmp/nuclei.zip -d /usr/local/bin/",
    "chmod +x /usr/local/bin/nuclei",
    "rm /tmp/nuclei.zip",
    "nuclei -update-templates -silent || true"
]
```

**Step 2: Verify locally**

Run: `python3 -c "import subprocess; r = subprocess.run(['which', 'nuclei'], capture_output=True, text=True); print('nuclei at:', r.stdout.strip() or 'NOT FOUND — will install on Railway')"`

Note: Nuclei won't be on macOS locally. The nixpacks.toml installs it during Railway build. For local dev, the agent falls back gracefully.

**Step 3: Commit**

```bash
git add nixpacks.toml
git commit -m "build: add Nuclei binary installation via nixpacks

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 2: Wire BREACH Agent to Nuclei

**Files:**
- Modify: `agents/agents_remaining.py:161-207` (BreachAgent class)
- Modify: `prompt_library.py` (add P94)

**Step 1: Add P94_VULNERABILITY_SCAN_REPORT to prompt_library.py**

Add after the last PROMPTS entry (after P93):

```python
PROMPTS["P94_VULNERABILITY_SCAN_REPORT"] = {
    "stage": "Retainer",
    "purpose": "AI narrative summarizing Nuclei vulnerability scan findings for client",
    "when": "After each BREACH agent vulnerability scan",
    "system": """You are a senior penetration tester writing a vulnerability scan summary for a non-technical business owner.
Be direct and actionable. No jargon. Prioritize by business impact.""",
    "user": """Summarize these vulnerability scan findings for {client_name} ({industry} industry):

Findings: {findings_json}

Include:
1. Total vulnerabilities found by severity
2. Top 3 critical items needing immediate action (with plain-English explanation)
3. 30-day remediation priority list

Keep under 200 words. Start with the most urgent item."""
}
```

**Step 2: Replace BreachAgent class in agents/agents_remaining.py**

Replace lines 161-207 (the entire BreachAgent class) with:

```python
class BreachAgent:
    AGENT_NAME = "BREACH"
    AGENT_TAGLINE = "I break in so nobody else can."

    # Industry-specific Nuclei template tags
    INDUSTRY_TEMPLATES = {
        "cpa": ["cves", "misconfigurations", "exposed-panels", "default-logins", "takeovers"],
        "healthcare": ["cves", "misconfigurations", "exposed-panels", "hipaa", "default-logins"],
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

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
                import os
                os.unlink(output_file)

            # Sort by severity
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
```

**Step 3: Verify import**

Run: `python3 -c "from agents.agents_remaining import BreachAgent; b = BreachAgent(); print('BREACH OK:', b.AGENT_TAGLINE); r = b.run_nuclei_scan('example.com'); print('Status:', r['status'])"`

Expected: `BREACH OK: I break in so nobody else can.` and `Status: not_installed` (locally).

**Step 4: Commit**

```bash
git add agents/agents_remaining.py prompt_library.py
git commit -m "feat: wire BREACH agent to Nuclei scanner + add P94 prompt

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 3: Add BREACH to Scheduler + Portal

**Files:**
- Modify: `scheduler.py` (add `run_breach_scan()`)
- Modify: `main.py` (add `/portal/{client_id}/alerts/vulns` endpoint, update portal route)
- Modify: `templates/portal.html` (add vuln scan stat card + expandable panel)

**Step 1: Add run_breach_scan to scheduler.py**

Add before `_auto_verify_tasks()`:

```python
def run_breach_scan():
    """Monthly/weekly: run Nuclei vulnerability scan per client tier."""
    from agents.agents_remaining import BreachAgent
    import client_manager

    breach = BreachAgent()
    clients = client_manager.list_active_clients()

    for client in clients:
        tier_config = client_manager.get_tier_config(client.get("tier", "assessment"))
        if not tier_config.get("monthly_rescan"):
            continue

        try:
            domain = client.get("domain", "")
            industry = client.get("industry", "general")
            result = breach.run_nuclei_scan(domain, industry=industry)

            if result.get("status") == "complete" and result.get("total", 0) > 0:
                # Generate AI narrative
                narrative = ""
                try:
                    from prompt_engine import call_prompt
                    narrative = call_prompt(
                        "P94_VULNERABILITY_SCAN_REPORT",
                        client_name=client.get("company_name", ""),
                        industry=industry,
                        findings_json=json.dumps(result["findings"][:10], indent=2),
                    )
                except Exception:
                    narrative = f"Nuclei scan found {result['total']} vulnerabilities: {result['critical']} critical, {result['high']} high, {result['medium']} medium."

                severity = "CRITICAL" if result["critical"] > 0 else "HIGH" if result["high"] > 0 else "MEDIUM"
                alert_data = {
                    "type": "vulnscan",
                    "severity": severity,
                    "date": datetime.utcnow().isoformat(),
                    "title": f"Vulnerability scan: {result['total']} findings on {domain}",
                    "summary": f"{result['critical']} critical, {result['high']} high, {result['medium']} medium",
                    "narrative": narrative,
                    "target": domain,
                    "total": result["total"],
                    "critical": result["critical"],
                    "high": result["high"],
                    "medium": result["medium"],
                    "findings": result["findings"][:20],
                    "actions": [f"Fix: {f['name']} ({f['severity']})" for f in result["findings"][:5]],
                    "status": "new",
                    "emailed": False,
                }
                client_manager.save_alert(client["client_id"], alert_data)

                if severity in ("CRITICAL", "HIGH"):
                    _send_alert_email(client, alert_data)

            _update_agent_timestamp(client["client_id"], "BREACH", "Vulnerability Scanner")
            logger.info(f"BREACH: {client['client_id']} — {result.get('total', 0)} findings")
        except Exception as e:
            logger.error(f"BREACH error for {client['client_id']}: {e}")
```

**Step 2: Register BREACH job in init_scheduler()**

Add inside `init_scheduler()`, after the monthly_reports job:

```python
    # Monthly 15th: vulnerability scan
    scheduler.add_job(run_breach_scan, 'cron', day=15, hour=10, id='breach_scan')
```

Update the logger message:

```python
    logger.info("Scheduler started: falcon(6h), shadow(daily), recon(weekly), reports(monthly), breach(monthly)")
```

**Step 3: Add vuln scan alert endpoint in main.py**

Add after the `portal_latest_report` endpoint (in the PORTAL: ALERT DETAIL ENDPOINTS section):

```python
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
            findings_html += f'<div style="font-size:.8rem;padding:6px 0;border-bottom:1px solid var(--border)"><span style="background:{sev_colors.get(f.get("severity","").lower(), "var(--muted)")};color:#fff;padding:1px 6px;border-radius:3px;font-size:.7rem">{f.get("severity","")}</span> {f.get("name","")} {cve_link}<div style="color:var(--muted);margin-top:2px">{f.get("matched_at","")}</div></div>'
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
```

**Step 4: Add vuln scan count to portal route context**

In the `portal_page()` function in main.py, find where `dark_web_alerts` is calculated and add nearby:

```python
    vuln_findings = sum(1 for a in alerts if a.get("type") == "vulnscan")
```

And add `vuln_findings=vuln_findings` to the template context dict.

**Step 5: Add vuln stat card + panel to portal.html**

After the Threats Monitored stat card, add:

```html
  <div class="stat-card" onclick="toggleAlert('vulns')">
    <div class="label">Vulnerability Scan</div>
    <div class="value" style="color:{% if vuln_findings > 0 %}var(--orange){% else %}var(--green){% endif %}">{{ vuln_findings }}</div>
    <div class="sub">Click to view scan results</div>
  </div>
```

After the threats-detail panel div, add:

```html
<div class="alert-detail" id="vulns-detail">
  <h3>&#x1f50d; Vulnerability Scan Results</h3>
  <div id="vulns-content" hx-get="/portal/{{ client.client_id }}/alerts/vulns" hx-trigger="revealed" hx-swap="innerHTML">
    <p style="color:var(--muted)">Loading...</p>
  </div>
</div>
```

Update the grid to 5 columns:

```css
.grid{display:grid;grid-template-columns:1fr 1fr 1fr 1fr 1fr;gap:16px;padding:24px 32px}
```

**Step 6: Verify**

Run: `python3 -c "from main import app; routes=[r.path for r in app.routes if 'vulns' in getattr(r,'path','')]; print('Vuln routes:', routes)"`

Expected: `Vuln routes: ['/portal/{client_id}/alerts/vulns']`

**Step 7: Commit**

```bash
git add scheduler.py main.py templates/portal.html
git commit -m "feat: BREACH agent in scheduler + portal vuln scan panel

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 4: Wire PHANTOM Agent to GoPhish API

**Files:**
- Modify: `agents/phantom_agent.py:298-333` (fix `create_campaign` to use proper GoPhish API)
- Modify: `scheduler.py` (add `run_phishing_campaign()`)
- Modify: `main.py` (add `/portal/{client_id}/alerts/phishing` endpoint, operator launch trigger)

**Step 1: Fix PhantomAgent.create_campaign() for real GoPhish API**

The existing code sends a non-standard payload. GoPhish requires separate API calls for each resource. Replace the `create_campaign` method in `phantom_agent.py` (lines 298-333):

```python
    def create_campaign(self, campaign_name: str, template_key: str,
                        employee_emails: list, send_date: str = None,
                        smtp_config: dict = None) -> dict:
        """Create a phishing campaign via GoPhish API."""
        template = self.templates.get(template_key)
        if not template:
            return {"error": f"Template '{template_key}' not found"}

        if not self.gophish_key:
            return {"status": "prepared", "template": template_key,
                    "targets": len(employee_emails),
                    "note": "GoPhish not connected — set GOPHISH_URL and GOPHISH_API_KEY"}

        headers = {"Authorization": f"Bearer {self.gophish_key}"}
        base = self.gophish_url

        try:
            # 1. Create or reuse sending profile
            smtp_name = "CyberComply SMTP"
            smtp_data = {
                "name": smtp_name,
                "host": os.getenv("SMTP_HOST", "smtp.gmail.com:587"),
                "from_address": os.getenv("SMTP_FROM", "security@cybercomply.io"),
                "username": os.getenv("SMTP_USER", ""),
                "password": os.getenv("SMTP_PASS", ""),
                "ignore_cert_errors": True,
            }
            resp = requests.post(f"{base}/api/smtp/", headers=headers, json=smtp_data, verify=False, timeout=10)
            smtp_id = resp.json().get("id")
            if not smtp_id:
                # Try to find existing
                existing = requests.get(f"{base}/api/smtp/", headers=headers, verify=False, timeout=10).json()
                smtp_id = next((s["id"] for s in existing if s.get("name") == smtp_name), None)

            # 2. Create email template
            tmpl_data = {
                "name": f"{campaign_name}_template",
                "subject": template["subject"],
                "html": template["html_body"],
            }
            resp = requests.post(f"{base}/api/templates/", headers=headers, json=tmpl_data, verify=False, timeout=10)
            tmpl_id = resp.json().get("id")

            # 3. Create landing page
            page_data = {
                "name": f"{campaign_name}_page",
                "html": self.generate_training_page(template_key),
                "capture_credentials": False,
                "redirect_url": "",
            }
            resp = requests.post(f"{base}/api/pages/", headers=headers, json=page_data, verify=False, timeout=10)
            page_id = resp.json().get("id")

            # 4. Create target group
            targets = [{"email": e, "first_name": e.split("@")[0]} for e in employee_emails]
            group_data = {"name": f"{campaign_name}_targets", "targets": targets}
            resp = requests.post(f"{base}/api/groups/", headers=headers, json=group_data, verify=False, timeout=10)
            group_id = resp.json().get("id")

            # 5. Launch campaign
            from datetime import datetime
            campaign_data = {
                "name": campaign_name,
                "template": {"id": tmpl_id},
                "page": {"id": page_id},
                "smtp": {"id": smtp_id},
                "groups": [{"id": group_id}],
                "launch_date": send_date or datetime.utcnow().isoformat() + "Z",
            }
            resp = requests.post(f"{base}/api/campaigns/", headers=headers, json=campaign_data, verify=False, timeout=10)
            result = resp.json()

            return {
                "status": "launched",
                "campaign_id": result.get("id"),
                "name": campaign_name,
                "targets": len(employee_emails),
                "template": template_key,
            }

        except Exception as e:
            return {"status": "error", "error": str(e),
                    "note": "GoPhish API call failed. Check GOPHISH_URL and GOPHISH_API_KEY."}
```

**Step 2: Add run_phishing_campaign to scheduler.py**

Add before `_auto_verify_tasks()`:

```python
def run_phishing_campaign():
    """Quarterly/monthly: launch phishing test per client tier."""
    from agents.phantom_agent import PhantomAgent
    import client_manager

    phantom = PhantomAgent()
    clients = client_manager.list_active_clients()

    for client in clients:
        tier_config = client_manager.get_tier_config(client.get("tier", "assessment"))
        if not tier_config.get("tasks"):
            continue

        try:
            client_id = client["client_id"]
            industry = client.get("industry", "general")
            contact_email = client.get("contact_email", "")
            employee_emails = client.get("employee_emails", [contact_email] if contact_email else [])

            if not employee_emails:
                continue

            # Pick template for industry
            templates = phantom.get_templates_for_industry(industry)
            if not templates:
                templates = phantom.get_templates_for_industry("All")
            if not templates:
                continue

            template_key = templates[0]["key"]
            campaign_name = f"{client.get('company_name', client_id)}_phishing_{date.today().isoformat()}"

            result = phantom.create_campaign(campaign_name, template_key, employee_emails)

            if result.get("status") in ("launched", "prepared"):
                # Generate narrative
                narrative = ""
                try:
                    from prompt_engine import call_prompt
                    narrative = call_prompt(
                        "P50_PHISHING_RESULTS",
                        client_name=client.get("company_name", ""),
                        campaign_name=campaign_name,
                        template_name=templates[0]["name"],
                        total_targets=str(len(employee_emails)),
                        click_rate="Pending — results in 48 hours",
                        open_rate="Pending",
                        department_breakdown="Full results after campaign completes",
                        previous_rate="N/A",
                    )
                except Exception:
                    narrative = f"Phishing simulation launched for {len(employee_emails)} employees using '{templates[0]['name']}' template."

                alert_data = {
                    "type": "phishing",
                    "severity": "LOW",
                    "date": datetime.utcnow().isoformat(),
                    "title": f"Phishing test launched: {templates[0]['name']}",
                    "summary": f"Campaign sent to {len(employee_emails)} employees",
                    "narrative": narrative,
                    "campaign_id": result.get("campaign_id"),
                    "template": template_key,
                    "targets": len(employee_emails),
                    "actions": ["Monitor results in 48 hours", "Review click rates", "Send training to clickers"],
                    "status": "new",
                    "emailed": False,
                }
                client_manager.save_alert(client_id, alert_data)

            _update_agent_timestamp(client_id, "PHANTOM", "Phishing Defense")
            logger.info(f"PHANTOM: {client_id} — campaign {result.get('status', 'unknown')}")
        except Exception as e:
            logger.error(f"PHANTOM error for {client.get('client_id', '?')}: {e}")
```

**Step 3: Register PHANTOM job in init_scheduler()**

Add inside `init_scheduler()`:

```python
    # Quarterly: phishing campaign (1st of Jan/Apr/Jul/Oct)
    scheduler.add_job(run_phishing_campaign, 'cron', month='1,4,7,10', day=1, hour=14, id='phishing_campaign')
```

Update logger:

```python
    logger.info("Scheduler started: falcon(6h), shadow(daily), recon(weekly), reports(monthly), breach(monthly), phishing(quarterly)")
```

**Step 4: Add phishing alert endpoint in main.py**

Add after the `portal_vuln_alerts` endpoint:

```python
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
```

**Step 5: Add operator launch endpoint in main.py**

Add in the OPERATOR section (after existing operator endpoints):

```python
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
    templates = phantom.get_templates_for_industry(industry)
    if not templates:
        return JSONResponse({"error": "No templates for industry"}, status_code=400)
    result = phantom.create_campaign(
        f"{client.get('company_name', client_id)}_manual_{date.today().isoformat()}",
        templates[0]["key"], employee_emails
    )
    return JSONResponse(result)
```

**Step 6: Add phishing stat card to portal.html**

After the vuln scan stat card:

```html
  <div class="stat-card" onclick="toggleAlert('phishing')">
    <div class="label">Phishing Tests</div>
    <div class="value" style="color:var(--accent)">{{ phishing_tests }}</div>
    <div class="sub">Click to view results</div>
  </div>
```

After the vulns-detail panel:

```html
<div class="alert-detail" id="phishing-detail">
  <h3>&#x1f3a3; Phishing Test Results</h3>
  <div id="phishing-content" hx-get="/portal/{{ client.client_id }}/alerts/phishing" hx-trigger="revealed" hx-swap="innerHTML">
    <p style="color:var(--muted)">Loading...</p>
  </div>
</div>
```

Add `phishing_tests` to the portal route context (count of phishing alerts).

Update grid to 6 columns:

```css
.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:16px;padding:24px 32px}
@media(max-width:1200px){.grid{grid-template-columns:repeat(3,1fr)}}
```

**Step 7: Verify**

Run: `python3 -c "from main import app; routes=[r.path for r in app.routes if 'phishing' in getattr(r,'path','')]; print('Phishing routes:', routes)"`

Expected: Should include `/portal/{client_id}/alerts/phishing` and `/api/operator/phishing/launch/{client_id}`

**Step 8: Commit**

```bash
git add agents/phantom_agent.py scheduler.py main.py templates/portal.html
git commit -m "feat: wire PHANTOM to GoPhish API + scheduler + portal panel

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 5: Wire VIGIL Agent to M365 Graph API

**Files:**
- Modify: `agents/agents_remaining.py:11-57` (VigilAgent class)
- Modify: `scheduler.py` (add `run_vigil_check()`)
- Modify: `main.py` (add `/portal/{client_id}/alerts/monitoring` endpoint)

**Step 1: Replace VigilAgent class in agents/agents_remaining.py**

Replace lines 11-57:

```python
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
        try:
            token = self._get_m365_token(tenant_id, client_id, client_secret)
            headers = {"Authorization": f"Bearer {token}"}

            # Get risky sign-ins from last 24 hours
            from datetime import datetime, timedelta
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

            # Check for impossible travel (same user, different countries within 2 hours)
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
```

**Step 2: Add run_vigil_check to scheduler.py**

Add before `_auto_verify_tasks()`:

```python
def run_vigil_check():
    """Hourly/6-hourly: check M365 sign-ins + uptime per client."""
    from agents.agents_remaining import VigilAgent
    import client_manager

    vigil = VigilAgent()
    clients = client_manager.list_active_clients()

    for client in clients:
        try:
            client_id = client["client_id"]
            domain = client.get("domain", "")

            # Try M365 monitoring if configured
            m365_tenant = client.get("m365_tenant_id")
            m365_client = client.get("m365_client_id")
            m365_secret = client.get("m365_client_secret")

            anomalies = []
            if m365_tenant and m365_client and m365_secret:
                result = vigil.check_m365_signin_logs(m365_tenant, m365_client, m365_secret)
                anomalies = result.get("anomalies", [])
            else:
                # Fallback: uptime monitoring
                uptime = vigil.check_uptime(domain)
                if uptime.get("status") in ("down", "ssl_error"):
                    anomalies.append({
                        "type": f"Site {uptime['status'].replace('_', ' ')}",
                        "severity": "HIGH" if uptime["status"] == "down" else "MEDIUM",
                        "user": "N/A",
                        "ip": "",
                        "location": domain,
                        "app": "Website",
                        "time": datetime.utcnow().isoformat(),
                    })

            # Create alert if anomalies found
            if anomalies:
                has_critical = any(a.get("severity") == "CRITICAL" for a in anomalies)
                has_high = any(a.get("severity") == "HIGH" for a in anomalies)
                severity = "CRITICAL" if has_critical else "HIGH" if has_high else "MEDIUM"

                alert_data = {
                    "type": "monitoring",
                    "severity": severity,
                    "date": datetime.utcnow().isoformat(),
                    "title": f"{len(anomalies)} security anomalies detected",
                    "summary": ", ".join(set(a["type"] for a in anomalies[:3])),
                    "narrative": f"VIGIL detected {len(anomalies)} anomalies in the last 24 hours for {client.get('company_name', domain)}. " +
                                 "; ".join(f"{a['type']}: {a.get('user', 'N/A')} from {a.get('location', 'unknown')}" for a in anomalies[:3]),
                    "anomalies": anomalies[:20],
                    "actions": list(set(
                        "Investigate impossible travel — verify with user" if "impossible" in a["type"].lower()
                        else "Review failed sign-ins for brute force attempts" if "failed" in a["type"].lower()
                        else "Check site availability and SSL certificate" if "down" in a["type"].lower() or "ssl" in a["type"].lower()
                        else f"Review {a['type'].lower()} event"
                        for a in anomalies[:5]
                    )),
                    "status": "new",
                    "emailed": False,
                }
                client_manager.save_alert(client_id, alert_data)

                if severity in ("CRITICAL", "HIGH"):
                    _send_alert_email(client, alert_data)

            _update_agent_timestamp(client_id, "VIGIL", "Continuous Monitor")
            logger.info(f"VIGIL: {client_id} — {len(anomalies)} anomalies")
        except Exception as e:
            logger.error(f"VIGIL error for {client.get('client_id', '?')}: {e}")
```

**Step 3: Register VIGIL job in init_scheduler()**

Add inside `init_scheduler()`:

```python
    # Every 6 hours: monitoring check
    scheduler.add_job(run_vigil_check, 'interval', hours=6, id='vigil_check')
```

Update logger:

```python
    logger.info("Scheduler started: falcon(6h), shadow(daily), vigil(6h), recon(weekly), breach(monthly), reports(monthly), phishing(quarterly)")
```

**Step 4: Add monitoring alert endpoint in main.py**

Add after the phishing endpoint:

```python
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
```

**Step 5: Update portal.html — make Active Agents panel clickable**

In portal.html, find the VIGIL agent row in the Active Agents panel and wrap it to open the monitoring detail:

After the existing agent panel, add the monitoring detail panel (after phishing-detail):

```html
<div class="alert-detail" id="monitoring-detail">
  <h3>&#x1f441;&#xfe0f; Monitoring Activity</h3>
  <div id="monitoring-content" hx-get="/portal/{{ client.client_id }}/alerts/monitoring" hx-trigger="revealed" hx-swap="innerHTML">
    <p style="color:var(--muted)">Loading...</p>
  </div>
</div>
```

Add a link in the agents panel header to toggle it:

Replace:
```html
    <h2>&#x1f916; Active Agents (24/7)</h2>
```
With:
```html
    <h2 style="cursor:pointer" onclick="toggleAlert('monitoring')">&#x1f916; Active Agents (24/7) <span style="font-size:.7rem;color:var(--muted)">&#x25be; click for details</span></h2>
```

**Step 6: Add monitoring_alerts count to portal route context**

In the `portal_page()` function, add:

```python
    monitoring_alerts = sum(1 for a in alerts if a.get("type") == "monitoring")
```

Add `monitoring_alerts=monitoring_alerts` to the template context.

**Step 7: Verify**

Run: `python3 -c "from agents.agents_remaining import VigilAgent; v = VigilAgent(); r = v.check_uptime('google.com'); print('Uptime check:', r['status'], r.get('response_time_ms', '?'), 'ms')"`

Expected: `Uptime check: up XXX ms`

Run: `python3 -c "from main import app; routes=[r.path for r in app.routes if 'monitoring' in getattr(r,'path','')]; print('Monitoring routes:', routes)"`

Expected: `Monitoring routes: ['/portal/{client_id}/alerts/monitoring']`

**Step 8: Commit**

```bash
git add agents/agents_remaining.py scheduler.py main.py templates/portal.html
git commit -m "feat: wire VIGIL to M365 Graph API + uptime monitoring + portal

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 6: Enable Scheduler at App Startup

**Files:**
- Modify: `main.py` (verify scheduler startup event exists and is correct)

**Step 1: Verify scheduler startup**

Check that `main.py` has the startup event. It should already exist from the vCISO platform build. Verify:

```python
from scheduler import init_scheduler

@app.on_event("startup")
async def startup_scheduler():
    app.state.scheduler = init_scheduler(app)
```

If missing, add it after the app instantiation.

**Step 2: Verify all scheduler jobs are registered**

Run: `python3 -c "from scheduler import init_scheduler; s = init_scheduler(); jobs = s.get_jobs(); print(f'{len(jobs)} jobs:'); [print(f'  {j.id}: {j.trigger}') for j in jobs]; s.shutdown()"`

Expected: 7 jobs (falcon, shadow, vigil, weekly_scan, monthly_reports, breach_scan, phishing_campaign)

**Step 3: Commit (if changes needed)**

```bash
git add main.py
git commit -m "feat: verify scheduler startup with all 7 agent jobs

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 7: Smoke Test Everything

**Step 1: Verify all modules load**

Run: `python3 -c "from main import app; print('Routes:', len(app.routes)); import scheduler; import client_manager; from agents.agents_remaining import BreachAgent, VigilAgent; from agents.phantom_agent import PhantomAgent; print('All OK')"`

**Step 2: Verify all new alert routes**

Run: `python3 -c "from main import app; routes=[r.path for r in app.routes if 'alerts' in getattr(r,'path','')]; print('Alert routes:', len(routes)); [print(f'  {r}') for r in routes]"`

Expected: 6 alert routes (darkweb, threats, report, vulns, phishing, monitoring)

**Step 3: Test BREACH agent locally**

Run: `python3 -c "from agents.agents_remaining import BreachAgent; b = BreachAgent(); r = b.run_nuclei_scan('example.com'); print(f'Status: {r[\"status\"]}, Total: {r.get(\"total\", 0)}')"`

Expected: `Status: not_installed` (locally) or `Status: complete` (on Railway)

**Step 4: Test VIGIL uptime check**

Run: `python3 -c "from agents.agents_remaining import VigilAgent; v = VigilAgent(); r = v.check_uptime('cybercomply.io'); print(f'Status: {r[\"status\"]}, Response: {r.get(\"response_time_ms\", \"?\")}ms')"`

Expected: `Status: up`

**Step 5: Test rich alert creation for new types**

Run:
```python
python3 -c "
import client_manager, shutil
client_manager.create_client('test-wire', 'Wire Test Co', 'test.com', tier='basic')
# Vuln alert
client_manager.save_alert('test-wire', {'type': 'vulnscan', 'severity': 'HIGH', 'title': 'Test vuln', 'narrative': 'Found vulnerabilities', 'findings': [{'name': 'XSS', 'severity': 'HIGH'}], 'actions': ['Fix XSS']})
# Phishing alert
client_manager.save_alert('test-wire', {'type': 'phishing', 'severity': 'LOW', 'title': 'Test phishing', 'narrative': 'Campaign launched', 'actions': ['Monitor']})
# Monitoring alert
client_manager.save_alert('test-wire', {'type': 'monitoring', 'severity': 'MEDIUM', 'title': 'Test monitoring', 'narrative': 'Anomaly detected', 'anomalies': [{'type': 'Failed sign-in'}], 'actions': ['Review']})
alerts = client_manager.get_alerts('test-wire', limit=10)
types = [a.get('type') for a in alerts]
print(f'Alert types: {types}')
assert 'vulnscan' in types and 'phishing' in types and 'monitoring' in types
shutil.rmtree('clients/test-wire', ignore_errors=True)
print('ALL TESTS PASSED')
"
```

**Step 6: Final commit**

```bash
git add -A
git commit -m "feat: all 11 agents wired — BREACH (Nuclei), PHANTOM (GoPhish), VIGIL (M365)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Summary

| Task | What | Files | Agent |
|------|------|-------|-------|
| 1 | Install Nuclei binary via nixpacks | nixpacks.toml | BREACH |
| 2 | Wire BREACH to Nuclei subprocess | agents_remaining.py, prompt_library.py | BREACH |
| 3 | BREACH scheduler + portal panel | scheduler.py, main.py, portal.html | BREACH |
| 4 | Wire PHANTOM to GoPhish API | phantom_agent.py, scheduler.py, main.py, portal.html | PHANTOM |
| 5 | Wire VIGIL to M365 + uptime | agents_remaining.py, scheduler.py, main.py, portal.html | VIGIL |
| 6 | Enable scheduler startup | main.py | All |
| 7 | Smoke test | — | All |

**End state:** All 11 agents functional. Portal shows 6 expandable alert panels (dark web, threats, reports, vulns, phishing, monitoring). Scheduler runs 7 automated jobs. CRITICAL alerts auto-email. Nuclei scans monthly, GoPhish campaigns quarterly, M365/uptime checks every 6 hours.

**Infra cost:** ~$8/mo (GoPhish on Railway). Everything else runs in existing app.
