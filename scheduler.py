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
                narrative = ""
                try:
                    from prompt_engine import call_prompt
                    narrative = call_prompt(
                        "P56_THREAT_BRIEF",
                        client_name=client.get("company_name", ""),
                        threats=json.dumps(threats[:3], indent=2, default=str),
                        tech_stack=", ".join(client.get("tech_stack", ["general infrastructure"])),
                    )
                except Exception:
                    narrative = f"{len(threats)} new vulnerabilities identified by CISA that may affect your infrastructure."

                has_critical = any(t.get("severity", "").upper() == "CRITICAL" for t in threats)
                severity = "CRITICAL" if has_critical else "HIGH" if len(threats) > 2 else "MEDIUM"

                alert_data = {
                    "type": "threat",
                    "severity": severity,
                    "date": datetime.utcnow().isoformat(),
                    "title": f"{len(threats)} relevant CISA vulnerabilities detected",
                    "summary": f"Filtered from CISA KEV catalog for your technology stack",
                    "narrative": narrative,
                    "source": "CISA KEV",
                    "count": len(threats),
                    "threats": threats[:5],
                    "actions": [f"Patch {t.get('cve_id', 'vulnerability')}: {t.get('name', 'Update required')}" for t in threats[:3]],
                    "status": "new",
                    "emailed": False,
                }
                client_manager.save_alert(client["client_id"], alert_data)

                if severity == "CRITICAL":
                    _send_alert_email(client, alert_data)

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
                    # Generate AI narrative for the alert
                    narrative = ""
                    try:
                        from prompt_engine import call_prompt
                        narrative = call_prompt(
                            "P54_DARK_WEB_ALERT",
                            client_name=client.get("company_name", ""),
                            domain=domain,
                            exposed_count=str(result.total_exposed),
                            critical_count=str(result.critical),
                            breaches=str([b.__dict__ if hasattr(b, '__dict__') else str(b) for b in (result.breaches if hasattr(result, 'breaches') else [])][:3]),
                        )
                    except Exception:
                        narrative = f"{result.total_exposed} credential(s) found exposed on the dark web for {domain}."

                    severity = "CRITICAL" if result.critical > 0 else "HIGH" if result.high > 0 else "MEDIUM"
                    alert_data = {
                        "type": "darkweb",
                        "severity": severity,
                        "date": datetime.utcnow().isoformat(),
                        "title": f"{result.total_exposed} credential(s) exposed for {domain}",
                        "summary": f"Found in breach databases: {result.critical} critical, {result.high} high severity",
                        "narrative": narrative,
                        "domain": domain,
                        "exposed_count": result.total_exposed,
                        "critical": result.critical,
                        "high": result.high,
                        "actions": [
                            "Force password reset for all exposed accounts",
                            "Enable MFA on all affected accounts",
                            "Check for unauthorized sign-ins in the last 30 days",
                        ],
                        "status": "new",
                        "emailed": False,
                    }
                    alert_id = client_manager.save_alert(client["client_id"], alert_data)

                    # Email alert if CRITICAL or HIGH
                    if severity in ("CRITICAL", "HIGH"):
                        _send_alert_email(client, alert_data)

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


def run_breach_scan():
    """Monthly/weekly: run Nuclei vulnerability scan per client tier."""
    from agents.agents_remaining import BreachAgent
    import client_manager

    breach_agent = BreachAgent()
    clients = client_manager.list_active_clients()

    for client in clients:
        tier_config = client_manager.get_tier_config(client.get("tier", "assessment"))
        if not tier_config.get("monthly_rescan"):
            continue

        try:
            domain = client.get("domain", "")
            industry = client.get("industry", "general")
            result = breach_agent.run_nuclei_scan(domain, industry=industry)

            if result.get("status") == "complete" and result.get("total", 0) > 0:
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


def run_vigil_check():
    """Hourly/6-hourly: check M365 sign-ins + uptime per client."""
    from agents.agents_remaining import VigilAgent
    import client_manager

    vigil_agent = VigilAgent()
    clients = client_manager.list_active_clients()

    for client in clients:
        try:
            client_id = client["client_id"]
            domain = client.get("domain", "")

            m365_tenant = client.get("m365_tenant_id")
            m365_client = client.get("m365_client_id")
            m365_secret = client.get("m365_client_secret")

            anomalies = []
            if m365_tenant and m365_client and m365_secret:
                result = vigil_agent.check_m365_signin_logs(m365_tenant, m365_client, m365_secret)
                anomalies = result.get("anomalies", [])
            else:
                uptime = vigil_agent.check_uptime(domain)
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


def run_phishing_campaign():
    """Quarterly/monthly: launch phishing test per client tier."""
    from agents.phantom_agent import PhantomAgent
    import client_manager

    phantom_agent = PhantomAgent()
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

            templates = phantom_agent.get_templates_for_industry(industry)
            if not templates:
                templates = phantom_agent.get_templates_for_industry("All")
            if not templates:
                continue

            template_key = templates[0]["key"]
            campaign_name = f"{client.get('company_name', client_id)}_phishing_{date.today().isoformat()}"

            result = phantom_agent.create_campaign(campaign_name, template_key, employee_emails)

            if result.get("status") in ("launched", "prepared"):
                narrative = f"Phishing simulation launched for {len(employee_emails)} employees using '{templates[0]['name']}' template."
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
                    pass

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
            s["last_run"] = f"Last check: {now.strftime('%b %d, %H:%M UTC')}"
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


def _send_alert_email(client: dict, alert: dict):
    """Send alert email to client contact for CRITICAL/HIGH alerts."""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    contact_email = client.get("contact_email", "")
    if not contact_email:
        return

    smtp_host = os.getenv("SMTP_HOST")
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    from_email = os.getenv("SMTP_FROM", "security@cybercomply.io")

    if not smtp_host or not smtp_user or not smtp_pass:
        logger.info(f"SMTP not configured — alert email skipped for {contact_email}")
        return

    severity_icon = {"CRITICAL": "\U0001f534", "HIGH": "\U0001f7e0"}.get(alert.get("severity", ""), "\u26a0\ufe0f")
    subject = f"{severity_icon} Security Alert — {alert.get('title', 'New Finding')} | {client.get('company_name', '')}"

    actions_text = "\n".join(f"  {i+1}. {a}" for i, a in enumerate(alert.get("actions", [])))
    base_url = os.getenv("BASE_URL", "https://www.cybercomply.io")
    client_id = client.get("client_id", "")

    body = f"""Security Alert for {client.get('company_name', '')}

{alert.get('severity', 'HIGH')} — {alert.get('title', '')}

{alert.get('narrative', alert.get('summary', ''))}

Recommended Actions:
{actions_text}

View full details in your Security Command Center:
{base_url}/portal/{client_id}

— CyberComply Security Team
11 AI Agents. Always On. Always Watching.
"""

    msg = MIMEMultipart()
    msg["From"] = f"CyberComply Security <{from_email}>"
    msg["To"] = contact_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        alert["emailed"] = True
        logger.info(f"Alert email sent to {contact_email}: {alert.get('title', '')}")
    except Exception as e:
        logger.error(f"Alert email failed for {contact_email}: {e}")


def init_scheduler(app=None):
    """Initialize APScheduler with all jobs."""
    from apscheduler.schedulers.asyncio import AsyncIOScheduler

    scheduler = AsyncIOScheduler()

    # Every 6 hours: threat intel
    scheduler.add_job(run_falcon_check, 'interval', hours=6, id='falcon_check',
                      next_run_time=datetime.utcnow())

    # Daily: dark web check
    scheduler.add_job(run_shadow_check, 'interval', hours=24, id='shadow_check')

    # Every 6 hours: monitoring check
    scheduler.add_job(run_vigil_check, 'interval', hours=6, id='vigil_check')

    # Weekly: quick scan (every Monday at 6am UTC)
    scheduler.add_job(run_weekly_scan, 'cron', day_of_week='mon', hour=6, id='weekly_scan')

    # Monthly: full report (1st of each month at 8am UTC)
    scheduler.add_job(run_monthly_reports, 'cron', day=1, hour=8, id='monthly_reports')

    # Monthly 15th: vulnerability scan
    scheduler.add_job(run_breach_scan, 'cron', day=15, hour=10, id='breach_scan')

    # Quarterly: phishing campaign (1st of Jan/Apr/Jul/Oct)
    scheduler.add_job(run_phishing_campaign, 'cron', month='1,4,7,10', day=1, hour=14, id='phishing_campaign')

    scheduler.start()
    logger.info("Scheduler started: falcon(6h), vigil(6h), shadow(daily), recon(weekly), reports(monthly), breach(monthly), phishing(quarterly)")
    return scheduler
