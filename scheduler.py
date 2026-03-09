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

    # Weekly: quick scan (every Monday at 6am UTC)
    scheduler.add_job(run_weekly_scan, 'cron', day_of_week='mon', hour=6, id='weekly_scan')

    # Monthly: full report (1st of each month at 8am UTC)
    scheduler.add_job(run_monthly_reports, 'cron', day=1, hour=8, id='monthly_reports')

    scheduler.start()
    logger.info("Scheduler started: falcon(6h), shadow(daily), recon(weekly), reports(monthly)")
    return scheduler
