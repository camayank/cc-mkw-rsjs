# Wire BREACH, PHANTOM, VIGIL Agents — Design Document

**Date:** 2026-03-10
**Status:** Approved
**Depends on:** Portal UX Overhaul (completed 2026-03-10)

## Problem

Three of eleven agents are stubs: BREACH (pentesting), PHANTOM (phishing), VIGIL (monitoring). These represent the highest-value deliverables for a $20K/year retainer — clients expect vulnerability scanning, phishing tests, and real-time monitoring. Without them, the "24/7 monitoring" and "11 AI agents" narrative falls apart.

## Decisions

- **BREACH:** Nuclei binary as Python subprocess in existing Docker image ($0/mo)
- **PHANTOM:** GoPhish as separate Railway Docker service (~$8/mo)
- **VIGIL:** M365 Graph API for sign-in anomaly monitoring ($0/mo) + HTTP uptime fallback
- **Order:** BREACH → PHANTOM → VIGIL (sequential, each independent)
- **NOT building:** Full Wazuh SIEM, dedicated pentest infrastructure, real-time WebSocket alerts

## Design

### 1. BREACH Agent — Nuclei Vulnerability Scanner

**Current state:** Stub with OWASP ZAP Docker integration (doesn't work) + pentest scope template.

**Upgrade:** Replace `run_web_scan()` with `run_nuclei_scan()`:
1. Install Nuclei binary in Dockerfile (single Go binary, ~50MB)
2. Run as subprocess: `nuclei -u {target} -severity critical,high,medium -jsonl -silent`
3. Parse JSONL output → list of findings with template-id, severity, matched-at, description
4. Generate AI narrative via new `P58_VULNERABILITY_SCAN_REPORT` prompt
5. Save rich alerts to client alerts directory
6. Email CRITICAL findings via existing `_send_alert_email()`

**Scheduler:** `run_breach_scan()` — monthly (basic tier), weekly (pro tier).

**Portal:** New `/portal/{client_id}/alerts/vulns` HTMX endpoint. Expandable "Vulnerability Scan" stat card.

**Nuclei template selection by industry:**
- CPA/Financial: web-cves, misconfigurations, exposed-panels, default-logins
- Healthcare: web-cves, misconfigurations, hipaa-relevant, exposed-panels
- Legal: web-cves, misconfigurations, exposed-panels
- General: web-cves, misconfigurations, default-logins, exposures

### 2. PHANTOM Agent — GoPhish Phishing Campaigns

**Current state:** Full implementation in `phantom_agent.py` with 6 industry templates, campaign creation, metrics calculation. Just needs GoPhish running.

**Upgrade:** Wire to real GoPhish REST API:
1. Deploy GoPhish Docker image on Railway (port 3333 admin, 8080 phishing)
2. Set `GOPHISH_URL` and `GOPHISH_API_KEY` env vars
3. Wire `create_campaign()` to GoPhish API:
   - POST /api/smtp — create sending profile from SMTP env vars
   - POST /api/pages — create landing page from existing templates
   - POST /api/templates — create email template from 6 industry templates
   - POST /api/groups — create target group from employee emails
   - POST /api/campaigns — launch campaign
4. Wire `get_campaign_results()` to GoPhish API:
   - GET /api/campaigns/{id}/results — pull real click/open/submit stats
5. Generate P50 narrative from results, P51 micro-training for clickers
6. Save campaign results as alerts

**Scheduler:** `run_phishing_campaign()` — quarterly (basic), monthly (pro). Staggered across clients.

**Portal:** New `/portal/{client_id}/alerts/phishing` HTMX endpoint. "Phishing Test Results" panel.

**Operator:** `/api/operator/phishing/launch/{client_id}` — manual campaign trigger.

### 3. VIGIL Agent — M365 Sign-In Monitoring

**Current state:** Has `check_m365_signin_logs()` method returning "requires OAuth" + `get_alerts()` calling Wazuh API (not connected).

**Upgrade:** Wire to Microsoft Graph API:
1. Per-client OAuth: store `m365_tenant_id`, `m365_client_id`, `m365_client_secret` in client profile
2. Implement real `check_m365_signin_logs()`:
   - GET token from `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`
   - GET `/auditLogs/signIns?$filter=riskState eq 'atRisk' or riskLevel ne 'none'`
   - Parse: impossible travel, failed MFA, unfamiliar location, risky IP
   - Generate alert with AI narrative
3. Fallback for non-M365 clients: HTTP uptime check + SSL expiry warning
4. Replace `get_alerts()` Wazuh code with M365 sign-in anomaly retrieval

**Scheduler:** `run_vigil_check()` — hourly (pro), every 6 hours (basic).

**Portal:** New `/portal/{client_id}/alerts/monitoring` HTMX endpoint. Clickable "Active Agents" showing recent anomalies.

### 4. New Prompt

```
P58_VULNERABILITY_SCAN_REPORT
System: You are a cybersecurity analyst writing a vulnerability scan report for {client_name}.
User: Summarize these Nuclei scan findings for a non-technical executive: {findings_json}.
Include: total vulnerabilities found, critical items needing immediate action, and a 30-day remediation timeline.
Keep under 200 words.
```

### 5. Scheduler Additions

| Job | Trigger | Tier |
|-----|---------|------|
| `run_breach_scan()` | Monthly 15th + Weekly Weds (pro) | basic/pro |
| `run_phishing_campaign()` | Quarterly + Monthly (pro) | basic/pro |
| `run_vigil_check()` | Every 6h + Hourly (pro) | basic/pro |

### 6. Environment Variables

```
# GoPhish (Railway Docker service)
GOPHISH_URL=http://gophish-service:3333
GOPHISH_API_KEY=<generated on first GoPhish login>

# Nuclei (installed in main app Docker image)
# No env vars needed — binary in PATH

# M365 per-client (stored in client profile.json, not env vars)
# m365_tenant_id, m365_client_id, m365_client_secret
```

### Not Building

- Full Wazuh SIEM deployment (use M365 API instead)
- Dedicated pentest VPS (Nuclei runs in-process)
- Real-time WebSocket push (HTMX polling sufficient)
- GoPhish training content library (use P51 AI-generated training)
- Multi-tenant GoPhish (single instance, campaigns tagged by client_id)

## Success Criteria

1. `python3 -c "from agents.agents_remaining import BreachAgent; b = BreachAgent(); print(b.run_nuclei_scan('example.com'))"` → returns real vulnerability findings
2. GoPhish campaign launches via API and tracks clicks/opens
3. VIGIL detects risky M365 sign-in and generates alert
4. All three appear in portal with expandable detail panels
5. Scheduler runs automated scans per tier configuration
6. CRITICAL findings trigger email alerts to clients
