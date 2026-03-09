# CyberComply vCISO Platform — Design Document

**Date:** 2026-03-09
**Status:** Approved
**Model:** Hybrid (client portal + monthly vCISO calls)
**Stack:** FastAPI + Jinja2 + HTMX (existing), APScheduler (new)

---

## Problem

CyberComply has a powerful backend (11 agents, 63 prompts, scan + policy generation) but delivers as a one-time assessment tool. To sell vCISO retainers at $2-5K/month, clients need an ongoing "Security Command Center" that demonstrates continuous protection — a portal with live scores, dark web alerts, compliance tracking, threat feeds, and monthly reports.

The 46K Tier 1 leads (CPA, Legal, Healthcare, Financial, SMB) are ready for outreach. The outreach strategy generates interest via scan-first cold emails. What's missing is the product behind the pitch — the thing that justifies $2-5K/month recurring revenue.

## Decisions

- **Approach:** Skin the existing engine (Approach A) — no frontend rewrite
- **Delivery model:** Hybrid — client portal for daily visibility + monthly vCISO call for strategy
- **Monitoring:** Smart narrative automation (scheduled scans, not real SOC)
- **Portal style:** Security Command Center — live score, agents, alerts, tasks, reports

## Pricing Tiers

| Feature | Assessment ($2.5-5K one-time) | vCISO Basic ($2K/mo) | vCISO Pro ($5K/mo) |
|---------|------|------|------|
| Initial scan + PDF report | Yes | Yes | Yes |
| 9 core policies | Yes | Yes | Yes |
| Client portal access | 90 days | Ongoing | Ongoing |
| Monthly rescan + report | No | Yes | Yes |
| Dark web monitoring | No | Weekly | Daily |
| Threat intel feed | No | CISA KEV | Full (4 feeds) |
| Phishing simulations | No | No | Quarterly |
| Remediation task board | No | Yes | Yes |
| Compliance tracking | Snapshot | Monthly updates | Continuous |
| Monthly vCISO call | No | 30 min | 60 min |
| Quarterly board report | No | No | Yes |

## Architecture

### 1. Client Authentication

Invite-based auth (no self-signup):

1. Operator clicks "Create Portal Access" in dashboard
2. System generates magic link, emails client
3. Client clicks link, sets password, lands in Command Center
4. JWT cookie session, 30-day expiry
5. `tier` field on client record controls feature visibility

Storage: `client_auth` entries in client's `profile.json` (hashed passwords via bcrypt). No separate user database needed for MVP — one login per client.

### 2. Client Portal — Security Command Center

**Route:** `/portal/{client_id}` (authenticated)

**Layout:**

```
┌─────────────────────────────────────────────────────────────┐
│  CYBERCOMPLY — Security Command Center                      │
│  [Company Name]                        [Score: 78/100  B+]  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ SECURITY │ │ DARK WEB │ │COMPLIANCE│ │ THREATS  │      │
│  │ SCORE    │ │ ALERTS   │ │ STATUS   │ │ BLOCKED  │      │
│  │  78/100  │ │  3 new   │ │  72%     │ │  1,247   │      │
│  │  ▲ +12   │ │  ⚠ HIGH  │ │  IRS4557 │ │ this mo  │      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
│                                                             │
│  SCORE TREND (6mo)    │  ACTIVE AGENTS (24/7)              │
│  ████████▓░  78       │  ✅ RECON — Last scan: 2h ago     │
│  ███████▓░░  71       │  ✅ SHADOW — Monitoring dark web   │
│  ██████▓░░░  64       │  ✅ FALCON — 3 new CISA alerts    │
│  █████▓░░░░  52       │  ✅ GUARDIAN — Compliance on track │
│  Jan Feb Mar Apr      │  ✅ PHANTOM — Next test: Apr 15   │
│                       │  ✅ DISPATCH — 0 active incidents  │
│                                                             │
│  REMEDIATION TASKS    │  REPORTS & POLICIES                │
│  ☐ Enable MFA (HIGH)  │  📄 March 2026 Monthly Report     │
│  ☐ Fix SPF record     │  📄 Q1 2026 Board Summary         │
│  ☑ Update SSL cert    │  📄 Initial Assessment (Feb)      │
│  ☑ Add DMARC policy   │  📄 WISP Policy v1.0              │
│                       │  📄 Incident Response Plan v1.0   │
└─────────────────────────────────────────────────────────────┘
```

**Data sources per widget:**
- Security Score + Trend → RECON scan history (score_history[] in profile.json)
- Dark Web Alerts → SHADOW breach checks (alerts/ directory)
- Compliance Status → GUARDIAN + COMPLY framework tracking
- Threats Blocked → FALCON CISA KEV feed filtered by client tech stack
- Active Agents → Scheduler last-run timestamps
- Remediation Tasks → Generated from RECON findings, stored in tasks.json
- Reports & Policies → Files in reports/ and policies/ directories

### 3. Scheduled Automation ("24/7 Monitoring")

APScheduler running inside FastAPI (async-compatible):

| Frequency | Agent | Action | Cost |
|-----------|-------|--------|------|
| Every 6 hours | FALCON | Pull CISA KEV + threat feeds, filter by client tech stack | $0 |
| Daily | SHADOW | Check breach databases for new exposures | $0 |
| Weekly | RECON | Quick scan (headers, SSL, DNS) → score delta | $0 |
| Monthly | RECON | Full deep scan | $0 |
| Monthly | CHRONICLE | Generate monthly report (P46) → PDF → email | ~$0.50 |
| Monthly | COMPLY | Compliance progress update (P57) | ~$0.25 |
| Quarterly | CHRONICLE | Board report (P47) — Pro tier only | ~$0.50 |
| Quarterly | PHANTOM | Phishing simulation — Pro tier only | $0 |
| Quarterly | GUARDIAN | Policy review cycle (P59) — Pro tier only | ~$0.25 |

**Total cost per client/month:** ~$0.50-2.00 in API calls.

**Job loop pattern:**
```python
for client in get_active_retainer_clients():
    if client.tier in allowed_tiers:
        result = agent.scan(client.domain)
        save_result(client.id, result)
        update_portal_data(client.id)
        if critical_finding(result):
            send_alert_email(client)
```

### 4. Remediation Task Board

Findings from RECON scans auto-generate tasks:

```
Finding: "Missing Content-Security-Policy header"
  → Task ID: task_001
  → Title: "Add CSP header to web server"
  → Severity: MEDIUM
  → Category: Web Security
  → Assigned to: (client's IT contact, optional)
  → Due: 30 days from detection
  → Status: open | in_progress | resolved | verified
```

**Auto-verification:** Monthly rescan checks if previously-flagged issues are fixed. If RECON no longer detects the issue → task auto-closes → score increases. Client sees measurable progress.

**Storage:** `tasks.json` per client in their data directory.

**Portal view:** Simple list grouped by status (Open → In Progress → Resolved). Not kanban — just a clean table with severity badges and status toggles.

### 5. Document Vault

```
/data/clients/{client_id}/
├── scans/           # Raw scan JSON (timestamped)
├── reports/         # PDF reports (assessment, monthly, quarterly)
├── policies/        # Generated policy PDFs (WISP, IRP, AUP, etc.)
├── alerts/          # Dark web + threat alerts (JSON)
├── tasks.json       # Remediation task board data
└── profile.json     # Client config: tier, contacts, frameworks, score_history, auth
```

Portal "Reports & Policies" tab lists all downloadable documents with dates and types.

### 6. Operator Dashboard Upgrades

Existing `/dashboard` enhanced with:

- **MRR tracker:** Sum of active retainer values
- **Scheduler status:** Last run time for each job type, any failures
- **Client management:** Tier, score trend, alert count, next action per client
- **"Create Portal Access" button:** Generate magic link for client onboarding
- **"Run Monthly Reports" button:** Manual trigger for all due reports

### 7. Agent Completion

Agents that need wiring to support the platform:

| Agent | What to Wire | Prompt |
|-------|-------------|--------|
| SHADOW | Dark web alert generation | P54 |
| CHRONICLE | Monthly report generation | P46 |
| CHRONICLE | Quarterly board report | P47 |
| COMPLY | Compliance progress updates | P57 |
| GUARDIAN | Policy review cycle | P59 |
| FALCON | Full threat feed integration (CISA Alerts, URLhaus, OTX) | — |

## What We're NOT Building

- No billing/payments — use Stripe invoicing or QuickBooks
- No chat/messaging — use Calendly + email
- No VIGIL/real SOC — scheduled automation IS the monitoring
- No BREACH/pentesting — outsource to vendors
- No VANGUARD workflow engine — APScheduler IS the orchestrator
- No multi-user client accounts — one login per client
- No white-labeling — sell direct first, MSP channel is Phase 2
- No React/SPA rewrite — Jinja2 + HTMX is sufficient

## Success Criteria

1. Client logs into portal and sees live security score, trend chart, active agents
2. Monthly report auto-generates and appears in portal + email
3. Dark web alerts appear within 24h of new breach detection
4. Remediation tasks auto-close when rescans confirm fixes
5. Operator dashboard shows MRR, all clients, scheduler health
6. End-to-end: free scan → assessment → portal access → monthly retainer delivery — all automated

## Revenue Target

- 5 clients at $3K/mo avg = $15K MRR within 90 days
- 20 clients at $3.5K/mo avg = $70K MRR within 6 months
- Platform cost: ~$50/mo (Railway) + ~$10-40/mo (API calls for all clients)
- Margin: >95%
