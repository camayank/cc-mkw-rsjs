# CyberComply Full Platform Build — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a production-ready multi-tenant vCISO SaaS platform from existing agent code (4,585 lines) into a full-stack application with FastAPI backend, Next.js 14 frontend, Supabase database, Stripe billing, and Docker deployment.

**Architecture:** Existing agents are copied to `agents/` and wrapped by a FastAPI backend with Supabase for persistence and auth. Next.js 14 frontend consumes the API. Docker Compose orchestrates all services. Multi-tenancy via org_id + RLS.

**Tech Stack:** Python 3.11 / FastAPI / Supabase / Celery+Redis / Next.js 14 / TypeScript / Tailwind+shadcn / Stripe / SendGrid / Docker

---

## Task 1: Project Structure & Agent Migration

**Files:**
- Create: `agents/__init__.py`
- Copy: existing agent files → `agents/` (with adjusted imports)
- Create: `.cursorrules` (from master prompt Section A)
- Create: `.env.template`

**Steps:**

1. Create directory structure:
```bash
mkdir -p agents backend/routers backend/services backend/tasks frontend database tests scripts docs infra
```

2. Copy agent files to `agents/`:
- `spectre_agent.py` → `agents/spectre_agent.py`
- `archer_agent.py` → `agents/archer_agent.py`
- `forge_agent.py` → `agents/forge_agent.py`
- `mirage_agent.py` → `agents/mirage_agent.py`
- `agents_remaining.py` → `agents/agents_remaining.py`
- `report_generator.py` → `agents/report_generator.py`

3. Create `agents/__init__.py` that re-exports all agent classes:
```python
from agents.shadow_agent import ShadowAgent
from agents.recon_agent import ReconAgent
from agents.guardian_agent import GuardianAgent
from agents.phantom_agent import PhantomAgent
from agents.agents_remaining import (
    VigilAgent, ComplyAgent, BreachAgent,
    DispatchAgent, FalconAgent, VanguardAgent
)
```

4. Fix internal imports in agents:
- `agents_remaining.py` line 72: `from forge.forge_agent import FRAMEWORKS` → `from agents.guardian_agent import FRAMEWORKS`
- `report_generator.py`: uses reportlab (no internal imports to fix)

5. Create `.env.template` from master prompt Section C.

6. Rename branding: DigiComply → CyberComply in agent taglines (search & replace).

**Verify:** `python -c "from agents import ShadowAgent, ReconAgent, GuardianAgent, PhantomAgent, VigilAgent, ComplyAgent, BreachAgent, DispatchAgent, FalconAgent, VanguardAgent; print('All 10 agents imported')"` succeeds.

---

## Task 2: Database Schema (Session 1)

**Files:**
- Create: `database/schema.sql`
- Create: `database/seed.sql`

**Steps:**

1. Write `database/schema.sql` with all tables from the master prompt DATABASE SCHEMA section:
   - `updated_at` trigger function
   - 18 tables: organizations, users, subscriptions, scans, findings, questionnaire_responses, compliance_frameworks, compliance_controls, evidence_vault, cross_framework_mappings, policies, vendors, vendor_assessments, alerts, incidents, phishing_campaigns, tasks, agent_logs, reports, leads
   - Every table: `id uuid DEFAULT gen_random_uuid() PRIMARY KEY`, `created_at timestamptz DEFAULT now()`, `updated_at timestamptz DEFAULT now()`
   - Foreign keys with ON DELETE CASCADE for org_id references
   - Add `parent_org_id uuid REFERENCES organizations(id)` to organizations table (MSP→client relationship)
   - Add `branding jsonb DEFAULT '{}'` to organizations (white-label)
   - RLS policies: users see own org + child orgs; leads: service role only; cross_framework_mappings: public read
   - Indexes on: org_id (every table), domain (scans, leads), severity (findings, alerts), status (findings, tasks, vendors), framework_key, created_at (scans, alerts, agent_logs)

2. Write `database/seed.sql`:
   - 10 compliance framework definitions with real control counts
   - 20+ cross_framework_mappings covering: Access Control, Encryption, Incident Response, Risk Assessment, Vendor Management, Logging & Monitoring, Data Classification, Business Continuity, Security Awareness, Change Management
   - Each mapping: control_area, nist_csf_control, soc2_control, iso27001_control, hipaa_control, pci_dss_control, irs_4557_control, ftc_safeguards_control

**Verify:** SQL is syntactically valid (can paste into Supabase SQL editor).

---

## Task 3: Backend Core (Session 2)

**Files:**
- Create: `backend/__init__.py`
- Create: `backend/config.py`
- Create: `backend/database.py`
- Create: `backend/auth.py`
- Create: `backend/models.py`
- Create: `backend/main.py`
- Create: `backend/requirements.txt`

**Steps:**

1. `backend/config.py` — Pydantic Settings class:
```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    supabase_url: str
    supabase_anon_key: str
    supabase_service_key: str
    anthropic_api_key: str
    stripe_secret_key: str
    stripe_webhook_secret: str
    stripe_price_basic: str = ""
    stripe_price_pro: str = ""
    stripe_price_enterprise: str = ""
    sendgrid_api_key: str = ""
    from_email: str = "security@cybercomply.io"
    hibp_api_key: str = ""
    gophish_url: str = "http://gophish:3333"
    gophish_api_key: str = ""
    wazuh_url: str = "https://wazuh:55000"
    wazuh_user: str = "wazuh"
    wazuh_pass: str = "wazuh"
    n8n_url: str = "http://n8n:5678"
    n8n_api_key: str = ""
    redis_url: str = "redis://redis:6379/0"
    app_url: str = "https://cybercomply.io"
    api_url: str = "https://api.cybercomply.io"
    app_secret: str = ""

    class Config:
        env_file = ".env"
```

2. `backend/database.py` — Supabase client helpers:
   - `get_supabase_client()` → anon key client (for user-context queries)
   - `get_service_client()` → service role client (background jobs, lead capture)

3. `backend/auth.py` — FastAPI dependency:
   - Extract Bearer JWT from Authorization header
   - Verify via Supabase JWKS (`{supabase_url}/auth/v1/.well-known/jwks.json`)
   - Cache JWKS with 1hr TTL
   - Return `{"id": str, "email": str, "org_id": str, "role": str}`
   - Raise 401 on failure

4. `backend/models.py` — Pydantic v2 models for all request/response types:
   - `ApiResponse[T]` generic wrapper: `{success: bool, data: T | None, error: str | None}`
   - `ScanRequest`, `ScanResponse`, `FreeScanRequest` (adds email, company_name)
   - `Finding`, `Policy`, `Vendor`, `Alert`, `Task`, `Report`, `Incident`
   - `PortfolioClient`, `PortfolioStats`
   - `ComplianceFramework`, `ComplianceControl`, `CrossFrameworkMap`
   - `PaginatedResponse[T]`
   - `CreateClientRequest`, `UpdateFindingRequest`, `GeneratePolicyRequest`
   - `VendorAssessment`, `PhishingCampaign`, `GenerateReportRequest`

5. `backend/main.py` — FastAPI app:
   - Include all routers with prefixes
   - CORS middleware (configurable origins)
   - Exception handlers (400, 401, 403, 404, 500)
   - Health check: `GET /` → `{status: "ok", agents: 10, version: "1.0.0"}`

6. `backend/requirements.txt` with pinned versions:
   - fastapi, uvicorn, pydantic, pydantic-settings
   - supabase, python-jose[cryptography], httpx
   - anthropic, stripe, sendgrid
   - celery, redis
   - dnspython, requests, python-nmap
   - reportlab, jinja2
   - python-dotenv, python-multipart

**Verify:** `cd backend && python -c "from main import app; print('FastAPI app created')"` succeeds.

---

## Task 4: Scan & Lead Capture Router (Session 3)

**Files:**
- Create: `backend/services/scan_service.py`
- Create: `backend/routers/scan.py`

**Steps:**

1. `backend/services/scan_service.py`:
   - `async run_free_scan(domain: str) → ScanResponse`: runs ReconAgent.scan() + ShadowAgent (domain-only check), combines results
   - `async run_full_scan(org_id: str, domain: str) → ScanResponse`: same + saves to scans/findings tables, updates compliance
   - Import agents from `agents` package

2. `backend/routers/scan.py`:
   - `POST /api/scan/free` (no auth) — run free scan, save lead, return results. Rate limit via in-memory dict (5/hr per IP).
   - `GET /api/scan/free/{lead_id}` (no auth) — retrieve saved free scan
   - `POST /api/clients/{org_id}/scan` (auth) — full scan with persistence
   - `GET /api/clients/{org_id}/scans` (auth) — scan history with pagination

---

## Task 5: Portfolio & Client Routers (Session 4)

**Files:**
- Create: `backend/routers/portfolio.py`
- Create: `backend/routers/clients.py`

**Steps:**

1. `backend/routers/portfolio.py`:
   - `GET /api/portfolio` — all clients for MSP org (parent_org_id = user's org_id)
   - `GET /api/portfolio/stats` — aggregate KPIs

2. `backend/routers/clients.py`:
   - `GET /api/clients/{org_id}` — full client detail
   - `POST /api/clients` — create sub-org (MSP creates client)
   - `PATCH /api/clients/{org_id}` — update
   - `DELETE /api/clients/{org_id}` — soft delete (archived=true)

---

## Task 6: Findings & Compliance Routers (Session 5)

**Files:**
- Create: `backend/routers/findings.py`
- Create: `backend/routers/compliance.py`
- Create: `backend/services/compliance_service.py`

**Steps:**

1. `backend/routers/findings.py`:
   - `GET /api/clients/{org_id}/findings` — with filters (severity, agent, status, framework, pagination)
   - `PATCH /api/findings/{id}` — update status, assign
   - `GET /api/clients/{org_id}/findings/summary` — counts + 6-month trend

2. `backend/services/compliance_service.py`:
   - `calculate_compliance(org_id, framework_key)` — score based on controls met
   - `get_cross_framework_map(framework_keys)` — uses ComplyAgent
   - `update_compliance_from_scan(org_id, scan_results)` — auto-update control statuses

3. `backend/routers/compliance.py`:
   - `GET /api/clients/{org_id}/compliance` — all frameworks with scores
   - `GET /api/clients/{org_id}/compliance/{framework}` — control-by-control
   - `GET /api/clients/{org_id}/compliance/cross-map` — cross-framework mapping
   - `POST /api/clients/{org_id}/evidence` — upload evidence to Supabase Storage
   - `GET /api/clients/{org_id}/evidence` — list evidence files

---

## Task 7: Policy & TPRM Routers (Session 6)

**Files:**
- Create: `backend/routers/policies.py`
- Create: `backend/services/policy_service.py`
- Create: `backend/routers/tprm.py`

**Steps:**

1. `backend/services/policy_service.py`:
   - `generate_policy(org_id, policy_type, custom_instructions)` — calls GuardianAgent + Anthropic Claude API
   - Policy types: wisp, incident_response, acceptable_use, access_control, data_classification, vendor_management, remote_work, bcp, risk_register

2. `backend/routers/policies.py`:
   - `GET /api/clients/{org_id}/policies` — list
   - `POST /api/clients/{org_id}/policies/generate` — AI generate
   - `GET /api/policies/{id}` — get content
   - `PATCH /api/policies/{id}` — update status/content
   - `GET /api/policies/{id}/download` — PDF download

3. `backend/routers/tprm.py`:
   - `GET /api/clients/{org_id}/vendors` — list with risk scores
   - `POST /api/clients/{org_id}/vendors` — add vendor
   - `POST /api/vendors/{id}/assess` — run AI assessment (ARCHER + SPECTRE + FALCON)
   - `GET /api/vendors/{id}/assessment` — latest assessment
   - `GET /api/clients/{org_id}/vendors/summary` — TPRM KPIs

---

## Task 8: Monitoring, Phishing, Reports, Agents Routers (Session 7)

**Files:**
- Create: `backend/routers/monitoring.py`
- Create: `backend/routers/phishing.py`
- Create: `backend/routers/reports.py`
- Create: `backend/routers/agents.py`
- Create: `backend/services/report_service.py`

**Steps:**

1. `backend/routers/monitoring.py`:
   - `GET /api/clients/{org_id}/alerts` — from VigilAgent
   - `PATCH /api/alerts/{id}` — acknowledge/resolve
   - `GET /api/clients/{org_id}/incidents` — incident list
   - `POST /api/clients/{org_id}/incidents` — create from alert (DispatchAgent playbook)

2. `backend/routers/phishing.py`:
   - `GET /api/phishing/templates` — from PhantomAgent
   - `POST /api/clients/{org_id}/phishing/campaigns` — launch
   - `GET /api/clients/{org_id}/phishing/campaigns` — history
   - `GET /api/phishing/campaigns/{id}/results` — results

3. `backend/services/report_service.py`:
   - `generate_monthly_report(org_id)` — compile data, use report_generator, upload to Supabase Storage

4. `backend/routers/reports.py`:
   - `GET /api/clients/{org_id}/reports` — archive
   - `POST /api/clients/{org_id}/reports/generate` — generate now
   - `GET /api/reports/{id}/download` — download PDF

5. `backend/routers/agents.py`:
   - `GET /api/agents/status` — health check for all 10
   - `GET /api/agents/{agent_id}/logs` — activity log

---

## Task 9: Billing & Scheduled Tasks (Session 8)

**Files:**
- Create: `backend/routers/billing.py`
- Create: `backend/services/billing_service.py`
- Create: `backend/services/email_service.py`
- Create: `backend/tasks/celery_app.py`
- Create: `backend/tasks/scheduled_scans.py`
- Create: `backend/tasks/monthly_reports.py`

**Steps:**

1. `backend/services/billing_service.py` — Stripe checkout, webhook handling
2. `backend/routers/billing.py` — checkout, webhook, portal endpoints
3. `backend/services/email_service.py` — SendGrid: scan results, alerts, monthly report, welcome
4. `backend/tasks/celery_app.py` — Celery + Redis config with beat schedule
5. `backend/tasks/scheduled_scans.py` — weekly scans, daily dark web, daily threat intel
6. `backend/tasks/monthly_reports.py` — monthly PDF generation for all active orgs

---

## Task 10: Frontend Setup & Landing Page (Session 9)

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/next.config.js`
- Create: `frontend/tailwind.config.ts`
- Create: `frontend/tsconfig.json`
- Create: `frontend/app/layout.tsx`
- Create: `frontend/app/globals.css`
- Create: `frontend/app/page.tsx` (landing page)
- Create: `frontend/app/scan/[id]/page.tsx` (public scan results)
- Create: `frontend/lib/api.ts`
- Create: `frontend/lib/supabase.ts`
- Create: `frontend/lib/utils.ts`
- Create: `frontend/components/ScanTool.tsx`

**Steps:**

1. Initialize Next.js 14 with App Router, TypeScript strict, Tailwind CSS
2. Custom tailwind config with CyberComply brand colors from master prompt
3. Root layout: dark theme, JetBrains Mono + Plus Jakarta Sans fonts
4. `lib/api.ts` — typed fetch wrapper with JWT auto-attach
5. `lib/supabase.ts` — Supabase browser client
6. `lib/utils.ts` — getScoreColor, getGradeColor, getSeverityColor, formatCurrency, cn
7. Landing page with: hero, interactive scan tool (real API call), 10 agent cards, how it works, pricing, industry targeting, CTA
8. Scan results page: CircularScore, findings list, breach details, CTA

**Design reference:** Use `digicomply-platform.jsx` for component patterns, sample data shapes, color scheme, and layout concepts.

---

## Task 11: Dashboard Layout & Portfolio (Session 10)

**Files:**
- Create: `frontend/app/dashboard/layout.tsx`
- Create: `frontend/app/dashboard/page.tsx`
- Create: `frontend/components/Sidebar.tsx`
- Create: `frontend/components/CircularScore.tsx`
- Create: `frontend/components/Sparkline.tsx`
- Create: `frontend/components/Badge.tsx`
- Create: `frontend/components/ProgressBar.tsx`
- Create: `frontend/components/StatCard.tsx`

**Steps:**

1. Dashboard layout with sidebar nav, auth check, client selector
2. Sidebar: nav items with lucide-react icons, active state, agent status dots
3. Portfolio page: KPI row, client table (sorted by worst score), revenue breakdown
4. Reusable components: CircularScore (SVG ring), Sparkline (inline chart), Badge, ProgressBar, StatCard
5. All components: dark theme, rgba surfaces, JetBrains Mono for numbers

---

## Task 12: Client Detail & Findings Pages (Session 11)

**Files:**
- Create: `frontend/app/dashboard/clients/[id]/page.tsx`
- Create: `frontend/app/dashboard/clients/[id]/findings/page.tsx`
- Create: `frontend/components/FindingRow.tsx`

**Steps:**

1. Client overview: header, score, KPI grid, framework cards, agent activity, recent findings
2. Findings page: filter bar, expandable finding cards with severity/remediation/framework, summary bar
3. FindingRow component: severity badge, title, agent badge, status, remediation box, actions

---

## Task 13: Compliance, TPRM, Policies Pages (Session 12)

**Files:**
- Create: `frontend/app/dashboard/clients/[id]/compliance/page.tsx`
- Create: `frontend/app/dashboard/clients/[id]/vendors/page.tsx`
- Create: `frontend/app/dashboard/clients/[id]/policies/page.tsx`
- Create: `frontend/components/ComplianceFrameworkCard.tsx`
- Create: `frontend/components/VendorTable.tsx`
- Create: `frontend/components/PolicyCard.tsx`

**Steps:**

1. Compliance page: framework cards with scores, cross-framework mapping table, evidence vault
2. Vendors page: TPRM stats, vendor table, add/assess modals, risk detail
3. Policies page: generate button, policy list, detail view, status workflow

---

## Task 14: Agents View, Reports, Settings, Auth (Session 13)

**Files:**
- Create: `frontend/app/dashboard/agents/page.tsx`
- Create: `frontend/app/dashboard/clients/[id]/reports/page.tsx`
- Create: `frontend/app/dashboard/settings/page.tsx`
- Create: `frontend/app/onboard/page.tsx`
- Create: `frontend/app/login/page.tsx`
- Create: `frontend/app/signup/page.tsx`

**Steps:**

1. Agents page: 10 agent cards in 2-col grid, status indicators, activity sparklines, 24h task count
2. Reports page: report type grid, generate/download buttons
3. Settings page: org settings, white-label branding, user management, billing, integrations, API keys
4. Onboarding wizard: 5 steps (company → connect → questionnaire → frameworks → dashboard ready)
5. Login/signup: Supabase Auth UI, dark theme, Google/Microsoft social login

---

## Task 15: Docker & Infrastructure (Session 14)

**Files:**
- Create: `docker-compose.yml`
- Create: `backend/Dockerfile`
- Create: `frontend/Dockerfile`
- Create: `infra/nginx.conf`
- Create: `infra/Caddyfile`
- Create: `Makefile`
- Create: `deploy.sh`

**Steps:**

1. docker-compose.yml: frontend, backend, redis, celery-worker, celery-beat, gophish, n8n
2. Backend Dockerfile: Python 3.11-slim, nmap binary, pip install
3. Frontend Dockerfile: Node 20-alpine, npm install, next build, next start
4. nginx.conf: reverse proxy, SSL termination, security headers, rate limiting
5. Makefile: dev, build, deploy, logs, migrate, seed commands
6. deploy.sh: SSH, git pull, docker compose build + up, health check

---

## Task 16: Tests & Verification (Session 15)

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `tests/test_scan.py`
- Create: `tests/test_agents.py`
- Create: `tests/test_api.py`
- Create: `scripts/verify_deployment.py`
- Create: `scripts/demo_scan.py`

**Steps:**

1. pytest fixtures: test client, mock Supabase, mock agents
2. Test free scan flow, agent imports, API endpoints
3. Deployment verification script
4. Demo scan CLI script

---

## Task 17: Documentation & Launch Checklist (Session 16)

**Files:**
- Create: `README.md`
- Create: `.env.example`
- Create: `docs/API.md`
- Create: `scripts/setup.sh`
- Create: `LAUNCH_CHECKLIST.md`

**Steps:**

1. Professional README with features, quick start, architecture diagram
2. Complete API documentation with curl examples
3. Setup script for first-time deployment
4. Launch checklist with all pre-launch verification items
