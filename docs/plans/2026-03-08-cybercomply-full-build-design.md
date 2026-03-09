# CyberComply Full Platform Build — Design Document

## Overview
Build a multi-tenant vCISO SaaS platform from existing agent code (4,585 lines across 8 Python files) into a production-ready application with FastAPI backend, Next.js 14 frontend, Supabase database, Stripe billing, and Docker deployment.

## Approach: Sequential 16-Session Build
Sessions execute in order, respecting dependency chain: schema → backend core → routers → services → frontend → infra → tests → polish.

## Architecture

```
Internet → Cloudflare → Nginx
  ├── cybercomply.io        → frontend:3000 (Next.js 14)
  ├── api.cybercomply.io    → backend:8000  (FastAPI)
  └── Internal: supabase, redis, gophish, n8n
```

### Directory Structure
```
cybercomply/
├── agents/              ← Existing agent files (copied, not rewritten)
├── database/            ← schema.sql + seed.sql
├── backend/
│   ├── config.py        ← Pydantic Settings
│   ├── auth.py          ← Supabase JWT verification
│   ├── database.py      ← Supabase client helpers
│   ├── models.py        ← Pydantic request/response models
│   ├── main.py          ← FastAPI app with router includes
│   ├── routers/         ← 11 route files (scan, portfolio, clients, findings, compliance, policies, tprm, monitoring, phishing, reports, billing, agents)
│   ├── services/        ← Business logic (scan, compliance, policy, report, billing, email)
│   └── tasks/           ← Celery config + scheduled jobs
├── frontend/
│   ├── app/             ← Next.js 14 App Router
│   ├── components/      ← Reusable UI (from JSX prototype)
│   └── lib/             ← API client, Supabase client, utils
├── infra/               ← nginx.conf, Caddyfile
├── tests/               ← pytest suites
├── scripts/             ← setup.sh, deploy.sh, demo_scan.py, verify_deployment.py
└── docs/                ← API.md, LAUNCH_CHECKLIST.md
```

## Session Dependency Chain
1. Database Schema → 2. Backend Core → 3-7. Routers/Services (partially parallelizable) → 8. Billing/Tasks → 9. Frontend Setup → 10-13. Frontend Pages → 14. Docker → 15. Tests → 16. Polish

## Key Decisions
- Agents copied to agents/ with adjusted imports (not rewritten)
- Brand: CyberComply (replacing DigiComply)
- digicomply-platform.jsx used as component/data reference
- Multi-tenancy via org_id + Supabase RLS
- MSP parent_org_id pattern for portfolio management
