# CyberComply

**Premium advisor-led cyber compliance and security validation portal.**

Issued by **DigComply Solutions Private Limited** (in association with **CA4CPA Global LLC**). CyberComply is the technology that delivers the service.

---

## What this product is

A managed-service portal for high-value regulated SMB and mid-market clients. The product is **advisor-led**: every customer-facing deliverable (report, policy, finding, evidence package, validation result) flows through a named security advisor before reaching the customer.

The product **does not** offer:
- Self-serve freemium portal access
- Guaranteed compliance certification
- Guaranteed breach prevention
- Active penetration testing without a separately-signed authorization
- 24/7 monitoring claims unless the integrations and scheduler are actually configured

The product **does** offer:
- A free external scan as a lead magnet (DNS, SSL, headers, email auth — passive only, with SSRF guards)
- Paid Diagnostic Review ($5K–$10K, one-time) and three annual retainers (Essentials $24K, Professional $48K, Enterprise+ from $96K)
- A managed customer portal with score, action items, service coverage, alerts, reports, policies, evidence vault, security validation, advisor profile, and plan scope
- An operator delivery console with per-client risk signals and filter views
- A unified advisor-review record across reports, policies, monthly summaries, evidence packages, validation findings, task verification, and audit packages
- An audit log covering every sensitive action, exportable as JSON or CSV and bundled into the customer audit package

## Required reading before launching to a real customer

1. `.env.example` — every required and optional environment variable, with short notes on what happens when an integration is absent (graceful degradation; the UI surfaces "Pending setup" rather than claiming the service is active).
2. `legal_authorization.py` — the gate that blocks any active security validation run without signed MSA / SOW / NDA / DPA, authorized representative, ownership confirmation, scope, testing window, emergency contact, and acknowledgments.
3. `advisor_review.py` — the single source of truth for "Advisor reviewed" claims. The UI never renders the badge without a signed-off record.
4. `sell_readiness.py` and `tests/test_sell_readiness.py` — the eleven invariants the product must hold to be safe to sell. Run these before every release.

## Operator first-time setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# edit .env — set DATA_DIR, JWT_SECRET, DASHBOARD_PASSWORD, BASE_URL,
#             RESET_TOKEN_SECRET at minimum

# 3. Run the API
uvicorn main:app --port 8000

# 4. Set up operator MFA (mandatory before going live)
curl -X POST "http://localhost:8000/api/operator/mfa/setup-secret?password=<DASHBOARD_PASSWORD>"
# copy the returned `secret` to OPERATOR_MFA_SECRET in .env, add it to
# your authenticator app, then restart the service to enforce MFA.

# 5. Run the test suite
python -m pytest tests/ -q

# 6. Run the sell-readiness gate before each release
python -m pytest tests/test_sell_readiness.py -v
```

## Customer onboarding flow

```
Public free scan → Lead capture
  ↓
Sales-led qualification (/qualify)
  ↓
qualification.evaluate() classifies into:
  qualified | needs_review | disqualified | waitlist
  ↓
Operator creates client in /dashboard
  ↓
Operator sends magic-link setup email
  ↓
Client signs MSA / SOW / NDA / DPA out-of-band
  ↓
Operator records signatures in /api/operator/clients/{cid}/legal-authorization
  ↓
For Professional/Enterprise+: operator scopes active-validation
  authorization (targets, exclusions, window, contact, rate limits)
  ↓
Customer signs the active-validation scope via portal
  ↓
Operator counter-approves
  ↓
Customer accesses portal at /portal/{client_id}
```

Any active security validation, scan, or pentest run cannot start without
an `approved` active-validation authorization on file. This is enforced
server-side in `legal_authorization.authorization_gate()` and
`security_validation.start_engagement()`.

## Advisor delivery flow

```
System produces deliverable (report, policy, finding, etc.)
  ↓
Advisor reviews via /api/operator/clients/{cid}/reviews/{subject_key}
  ↓
Advisor sets review_status=approved with reviewed_by, reviewed_on,
sign_off_timestamp (server stamps timestamp if missing)
  ↓
The advisor-reviewed badge appears in the customer portal,
along with the client_facing_recommendation
  ↓
Internal_operator_notes are NEVER shown to the customer
```

## Audit log

Every sensitive action is recorded to `clients/{cid}/audit.json` and
`audit/global.json` with actor, role, client_id, action, timestamp, IP,
user-agent, before/after delta, and metadata:

- login / logout / failed login / operator login
- document download / audit package download / evidence upload
- task status change / task verify / task reject / task defer
- advisor review create/update
- authorization approve / revoke
- scan start/stop / security validation start/stop/complete
- invoice create / plan change / client profile update

Exports:
- `GET /api/operator/audit-log?client_id=&action=&since=&until=&format=json|csv`
- `GET /api/operator/audit-log/{cid}/export?format=csv`
- `GET /api/portal/{cid}/audit-log` (customer view of own stream)
- Bundled as `audit_log.json` + `audit_log.csv` into the audit package ZIP

## Backup / restore

The product is file-backed under `DATA_DIR`:

```
DATA_DIR/
├── clients/{client_id}/
│   ├── profile.json
│   ├── tasks.json
│   ├── reviews.json
│   ├── legal_authorization.json
│   ├── authorization_audit.json
│   ├── audit.json
│   ├── reports/
│   ├── policies/
│   ├── scans/
│   ├── alerts/
│   ├── security_validations/
│   └── communications/
├── audit/
│   └── global.json
├── qualifications/
├── leads.json
└── client-deliverables/
```

For production:

1. Mount `DATA_DIR` on a persistent volume (Railway volume, EBS, etc.).
2. Schedule daily backups: `tar czf cybercomply-$(date +%Y%m%d).tar.gz $DATA_DIR`.
3. Test restore quarterly. Restore is a tar extraction; no DB migrations.
4. Keep at least 90 days of audit-log archives off-site.

## Manual business / legal steps that live OUTSIDE this codebase

These cannot be automated and must be completed by the operator before
the first paying customer:

1. **Legal entity setup** — DigComply Solutions Private Limited registered with relevant tax authorities. Sales contracts and invoices must originate from this legal entity.
2. **MSA / SOW / NDA / DPA templates** — drafted with qualified counsel for the jurisdictions you intend to sell into. The portal records signatures; the templates themselves live in your DocuSign / contract-management system.
3. **Insurance** — Professional liability + Cyber liability insurance, with the policy limits matching the engagement values you'll be quoting.
4. **Privacy notices** — privacy policy hosted at a stable URL; cookie banner if marketing in EU.
5. **Operator MFA seed** — one-time setup; secret never leaves the operator's authenticator app + the `OPERATOR_MFA_SECRET` env var.
6. **Stripe account** — connected to the same legal entity; webhook endpoint set to `/api/webhooks/stripe`.
7. **Per-customer MSA / SOW / authorization signing** — out-of-band, recorded in the legal-authorization model, before any active validation runs.
8. **Advisor onboarding** — named advisors must be assigned to clients; `advisor_name` is the metadata field that drives the customer-portal advisor card.
9. **Apex / Pensar account** — if running active validation, the operator must have a Pensar Apex license and the binary on the runner's PATH.
10. **OFAC / geo screening** — qualification module already filters Tier-1/Tier-2 markets and blocks sanctioned countries; revisit annually.

## Test suite

```bash
# Run everything (484 tests across all surfaces)
python -m pytest tests/ -q

# Run just the launch gate
python -m pytest tests/test_sell_readiness.py -v

# Run the SSRF / public-scan guard tests
python -m pytest tests/test_ssrf_guard.py -v
```

## License & attribution

Proprietary. © DigComply Solutions Private Limited (in association with CA4CPA Global LLC).
