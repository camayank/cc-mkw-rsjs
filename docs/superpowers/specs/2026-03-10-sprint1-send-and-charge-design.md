# Sprint 1: Can Send & Charge — Design Spec

**Goal:** Turn the existing delivery pipeline into an automated revenue machine by adding email sending, Stripe invoicing, security hardening, and batch outreach automation.

**Duration:** 2 weeks
**Context:** CyberComply has 52 working API endpoints, 93 AI prompts, a full delivery CLI, 5-email sequence generator, and client portal. The only gaps blocking revenue are: emails don't send, payments aren't collected, and security has 4 known issues.

**Success criteria:**
- Batch scan 20 domains → auto-send Day 0 cold emails → schedule Day 3/7/14/21 follow-ups
- Send Stripe invoice link from dashboard → client pays → tier auto-updates
- Zero known security vulnerabilities in production

---

## Component 1: Email Sending

### Current State
- `email_scheduler.py` (504 lines) generates 5-email sequences as text files in `outreach_emails/`
- `outreach_schedule.json` tracks scheduled send dates per client
- `scheduler.py:_send_alert_email()` already has working SMTP code for alerts
- Prompts P03-P07 generate personalized cold emails with scan findings
- **Schedule format stores `contact` (name) but NOT `contact_email`** — must be added
- **Email files use format `day00_p03_cold_email_1_20260310.txt`** with a header block, not `Subject:` prefix
- **File paths stored as `email["file"]`** in schedule entries — use these directly
- **`outreach_emails/` and `outreach_schedule.json` use relative paths** — must move under `DATA_DIR` for Railway persistence
- **`SENDER_EMAIL` env var does not exist** — only `SMTP_FROM` exists in `scheduler.py`
- **SendGrid is commented out** in requirements.txt — this is new code, not existing

### What to Build

**1a. Update `generate_sequence()` to accept and store `contact_email`**

Add `contact_email` parameter to `generate_sequence()` signature. Store in schedule:
```python
schedule[company_safe] = {
    "company_name": company_name,
    "domain": domain,
    "industry": industry,
    "contact": contact,
    "contact_email": contact_email,  # NEW — required for sending
    "score": score,
    "start_date": ...,
    "emails": [...]
}
```

Update `generate_batch()` to read column 5 (email) from CSV and pass it through.

**1b. Move outreach paths under `DATA_DIR`**

Change `email_scheduler.py`:
```python
DATA_DIR = Path(os.getenv("DATA_DIR", "."))
OUTPUT_DIR = DATA_DIR / "outreach_emails"   # was: Path("outreach_emails")
SCHEDULE_FILE = DATA_DIR / "outreach_schedule.json"  # was: Path("outreach_schedule.json")
```

This ensures files persist on Railway's `/data` volume.

**1c. Send function in `email_scheduler.py`**

Add `send_email(to_email, subject, body, attachments=None)` using the same SMTP pattern from `scheduler.py:_send_alert_email()`. Support SendGrid as optional alternative.

Environment variables:
- `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_USER`, `SMTP_PASS` — existing in scheduler.py
- `SMTP_FROM` — existing (default: security@cybercomply.io)
- `SENDGRID_API_KEY` — new, optional (preferred over SMTP if set)

Logic: If `SENDGRID_API_KEY` is set, use SendGrid. Otherwise fall back to SMTP.

**1d. `send_due_emails()` function**

- Read `outreach_schedule.json` from `DATA_DIR`
- Find entries where `contact_email` exists
- For each email in entry's `emails` list where `send_date <= today` and `status != "sent"`
- Load email body from `email["file"]` (absolute path stored in schedule)
- Extract subject: parse the AI-generated content after the header block (lines starting with `=====`). If no clear `Subject:` line, use first non-header line as subject, or fall back to `"Security Alert — {company_name} scored {score}/100"`
- Send via `send_email(contact_email, subject, body)`
- If Day 0 email: attach PDF report from `client-deliverables/` if it exists
- Update `email["status"]` to `"sent"` and `email["sent_at"]` to ISO timestamp
- Write updated schedule back to file
- Log success/failure per email

**Concurrency note:** Since Railway runs a single process and the scheduler runs in the same process, file locking is not needed. If this changes (multiple workers), add `fcntl.flock()`.

**1e. Scheduler job**

Add to `scheduler.py:init_scheduler()`:
```python
from email_scheduler import send_due_emails
scheduler.add_job(send_due_emails, 'cron', hour=9, minute=0, id='outreach_emails')
```

**1f. Dashboard visibility**

Add outreach status to `/api/clients` response:
- `email_status`: "not_started" | "day_0_sent" | "day_3_sent" | ... | "sequence_complete"
- `last_email_sent`: ISO date
- `next_email_due`: ISO date

Show status dot on dashboard client row (same pattern as existing PDF/proposal dots).

### Dependencies
- Existing: `email_scheduler.py`, `scheduler.py`, `outreach_schedule.json`
- New: `sendgrid` package (optional) in requirements.txt

---

## Component 2: Stripe Invoicing

### Current State
- No billing code exists
- `client_manager.py` has tier management (assessment/basic/pro) with `get_tier_config()`
- Dashboard has vCISO client management with MRR tracking
- Tier prices defined in memory: basic=$2,000/mo, pro=$5,000/mo
- **Stripe amounts are in cents** (e.g., $5,000 = 500000 cents)

### What to Build

**2a. Stripe setup**

Add `stripe` to requirements.txt. Environment:
- `STRIPE_SECRET_KEY` — new
- `STRIPE_WEBHOOK_SECRET` — new

**2b. New file: `billing.py`**

Isolate all Stripe logic in a dedicated module:

```python
# billing.py — Stripe customer/invoice/subscription management
import stripe
import os

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

def get_or_create_customer(client_profile: dict) -> str: ...
def create_invoice(client_id: str, items: list, due_days: int = 7) -> dict: ...
def create_subscription(client_id: str, price_id: str) -> dict: ...
def handle_webhook(payload: bytes, sig_header: str) -> dict: ...
```

All amounts handled internally in cents. API accepts dollars, converts to cents before Stripe calls.

**2c. Invoice creation endpoint**

`POST /api/operator/clients/{client_id}/invoice`

Request body:
```json
{
  "items": [
    {"description": "Security Assessment + Risk Report", "amount": 5000},
    {"description": "vCISO Retainer (Monthly)", "amount": 3000, "recurring": true}
  ],
  "due_days": 7
}
```

Implementation:
- Create Stripe Customer (or retrieve if `stripe_customer_id` exists in profile)
- For one-time items: create Stripe Invoice with line items (amount converted to cents)
- For recurring items: create Stripe Subscription with appropriate Price object
- Finalize and send invoice (Stripe handles the email)
- Save `stripe_customer_id` and `stripe_invoice_id` to client profile
- Return: `{"invoice_url": "https://invoice.stripe.com/...", "status": "sent"}`

**2d. Webhook endpoint**

`POST /api/webhooks/stripe`

Handle events with correct tier logic:
- `customer.subscription.created` → Update client tier based on subscription amount: amount_paid (in cents) >= 500000 → pro, >= 200000 → basic
- `customer.subscription.updated` → Same tier logic as above
- `customer.subscription.deleted` → Downgrade tier to assessment
- `invoice.paid` (one-time only, no subscription) → Update `payment_status` to "paid", do NOT change tier
- `invoice.payment_failed` → Log, update `payment_status` to "overdue", optionally alert operator

**Important:** Tier promotion ONLY on subscription events, not one-time invoice payments. A $5,000 assessment payment should NOT upgrade to "pro" tier.

Verify webhook signature with `STRIPE_WEBHOOK_SECRET` using `stripe.Webhook.construct_event()`.

**2e. Dashboard button**

Add "Send Invoice" button on client detail row (`partials/client_detail.html`).
Opens modal with pre-filled line items based on tier. Calls invoice endpoint.
Shows invoice URL after creation.

**2f. Client profile updates**

Add to `client_manager.py` profile:
- `stripe_customer_id`: str
- `stripe_subscription_id`: str (if recurring)
- `payment_status`: "none" | "invoiced" | "paid" | "overdue"
- `paid_at`: ISO date

### Dependencies
- New: `stripe` package in requirements.txt
- New: `billing.py` module
- Existing: `client_manager.py`, `main.py` operator endpoints, `dashboard.html`

---

## Component 3: Security Hardening

### Current State (5 known issues from deep analysis + review)

1. **CORS** — `allow_origins=["*"]` with `allow_credentials=True` (browsers reject this combination per CORS spec)
2. **Dashboard cookie** — not httponly, stores plaintext password as cookie value
3. **Download paths** — no validation for `..` traversal on both `dir_name`, `client_id`, and `filename` params
4. **Rate limiting** — none on scan endpoints
5. **Query string password** — `?password=` in URL appears in server logs

### What to Fix

**3a. CORS lockdown**

Fix BOTH the origins and the credentials flag:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://www.cybercomply.io",
        "https://cybercomply.io",
        "http://localhost:8000",  # dev only
    ],
    allow_credentials=False,  # Not needed — dashboard/portal are same-origin
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)
```

Read origins from `ALLOWED_ORIGINS` env var in production (comma-separated).

**3b. Cookie security — replace plaintext password with session token**

Current (insecure):
```python
resp.set_cookie("dashboard_auth", DASHBOARD_PASSWORD, max_age=86400)
```

Replace with random session token:
```python
import secrets

# Module-level: store active session tokens in memory
_dashboard_sessions = set()

# On login:
session_token = secrets.token_hex(32)
_dashboard_sessions.add(session_token)
resp.set_cookie("dashboard_auth", session_token,
                max_age=86400, httponly=True, secure=True, samesite="lax")

# On auth check:
def check_dashboard_auth(request):
    token = request.cookies.get("dashboard_auth")
    if token and token in _dashboard_sessions:
        return True
    # Fall back to password check for initial login
    password = request.query_params.get("password")
    return password == DASHBOARD_PASSWORD
```

This prevents the plaintext password from being stored in cookies or visible in browser dev tools. Session tokens are ephemeral (cleared on server restart, which is acceptable for a single-operator dashboard).

**3c. Path validation**

Add validation function:
```python
def safe_path_component(value: str) -> str:
    """Reject directory traversal attempts in any path component."""
    name = Path(value).name  # strips any path components
    if name != value or ".." in value:
        raise HTTPException(400, "Invalid path")
    return name
```

Apply to ALL user-supplied path components:
- `/api/clients/{dir_name}/download/{file_type}` — validate `dir_name`
- `/portal/{client_id}/download/{doc_type}/{filename}` — validate `client_id`, `doc_type`, AND `filename`
- `/report/{client_dir}` — validate `client_dir`

**3d. Rate limiting**

Add `slowapi` to requirements.txt. Apply to:
- `/api/scan/free` and `/api/scan/free/stream`: 10 requests/minute per IP
- `/portal/login` POST: 5 attempts/minute per IP (brute force protection)
- `/api/lead/capture`: 10 requests/minute per IP
- Exempt: authenticated dashboard sessions (check cookie before rate limit)

### Dependencies
- New: `slowapi` package in requirements.txt
- Existing: `main.py`

---

## Component 4: Batch Outreach Automation

### Current State
- `deliver.py batch clients.csv` scans 20+ domains and calculates revenue opportunity
- `email_scheduler.py` can generate sequences but needs scan data
- **CSV formats differ:** `deliver.py` expects 6 columns (domain,company,industry,contact_name,contact_title,email) while `email_scheduler.py` expects 4 columns (domain,company,industry,contact_name)
- No connection between batch scan output and email sequence generation

### What to Build

**4a. Align CSV format**

Standardize on 6-column CSV: `domain,company,industry,contact_name,contact_title,contact_email`

Update `email_scheduler.py:generate_batch()` to accept and parse the same 6-column format, passing `contact_email` to `generate_sequence()`.

**4b. New CLI command: `deliver.py outreach clients.csv`**

Combines batch scan + email generation + schedule creation in one command:
```bash
python deliver.py outreach clients.csv
```

Steps:
1. Batch scan all domains (existing `batch_scan()`)
2. For each result with score < 70 AND contact_email present:
   - Generate 5-email sequence via `generate_sequence()` with contact_email
   - Create/update `outreach_schedule.json` entry
3. Skip entries without contact_email (log: "Skipping {company} — no contact email")
4. Print summary: "20 scanned, 15 qualify, 75 emails scheduled over 21 days"

**4c. Dashboard outreach pipeline**

Update `/api/pipeline` to include outreach metrics:
```json
{
  "leads": 5,
  "scanned": 20,
  "emailed": 15,
  "proposed": 3,
  "total_value": 15000,
  "ai_cost": 12.50,
  "email_stats": {
    "total_scheduled": 75,
    "sent": 30,
    "pending": 45,
    "next_batch": "2026-03-13"
  }
}
```

Read stats from `outreach_schedule.json`. Update `dashboard.html` pipeline cards to show email funnel.

### Dependencies
- Existing: `deliver.py`, `email_scheduler.py`, `outreach_schedule.json`
- Existing: `main.py` pipeline endpoint, `dashboard.html`

---

## File Changes Summary

| File | Change Type | What |
|------|------------|------|
| `email_scheduler.py` | Modify | Add `contact_email` param, move paths under DATA_DIR, add `send_email()`, `send_due_emails()`, align CSV format |
| `scheduler.py` | Modify | Add daily outreach email job |
| `main.py` | Modify | CORS+credentials, session-token cookie, path validation, rate limiting, Stripe webhook, invoice endpoint, pipeline update |
| `client_manager.py` | Modify | Add Stripe fields to profile |
| `deliver.py` | Modify | Add `outreach` CLI command, connect batch → email |
| `templates/dashboard.html` | Modify | Add invoice button, outreach pipeline, email status dots |
| `templates/partials/client_detail.html` | Modify | Add "Send Invoice" button + modal |
| `requirements.txt` | Modify | Add `stripe`, `slowapi`, optionally `sendgrid` |
| **New:** `billing.py` | Create | Stripe customer/invoice/subscription/webhook logic |

---

## Testing Plan

1. **Email sending**: Send test email to yourself, verify delivery + formatting
2. **Email scheduling**: Generate sequence with contact_email, advance schedule dates, verify `send_due_emails()` picks them up and sends to correct address
3. **Missing contact_email**: Generate sequence without contact_email, verify `send_due_emails()` skips gracefully
4. **Stripe invoice**: Create test invoice in Stripe test mode, verify amount conversion (dollars → cents), pay invoice, verify webhook fires
5. **Stripe subscription**: Create subscription, verify `customer.subscription.created` webhook promotes tier correctly
6. **Stripe one-time**: Pay one-time invoice, verify it does NOT change tier (only updates payment_status)
7. **Security — CORS**: Test request from non-allowed origin, verify rejection
8. **Security — path traversal**: Test `../` in dir_name, client_id, and filename params, verify 400 response
9. **Security — rate limit**: Hit `/api/scan/free` 11 times in 1 minute, verify 429 response
10. **Security — cookie**: Verify dashboard cookie is httponly and does not contain plaintext password
11. **Batch outreach**: Run `deliver.py outreach test.csv` with 3 domains (one without email), verify scan + email generation for 2, skip message for 1

---

## Risk Factors

1. **SendGrid/SMTP deliverability** — Cold emails may hit spam. Mitigate: Use verified domain, warm IP, start with small batches (5-10/day)
2. **Stripe webhook reliability** — Webhook may fail. Mitigate: Add retry logic, manual tier override in dashboard
3. **Rate limiting false positives** — Legitimate operators hitting limits. Mitigate: Exempt authenticated dashboard sessions
4. **Session token persistence** — In-memory session tokens clear on server restart. Mitigate: Acceptable for single-operator dashboard; if needed later, store in file or DB

## Out of Scope (Sprint 2+)

- Database migration (PostgreSQL)
- Self-serve signup
- Portal polish
- GoPhish deployment
- VIGIL/BREACH testing
- Tests beyond critical paths
