# Zero-Effort Delivery System — Design Spec

> **Goal:** Fix every product gap so that client effort = 0 beyond a single sales call, and operator effort = 1 click per onboarding + 30 min/month per retainer client.

---

## GAP 0 (BLOCKING): Findings → Tasks Pipeline

### Problem
The entire design assumes findings auto-become tasks. But `full_delivery()` in deliver.py never calls `client_manager.add_task()`. Tasks only get created by `scheduler._generate_tasks_from_findings()` which runs on monthly cron — NOT at onboarding. A newly onboarded client has zero tasks until the next monthly scan.

Weekly task emails (Gap C) send nothing. Roadmap PDF (Gap F) has no tasks. Call agenda (Gap B) has empty task list. Everything downstream breaks.

### What exists
- `client_manager.add_task(client_id, title, severity, category, description, fix)` — works, writes to `tasks.json`
- `scheduler._generate_tasks_from_findings(client_id, findings)` — works, deduplicates by title
- `_auto_verify_tasks(client_id, findings)` — works, marks tasks "verified" when finding disappears

### Fix
Add `_generate_tasks_from_findings()` call at the end of `full_delivery()` in deliver.py, right after Step 6 (save raw data). This creates tasks immediately at onboarding.

```python
# Step 7: Generate remediation tasks from findings
findings = scan_data["archer"].get("findings", [])
if client_id:  # only if client was created in client_manager
    from scheduler import _generate_tasks_from_findings
    _generate_tasks_from_findings(client_id, findings)
```

Also: add non-scannable tasks from GUARDIAN gaps:
```python
for gap in forge_data["profile"].get("gaps", []):
    add_task(client_id, title=gap, severity="HIGH", category="Compliance",
             description=f"Required by {', '.join(forge_data['profile'].get('applicable_frameworks',[]))}",
             fix=f"CyberComply provides this — review and adopt the {gap} document")
```

### Files changed
- `deliver.py` — add task generation after raw data save
- `scheduler.py` — extract `_generate_tasks_from_findings()` into importable function (currently it's a private method, needs to be callable from deliver.py)

---

## GAP 0.5 (BLOCKING): deliver.py OUTPUT_DIR Hardcoded Path

### Problem
```python
# deliver.py line 48
OUTPUT_DIR = Path("./client-deliverables")  # HARDCODED

# main.py line 93-95
DATA_DIR = Path(os.getenv("DATA_DIR", "."))
OUTPUT_DIR = DATA_DIR / "client-deliverables"  # ENV-VAR AWARE
```

When `full_delivery()` is called from a web endpoint on Railway, files land in `/app/client-deliverables/` (ephemeral container filesystem) instead of `/data/client-deliverables/` (persistent volume). Files vanish on container restart.

### Fix
```python
# deliver.py line 48 — replace
DATA_DIR = Path(os.getenv("DATA_DIR", "."))
OUTPUT_DIR = DATA_DIR / "client-deliverables"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
```

### Files changed
- `deliver.py` line 48

---

## A. CLI Profile Overrides — Complete Fix

### A1. --employees flag doesn't actually merge into questionnaire

**Current bug (confirmed):** `--employees 8` is passed to `full_delivery()` but `run_questionnaire()` at line 738 ignores it. The QUICK_PROFILE q3 stays at "11-25" regardless.

**Fix:** In `run_questionnaire()`, accept overrides dict:
```python
def run_questionnaire(company_name, industry="cpa", overrides=None):
    profile_data = QUICK_PROFILES.get(industry, QUICK_PROFILES["cpa"]).copy()
    profile_data["q1"] = company_name
    if overrides:
        profile_data.update(overrides)
    ...
```

In `full_delivery()`:
```python
# Build overrides from CLI args
overrides = {}
if employee_count:
    # Map integer to questionnaire range string
    ranges = {3: "1-10", 10: "1-10", 25: "11-25", 50: "26-50", 100: "51-100", 250: "101-250"}
    for threshold, label in sorted(ranges.items()):
        if employee_count <= threshold:
            overrides["q3"] = label
            break
    else:
        overrides["q3"] = "250+"

if email_provider:
    provider_map = {"microsoft": "Microsoft 365", "google": "Google Workspace", "other": "Other"}
    overrides["q6"] = provider_map.get(email_provider, email_provider)

if mfa:
    mfa_map = {"full": "Yes — for all users", "partial": "Yes — for some users",
               "none": "No", "unknown": "I don't know"}
    overrides["q7"] = mfa_map.get(mfa, mfa)

if has_wisp is not None:
    overrides["q15"] = "Yes — current and reviewed annually" if has_wisp else "No"

if has_irp is not None:
    overrides["q16"] = "Yes — tested within last 12 months" if has_irp else "No"

if cyber_insurance is not None:
    overrides["q20"] = "Yes — active policy" if cyber_insurance else "No"

if data_types:
    overrides["q12"] = data_types  # list like ["Social Security Numbers", "Tax Returns (FTI)"]

if handles_fti is not None:
    if not handles_fti and "q12" not in overrides:
        # Remove FTI from default data types
        default_types = profile_data.get("q12", [])
        overrides["q12"] = [t for t in default_types if "Tax" not in t and "FTI" not in t]

forge_data = run_questionnaire(scan_data["company_name"], industry, overrides=overrides)
```

### A2. No "general" industry quick profile

**Fix:** Add missing profiles to QUICK_PROFILES:
```python
"general": {
    "q1": "", "q2": "Professional Services", "q3": "11-25",
    "q6": "Microsoft 365", "q7": "No",
    "q12": ["Client Data", "Employee PII"],
    "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
    "q21": ["NIST CSF"],
    "q24": "Yes — some employees", "q25": "No", "q26": "I don't know",
    "q27": ["Employees sharing client data with AI"],
},
"nonprofit": { ... },
"education": { ... },
"manufacturing": { ... },
"real_estate": { ... },
```

### A3. New CLI flags

```python
deliver.add_argument("--email-provider", choices=["microsoft", "google", "other"])
deliver.add_argument("--mfa", choices=["full", "partial", "none", "unknown"])
deliver.add_argument("--has-wisp", type=lambda x: x.lower() == "yes", metavar="yes/no")
deliver.add_argument("--has-irp", type=lambda x: x.lower() == "yes", metavar="yes/no")
deliver.add_argument("--cyber-insurance", type=lambda x: x.lower() == "yes", metavar="yes/no")
deliver.add_argument("--no-fti", action="store_true", help="Client does not handle Federal Tax Information")
deliver.add_argument("--data-types", nargs="+", help="Override sensitive data types")
```

### A4. Dashboard form alignment

The same overrides dict must be accepted by the `/api/operator/onboard` endpoint (Gap E). The data model is:
```json
{
  "overrides": {
    "employee_count": 8,
    "email_provider": "google",
    "mfa": "full",
    "has_wisp": false,
    "has_irp": false,
    "cyber_insurance": true,
    "handles_fti": true,
    "data_types": ["Social Security Numbers"]
  }
}
```

Both CLI args and dashboard JSON map to the same `overrides` dict → same `run_questionnaire()` path.

### Files changed
- `deliver.py` — run_questionnaire() signature, full_delivery() override building, CLI args, QUICK_PROFILES additions

---

## B. Monthly Call Agenda — Complete Fix

### B1. New prompt (P60_MONTHLY_CALL_AGENDA)

Add to `prompt_library.py`:
```python
"P60_MONTHLY_CALL_AGENDA": {
    "system": "You are a virtual CISO preparing a monthly client call agenda...",
    "user": """Generate a 1-page call prep for {company_name}.

SCORE: {current_score}/100 ({current_grade}) — was {previous_score}/100 ({previous_grade}) last month
RESOLVED TASKS THIS MONTH: {resolved_tasks}
NEW ALERTS THIS MONTH: {new_alerts}
OPEN TASKS: {open_tasks}
THREAT INTEL: {threat_intel}
COMPLIANCE STATUS: {compliance_status}
CALL NOTES FROM LAST MONTH: {previous_notes}

Format as: SCORE CHANGE, WINS THIS MONTH, NEW ISSUES, OPEN TASKS (top 5), THREAT INTEL, RECOMMENDED DISCUSSION TOPICS, COMPLIANCE STATUS."""
}
```

### B2. Call notes storage

Add to client_manager.py:
```python
def save_call_notes(client_id: str, notes: str, call_date: str = None):
    """Save notes from a monthly call. Persists for next month's agenda."""
    client_dir = _client_dir(client_id)
    notes_file = client_dir / "call_notes.json"
    existing = json.loads(notes_file.read_text()) if notes_file.exists() else []
    existing.append({
        "date": call_date or datetime.utcnow().strftime("%Y-%m-%d"),
        "notes": notes,
    })
    # Keep last 12 months
    notes_file.write_text(json.dumps(existing[-12:], indent=2))

def get_latest_call_notes(client_id: str) -> str:
    """Get notes from last month's call for agenda carry-forward."""
    client_dir = _client_dir(client_id)
    notes_file = client_dir / "call_notes.json"
    if not notes_file.exists():
        return "First month — no previous call notes."
    notes = json.loads(notes_file.read_text())
    return notes[-1]["notes"] if notes else "No notes from last call."
```

Add endpoint in main.py:
```python
@app.post("/api/operator/call-notes/{client_id}")
async def save_call_notes(client_id: str, request: Request):
    """Save notes after a monthly call."""
    body = await request.json()
    client_manager.save_call_notes(client_id, body.get("notes", ""))
    return {"status": "saved"}
```

### B3. First-month variant

In the scheduler, when generating agenda:
```python
if previous_score is None:
    # First month — use baseline template
    prompt_key = "P60_MONTHLY_CALL_AGENDA_FIRST"
    # Template says: "This is your baseline. Here's what we'll track..."
else:
    prompt_key = "P60_MONTHLY_CALL_AGENDA"
```

### B4. Threat intel filtering fix

When onboarding a client, populate `tech_stack` from questionnaire answers:
```python
# In onboarding flow, after questionnaire:
tech_stack = []
if profile.get("email_provider") == "Microsoft 365":
    tech_stack.extend(["Microsoft Exchange", "Microsoft 365", "Outlook"])
elif profile.get("email_provider") == "Google Workspace":
    tech_stack.extend(["Google Workspace", "Gmail"])
# Add from q8 (cloud services)
tech_stack.extend(profile.get("cloud_services", []))
client_manager.update_field(client_id, "tech_stack", tech_stack)
```

### B5. Operator email routing

Add `OPERATOR_EMAIL` env var (already exists as `ADMIN_EMAIL` in some places). For multi-operator, add optional `assigned_operator` field on client profile. Agenda sends to assigned operator's email, or falls back to OPERATOR_EMAIL.

### Files changed
- `prompt_library.py` — add P60_MONTHLY_CALL_AGENDA + first-month variant
- `client_manager.py` — add save_call_notes(), get_latest_call_notes(), update_field()
- `scheduler.py` — add generate_call_agendas() job on 1st of month
- `main.py` — add /api/operator/call-notes endpoint
- `deliver.py` — populate tech_stack on onboarding

---

## C. Weekly Task Emails — Complete Fix

### C1. Task categorization (scannable vs manual)

When creating tasks, tag them:
```python
def add_task(client_id, title, severity, category, description, fix, verifiable="auto"):
    """
    verifiable: "auto" = RECON can detect completion
                "manual" = requires human confirmation (policy adoption, training, vendor review)
    """
    task = {
        ...existing fields...,
        "verifiable": verifiable,
    }
```

Compliance/policy tasks → `verifiable="manual"`.
Technical findings (DMARC, SSL, headers, ports) → `verifiable="auto"`.

### C2. Reply-to-mark-done for manual tasks

Option A (simple): Weekly email includes "Reply DONE 1, DONE 2 to mark tasks complete."
Parse incoming emails for "DONE" + task number. Requires email receiving (complex).

Option B (better): Include unique one-click links:
```
[✅ Mark as done](https://www.cybercomply.io/portal/{client_id}/task/{task_id}/resolve?token={magic_token})
```
Client clicks → task status changes to "resolved" → disappears from next email.
No login required — magic token authenticates the action.

### C3. Task cap per email

```python
# In P61_WEEKLY_TASK_DIGEST prompt:
MAX_TASKS_IN_EMAIL = 5

critical_tasks = [t for t in open_tasks if t["severity"] == "CRITICAL"]
high_tasks = [t for t in open_tasks if t["severity"] == "HIGH"]
medium_tasks = [t for t in open_tasks if t["severity"] == "MEDIUM"]

# Show: all CRITICAL, then HIGH until cap, then count remaining
shown_tasks = critical_tasks[:MAX_TASKS_IN_EMAIL]
remaining = MAX_TASKS_IN_EMAIL - len(shown_tasks)
if remaining > 0:
    shown_tasks += high_tasks[:remaining]
    remaining = MAX_TASKS_IN_EMAIL - len(shown_tasks)
if remaining > 0:
    shown_tasks += medium_tasks[:remaining]

overflow_count = len(open_tasks) - len(shown_tasks)
# Template: "...and {overflow_count} more items in your portal"
```

### C4. Platform-aware HOW instructions

The prompt receives `email_provider` from client profile:
```python
call_prompt("P61_WEEKLY_TASK_DIGEST",
    tasks=json.dumps(shown_tasks),
    email_provider=client.get("tech_stack_primary", "Microsoft 365"),
    company_name=client["company_name"],
    current_score=current_score,
    ...
)
```

Prompt instructions:
```
When writing HOW instructions:
- If email_provider is "Microsoft 365": use admin.microsoft.com paths
- If email_provider is "Google Workspace": use admin.google.com paths
- If email_provider is "Other": say "Contact your email administrator"
- For DNS tasks: say "Contact your domain registrar or IT provider"
- For web server tasks: say "Contact your web developer or hosting provider"
```

### C5. Conservative score projection

Instead of summing all finding points:
```python
# Group findings by category, respect category caps
category_potential = {}
for task in open_tasks:
    finding = task.get("source_finding", {})
    cat = finding.get("category", "general")
    points = abs(finding.get("points", 3))
    if cat not in category_potential:
        category_potential[cat] = {"gained": 0, "max": CATEGORY_CAPS.get(cat, 15)}
    category_potential[cat]["gained"] += points

# Cap each category
total_gain = sum(min(v["gained"], v["max"]) for v in category_potential.values())
projected = min(current_score + total_gain, 100)

# Round down to be conservative
projected = (projected // 5) * 5  # Round to nearest 5
```

Show in email as: "Completing these tasks could bring your score to approximately {projected}/100."

### C6. Frequency/pause control

Add to client profile: `task_email_frequency: "weekly" | "biweekly" | "monthly" | "paused"`
Default: "weekly". Operator can change via dashboard. Client can request change via reply.

Scheduler checks: `if client["task_email_frequency"] == "paused": continue`

### C7. New prompt (P61_WEEKLY_TASK_DIGEST)

```python
"P61_WEEKLY_TASK_DIGEST": {
    "system": "You are a cybersecurity advisor writing a brief, actionable weekly security task email for a business owner. Be specific with HOW instructions based on their email platform. Include time estimates. Keep it under 300 words.",
    "user": """Write a weekly task digest email for {company_name}.

EMAIL PROVIDER: {email_provider}
CURRENT SCORE: {current_score}/100
PROJECTED SCORE IF ALL DONE: {projected_score}/100

TASKS (top {task_count}, sorted by severity):
{tasks_json}

OVERFLOW: {overflow_count} more items available in portal.

RECENTLY COMPLETED (auto-verified this week):
{recently_resolved}

Format: Greeting → grouped by severity (CRITICAL/HIGH/MEDIUM) → each task has WHY (1 line), HOW (step-by-step for their platform), TIME estimate → score projection → sign-off."""
}
```

### Files changed
- `prompt_library.py` — add P61_WEEKLY_TASK_DIGEST
- `client_manager.py` — add verifiable field to add_task(), add task_email_frequency to profile
- `scheduler.py` — add send_weekly_task_digest() job Monday 10am UTC
- `main.py` — add /portal/{client_id}/task/{task_id}/resolve endpoint (one-click resolve)

---

## D. AI Governance Quick Audit — Complete Fix

### D1. AI-specific PDF report (3-4 pages)

New function in `report_generator.py`:
```python
def generate_ai_governance_report(report_data: dict, output_path: str):
    """Generate a focused 3-4 page AI Governance Audit report."""
    # Page 1: AI Risk Summary
    #   - Which AI tools detected/reported in use
    #   - What data types are at risk
    #   - Current AI policy status (none/informal/formal)
    #   - AI risk score from GUARDIAN
    #   - Breach exposure count from SHADOW

    # Page 2: Framework Impact
    #   - Table: 15 AI controls across 5 frameworks
    #   - Plain English description of each control
    #   - Status: "Gap" or "Addressed"
    #   - Column: "What this means for you"

    # Page 3: AI Acceptable Use Policy Summary
    #   - Key policy sections (not full text — that's the attached doc)
    #   - Employee acknowledgment requirements
    #   - Prohibited actions (specific to their data types)
    #   - Training requirements

    # Page 4: Implementation Roadmap + CTA
    #   - Week 1: Distribute AI policy, collect signatures
    #   - Week 2: Configure AI tool restrictions (block ChatGPT on work devices OR approve specific tools)
    #   - Week 3: Employee training session on AI data handling
    #   - Week 4: Vendor AI risk assessment (which SaaS tools use AI with your data?)
    #   - CTA: "Full security assessment available — covers all 50+ findings"
```

### D2. AI-specific CLI overrides

For AI audits, the operator needs to capture 3 things on the call:
```python
deliver.add_argument("--ai-tools", nargs="+", help="AI tools in use (chatgpt, copilot, claude, gemini)")
deliver.add_argument("--ai-data-risk", choices=["none", "unknown", "names-only", "financial", "tax-data", "phi"],
                     help="What data employees put into AI tools")
deliver.add_argument("--ai-incidents", type=lambda x: x.lower() == "yes", metavar="yes/no",
                     help="Any known AI-related data incidents")
```

These override q24-q27 and feed into the AI policy generation prompt for specificity:
```
"Your employees use ChatGPT and Microsoft Copilot. Tax return data (FTI) has been entered
into ChatGPT. Your policy must specifically prohibit FTI input into AI tools and list
approved AI tools: Microsoft Copilot (with data protection enabled) only."
```

vs the current generic: "Employees shall not input sensitive data into AI tools."

### D3. Crossmap as formatted deliverable

Add function to generate crossmap as a formatted text/HTML section (reusable in PDF and email):
```python
def format_crossmap_for_client(crossmap: dict, frameworks: list) -> list:
    """Convert raw crossmap JSON into client-readable items for PDF/email."""
    items = []
    plain_english = {
        "AI Acceptable Use Policy": "A written policy that tells employees which AI tools they can use and what data they cannot enter",
        "AI Tool Data Input Controls": "Technical or procedural controls that prevent sensitive data from being pasted into AI tools",
        "AI Risk Management Policy": "A documented approach to identifying and managing risks from AI tool usage",
        "AI Tool Inventory and Data Flow Controls": "A list of all AI tools in use and where data flows when employees use them",
        "AI Usage Monitoring and Shadow AI Detection": "The ability to detect when employees use unauthorized AI tools",
        "AI Vendor and Model Risk Assessment": "Evaluation of AI vendors' data handling, security, and compliance practices",
        "AI Disclosure and Transparency Controls": "Rules about when and how to disclose AI usage to clients and stakeholders",
        "AI and Automated Processing of PHI Controls": "Specific protections when AI tools process health information",
        "AI Tool Access Restrictions for PHI Systems": "Technical controls limiting which AI tools can access health data systems",
        "AI and Automated Decision-Making Risk Controls": "Governance over AI tools that make or influence business decisions",
        "AI Tool Data Protection": "Controls ensuring AI tools don't store, leak, or misuse customer information",
    }
    for control in crossmap.get("ai_governance", {}).get("controls", []):
        name = control["control_name"]
        items.append({
            "framework": control["framework"],
            "control_id": control["control_id"],
            "control_name": name,
            "plain_english": plain_english.get(name, name),
        })
    return items
```

### D4. Follow-up task creation

After AI audit delivery, auto-create 4 tasks:
1. "Distribute AI Acceptable Use Policy to all employees" (manual, due 7 days)
2. "Collect signed AI policy acknowledgments" (manual, due 14 days)
3. "Configure AI tool restrictions on work devices" (manual, due 21 days)
4. "Conduct AI data handling training session" (manual, due 30 days)

These enter the weekly task email flow automatically.

### Files changed
- `report_generator.py` — add generate_ai_governance_report()
- `deliver.py` — add --ai-tools, --ai-data-risk, --ai-incidents CLI args
- `agents/agents_remaining.py` — add format_crossmap_for_client() to ComplyAgent
- `prompt_library.py` — enhance P46_AI_GOVERNANCE user prompt with specific tool/data placeholders

---

## E. Dashboard Onboarding — Complete Fix

### E1. Async pipeline with SSE progress

The onboarding endpoint must NOT call `full_delivery()` synchronously. Instead:

```python
@app.post("/api/operator/onboard")
async def onboard_client(request: OnboardRequest, background_tasks: BackgroundTasks):
    """Start async onboarding pipeline. Returns job_id for SSE progress."""
    # Validate no duplicate
    existing = client_manager.find_by_domain(request.domain)
    if existing:
        raise HTTPException(400, f"Client already exists: {existing['company_name']} ({existing['client_id']})")

    job_id = secrets.token_hex(8)
    # Store job state in memory
    _onboard_jobs[job_id] = {"status": "started", "steps": [], "client_id": None}

    background_tasks.add_task(_run_onboard_pipeline, job_id, request)
    return {"job_id": job_id, "stream_url": f"/api/operator/onboard/progress/{job_id}"}

@app.get("/api/operator/onboard/progress/{job_id}")
async def onboard_progress(job_id: str):
    """SSE stream for onboarding progress."""
    async def event_stream():
        while True:
            job = _onboard_jobs.get(job_id, {})
            for step in job.get("steps", []):
                yield f"data: {json.dumps(step)}\n\n"
            if job.get("status") in ("complete", "failed"):
                yield f"data: {json.dumps({'type': 'done', 'status': job['status'], 'client_id': job.get('client_id')})}\n\n"
                break
            await asyncio.sleep(1)
    return StreamingResponse(event_stream(), media_type="text/event-stream")
```

### E2. Pipeline steps (background task)

```python
async def _run_onboard_pipeline(job_id, request):
    job = _onboard_jobs[job_id]
    try:
        # Step 1: RECON scan
        _update_job(job_id, "Scanning domain...", "in_progress")
        scan_data = run_scan(request.domain, request.company_name)
        _update_job(job_id, f"Scan complete — Score: {scan_data['score']}/100", "done")

        # Step 2: SHADOW breach check
        if request.employee_emails:
            _update_job(job_id, f"Checking {len(request.employee_emails)} emails against dark web...", "in_progress")
            shadow_results = _run_shadow_check(request.employee_emails)
            _update_job(job_id, f"Breach check complete — {shadow_results['total_exposed']} exposed", "done")

        # Step 3: GUARDIAN assessment
        _update_job(job_id, "Running risk assessment...", "in_progress")
        overrides = _build_overrides(request.overrides, request.employee_count)
        forge_data = run_questionnaire(request.company_name, request.industry, overrides)
        _update_job(job_id, f"Assessment complete — {len(forge_data['profile'].get('gaps',[]))} gaps found", "done")

        # Step 4: PDF report
        _update_job(job_id, "Generating PDF report...", "in_progress")
        pdf_path = generate_pdf_report(scan_data, forge_data, client_dir)
        _update_job(job_id, "PDF report generated", "done")

        # Step 5: Policies
        _update_job(job_id, "Generating policy documents...", "in_progress")
        policy_docs = generate_core_policies(client_profile)
        save_policies(request.company_name, policy_docs, client_dir)
        _update_job(job_id, f"{len(policy_docs)} policies generated", "done")

        # Step 6: Create client in client_manager
        _update_job(job_id, "Creating client profile...", "in_progress")
        client_id = request.domain.replace(".", "_")
        client_manager.create_client(client_id, request.company_name, request.domain,
                                      request.industry, request.tier, request.contact_email)
        # Populate tech_stack from questionnaire
        tech_stack = _build_tech_stack(forge_data["profile"])
        client_manager.update_field(client_id, "tech_stack", tech_stack)
        client_manager.update_field(client_id, "contact_name", request.contact_name)

        # Step 7: Generate tasks from findings
        _generate_tasks_from_findings(client_id, scan_data["archer"].get("findings", []))
        _generate_tasks_from_gaps(client_id, forge_data["profile"].get("gaps", []))

        # Step 8: Generate magic link + send welcome email
        _update_job(job_id, "Sending welcome email...", "in_progress")
        magic_token = client_manager.generate_magic_link(client_id)
        portal_url = f"https://www.cybercomply.io/portal/setup/{client_id}?token={magic_token}"
        _send_welcome_email(request.contact_email, request.contact_name, request.company_name,
                           pdf_path, portal_url, policy_docs)
        _update_job(job_id, "Welcome email sent", "done")

        # Step 9: Add initial score
        client_manager.add_score(client_id, scan_data["score"], scan_data["grade"])

        job["status"] = "complete"
        job["client_id"] = client_id

    except Exception as e:
        job["status"] = "failed"
        job["error"] = str(e)
```

### E3. Duplicate detection

Add to client_manager.py:
```python
def find_by_domain(domain: str) -> dict | None:
    """Check if a client with this domain already exists."""
    for client_id in _list_client_dirs():
        profile = get_client(client_id)
        if profile and profile.get("domain") == domain:
            return profile
    return None
```

### E4. Client update endpoint

```python
@app.put("/api/operator/client/{client_id}")
async def update_client(client_id: str, request: Request):
    """Update client profile fields (tier, contact, industry, etc.)."""
    body = await request.json()
    allowed_fields = ["tier", "contact_name", "contact_email", "contact_title",
                      "industry", "tech_stack", "employee_emails", "task_email_frequency"]
    for field in allowed_fields:
        if field in body:
            client_manager.update_field(client_id, field, body[field])
    return {"status": "updated", "client_id": client_id}
```

`update_field()` in client_manager.py:
```python
def update_field(client_id: str, field: str, value):
    profile = get_client(client_id)
    if not profile:
        return False
    profile[field] = value
    _save_profile(client_id, profile)
    return True
```

### E5. Magic link auto-refresh

When client accesses portal, refresh magic link if it expires within 2 days:
```python
def verify_magic_token(client_id, token):
    ...existing logic...
    # Auto-extend if close to expiry
    expires = datetime.fromisoformat(profile["magic_token_expires"])
    if (expires - datetime.utcnow()).days < 2:
        # Extend by 7 more days
        profile["magic_token_expires"] = (datetime.utcnow() + timedelta(days=7)).isoformat()
        _save_profile(client_id, profile)
    return True
```

Also add a "Request new link" button on the portal login page that sends a new magic link email.

### E6. Welcome email template

```python
def _send_welcome_email(to_email, contact_name, company_name, pdf_path, portal_url, policy_docs):
    subject = f"Welcome to CyberComply — {company_name} Security Package"
    body = f"""Hi {contact_name},

Welcome to CyberComply. Your security package is ready.

YOUR SECURITY SCORE: See attached PDF report for your full assessment.

YOUR PORTAL: Access your security dashboard anytime:
{portal_url}
(This link expires in 7 days — you'll set a password on first login.)

ATTACHED:
- Security Assessment Report (PDF)
- Written Information Security Plan (WISP)
- Incident Response Plan (IRP)
- {len(policy_docs) - 2} additional security policies

FIRST STEP: Review and sign your WISP by {(date.today() + timedelta(days=7)).strftime('%B %d')}.
Your WISP is required by {frameworks_text}. We've customized it to your organization —
just review, sign, and distribute to all employees.

We'll send you a weekly security task digest every Monday with specific,
actionable items to improve your security posture.

Your first monthly review call is scheduled for {next_month_1st}.

Questions? Reply to this email or call us at {BRAND['phone']}.

— CyberComply Security Team
{BRAND['website']}
"""
    # Attach PDF (always)
    attachments = [pdf_path]
    # Attach WISP + IRP only (not all 10 — email size limit)
    # Other policies available in portal
    for key in ["P29_WISP", "P30_IRP"]:
        policy_path = policy_dir / f"{key.split('_',1)[1]}.txt"
        if policy_path.exists():
            attachments.append(str(policy_path))

    send_email(to_email, subject, body, attachments=attachments)
```

### Files changed
- `main.py` — add /api/operator/onboard, /api/operator/onboard/progress, /api/operator/client/{id}
- `client_manager.py` — add find_by_domain(), update_field(), auto-refresh magic link
- `deliver.py` — fix OUTPUT_DIR, make run_questionnaire accept overrides
- `templates/dashboard.html` — add "New Client" onboarding form + SSE progress UI

---

## F. 90-Day Roadmap PDF — Complete Fix

### F1. Task categorization by effort, not just severity

```python
TASK_EFFORT = {
    # Quick wins (client can do in <15 min)
    "quick": ["Reset password", "Enable MFA", "Add DMARC", "Add SPF", "Enable DKIM",
              "Sign WISP", "Sign IRP", "Sign AI Policy"],
    # IT tasks (need technical person, <1 hour)
    "it_task": ["Add HSTS header", "Add CSP header", "Update SSL", "Configure DNSSEC",
                "Add CAA record", "Update WordPress", "Close open port"],
    # Projects (need budget/vendor, multi-day)
    "project": ["Deploy endpoint protection", "Implement network segmentation",
                "Replace firewall", "Set up SIEM", "Configure DLP"],
    # CyberComply provides (client just reviews)
    "we_provide": ["WISP", "Incident Response Plan", "AI Acceptable Use Policy",
                   "Encryption Policy", "Password Policy", "Vendor Management Policy",
                   "Data Classification Policy", "Remote Work Policy", "Training Program"],
}

def categorize_task(title: str) -> tuple:
    """Returns (effort_category, owner)."""
    title_lower = title.lower()
    for category, keywords in TASK_EFFORT.items():
        if any(kw.lower() in title_lower for kw in keywords):
            owners = {
                "quick": "You (Managing Partner)",
                "it_task": "Your IT Person / Provider",
                "project": "IT Provider (requires budget)",
                "we_provide": "CyberComply (included in your package)",
            }
            return category, owners[category]
    return "it_task", "Your IT Person / Provider"
```

### F2. Roadmap generation with correct score math

```python
CATEGORY_CAPS = {
    "email_security": 35, "ssl_tls": 15, "security_headers": 15,
    "network_exposure": 15, "technology": 10, "dns_security": 10,
}

def build_roadmap(findings, profile, shadow_data, current_score):
    """Build 90-day roadmap from findings, profile gaps, and breach data."""

    week_1_2 = []  # Quick wins + critical items
    week_3_4 = []  # Policy adoption (we provide)
    month_2 = []   # IT tasks
    month_3 = []   # Projects + training

    # Add breach remediation first (most urgent)
    if shadow_data and shadow_data.get("total_exposed", 0) > 0:
        for breach in shadow_data.get("results", shadow_data.get("breaches", []))[:3]:
            email = breach.get("email", "unknown")
            week_1_2.append({
                "title": f"Reset password for {email}",
                "why": "Credentials found in a data breach",
                "how": "Reset in your email admin panel + enable MFA",
                "time": "2 minutes",
                "owner": "You (Managing Partner)",
                "effort": "quick",
            })

    # Categorize findings
    for f in findings:
        effort, owner = categorize_task(f.get("title", ""))
        item = {
            "title": f.get("title", "Unknown"),
            "why": f.get("description", "")[:100],
            "severity": f.get("severity", "MEDIUM"),
            "time": _estimate_time(effort),
            "owner": owner,
            "effort": effort,
            "points": abs(f.get("points", 3)),
            "category": f.get("category", "general"),
        }

        if effort == "quick" and f.get("severity") in ("CRITICAL", "HIGH"):
            week_1_2.append(item)
        elif effort == "quick":
            month_2.append(item)
        elif effort == "it_task":
            month_2.append(item)
        elif effort == "project":
            month_3.append(item)

    # Add policy gaps to week 3-4
    for gap in profile.get("gaps", []):
        week_3_4.append({
            "title": f"Adopt {gap}",
            "why": f"Required by {', '.join(profile.get('applicable_frameworks', [])[:2])}",
            "how": "We provide this — just review and sign",
            "time": "30 min review",
            "owner": "CyberComply + You",
            "effort": "we_provide",
        })

    # Always add training + AI policy to month 3
    month_3.append({
        "title": "Complete employee security awareness training",
        "why": "Required by most frameworks + reduces phishing risk by 70%",
        "time": "1 hour (all employees)",
        "owner": "CyberComply conducts, you schedule",
        "effort": "we_provide",
    })

    # Conservative score projection
    category_gains = {}
    all_items = week_1_2 + week_3_4 + month_2 + month_3
    for item in all_items:
        cat = item.get("category", "general")
        pts = item.get("points", 3)
        if cat not in category_gains:
            category_gains[cat] = 0
        category_gains[cat] += pts

    # Cap per category
    total_gain = 0
    for cat, gained in category_gains.items():
        cap = CATEGORY_CAPS.get(cat, 15)
        total_gain += min(gained, cap)

    projected = min(current_score + total_gain, 100)
    projected = (projected // 5) * 5  # Round to nearest 5

    return {
        "week_1_2": week_1_2[:5],      # Cap at 5 items per section
        "week_3_4": week_3_4[:4],
        "month_2": month_2[:5],
        "month_3": month_3[:4],
        "current_score": current_score,
        "projected_score": projected,
        "total_items": len(all_items),
    }

def _estimate_time(effort):
    return {"quick": "2-10 minutes", "it_task": "30-60 minutes",
            "project": "Multi-day project", "we_provide": "30 min review"}[effort]
```

### F3. ReportLab page (Page 10)

```python
def _build_roadmap_page(story, styles, roadmap_data):
    """Add 90-Day Security Roadmap as page 10."""
    story.append(PageBreak())
    story.append(Paragraph("YOUR 90-DAY SECURITY ROADMAP", styles['SectionHead']))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 12))

    sections = [
        ("WEEK 1-2: QUICK WINS", roadmap_data["week_1_2"], colors.HexColor("#dc3545")),
        ("WEEK 3-4: POLICY FOUNDATION", roadmap_data["week_3_4"], colors.HexColor("#fd7e14")),
        ("MONTH 2: TECHNICAL HARDENING", roadmap_data["month_2"], colors.HexColor("#ffc107")),
        ("MONTH 3: TRAINING & TESTING", roadmap_data["month_3"], colors.HexColor("#28a745")),
    ]

    for section_title, items, color in sections:
        story.append(Paragraph(section_title, styles['SubHead']))
        for item in items:
            # Each task: checkbox + title + owner badge + time
            task_text = f"""<b>☐ {item['title']}</b>
            <br/><i>{item.get('why', '')[:80]}</i>
            <br/><font color="gray">Owner: {item['owner']} | Time: {item['time']}</font>"""
            story.append(Paragraph(task_text, styles['TaskItem']))
            story.append(Spacer(1, 4))
        story.append(Spacer(1, 8))

    # Score projection bar
    current = roadmap_data["current_score"]
    projected = roadmap_data["projected_score"]
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        f"<b>PROJECTED IMPROVEMENT:</b> {current}/100 → {projected}/100",
        styles['ProjectionText']
    ))

    # Soft CTA (not hard sell)
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "Need help implementing this roadmap? Schedule a call to discuss priorities.",
        styles['CTAText']
    ))
    story.append(Paragraph(
        f"<link href='{BRAND['calendly']}'>{BRAND['calendly']}</link>",
        styles['CTALink']
    ))
```

### F4. SHADOW data dependency

The free scan (lead magnet PDF) won't have breach data. Handle gracefully:
```python
if not shadow_data or shadow_data.get("total_exposed", 0) == 0:
    # No breach data — still show roadmap but skip breach tasks
    # Add note: "Run a dark web scan with employee emails to check for exposed credentials"
    week_1_2.insert(0, {
        "title": "Run dark web credential scan",
        "why": "Check if employee passwords are exposed in data breaches",
        "how": "Provide your employee email list — we'll check for free",
        "time": "5 minutes (just send us the list)",
        "owner": "CyberComply",
        "effort": "we_provide",
    })
```

### F5. Ownership column

Already handled in F1 — every task has an `owner` field shown in the PDF.

### F6. Soft CTA instead of hard sell

Changed in F3 — the page ends with "Need help implementing this roadmap? Schedule a call to discuss priorities." + Calendly link. No pricing on the assessment page. Pricing stays in the proposal email (separate document).

### Files changed
- `report_generator.py` — add _build_roadmap_page(), build_roadmap(), categorize_task()
- `deliver.py` — pass shadow_data to generate_pdf_report() for roadmap, call build_roadmap()

---

## CROSS-CUTTING FIXES

### X1. Communication log

Add to client_manager.py:
```python
def log_communication(client_id: str, comm_type: str, subject: str, recipient: str):
    """Log every email/alert sent to client for audit trail."""
    log_dir = _client_dir(client_id) / "communications"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "log.jsonl"
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": comm_type,  # "welcome_email", "task_digest", "alert", "call_agenda"
        "subject": subject,
        "recipient": recipient,
    }
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")
```

Call this from every email send: welcome, weekly digest, alerts, call agendas.

### X2. Portal task "Mark Done" button

In portal.html task section, add a "Done" button alongside the existing "Start" button:
```html
<button hx-post="/portal/{{client_id}}/task/{{task.id}}/resolve"
        hx-swap="outerHTML"
        class="btn btn-sm btn-success">
  ✓ Done
</button>
```

Add endpoint in main.py:
```python
@app.post("/portal/{client_id}/task/{task_id}/resolve")
async def resolve_task(client_id: str, task_id: str):
    client_manager.update_task_status(client_id, task_id, "resolved")
    return HTMLResponse('<span class="badge bg-success">Resolved ✓</span>')
```

---

## IMPLEMENTATION PRIORITY ORDER

| # | Item | Blocks | Effort | Impact |
|---|------|--------|--------|--------|
| 0 | **Fix OUTPUT_DIR path** (deliver.py) | Everything on Railway | 5 min | Critical |
| 0.5 | **Findings → Tasks pipeline** | C, F, B | 1 hour | Critical |
| 1 | **CLI overrides + missing profiles** (A) | E (dashboard) | 2 hours | High |
| 2 | **90-Day Roadmap PDF page** (F) | — | 3-4 hours | High (sales conversion) |
| 3 | **Weekly task emails** (C) | — | 3 hours | High (retention) |
| 4 | **Dashboard onboarding** (E) | — | 4-5 hours | Medium (team scale) |
| 5 | **Monthly call agenda** (B) | — | 2 hours | Medium (operator efficiency) |
| 6 | **AI Governance report** (D) | — | 3-4 hours | Medium (new product) |
| X | **Cross-cutting** (comm log, portal task button) | — | 1 hour | Low (quality) |

**Total: ~20-22 hours of development**

Items 0, 0.5, 1 are blockers — do first. Items 2-3 are the highest business impact. Items 4-6 are scaling/efficiency plays.
