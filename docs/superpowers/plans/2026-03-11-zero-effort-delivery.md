# Zero-Effort Delivery System Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all product gaps so client effort = 0 beyond a sales call, operator effort = 1 click + 30 min/month per retainer.

**Architecture:** Patch existing deliver.py, scheduler.py, client_manager.py, report_generator.py, main.py, and prompt_library.py. No new services — all changes within existing FastAPI + file-based architecture. Add tests alongside implementation.

**Tech Stack:** Python 3, FastAPI, ReportLab, APScheduler, Anthropic Claude API, HIBP API, Jinja2

**Spec:** `docs/superpowers/specs/2026-03-11-zero-effort-delivery-design.md`

---

## File Structure

**Modified files:**
- `deliver.py` — Fix OUTPUT_DIR, add overrides to run_questionnaire(), add CLI args, add task generation at onboarding
- `client_manager.py` — Add update_field(), find_by_domain(), save_call_notes(), get_latest_call_notes(), log_communication(), verifiable field on add_task()
- `scheduler.py` — Extract _generate_tasks_from_findings() to be importable, add weekly task digest job, add monthly call agenda job
- `main.py` — Add onboard endpoint, call-notes endpoint, client update endpoint, portal task resolve endpoint
- `agents/report_generator.py` — Add 90-day roadmap page (Page 10), add AI governance mini-report
- `prompt_library.py` — Add P60_MONTHLY_CALL_AGENDA, P61_WEEKLY_TASK_DIGEST prompts

**New files:**
- `tests/test_client_manager.py` — Unit tests for client_manager additions
- `tests/test_deliver.py` — Unit tests for deliver.py fixes
- `tests/test_roadmap.py` — Unit tests for roadmap generation
- `tests/__init__.py` — Test package init

---

## Chunk 1: Blockers (Gap 0 + Gap 0.5)

### Task 1: Fix OUTPUT_DIR hardcoded path in deliver.py

**Files:**
- Modify: `deliver.py:48`
- Create: `tests/__init__.py`
- Create: `tests/test_deliver.py`

- [ ] **Step 1: Write the failing test**

Create `tests/__init__.py` (empty) and `tests/test_deliver.py`:

```python
"""Tests for deliver.py fixes."""
import os
import sys
import importlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_output_dir_respects_data_dir_env(tmp_path, monkeypatch):
    """OUTPUT_DIR must use DATA_DIR env var, not hardcoded path."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    # Force reimport to pick up new env var
    if "deliver" in sys.modules:
        del sys.modules["deliver"]
    import deliver
    assert str(tmp_path) in str(deliver.OUTPUT_DIR), \
        f"OUTPUT_DIR should contain DATA_DIR path. Got: {deliver.OUTPUT_DIR}"
    assert deliver.OUTPUT_DIR == tmp_path / "client-deliverables"


def test_output_dir_defaults_to_cwd(monkeypatch):
    """Without DATA_DIR, OUTPUT_DIR defaults to ./client-deliverables."""
    monkeypatch.delenv("DATA_DIR", raising=False)
    if "deliver" in sys.modules:
        del sys.modules["deliver"]
    import deliver
    assert str(deliver.OUTPUT_DIR).endswith("client-deliverables")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_deliver.py -v`
Expected: FAIL — `test_output_dir_respects_data_dir_env` fails because OUTPUT_DIR ignores DATA_DIR.

- [ ] **Step 3: Fix OUTPUT_DIR in deliver.py**

In `deliver.py`, replace line 48:
```python
# OLD:
OUTPUT_DIR = Path("./client-deliverables")
OUTPUT_DIR.mkdir(exist_ok=True)

# NEW:
DATA_DIR = Path(os.getenv("DATA_DIR", "."))
OUTPUT_DIR = DATA_DIR / "client-deliverables"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_deliver.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/__init__.py tests/test_deliver.py deliver.py
git commit -m "fix: OUTPUT_DIR uses DATA_DIR env var instead of hardcoded path"
```

---

### Task 2: Make _generate_tasks_from_findings importable from deliver.py

**Files:**
- Modify: `scheduler.py:452-469`

The function `_generate_tasks_from_findings()` in scheduler.py is already module-level (not a method on a class), so it's importable as `from scheduler import _generate_tasks_from_findings`. No code change needed to the function itself.

However, the function imports `client_manager` internally. Verify this import works when called from deliver.py context.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_deliver.py`:

```python
def test_generate_tasks_from_findings_importable():
    """scheduler._generate_tasks_from_findings must be importable."""
    from scheduler import _generate_tasks_from_findings
    assert callable(_generate_tasks_from_findings)
```

- [ ] **Step 2: Run test to verify it passes (this is a verification, not TDD)**

Run: `python3 -m pytest tests/test_deliver.py::test_generate_tasks_from_findings_importable -v`
Expected: PASS (function already exists and is importable)

- [ ] **Step 3: Commit (no code change, just test)**

```bash
git add tests/test_deliver.py
git commit -m "test: verify _generate_tasks_from_findings is importable"
```

---

### Task 3: Call task generation at end of full_delivery()

**Files:**
- Modify: `deliver.py:826-836` (after "Step 6: Save raw data")

- [ ] **Step 1: Write the failing test**

Add to `tests/test_deliver.py`:

```python
from unittest.mock import patch, MagicMock


def test_full_delivery_generates_tasks(tmp_path, monkeypatch):
    """full_delivery() must call _generate_tasks_from_findings after scan."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    # Mock out all the heavy dependencies
    mock_scan = MagicMock(return_value={
        "domain": "test.com",
        "company_name": "Test Corp",
        "archer": {"findings": [
            {"title": "Missing DMARC", "severity": "HIGH", "category": "email_security",
             "description": "No DMARC record", "fix": "Add DMARC record"}
        ], "score": {"total": 45, "grade": "D", "label": "POOR", "breakdown": {}}},
        "score": 45, "grade": "D", "scan_date": "2026-01-01",
    })
    mock_questionnaire = MagicMock(return_value={
        "profile": {"gaps": [], "applicable_frameworks": [], "risk_score": 50,
                     "industry": "CPA", "employee_range": "11-25", "sensitive_data": []},
        "compliance": {},
    })
    mock_pdf = MagicMock(return_value=str(tmp_path / "report.pdf"))
    mock_proposal = MagicMock(return_value="Proposal text")
    mock_gen_tasks = MagicMock()

    with patch("deliver.run_scan", mock_scan), \
         patch("deliver.run_questionnaire", mock_questionnaire), \
         patch("deliver.generate_pdf_report", mock_pdf), \
         patch("deliver.generate_proposal", mock_proposal), \
         patch("deliver._generate_onboard_tasks", mock_gen_tasks):
        if "deliver" in sys.modules:
            del sys.modules["deliver"]
        import deliver
        deliver.OUTPUT_DIR = tmp_path / "client-deliverables"
        deliver.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        deliver.full_delivery("test.com", company_name="Test Corp", no_ai=True)

    mock_gen_tasks.assert_called_once()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_deliver.py::test_full_delivery_generates_tasks -v`
Expected: FAIL — `_generate_onboard_tasks` doesn't exist yet.

- [ ] **Step 3: Add task generation to deliver.py**

Add a new function and call it at end of `full_delivery()`, right after the raw data save (after line 835):

```python
def _generate_onboard_tasks(scan_data, forge_data):
    """Generate remediation tasks from scan findings + compliance gaps at onboarding."""
    from scheduler import _generate_tasks_from_findings
    import client_manager

    domain = scan_data.get("domain", "")
    client_id = domain.replace(".", "_")

    # Check if client exists in client_manager
    client = client_manager.get_client(client_id)
    if not client:
        return

    # Tasks from scan findings
    findings = scan_data.get("archer", {}).get("findings", [])
    if findings:
        _generate_tasks_from_findings(client_id, findings)

    # Tasks from compliance gaps (manual — not scannable, use verifiable="manual")
    gaps = forge_data.get("profile", {}).get("gaps", [])
    frameworks = forge_data.get("profile", {}).get("applicable_frameworks", [])
    for gap in gaps:
        client_manager.add_task(
            client_id=client_id,
            title=gap,
            severity="HIGH",
            category="Compliance",
            description=f"Required by {', '.join(frameworks[:2])}",
            fix=f"CyberComply provides this — review and adopt the {gap} document",
            verifiable="manual",
        )
```

Add call at end of `full_delivery()`, after the raw data save block (after line 835):

```python
    # Step 7: Generate remediation tasks from findings
    _generate_onboard_tasks(scan_data, forge_data)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_deliver.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add deliver.py tests/test_deliver.py
git commit -m "feat: generate remediation tasks at onboarding (findings + compliance gaps)"
```

---

## Chunk 2: Client Manager Additions

### Task 4: Add update_field() to client_manager.py

**Files:**
- Modify: `client_manager.py`
- Create: `tests/test_client_manager.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_client_manager.py`:

```python
"""Tests for client_manager additions."""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_update_field(tmp_path, monkeypatch):
    """update_field() should update a single field in client profile."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    # Force reimport
    if "client_manager" in sys.modules:
        del sys.modules["client_manager"]
    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"

    client_manager.create_client("test_com", "Test Corp", "test.com")
    result = client_manager.update_field("test_com", "tech_stack", ["Microsoft 365"])
    assert result is True

    profile = client_manager.get_client("test_com")
    assert profile["tech_stack"] == ["Microsoft 365"]


def test_update_field_nonexistent_client(tmp_path, monkeypatch):
    """update_field() returns False for non-existent client."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    if "client_manager" in sys.modules:
        del sys.modules["client_manager"]
    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"

    result = client_manager.update_field("nonexistent", "tech_stack", [])
    assert result is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_client_manager.py -v`
Expected: FAIL — `update_field` doesn't exist.

- [ ] **Step 3: Implement update_field()**

Add to `client_manager.py` after `get_client()` (after line 129):

```python
def update_field(client_id: str, field: str, value) -> bool:
    """Update a single field in client profile."""
    profile = _load_profile(client_id)
    if not profile.get("client_id"):
        return False
    profile[field] = value
    _save_profile(client_id, profile)
    return True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_client_manager.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add client_manager.py tests/test_client_manager.py
git commit -m "feat: add update_field() to client_manager"
```

---

### Task 5: Add find_by_domain() to client_manager.py

**Files:**
- Modify: `client_manager.py`
- Modify: `tests/test_client_manager.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_client_manager.py`:

```python
def test_find_by_domain(tmp_path, monkeypatch):
    """find_by_domain() should find client by domain name."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    if "client_manager" in sys.modules:
        del sys.modules["client_manager"]
    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"

    client_manager.create_client("test_com", "Test Corp", "test.com")
    result = client_manager.find_by_domain("test.com")
    assert result is not None
    assert result["company_name"] == "Test Corp"


def test_find_by_domain_not_found(tmp_path, monkeypatch):
    """find_by_domain() returns None when no match."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    if "client_manager" in sys.modules:
        del sys.modules["client_manager"]
    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"

    result = client_manager.find_by_domain("nonexistent.com")
    assert result is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_client_manager.py::test_find_by_domain -v`
Expected: FAIL — `find_by_domain` doesn't exist.

- [ ] **Step 3: Implement find_by_domain()**

Add to `client_manager.py` after `update_field()`:

```python
def find_by_domain(domain: str) -> Optional[dict]:
    """Find a client by their domain. Returns profile or None."""
    if not CLIENTS_DIR.exists():
        return None
    for d in CLIENTS_DIR.iterdir():
        if d.is_dir() and (d / "profile.json").exists():
            profile = json.loads((d / "profile.json").read_text())
            if profile.get("domain") == domain:
                return profile
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_client_manager.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add client_manager.py tests/test_client_manager.py
git commit -m "feat: add find_by_domain() to client_manager"
```

---

### Task 6: Add call notes storage to client_manager.py

**Files:**
- Modify: `client_manager.py`
- Modify: `tests/test_client_manager.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_client_manager.py`:

```python
def test_save_and_get_call_notes(tmp_path, monkeypatch):
    """Call notes round-trip: save then retrieve."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    if "client_manager" in sys.modules:
        del sys.modules["client_manager"]
    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"

    client_manager.create_client("test_com", "Test Corp", "test.com")
    client_manager.save_call_notes("test_com", "Discussed DMARC fix timeline.")
    result = client_manager.get_latest_call_notes("test_com")
    assert "Discussed DMARC fix timeline" in result


def test_get_call_notes_first_month(tmp_path, monkeypatch):
    """First month has no notes — returns default message."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    if "client_manager" in sys.modules:
        del sys.modules["client_manager"]
    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"

    client_manager.create_client("test_com", "Test Corp", "test.com")
    result = client_manager.get_latest_call_notes("test_com")
    assert "First month" in result or "no previous" in result.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_client_manager.py::test_save_and_get_call_notes -v`
Expected: FAIL

- [ ] **Step 3: Implement save_call_notes() and get_latest_call_notes()**

Add to `client_manager.py`:

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
    return notes[-1]["notes"] if notes else "First month — no previous call notes."
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_client_manager.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add client_manager.py tests/test_client_manager.py
git commit -m "feat: add call notes storage to client_manager"
```

---

### Task 7: Add communication log to client_manager.py

**Files:**
- Modify: `client_manager.py`
- Modify: `tests/test_client_manager.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_client_manager.py`:

```python
def test_log_communication(tmp_path, monkeypatch):
    """log_communication() writes to JSONL file."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    if "client_manager" in sys.modules:
        del sys.modules["client_manager"]
    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"

    client_manager.create_client("test_com", "Test Corp", "test.com")
    client_manager.log_communication("test_com", "welcome_email", "Welcome to CyberComply", "john@test.com")

    log_file = tmp_path / "clients" / "test_com" / "communications" / "log.jsonl"
    assert log_file.exists()
    entry = json.loads(log_file.read_text().strip())
    assert entry["type"] == "welcome_email"
    assert entry["recipient"] == "john@test.com"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_client_manager.py::test_log_communication -v`
Expected: FAIL

- [ ] **Step 3: Implement log_communication()**

Add to `client_manager.py`:

```python
def log_communication(client_id: str, comm_type: str, subject: str, recipient: str):
    """Log every email/alert sent to client for audit trail."""
    log_dir = _client_dir(client_id) / "communications"
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / "log.jsonl"
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": comm_type,
        "subject": subject,
        "recipient": recipient,
    }
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_client_manager.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add client_manager.py tests/test_client_manager.py
git commit -m "feat: add communication log to client_manager"
```

---

### Task 8: Add verifiable field to add_task() and magic link auto-refresh

**Files:**
- Modify: `client_manager.py:188-205` (add_task)
- Modify: `client_manager.py:99-107` (verify_magic_token)
- Modify: `tests/test_client_manager.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_client_manager.py`:

```python
def test_add_task_with_verifiable_field(tmp_path, monkeypatch):
    """add_task() should accept and store verifiable field."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    if "client_manager" in sys.modules:
        del sys.modules["client_manager"]
    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"

    client_manager.create_client("test_com", "Test Corp", "test.com")
    task = client_manager.add_task("test_com", "Adopt WISP", "HIGH", "Compliance",
                                    "Sign and distribute", "Review document", verifiable="manual")
    assert task["verifiable"] == "manual"

    task2 = client_manager.add_task("test_com", "Fix DMARC", "CRITICAL", "Email",
                                     "Add DMARC record", "Add DNS record")
    assert task2["verifiable"] == "auto"  # default


def test_magic_link_auto_refresh(tmp_path, monkeypatch):
    """Magic link should auto-extend if close to expiry."""
    from datetime import datetime, timedelta
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    if "client_manager" in sys.modules:
        del sys.modules["client_manager"]
    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"

    client_manager.create_client("test_com", "Test Corp", "test.com")
    token = client_manager.generate_magic_link("test_com")

    # Use update_field to set expiry close to now (within 2 days)
    client_manager.update_field("test_com", "magic_token_expires",
                                (datetime.utcnow() + timedelta(days=1)).isoformat())

    # Verify should succeed AND extend the expiry
    assert client_manager.verify_magic_token("test_com", token) is True

    # Check that expiry was extended
    profile_after = client_manager.get_client("test_com")
    new_expires = datetime.fromisoformat(profile_after["magic_token_expires"])
    assert (new_expires - datetime.utcnow()).days >= 5  # Extended to 7 days
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_client_manager.py::test_add_task_with_verifiable_field tests/test_client_manager.py::test_magic_link_auto_refresh -v`
Expected: FAIL

- [ ] **Step 3: Implement changes**

In `client_manager.py`, update `add_task()` (around line 188):

```python
def add_task(client_id: str, title: str, severity: str, category: str,
             description: str = "", fix: str = "", verifiable: str = "auto") -> dict:
    tasks = get_tasks(client_id)
    task = {
        "id": f"task_{len(tasks)+1:03d}",
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "fix": fix,
        "verifiable": verifiable,
        "status": "open",
        "created_at": date.today().isoformat(),
        "due_date": (date.today() + timedelta(days=30)).isoformat(),
        "resolved_at": None,
    }
    tasks.append(task)
    save_tasks(client_id, tasks)
    return task
```

Update `verify_magic_token()` (around line 99):

```python
def verify_magic_token(client_id: str, token: str) -> bool:
    profile = _load_profile(client_id)
    stored = profile.get("magic_token", "")
    expires = profile.get("magic_token_expires", "")
    if not stored or stored != token:
        return False
    if expires and datetime.fromisoformat(expires) < datetime.utcnow():
        return False
    # Auto-extend if close to expiry (within 2 days)
    if expires:
        exp_dt = datetime.fromisoformat(expires)
        if (exp_dt - datetime.utcnow()).days < 2:
            profile["magic_token_expires"] = (datetime.utcnow() + timedelta(days=7)).isoformat()
            _save_profile(client_id, profile)
    return True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_client_manager.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add client_manager.py tests/test_client_manager.py
git commit -m "feat: verifiable field on tasks + magic link auto-refresh"
```

---

## Chunk 3: CLI Overrides (Gap A)

### Task 9: Add overrides parameter to run_questionnaire()

**Files:**
- Modify: `deliver.py:166-185`
- Modify: `tests/test_deliver.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_deliver.py`:

```python
def test_run_questionnaire_accepts_overrides(monkeypatch):
    """run_questionnaire() should merge overrides into profile data."""
    # Mock GuardianAgent
    mock_guardian = MagicMock()
    mock_guardian.process_questionnaire = MagicMock(return_value={
        "risk_score": 50, "applicable_frameworks": ["NIST CSF"], "gaps": [],
        "industry": "CPA", "employee_range": "1-10", "sensitive_data": [],
    })
    mock_guardian.get_compliance_status = MagicMock(return_value={})

    with patch("deliver.GuardianAgent", return_value=mock_guardian):
        if "deliver" in sys.modules:
            del sys.modules["deliver"]
        from deliver import run_questionnaire
        result = run_questionnaire("Test Corp", "cpa", overrides={"q3": "1-10", "q7": "Yes — for all users"})

    # Verify the overrides were passed to process_questionnaire
    call_args = mock_guardian.process_questionnaire.call_args[0][0]
    assert call_args["q3"] == "1-10"
    assert call_args["q7"] == "Yes — for all users"
    assert call_args["q1"] == "Test Corp"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_deliver.py::test_run_questionnaire_accepts_overrides -v`
Expected: FAIL — `run_questionnaire` doesn't accept `overrides` param.

- [ ] **Step 3: Update run_questionnaire()**

In `deliver.py`, change `run_questionnaire()` at line 166:

```python
def run_questionnaire(company_name, industry="cpa", overrides=None):
    """Run GUARDIAN questionnaire with quick industry profile."""
    from agents.guardian_agent import GuardianAgent

    profile_data = QUICK_PROFILES.get(industry, QUICK_PROFILES["cpa"]).copy()
    profile_data["q1"] = company_name
    if overrides:
        profile_data.update(overrides)

    print(f"\n🏗  GUARDIAN processing questionnaire for {company_name} ({industry})...")
    forge = GuardianAgent()
    profile = forge.process_questionnaire(profile_data)
    compliance = forge.get_compliance_status(profile)

    print(f"  Risk Score: {profile.get('risk_score', 'N/A')}")
    print(f"  Frameworks: {', '.join(profile.get('applicable_frameworks', []))}")
    print(f"  Gaps Found: {len(profile.get('gaps', []))}")

    return {
        "profile": profile,
        "compliance": compliance,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_deliver.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add deliver.py tests/test_deliver.py
git commit -m "feat: run_questionnaire() accepts overrides dict"
```

---

### Task 10: Build overrides from CLI args in full_delivery() + add new CLI flags

**Files:**
- Modify: `deliver.py:715-738` (full_delivery signature + body)
- Modify: `deliver.py:944-959` (CLI args)

- [ ] **Step 1: Update full_delivery() signature and override building**

In `deliver.py`, update `full_delivery()` signature at line 715:

```python
def full_delivery(domain, company_name=None, industry="cpa", no_ai=False, employee_count=15,
                  policies_mode=None, policy_single=None,
                  contact_name=None, contact_title=None, contact_email=None,
                  email_provider=None, mfa=None, has_wisp=None, has_irp=None,
                  cyber_insurance=None, no_fti=False, data_types=None):
```

Before the questionnaire call (around line 738), add override building:

```python
    # Build overrides from arguments
    overrides = {}
    if employee_count:
        ranges = [(10, "1-10"), (25, "11-25"), (50, "26-50"), (100, "51-100"), (250, "101-250")]
        for threshold, label in ranges:
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
        overrides["q12"] = data_types

    if no_fti:
        profile_data = QUICK_PROFILES.get(industry, QUICK_PROFILES["cpa"])
        default_types = profile_data.get("q12", [])
        overrides["q12"] = [t for t in default_types if "Tax" not in t and "FTI" not in t]

    # Step 2: Questionnaire (with overrides)
    forge_data = run_questionnaire(scan_data["company_name"], industry, overrides=overrides)
```

- [ ] **Step 2: Add new CLI args**

After the existing `--no-policies` arg (around line 959), add:

```python
    deliver.add_argument("--email-provider", choices=["microsoft", "google", "other"],
                        help="Email platform (microsoft, google, other)")
    deliver.add_argument("--mfa", choices=["full", "partial", "none", "unknown"],
                        help="MFA status")
    deliver.add_argument("--has-wisp", type=lambda x: x.lower() == "yes", metavar="yes/no",
                        help="Has Written Information Security Plan")
    deliver.add_argument("--has-irp", type=lambda x: x.lower() == "yes", metavar="yes/no",
                        help="Has Incident Response Plan")
    deliver.add_argument("--cyber-insurance", type=lambda x: x.lower() == "yes", metavar="yes/no",
                        help="Has cyber insurance")
    deliver.add_argument("--no-fti", action="store_true",
                        help="Client does not handle Federal Tax Information")
    deliver.add_argument("--data-types", nargs="+",
                        help="Override sensitive data types")
```

Update the CLI handler where `full_delivery()` is called (around line 990-994). Find the existing call:

```python
        full_delivery(args.domain, company_name=args.company, industry=args.industry,
                      no_ai=args.no_ai, employee_count=args.employees,
                      policies_mode=policies_mode, policy_single=args.policy,
                      contact_name=args.contact, contact_title=args.title,
                      contact_email=args.email)
```

Replace with:

```python
        full_delivery(args.domain, company_name=args.company, industry=args.industry,
                      no_ai=args.no_ai, employee_count=args.employees,
                      policies_mode=policies_mode, policy_single=args.policy,
                      contact_name=args.contact, contact_title=args.title,
                      contact_email=args.email,
                      email_provider=args.email_provider, mfa=args.mfa,
                      has_wisp=args.has_wisp, has_irp=args.has_irp,
                      cyber_insurance=args.cyber_insurance, no_fti=args.no_fti,
                      data_types=args.data_types)
```

- [ ] **Step 3: Run all tests**

Run: `python3 -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add deliver.py
git commit -m "feat: CLI overrides for employee count, MFA, email provider, WISP, IRP, insurance"
```

---

### Task 11: Add missing industry profiles to QUICK_PROFILES

**Files:**
- Modify: `deliver.py:108-163` (QUICK_PROFILES dict)

- [ ] **Step 1: Add missing profiles**

After `"govcon"` profile (around line 163), add:

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
    "nonprofit": {
        "q1": "", "q2": "Nonprofit Organization", "q3": "11-25",
        "q6": "Google Workspace", "q7": "No",
        "q12": ["Donor PII", "Employee PII"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["NIST CSF"],
        "q24": "Yes — some employees", "q25": "No", "q26": "I don't know",
        "q27": ["Employees sharing client data with AI"],
    },
    "education": {
        "q1": "", "q2": "Education", "q3": "26-50",
        "q6": "Google Workspace", "q7": "Yes — for some users",
        "q12": ["Student Records (FERPA)", "Employee PII"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["NIST CSF", "FERPA"],
        "q24": "Yes — some employees", "q25": "No", "q26": "I don't know",
        "q27": ["Employees sharing client data with AI"],
    },
    "manufacturing": {
        "q1": "", "q2": "Manufacturing", "q3": "51-100",
        "q6": "Microsoft 365", "q7": "No",
        "q12": ["Employee PII", "Trade Secrets / IP"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["NIST CSF", "CMMC"],
        "q24": "No", "q25": "No", "q26": "I don't know",
        "q27": ["Compliance violations from AI use"],
    },
    "real_estate": {
        "q1": "", "q2": "Real Estate", "q3": "11-25",
        "q6": "Google Workspace", "q7": "No",
        "q12": ["Client Financial Data", "Social Security Numbers"],
        "q15": "No", "q16": "No", "q17": "Never", "q18": "No", "q20": "No",
        "q21": ["FTC Safeguards Rule", "NIST CSF"],
        "q24": "Yes — some employees", "q25": "No", "q26": "I don't know",
        "q27": ["Employees sharing client data with AI"],
    },
```

- [ ] **Step 2: Verify industry choices list includes new profiles**

Run: `python3 -c "exec(open('deliver.py').read().split('choices=')[1].split(']')[0])" 2>/dev/null; grep -A2 'choices=' deliver.py | head -3`

The `--industry` choices list at deliver.py line 949 already includes these:
```python
choices=["cpa", "healthcare", "legal", "financial", "saas", "govcon",
         "government", "nonprofit", "education", "manufacturing", "real_estate", "general"]
```

- [ ] **Step 3: Run tests**

Run: `python3 -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add deliver.py
git commit -m "feat: add general, nonprofit, education, manufacturing, real_estate industry profiles"
```

---

## Chunk 4: 90-Day Roadmap PDF (Gap F)

### Task 12: Add roadmap building logic to report_generator.py

**Files:**
- Modify: `agents/report_generator.py`
- Create: `tests/test_roadmap.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_roadmap.py`:

```python
"""Tests for 90-day roadmap generation."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_build_roadmap_basic():
    """build_roadmap() should categorize findings into time buckets."""
    from agents.report_generator import build_roadmap

    findings = [
        {"title": "Missing DMARC record", "severity": "CRITICAL", "category": "email_security",
         "description": "No DMARC", "fix": "Add DMARC", "points": -10},
        {"title": "Add HSTS header", "severity": "HIGH", "category": "security_headers",
         "description": "Missing HSTS", "fix": "Add header", "points": -5},
    ]
    profile = {"gaps": ["Written Information Security Plan"], "applicable_frameworks": ["NIST CSF"]}

    result = build_roadmap(findings, profile, shadow_data=None, current_score=45)

    assert "week_1_2" in result
    assert "week_3_4" in result
    assert "month_2" in result
    assert "month_3" in result
    assert result["current_score"] == 45
    assert result["projected_score"] >= 45
    assert result["projected_score"] <= 100


def test_build_roadmap_category_caps():
    """Score projection must respect category caps (e.g., email max 35)."""
    from agents.report_generator import build_roadmap

    # 50 points of email findings — should cap at 35
    findings = [
        {"title": f"Email issue {i}", "severity": "HIGH", "category": "email_security",
         "description": "Issue", "fix": "Fix", "points": -10}
        for i in range(5)
    ]
    result = build_roadmap(findings, {"gaps": [], "applicable_frameworks": []},
                          shadow_data=None, current_score=20)

    # Max email gain is 35 points, so projected should be at most 55 (20+35)
    assert result["projected_score"] <= 55


def test_categorize_task():
    """categorize_task() should correctly identify effort level."""
    from agents.report_generator import categorize_task

    effort, owner = categorize_task("Enable MFA for all users")
    assert effort == "quick"

    effort, owner = categorize_task("Add HSTS header")
    assert effort == "it_task"

    effort, owner = categorize_task("Deploy endpoint protection solution")
    assert effort == "project"

    effort, owner = categorize_task("Written Information Security Plan")
    assert effort == "we_provide"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_roadmap.py -v`
Expected: FAIL — `build_roadmap` and `categorize_task` don't exist.

- [ ] **Step 3: Implement build_roadmap() and categorize_task()**

Add to the end of `agents/report_generator.py` (before `if __name__ == "__main__"`):

```python
# ─── 90-DAY ROADMAP ─────────────────────────────────────

CATEGORY_CAPS = {
    "email_security": 35, "ssl_tls": 15, "security_headers": 15,
    "network_exposure": 15, "technology": 10, "dns_security": 10,
}

TASK_EFFORT = {
    "quick": ["Reset password", "Enable MFA", "Add DMARC", "Add SPF", "Enable DKIM",
              "Sign WISP", "Sign IRP", "Sign AI Policy"],
    "it_task": ["Add HSTS header", "Add CSP header", "Update SSL", "Configure DNSSEC",
                "Add CAA record", "Update WordPress", "Close open port", "header"],
    "project": ["Deploy endpoint protection", "Implement network segmentation",
                "Replace firewall", "Set up SIEM", "Configure DLP"],
    "we_provide": ["WISP", "Incident Response Plan", "AI Acceptable Use Policy",
                   "Encryption Policy", "Password Policy", "Vendor Management Policy",
                   "Data Classification Policy", "Remote Work Policy", "Written Information Security Plan"],
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


def _estimate_time(effort):
    return {"quick": "2-10 minutes", "it_task": "30-60 minutes",
            "project": "Multi-day project", "we_provide": "30 min review"}[effort]


def build_roadmap(findings, profile, shadow_data, current_score):
    """Build 90-day roadmap from findings, profile gaps, and breach data."""
    week_1_2 = []
    week_3_4 = []
    month_2 = []
    month_3 = []

    # Breach remediation first (most urgent)
    if shadow_data and shadow_data.get("total_exposed", 0) > 0:
        breach_results = shadow_data.get("results", shadow_data.get("breaches", []))
        for breach in breach_results[:3]:
            email = breach.get("email", "unknown")
            week_1_2.append({
                "title": f"Reset password for {email}",
                "why": "Credentials found in a data breach",
                "how": "Reset in your email admin panel + enable MFA",
                "time": "2 minutes",
                "owner": "You (Managing Partner)",
                "effort": "quick",
                "points": 0,
                "category": "breach",
            })
    elif not shadow_data or shadow_data.get("total_exposed", 0) == 0:
        week_1_2.append({
            "title": "Run dark web credential scan",
            "why": "Check if employee passwords are exposed in data breaches",
            "how": "Provide your employee email list — we'll check for free",
            "time": "5 minutes (just send us the list)",
            "owner": "CyberComply",
            "effort": "we_provide",
            "points": 0,
            "category": "breach",
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

    # Policy gaps to week 3-4
    frameworks = profile.get("applicable_frameworks", [])
    for gap in profile.get("gaps", []):
        week_3_4.append({
            "title": f"Adopt {gap}",
            "why": f"Required by {', '.join(frameworks[:2])}" if frameworks else "Best practice",
            "how": "We provide this — just review and sign",
            "time": "30 min review",
            "owner": "CyberComply + You",
            "effort": "we_provide",
            "points": 0,
            "category": "compliance",
        })

    # Always add training to month 3
    month_3.append({
        "title": "Complete employee security awareness training",
        "why": "Required by most frameworks + reduces phishing risk by 70%",
        "time": "1 hour (all employees)",
        "owner": "CyberComply conducts, you schedule",
        "effort": "we_provide",
        "points": 0,
        "category": "training",
    })

    # Conservative score projection with category caps
    category_gains = {}
    all_items = week_1_2 + week_3_4 + month_2 + month_3
    for item in all_items:
        cat = item.get("category", "general")
        pts = item.get("points", 0)
        if cat not in category_gains:
            category_gains[cat] = 0
        category_gains[cat] += pts

    total_gain = 0
    for cat, gained in category_gains.items():
        cap = CATEGORY_CAPS.get(cat, 15)
        total_gain += min(gained, cap)

    projected = min(current_score + total_gain, 100)
    projected = (projected // 5) * 5  # Round to nearest 5

    return {
        "week_1_2": week_1_2[:5],
        "week_3_4": week_3_4[:4],
        "month_2": month_2[:5],
        "month_3": month_3[:4],
        "current_score": current_score,
        "projected_score": projected,
        "total_items": len(all_items),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_roadmap.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agents/report_generator.py tests/test_roadmap.py
git commit -m "feat: add build_roadmap() and categorize_task() for 90-day roadmap"
```

---

### Task 13: Add roadmap PDF page to report_generator.py

**Files:**
- Modify: `agents/report_generator.py:188-612` (generate_report function)

- [ ] **Step 1: Add roadmap styles and page builder**

Add new styles in `create_styles()` (around line 150, before `return styles`):

```python
    styles.add(ParagraphStyle(
        'TaskItem', fontName='Helvetica', fontSize=9,
        textColor=DARK_GRAY, spaceAfter=2, leading=12, leftIndent=12
    ))
    styles.add(ParagraphStyle(
        'ProjectionText', fontName='Helvetica-Bold', fontSize=12,
        textColor=ACCENT, alignment=TA_CENTER, spaceAfter=8
    ))
    styles.add(ParagraphStyle(
        'CTAText', fontName='Helvetica', fontSize=10,
        textColor=DARK_GRAY, alignment=TA_CENTER, spaceAfter=4
    ))
    styles.add(ParagraphStyle(
        'CTALink', fontName='Helvetica-Bold', fontSize=10,
        textColor=ACCENT, alignment=TA_CENTER, spaceAfter=4
    ))
```

Add the roadmap page builder function (before `generate_report()`). **Note:** `RED`, `ORANGE`, `YELLOW`, `GREEN`, `ACCENT`, etc. are already defined at the top of `report_generator.py` (lines 21-33) — do NOT redeclare them:

```python
def _build_roadmap_page(story, styles, roadmap_data):
    """Add 90-Day Security Roadmap as page 10."""
    story.append(PageBreak())
    story.append(Paragraph("YOUR 90-DAY SECURITY ROADMAP", styles['SectionHead']))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT, spaceAfter=12))

    sections = [
        ("WEEK 1-2: QUICK WINS", roadmap_data.get("week_1_2", []), RED),
        ("WEEK 3-4: POLICY FOUNDATION", roadmap_data.get("week_3_4", []), ORANGE),
        ("MONTH 2: TECHNICAL HARDENING", roadmap_data.get("month_2", []), YELLOW),
        ("MONTH 3: TRAINING & TESTING", roadmap_data.get("month_3", []), GREEN),
    ]

    for section_title, items, color in sections:
        if not items:
            continue
        story.append(Paragraph(section_title, styles['SubHead']))
        for item in items:
            task_text = (
                f"<b>&#x2610; {item['title']}</b>"
                f"<br/><i>{item.get('why', '')[:80]}</i>"
                f"<br/><font color='gray'>Owner: {item.get('owner', 'TBD')} | "
                f"Time: {item.get('time', 'TBD')}</font>"
            )
            story.append(Paragraph(task_text, styles['TaskItem']))
            story.append(Spacer(1, 4))
        story.append(Spacer(1, 8))

    # Score projection
    current = roadmap_data.get("current_score", 0)
    projected = roadmap_data.get("projected_score", 0)
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        f"<b>PROJECTED IMPROVEMENT:</b> {current}/100 &rarr; {projected}/100",
        styles['ProjectionText']
    ))

    # Soft CTA
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "Need help implementing this roadmap? Schedule a call to discuss priorities.",
        styles['CTAText']
    ))
    story.append(Paragraph(
        '<link href="https://calendly.com/security-cybercomply/30min">calendly.com/security-cybercomply/30min</link>',
        styles['CTALink']
    ))
```

- [ ] **Step 2: Wire roadmap into generate_report()**

In `generate_report()`, add `roadmap_data` parameter and call the builder.

Update the function signature (line 188):

```python
def generate_report(scan_data: dict, output_path: str = "security_report.pdf", roadmap_data: dict = None):
```

Before the `doc.build()` call (around line 610), insert:

```python
    # ═══ PAGE 10: 90-DAY ROADMAP (optional) ═══
    if roadmap_data:
        _build_roadmap_page(story, styles, roadmap_data)
```

- [ ] **Step 3: Wire roadmap into deliver.py full_delivery()**

In `deliver.py`, in `full_delivery()`, before the PDF generation (around line 756), add:

```python
    # Build roadmap data for PDF
    roadmap_data = None
    try:
        from agents.report_generator import build_roadmap
        shadow_data = None  # Shadow scan is optional; build_roadmap() handles the absent-data case gracefully
        roadmap_data = build_roadmap(
            scan_data["archer"].get("findings", []),
            forge_data["profile"],
            shadow_data,
            scan_data["score"],
        )
    except Exception as e:
        print(f"  ⚠️  Roadmap generation failed: {e}")
```

Update the `generate_pdf_report` call to pass `roadmap_data`:

```python
    pdf_path = generate_pdf_report(scan_data, forge_data, client_dir,
                                    executive_summary=executive_summary,
                                    roadmap_data=roadmap_data)
```

Also update `generate_pdf_report()` in deliver.py to accept and pass `roadmap_data`:

Find `def generate_pdf_report(` and add `roadmap_data=None` parameter. Then pass it to `generate_report()`:

```python
    report_path = generate_report(report_data, str(pdf_path), roadmap_data=roadmap_data)
```

- [ ] **Step 4: Run all tests**

Run: `python3 -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agents/report_generator.py deliver.py
git commit -m "feat: add 90-day security roadmap as PDF page 10"
```

---

## Chunk 5: Prompts + Scheduler Jobs (Gaps B + C)

### Task 14: Add P60_MONTHLY_CALL_AGENDA prompt

**Files:**
- Modify: `prompt_library.py`

- [ ] **Step 1: Add prompt**

Add to `prompt_library.py` after the last PROMPTS entry:

```python
PROMPTS["P60_MONTHLY_CALL_AGENDA"] = {
    "name": "Monthly Call Agenda",
    "system": "You are a virtual CISO preparing a monthly client call agenda. Be specific, data-driven, and actionable. Keep it to one page. Use plain language a business owner understands.",
    "user": """Generate a 1-page monthly call prep for {company_name}.

SCORE: {current_score}/100 ({current_grade}) — was {previous_score}/100 ({previous_grade}) last month
SCORE CHANGE: {score_delta} points
RESOLVED TASKS THIS MONTH: {resolved_tasks}
NEW ALERTS THIS MONTH: {new_alerts}
OPEN TASKS (top 5): {open_tasks}
THREAT INTEL: {threat_intel}
COMPLIANCE STATUS: {compliance_status}
CALL NOTES FROM LAST MONTH: {previous_notes}

Format as sections:
1. SCORE CHANGE (celebrate improvement or explain decline)
2. WINS THIS MONTH (resolved tasks, auto-verified fixes)
3. NEW ISSUES (new findings or alerts since last month)
4. TOP 5 OPEN TASKS (with suggested priority)
5. THREAT INTEL (relevant CISA alerts for their tech stack)
6. RECOMMENDED DISCUSSION TOPICS
7. ACTION ITEMS FOR NEXT MONTH""",
}

PROMPTS["P60_MONTHLY_CALL_AGENDA_FIRST"] = {
    "name": "Monthly Call Agenda (First Month)",
    "system": "You are a virtual CISO preparing the first monthly call agenda for a new client. Be welcoming and educational. Explain what each metric means. Keep it to one page.",
    "user": """Generate a first-month call prep for {company_name}.

BASELINE SCORE: {current_score}/100 ({current_grade})
TOTAL FINDINGS: {total_findings}
CRITICAL FINDINGS: {critical_findings}
OPEN TASKS: {open_tasks}
COMPLIANCE STATUS: {compliance_status}

This is the FIRST call — the client just received their initial assessment. Format as:
1. WELCOME & WHAT WE'VE DONE (scan, report, policies delivered)
2. BASELINE SCORE EXPLAINED (what the number means, where they rank)
3. TOP FINDINGS WALKTHROUGH (explain top 3-5 in plain language)
4. QUICK WINS FOR THIS MONTH (what they can do in the next 30 days)
5. WHAT HAPPENS NEXT (weekly emails, auto-monitoring, next month's call)
6. Q&A TOPICS TO PREPARE FOR""",
}
```

- [ ] **Step 2: Verify prompt loads**

Run: `python3 -c "from prompt_library import PROMPTS; assert 'P60_MONTHLY_CALL_AGENDA' in PROMPTS; print('OK')"`
Expected: "OK"

- [ ] **Step 3: Commit**

```bash
git add prompt_library.py
git commit -m "feat: add P60_MONTHLY_CALL_AGENDA prompt (regular + first month)"
```

---

### Task 15: Add P61_WEEKLY_TASK_DIGEST prompt

**Files:**
- Modify: `prompt_library.py`

- [ ] **Step 1: Add prompt**

Add to `prompt_library.py`:

```python
PROMPTS["P61_WEEKLY_TASK_DIGEST"] = {
    "name": "Weekly Task Digest",
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

When writing HOW instructions:
- If email_provider is "Microsoft 365": use admin.microsoft.com paths
- If email_provider is "Google Workspace": use admin.google.com paths
- If email_provider is "Other": say "Contact your email administrator"
- For DNS tasks: say "Contact your domain registrar or IT provider"
- For web server tasks: say "Contact your web developer or hosting provider"

Format: Greeting → grouped by severity (CRITICAL/HIGH/MEDIUM) → each task has WHY (1 line), HOW (step-by-step for their platform), TIME estimate → score projection → sign-off.""",
}
```

- [ ] **Step 2: Verify prompt loads**

Run: `python3 -c "from prompt_library import PROMPTS; assert 'P61_WEEKLY_TASK_DIGEST' in PROMPTS; print('OK')"`
Expected: "OK"

- [ ] **Step 3: Commit**

```bash
git add prompt_library.py
git commit -m "feat: add P61_WEEKLY_TASK_DIGEST prompt"
```

---

### Task 16: Add weekly task digest job to scheduler.py

**Files:**
- Modify: `scheduler.py`

- [ ] **Step 1: Add send_weekly_task_digest() function**

Add after `run_phishing_campaign()` (around line 430):

```python
def send_weekly_task_digest():
    """Monday 10am UTC: send task digest email to retainer clients."""
    import client_manager

    clients = client_manager.list_active_clients()

    for client in clients:
        try:
            client_id = client["client_id"]
            tier_config = client_manager.get_tier_config(client.get("tier", "assessment"))
            if not tier_config.get("tasks"):
                continue

            # Check frequency preference
            freq = client.get("task_email_frequency", "weekly")
            if freq == "paused":
                continue
            if freq == "biweekly" and date.today().isocalendar()[1] % 2 != 0:
                continue  # Only send on even-numbered weeks
            if freq == "monthly" and date.today().day > 7:
                continue  # Only send on first Monday of the month

            tasks = client_manager.get_tasks(client_id)
            open_tasks = [t for t in tasks if t["status"] in ("open", "in_progress")]
            if not open_tasks:
                continue

            # Sort by severity
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            open_tasks.sort(key=lambda t: sev_order.get(t.get("severity", "LOW"), 3))

            # Cap at 5 tasks
            MAX_TASKS = 5
            shown_tasks = open_tasks[:MAX_TASKS]
            overflow_count = len(open_tasks) - len(shown_tasks)

            # Recently resolved
            recently_resolved = [t for t in tasks if t.get("status") == "verified"
                                and t.get("resolved_at", "") >= date.today().isoformat()[:7]]

            # Get score
            current_score = client.get("current_score", 0)

            # Build email via AI prompt
            contact_email = client.get("contact_email", "")
            if not contact_email:
                continue

            try:
                from prompt_engine import call_prompt
                email_body = call_prompt(
                    "P61_WEEKLY_TASK_DIGEST",
                    company_name=client.get("company_name", ""),
                    email_provider=client.get("tech_stack", ["Microsoft 365"])[0] if client.get("tech_stack") else "Microsoft 365",
                    current_score=str(current_score),
                    projected_score=str(min(current_score + len(shown_tasks) * 5, 100)),
                    task_count=str(len(shown_tasks)),
                    tasks_json=json.dumps([{"title": t["title"], "severity": t["severity"],
                                           "fix": t.get("fix", ""), "category": t.get("category", "")}
                                          for t in shown_tasks], indent=2),
                    overflow_count=str(overflow_count),
                    recently_resolved=json.dumps([t["title"] for t in recently_resolved[:3]]) if recently_resolved else "None this week.",
                )
            except Exception as e:
                logger.error(f"Task digest AI failed for {client_id}: {e}")
                # Fallback: simple text
                task_list = "\n".join(f"- [{t['severity']}] {t['title']}" for t in shown_tasks)
                email_body = f"Weekly Security Tasks for {client.get('company_name', '')}\n\nYour top {len(shown_tasks)} tasks:\n{task_list}\n\n{overflow_count} more items in your portal."

            # Send email
            _send_task_digest_email(client, email_body, len(shown_tasks))

            # Log communication
            client_manager.log_communication(client_id, "task_digest",
                                            f"Weekly task digest ({len(shown_tasks)} tasks)",
                                            contact_email)

            logger.info(f"Task digest: {client_id} — {len(shown_tasks)} tasks sent")
        except Exception as e:
            logger.error(f"Task digest error for {client.get('client_id', '?')}: {e}")


def _send_task_digest_email(client, body, task_count):
    """Send the weekly task digest email."""
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
        logger.info(f"SMTP not configured — task digest skipped for {contact_email}")
        return

    subject = f"Your Weekly Security Tasks ({task_count} items) | {client.get('company_name', '')}"

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
        logger.info(f"Task digest sent to {contact_email}")
    except Exception as e:
        logger.error(f"Task digest email failed for {contact_email}: {e}")
```

- [ ] **Step 2: Register job in init_scheduler()**

In `init_scheduler()`, before `scheduler.start()`, add:

```python
    # Weekly Monday 10am UTC: task digest emails
    scheduler.add_job(send_weekly_task_digest, 'cron', day_of_week='mon', hour=10, id='weekly_task_digest')
```

Update the logger.info line to include the new job.

- [ ] **Step 3: Run tests**

Run: `python3 -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add scheduler.py
git commit -m "feat: add weekly task digest email job (Monday 10am UTC)"
```

---

### Task 17: Add monthly call agenda job to scheduler.py

**Files:**
- Modify: `scheduler.py`

- [ ] **Step 1: Add generate_call_agendas() function**

Add to `scheduler.py`:

```python
def generate_call_agendas():
    """1st of month at 7am UTC: generate call agendas for all retainer clients."""
    import client_manager

    clients = client_manager.list_active_clients()

    for client in clients:
        try:
            client_id = client["client_id"]
            tier_config = client_manager.get_tier_config(client.get("tier", "assessment"))
            if not tier_config.get("monthly_call"):
                continue

            # Gather data for agenda
            tasks = client_manager.get_tasks(client_id)
            open_tasks = [t for t in tasks if t["status"] in ("open", "in_progress")]
            resolved_this_month = [t for t in tasks if t.get("status") in ("resolved", "verified")
                                  and (t.get("resolved_at", "") or "")[:7] == date.today().strftime("%Y-%m")]

            alerts = client_manager.get_alerts(client_id, limit=10)
            new_alerts = [a for a in alerts if a.get("date", "")[:7] == date.today().strftime("%Y-%m")]

            scores = client.get("score_history", [])
            current_score = client.get("current_score", 0)
            current_grade = client.get("current_grade", "N/A")
            previous_score = scores[-2]["score"] if len(scores) >= 2 else None
            previous_grade = scores[-2]["grade"] if len(scores) >= 2 else "N/A"

            previous_notes = client_manager.get_latest_call_notes(client_id)

            # Choose prompt
            prompt_key = "P60_MONTHLY_CALL_AGENDA" if previous_score is not None else "P60_MONTHLY_CALL_AGENDA_FIRST"

            try:
                from prompt_engine import call_prompt

                if previous_score is not None:
                    agenda = call_prompt(
                        prompt_key,
                        company_name=client.get("company_name", ""),
                        current_score=str(current_score),
                        current_grade=current_grade,
                        previous_score=str(previous_score),
                        previous_grade=previous_grade,
                        score_delta=str(current_score - previous_score),
                        resolved_tasks=json.dumps([t["title"] for t in resolved_this_month[:5]]),
                        new_alerts=json.dumps([a.get("title", "") for a in new_alerts[:5]]),
                        open_tasks=json.dumps([{"title": t["title"], "severity": t["severity"]} for t in open_tasks[:5]]),
                        threat_intel="See FALCON alerts" if any(a.get("type") == "threat" for a in new_alerts) else "No new threats this month.",
                        compliance_status="Active monitoring",
                        previous_notes=previous_notes,
                    )
                else:
                    agenda = call_prompt(
                        prompt_key,
                        company_name=client.get("company_name", ""),
                        current_score=str(current_score),
                        current_grade=current_grade,
                        total_findings=str(len(open_tasks)),
                        critical_findings=str(sum(1 for t in open_tasks if t.get("severity") == "CRITICAL")),
                        open_tasks=json.dumps([{"title": t["title"], "severity": t["severity"]} for t in open_tasks[:5]]),
                        compliance_status="Initial baseline",
                    )
            except Exception as e:
                logger.error(f"Call agenda AI failed for {client_id}: {e}")
                agenda = f"Call Agenda for {client.get('company_name', '')}\nScore: {current_score}/100\nOpen tasks: {len(open_tasks)}\nSee dashboard for details."

            # Save agenda
            reports_dir = client_manager._client_dir(client_id) / "reports"
            reports_dir.mkdir(exist_ok=True)
            agenda_file = reports_dir / f"{date.today().isoformat()}-call-agenda.txt"
            agenda_file.write_text(agenda)

            # Email agenda to operator
            operator_email = os.getenv("OPERATOR_EMAIL", os.getenv("ADMIN_EMAIL", ""))
            if operator_email:
                _send_agenda_email(operator_email, client, agenda)
                client_manager.log_communication(client_id, "call_agenda",
                                                f"Monthly call agenda for {date.today().strftime('%B %Y')}",
                                                operator_email)

            logger.info(f"Call agenda: {client_id} — generated for {date.today().strftime('%B')}")
        except Exception as e:
            logger.error(f"Call agenda error for {client.get('client_id', '?')}: {e}")


def _send_agenda_email(operator_email, client, agenda):
    """Send call agenda to operator."""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    smtp_host = os.getenv("SMTP_HOST")
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    from_email = os.getenv("SMTP_FROM", "security@cybercomply.io")

    if not smtp_host or not smtp_user or not smtp_pass:
        return

    subject = f"Call Prep: {client.get('company_name', '')} — {date.today().strftime('%B %Y')}"

    msg = MIMEMultipart()
    msg["From"] = f"CyberComply <{from_email}>"
    msg["To"] = operator_email
    msg["Subject"] = subject
    msg.attach(MIMEText(agenda, "plain"))

    try:
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    except Exception as e:
        logger.error(f"Agenda email failed for {operator_email}: {e}")
```

- [ ] **Step 2: Register job in init_scheduler()**

Add before `scheduler.start()`:

```python
    # Monthly 1st at 7am UTC: generate call agendas (before monthly reports)
    scheduler.add_job(generate_call_agendas, 'cron', day=1, hour=7, id='call_agendas')
```

- [ ] **Step 3: Run tests**

Run: `python3 -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add scheduler.py
git commit -m "feat: add monthly call agenda generation job (1st of month 7am UTC)"
```

---

## Chunk 6: API Endpoints (Gaps E + X)

### Task 18: Add portal task resolve endpoint to main.py

**Files:**
- Modify: `main.py`

- [ ] **Step 1: Add endpoint**

Add to `main.py` in the portal routes section:

```python
@app.post("/portal/{client_id}/task/{task_id}/resolve")
async def resolve_portal_task(client_id: str, task_id: str, request: Request):
    """One-click task resolution from portal or email link."""
    # Auth: magic token (from email link) or JWT cookie (from portal session)
    token = request.query_params.get("token")
    jwt_cookie = request.cookies.get("portal_token")

    authenticated = False
    if token:
        authenticated = client_manager.verify_magic_token(client_id, token)
    elif jwt_cookie:
        jwt_client = client_manager.verify_jwt(jwt_cookie)
        authenticated = (jwt_client == client_id)

    if not authenticated:
        raise HTTPException(status_code=403, detail="Authentication required. Use magic link or log in to portal.")

    client_manager.update_task_status(client_id, task_id, "resolved")
    return HTMLResponse('<span class="badge bg-success">Resolved &#x2713;</span>')
```

- [ ] **Step 2: Add call notes endpoint**

```python
@app.post("/api/operator/call-notes/{client_id}")
async def save_call_notes_endpoint(client_id: str, request: Request):
    """Save notes after a monthly call."""
    body = await request.json()
    notes = body.get("notes", "")
    if not notes:
        raise HTTPException(status_code=400, detail="Notes required")
    client_manager.save_call_notes(client_id, notes)
    return {"status": "saved", "client_id": client_id}
```

- [ ] **Step 3: Add client update endpoint**

```python
@app.put("/api/operator/client/{client_id}")
async def update_client_endpoint(client_id: str, request: Request):
    """Update client profile fields."""
    body = await request.json()
    allowed_fields = ["tier", "contact_name", "contact_email", "contact_title",
                      "industry", "tech_stack", "employee_emails", "task_email_frequency"]
    updated = []
    for field in allowed_fields:
        if field in body:
            client_manager.update_field(client_id, field, body[field])
            updated.append(field)
    if not updated:
        raise HTTPException(status_code=400, detail="No valid fields to update")
    return {"status": "updated", "client_id": client_id, "updated_fields": updated}
```

- [ ] **Step 4: Verify import works**

Run: `python3 -c "import main; print(f'{len(main.app.routes)} routes')" 2>/dev/null || echo "Check imports"`
Expected: Shows route count (should be ~61+)

- [ ] **Step 5: Commit**

```bash
git add main.py
git commit -m "feat: add portal task resolve, call notes, and client update endpoints"
```

---

### Task 19: Add "Mark Done" button to portal.html

**Files:**
- Modify: `templates/portal.html`

- [ ] **Step 1: Update task row in portal template**

In `templates/portal.html`, find the task row section (around line 182-193). Update each task's action area to include a "Done" button:

Find the existing button/action in the task row and add alongside it:

```html
    {% for task in open_tasks[:8] %}
    <div class="task-row" id="task-{{ task.id }}">
      <div style="flex:1">
        <span class="sev sev-{{ task.severity|lower }}">{{ task.severity }}</span>
        <span style="margin-left:8px;font-size:.9rem">{{ task.title }}</span>
        {% if task.fix %}<div style="color:var(--muted);font-size:.8rem;margin-left:60px">Fix: {{ task.fix[:80] }}</div>{% endif %}
      </div>
      <button hx-post="/portal/{{ client.client_id }}/task/{{ task.id }}/resolve"
              hx-target="#task-{{ task.id }}"
              hx-swap="outerHTML"
              class="btn btn-sm btn-success"
              style="margin-left:8px;padding:4px 12px;background:var(--green);color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem">
        &#x2713; Done
      </button>
    </div>
    {% endfor %}
```

- [ ] **Step 2: Verify template renders**

Run: `python3 -c "from jinja2 import Environment, FileSystemLoader; e=Environment(loader=FileSystemLoader('templates')); t=e.get_template('portal.html'); print('Template OK')"`
Expected: "Template OK"

- [ ] **Step 3: Commit**

```bash
git add templates/portal.html
git commit -m "feat: add 'Done' button on portal tasks for one-click resolution"
```

---

### Task 20: Add tech_stack population from questionnaire in deliver.py

**Files:**
- Modify: `deliver.py`

- [ ] **Step 1: Add tech_stack builder helper**

Add to `deliver.py` after `_generate_onboard_tasks()`:

```python
def _build_tech_stack(profile):
    """Extract tech stack from questionnaire answers for threat intel filtering."""
    tech_stack = []
    email_provider = profile.get("email_provider", "")
    if not email_provider:
        # Derive from questionnaire q6
        q6 = profile.get("q6", profile.get("raw_answers", {}).get("q6", ""))
        if "Microsoft" in str(q6) or "365" in str(q6):
            tech_stack.extend(["Microsoft Exchange", "Microsoft 365", "Outlook"])
        elif "Google" in str(q6):
            tech_stack.extend(["Google Workspace", "Gmail"])
    else:
        if "microsoft" in email_provider.lower():
            tech_stack.extend(["Microsoft Exchange", "Microsoft 365", "Outlook"])
        elif "google" in email_provider.lower():
            tech_stack.extend(["Google Workspace", "Gmail"])
    return tech_stack
```

- [ ] **Step 2: Commit**

```bash
git add deliver.py
git commit -m "feat: extract tech_stack from questionnaire for threat intel filtering"
```

---

### Task 21: Final integration test

- [ ] **Step 1: Run all tests**

Run: `python3 -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 2: Verify main.py loads without errors**

Run: `python3 -c "import main; print(f'Routes: {len(main.app.routes)}')" 2>/dev/null || python3 -c "import main"`
Expected: Shows route count, no import errors

- [ ] **Step 3: Verify deliver.py CLI help works**

Run: `python3 deliver.py deliver --help`
Expected: Shows all new flags (--email-provider, --mfa, --has-wisp, --has-irp, --cyber-insurance, --no-fti, --data-types)

- [ ] **Step 4: Commit any remaining fixes**

```bash
git add deliver.py client_manager.py scheduler.py main.py agents/report_generator.py prompt_library.py templates/portal.html tests/
git commit -m "feat: zero-effort delivery system — all gaps fixed"
```

---

## Summary

| Task | Description | Files | Est. |
|------|-------------|-------|------|
| 1 | Fix OUTPUT_DIR | deliver.py | 5 min |
| 2 | Verify task import | scheduler.py | 2 min |
| 3 | Task gen at onboarding | deliver.py | 15 min |
| 4 | update_field() | client_manager.py | 10 min |
| 5 | find_by_domain() | client_manager.py | 10 min |
| 6 | Call notes storage | client_manager.py | 10 min |
| 7 | Communication log | client_manager.py | 10 min |
| 8 | Verifiable field + magic refresh | client_manager.py | 15 min |
| 9 | Questionnaire overrides | deliver.py | 10 min |
| 10 | CLI flags + override building | deliver.py | 20 min |
| 11 | New industry profiles | deliver.py | 10 min |
| 12 | Roadmap logic | report_generator.py | 20 min |
| 13 | Roadmap PDF page | report_generator.py + deliver.py | 25 min |
| 14 | Call agenda prompt | prompt_library.py | 5 min |
| 15 | Task digest prompt | prompt_library.py | 5 min |
| 16 | Weekly task digest job | scheduler.py | 25 min |
| 17 | Monthly call agenda job | scheduler.py | 25 min |
| 18 | API endpoints | main.py | 15 min |
| 19 | Portal Done button | portal.html | 5 min |
| 20 | Tech stack builder | deliver.py | 5 min |
| 21 | Integration test | all | 10 min |

**Total: ~4-5 hours of implementation**
