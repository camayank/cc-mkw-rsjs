#!/usr/bin/env python3
"""
CyberComply — Email Outreach Sequence Generator

Phase 1 workaround for automated email scheduling.
Generates the full 5-email follow-up sequence (P03-P07) for each prospect,
saved as dated files so you know exactly which to send on which day.

Usage:
  # Generate follow-ups for a single client (scan data must exist)
  python email_scheduler.py generate smithcpa.com -c "Smith CPA" -i cpa -e 15

  # Generate follow-ups for all clients in a batch CSV
  python email_scheduler.py batch clients.csv

  # List pending follow-ups due today
  python email_scheduler.py due

  # List all scheduled follow-ups
  python email_scheduler.py list
"""

from __future__ import annotations

import sys
import os
import json
import argparse
import logging
from datetime import datetime, date, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from prompt_engine import call_prompt, get_industry_context, get_total_cost
from prompt_library import INDUSTRY_CONTEXT

logger = logging.getLogger("email_scheduler")

OUTPUT_DIR = Path("outreach_emails")
SCHEDULE_FILE = Path("outreach_schedule.json")

# Follow-up sequence: (prompt_id, days_after_p03, label)
SEQUENCE = [
    ("P03_COLD_EMAIL_1", 0, "Email 1 — Security Alert"),
    ("P04_FOLLOWUP_DARKWEB", 3, "Email 2 — Dark Web Hook"),
    ("P05_FOLLOWUP_COMPLIANCE", 7, "Email 3 — Compliance Deadline"),
    ("P06_FOLLOWUP_INSURANCE", 14, "Email 4 — Insurance Hook"),
    ("P07_FOLLOWUP_PEER", 21, "Email 5 — Peer Comparison (Final)"),
]

BRAND = {
    "calendly": "https://calendly.com/cybercomply/security-review",
}


def _load_schedule() -> dict:
    if SCHEDULE_FILE.exists():
        try:
            return json.loads(SCHEDULE_FILE.read_text())
        except json.JSONDecodeError:
            pass
    return {}


def _save_schedule(schedule: dict):
    SCHEDULE_FILE.write_text(json.dumps(schedule, indent=2, default=str))


def _load_scan_data(client_dir: Path) -> dict | None:
    """Try to load scan_data.json from a client deliverables directory."""
    scan_file = client_dir / "scan_data.json"
    if scan_file.exists():
        return json.loads(scan_file.read_text())
    return None


def generate_sequence(
    domain: str,
    company_name: str,
    industry: str = "cpa",
    employee_count: int = 15,
    contact_name: str = None,
    contact_title: str = None,
    scan_data: dict = None,
    start_date: date = None,
):
    """
    Generate the full 5-email outreach sequence for one prospect.
    Saves emails as dated files and records schedule for tracking.
    """
    start_date = start_date or date.today()
    company_safe = company_name.replace(" ", "_").replace("&", "and")
    email_dir = OUTPUT_DIR / company_safe
    email_dir.mkdir(parents=True, exist_ok=True)

    # Get industry context
    ctx = get_industry_context(industry)
    data_types = ctx.get("data_types", "business data")
    frameworks = ctx.get("frameworks", "NIST CSF")
    industry_avg = ctx.get("industry_avg_score", 42)
    key_regulation = ctx.get("key_regulation", "")
    compliance_deadline = ctx.get("compliance_deadline", "")
    insurance_context = ctx.get("insurance_context", "")
    client_title = contact_title or ctx.get("client_title", "Decision Maker")
    contact = contact_name or client_title

    # Extract scan info
    score = 0
    grade = "F"
    findings = []
    breach_count = 0
    breach_details = "None found"

    if scan_data:
        scan = scan_data.get("scan", scan_data)
        archer = scan.get("archer", {})
        score_data = archer.get("score", {})
        score = score_data.get("total", 0)
        grade = score_data.get("grade", "F")
        findings = archer.get("findings", [])
        spectre = scan.get("spectre", archer.get("spectre", {}))
        breach_count = spectre.get("total_exposed", 0)
        breaches = spectre.get("breaches", [])
        if breaches:
            breach_details = "; ".join(
                f"{b.get('email', '?')} in {b.get('breach_name', '?')} ({b.get('breach_date', '?')})"
                for b in breaches[:5]
            )

    top_findings = [f.get("title", "Unknown") for f in findings[:3]]
    while len(top_findings) < 3:
        top_findings.append("N/A")

    # Sender info from .env
    sender_name = os.getenv("SENDER_NAME", "[YOUR NAME]")
    sender_title = os.getenv("SENDER_TITLE", "Cybersecurity Advisor")
    calendar_link = os.getenv("CALENDAR_LINK", BRAND["calendly"])

    schedule_entries = []
    generated = []

    for prompt_id, days_offset, label in SEQUENCE:
        send_date = start_date + timedelta(days=days_offset)
        filename = f"day{days_offset:02d}_{prompt_id.lower()}_{send_date.strftime('%Y%m%d')}.txt"
        filepath = email_dir / filename

        print(f"  Generating {label} (send: {send_date})...")

        try:
            if prompt_id == "P03_COLD_EMAIL_1":
                email_text = call_prompt(
                    prompt_id,
                    client_name=company_name,
                    company_name=company_name,
                    contact_name=contact,
                    contact_title=client_title,
                    industry=ctx.get("label", industry),
                    score=str(score),
                    grade=grade,
                    finding_1=top_findings[0],
                    finding_2=top_findings[1],
                    finding_3=top_findings[2],
                    breach_count=str(breach_count),
                    sender_name=sender_name,
                    sender_title=sender_title,
                    calendar_link=calendar_link,
                )
            elif prompt_id == "P04_FOLLOWUP_DARKWEB":
                email_text = call_prompt(
                    prompt_id,
                    client_name=company_name,
                    company_name=company_name,
                    contact_name=contact,
                    industry=ctx.get("label", industry),
                    data_types=data_types,
                    breach_count=str(breach_count),
                    breach_details=breach_details,
                    calendar_link=calendar_link,
                )
            elif prompt_id == "P05_FOLLOWUP_COMPLIANCE":
                email_text = call_prompt(
                    prompt_id,
                    client_name=company_name,
                    company_name=company_name,
                    contact_name=contact,
                    contact_title=client_title,
                    industry=ctx.get("label", industry),
                    key_regulation=key_regulation,
                    compliance_deadline=compliance_deadline,
                    calendar_link=calendar_link,
                )
            elif prompt_id == "P06_FOLLOWUP_INSURANCE":
                email_text = call_prompt(
                    prompt_id,
                    client_name=company_name,
                    company_name=company_name,
                    contact_name=contact,
                    industry=ctx.get("label", industry),
                    score=str(score),
                    insurance_context=insurance_context,
                    calendar_link=calendar_link,
                )
            elif prompt_id == "P07_FOLLOWUP_PEER":
                email_text = call_prompt(
                    prompt_id,
                    client_name=company_name,
                    company_name=company_name,
                    contact_name=contact,
                    industry=ctx.get("label", industry),
                    score=str(score),
                    industry_avg=str(industry_avg),
                    calendar_link=calendar_link,
                )
            else:
                continue

            # Add header with send instructions
            header = (
                f"{'='*60}\n"
                f"  {label}\n"
                f"  Company: {company_name}\n"
                f"  Contact: {contact} ({client_title})\n"
                f"  SEND DATE: {send_date.strftime('%A, %B %d, %Y')}\n"
                f"{'='*60}\n\n"
            )
            filepath.write_text(header + email_text)
            generated.append((label, send_date, filepath))

            schedule_entries.append({
                "prompt_id": prompt_id,
                "label": label,
                "send_date": send_date.isoformat(),
                "file": str(filepath),
                "status": "pending",
            })

        except Exception as e:
            print(f"    FAILED: {e}")
            logger.warning(f"Failed to generate {prompt_id} for {company_name}: {e}")

    # Save to schedule tracker
    schedule = _load_schedule()
    schedule[company_safe] = {
        "company_name": company_name,
        "domain": domain,
        "industry": industry,
        "contact": contact,
        "score": score,
        "start_date": start_date.isoformat(),
        "emails": schedule_entries,
    }
    _save_schedule(schedule)

    return generated


def generate_batch(csv_file: str):
    """Generate outreach sequences for all prospects in a CSV file."""
    results = []
    with open(csv_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            domain = parts[0]
            company = parts[1] if len(parts) > 1 else domain.split(".")[0].title()
            industry = parts[2] if len(parts) > 2 else "cpa"
            contact = parts[3] if len(parts) > 3 else None
            email_count = parts[4] if len(parts) > 4 else None

            print(f"\n{'='*60}")
            print(f"  Generating sequence for: {company} ({domain})")
            print(f"{'='*60}")

            # Try to load existing scan data
            company_safe = company.replace(" ", "_").replace("&", "and")
            scan_data = None
            for d in Path("client-deliverables").glob(f"{company_safe}_*"):
                sd = _load_scan_data(d)
                if sd:
                    scan_data = sd
                    print(f"  Found scan data in {d}")
                    break

            if not scan_data:
                print(f"  No scan data found — run 'python deliver.py deliver {domain}' first")
                print(f"  Generating with minimal data (score=0)...")

            generated = generate_sequence(
                domain=domain,
                company_name=company,
                industry=industry,
                contact_name=contact,
                scan_data=scan_data,
            )
            results.append((company, len(generated)))

    # Summary
    print(f"\n{'='*60}")
    print(f"  BATCH COMPLETE — {len(results)} prospects")
    print(f"{'='*60}")
    for company, count in results:
        print(f"  {company}: {count} emails generated")

    cost = get_total_cost()
    print(f"\n  AI cost: ${cost['total_cost']:.4f} ({cost['total_calls']} calls, {cost['cached_calls']} cached)")


def list_due(target_date: date = None):
    """List all emails due on a given date (default: today)."""
    target = target_date or date.today()
    schedule = _load_schedule()

    due_items = []
    for company_key, data in schedule.items():
        for email in data.get("emails", []):
            if email.get("status") == "pending":
                send_date = date.fromisoformat(email["send_date"])
                if send_date <= target:
                    due_items.append({
                        "company": data["company_name"],
                        "contact": data.get("contact", "?"),
                        "label": email["label"],
                        "send_date": email["send_date"],
                        "file": email["file"],
                        "overdue": (target - send_date).days,
                    })

    if not due_items:
        print(f"  No emails due on {target.strftime('%Y-%m-%d')}.")
        return

    print(f"\n{'='*60}")
    print(f"  EMAILS DUE — {target.strftime('%A, %B %d, %Y')}")
    print(f"{'='*60}")

    for item in sorted(due_items, key=lambda x: x["send_date"]):
        overdue = f" (OVERDUE {item['overdue']}d)" if item["overdue"] > 0 else ""
        print(f"\n  {item['company']} — {item['contact']}")
        print(f"  {item['label']}{overdue}")
        print(f"  File: {item['file']}")

    print(f"\n  Total: {len(due_items)} emails to send")
    print(f"  After sending, mark as sent: python email_scheduler.py sent \"{due_items[0]['company']}\" {due_items[0]['label'].split(' ')[1]}")


def list_all():
    """List entire outreach schedule."""
    schedule = _load_schedule()
    if not schedule:
        print("  No outreach sequences scheduled.")
        return

    print(f"\n{'='*60}")
    print(f"  OUTREACH SCHEDULE — {len(schedule)} prospects")
    print(f"{'='*60}")

    for company_key, data in schedule.items():
        score = data.get("score", "?")
        print(f"\n  {data['company_name']} ({data['domain']}) — Score: {score}")
        for email in data.get("emails", []):
            status = email.get("status", "pending")
            icon = "  " if status == "pending" else "  "
            send_date = email["send_date"]
            today = date.today()
            email_date = date.fromisoformat(send_date)
            if status == "sent":
                marker = "SENT"
            elif email_date <= today:
                marker = "DUE"
            else:
                marker = f"in {(email_date - today).days}d"
            print(f"    {icon} [{marker:>6}] {send_date} — {email['label']}")


def mark_sent(company_name: str, email_num: int):
    """Mark a specific email as sent."""
    schedule = _load_schedule()
    company_safe = company_name.replace(" ", "_").replace("&", "and")

    if company_safe not in schedule:
        # Try fuzzy match
        for key in schedule:
            if company_name.lower() in key.lower():
                company_safe = key
                break

    if company_safe not in schedule:
        print(f"  Company '{company_name}' not found in schedule.")
        return

    emails = schedule[company_safe].get("emails", [])
    idx = email_num - 1
    if 0 <= idx < len(emails):
        emails[idx]["status"] = "sent"
        emails[idx]["sent_date"] = date.today().isoformat()
        _save_schedule(schedule)
        print(f"  Marked as sent: {emails[idx]['label']} for {schedule[company_safe]['company_name']}")
    else:
        print(f"  Email #{email_num} not found (valid: 1-{len(emails)})")


# ─── CLI ──────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberComply — Email Outreach Sequence")
    subparsers = parser.add_subparsers(dest="command")

    # Generate for single prospect
    gen = subparsers.add_parser("generate", help="Generate 5-email sequence for one prospect")
    gen.add_argument("domain", help="Prospect domain")
    gen.add_argument("--company", "-c", required=True, help="Company name")
    gen.add_argument("--industry", "-i", default="cpa", help="Industry key")
    gen.add_argument("--employees", "-e", type=int, default=15, help="Employee count")
    gen.add_argument("--contact", help="Contact name")
    gen.add_argument("--title", help="Contact title")

    # Batch generate
    batch = subparsers.add_parser("batch", help="Generate sequences for CSV of prospects")
    batch.add_argument("file", help="CSV: domain,company,industry[,contact]")

    # List due emails
    due = subparsers.add_parser("due", help="List emails due today")

    # List all
    ls = subparsers.add_parser("list", help="List all scheduled outreach")

    # Mark sent
    sent = subparsers.add_parser("sent", help="Mark an email as sent")
    sent.add_argument("company", help="Company name")
    sent.add_argument("email_num", type=int, help="Email number (1-5)")

    args = parser.parse_args()

    if args.command == "generate":
        # Try to find scan data
        company_safe = args.company.replace(" ", "_").replace("&", "and")
        scan_data = None
        for d in Path("client-deliverables").glob(f"{company_safe}_*"):
            sd = _load_scan_data(d)
            if sd:
                scan_data = sd
                break

        print(f"\n  Generating 5-email sequence for {args.company}...")
        generated = generate_sequence(
            domain=args.domain,
            company_name=args.company,
            industry=args.industry,
            employee_count=args.employees,
            contact_name=args.contact,
            contact_title=args.title,
            scan_data=scan_data,
        )

        print(f"\n  Generated {len(generated)} emails:")
        for label, send_date, filepath in generated:
            print(f"    {send_date.strftime('%Y-%m-%d')} — {label}")
            print(f"      {filepath}")

        cost = get_total_cost()
        print(f"\n  AI cost: ${cost['total_cost']:.4f}")

    elif args.command == "batch":
        generate_batch(args.file)

    elif args.command == "due":
        list_due()

    elif args.command == "list":
        list_all()

    elif args.command == "sent":
        mark_sent(args.company, args.email_num)

    else:
        print("""
  CyberComply — Email Outreach Sequence Generator

  Usage:
    python email_scheduler.py generate smithcpa.com -c "Smith CPA" -i cpa
    python email_scheduler.py batch prospects.csv
    python email_scheduler.py due                    # What to send today
    python email_scheduler.py list                   # Full schedule
    python email_scheduler.py sent "Smith CPA" 2     # Mark email #2 as sent

  The 5-email sequence:
    Day 0:  Email 1 — Security Alert (P03)
    Day 3:  Email 2 — Dark Web Hook (P04)
    Day 7:  Email 3 — Compliance Deadline (P05)
    Day 14: Email 4 — Insurance Hook (P06)
    Day 21: Email 5 — Peer Comparison / Final (P07)

  Workflow:
    1. Run 'python deliver.py deliver domain.com -c "Name" -i cpa' first
    2. Run 'python email_scheduler.py generate domain.com -c "Name" -i cpa'
    3. Check 'python email_scheduler.py due' daily
    4. Send the email, then 'python email_scheduler.py sent "Name" N'
""")
