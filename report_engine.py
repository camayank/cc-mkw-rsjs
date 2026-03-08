"""
CyberComply — Report Engine
Generates monthly retainer reports and score analysis narratives.
Keeps retainer clients paying $2,500-$10,000/month.

Usage:
    python report_engine.py monthly "Smith CPA" --data client_data.json
    python report_engine.py score-change "Smith CPA" --prev 45 --curr 67
"""

from __future__ import annotations

import sys
import os
import json
import argparse
import logging
from datetime import datetime, date
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from prompt_engine import call_prompt, get_industry_context, get_total_cost

logger = logging.getLogger("report_engine")

OUTPUT_DIR = Path("./client-deliverables")


def generate_monthly_narrative(client_data: dict) -> str:
    """
    Generate the monthly report narrative via P46.

    client_data keys:
        company_name, industry, tier, months_active,
        previous_score, current_score,
        resolved_count, new_findings_count, open_findings_count, critical_open,
        prev_compliance_pct, compliance_pct,
        phishing_results, vendor_results, threat_highlights, key_events
    """
    company = client_data["company_name"]
    industry = client_data.get("industry", "Professional Services")

    # Get industry context for defaults
    ctx = get_industry_context(industry)

    narrative = call_prompt(
        "P46_MONTHLY_REPORT",
        client_name=company,
        company_name=company,
        industry=ctx.get("label", industry),
        tier=client_data.get("tier", "Professional"),
        months_active=str(client_data.get("months_active", 1)),
        previous_score=str(client_data.get("previous_score", 0)),
        current_score=str(client_data.get("current_score", 0)),
        resolved_count=str(client_data.get("resolved_count", 0)),
        new_findings_count=str(client_data.get("new_findings_count", 0)),
        open_findings_count=str(client_data.get("open_findings_count", 0)),
        critical_open=str(client_data.get("critical_open", 0)),
        prev_compliance_pct=str(client_data.get("prev_compliance_pct", 0)),
        compliance_pct=str(client_data.get("compliance_pct", 0)),
        phishing_results=client_data.get("phishing_results", "No campaign this month"),
        vendor_results=client_data.get("vendor_results", "No vendor assessments this month"),
        threat_highlights=client_data.get("threat_highlights", "No notable threats this month"),
        key_events=client_data.get("key_events", "Routine monitoring"),
    )

    return narrative


def generate_score_analysis(company_name: str, previous_score: int, current_score: int,
                            resolved_items: str = "", new_items: str = "",
                            external_changes: str = "") -> str:
    """
    Generate score change explanation via P49.
    Returns 150-word explanation of why the score changed.
    """
    score_change = current_score - previous_score
    change_str = f"+{score_change}" if score_change > 0 else str(score_change)

    analysis = call_prompt(
        "P49_SCORE_CHANGE_ANALYSIS",
        client_name=company_name,
        company_name=company_name,
        previous_score=str(previous_score),
        current_score=str(current_score),
        score_change=change_str,
        resolved_items=resolved_items or "None documented",
        new_items=new_items or "None detected",
        external_changes=external_changes or "No significant external changes",
    )

    return analysis


def generate_monthly_report(client_data: dict, output_dir: Path = None) -> Path:
    """
    Generate complete monthly report: narrative + score analysis + save to disk.

    Returns path to the saved report file.
    """
    company = client_data["company_name"]
    company_safe = company.replace(" ", "_").replace("&", "and")

    if output_dir is None:
        output_dir = OUTPUT_DIR / company_safe
    output_dir.mkdir(parents=True, exist_ok=True)

    month_str = date.today().strftime("%Y-%m")
    report_path = output_dir / f"monthly_report_{month_str}.txt"

    print(f"\n{'='*60}")
    print(f"  MONTHLY REPORT — {company}")
    print(f"  {date.today().strftime('%B %Y')}")
    print(f"{'='*60}")

    # 1. Generate narrative (P46)
    print(f"\n  Generating monthly narrative (P46)...", end=" ", flush=True)
    try:
        narrative = generate_monthly_narrative(client_data)
        print(f"done ({len(narrative.split())} words)")
    except Exception as e:
        narrative = "AI narrative unavailable — set ANTHROPIC_API_KEY to enable."
        print(f"skipped ({e})")

    # 2. Generate score change analysis (P49)
    prev = client_data.get("previous_score", 0)
    curr = client_data.get("current_score", 0)
    resolved = client_data.get("resolved_items_detail", "")
    new = client_data.get("new_items_detail", "")

    print(f"  Generating score analysis (P49)...", end=" ", flush=True)
    try:
        score_analysis = generate_score_analysis(
            company, prev, curr,
            resolved_items=resolved,
            new_items=new,
            external_changes=client_data.get("external_changes", ""),
        )
        print(f"done ({len(score_analysis.split())} words)")
    except Exception as e:
        score_analysis = "Score analysis unavailable — set ANTHROPIC_API_KEY to enable."
        print(f"skipped ({e})")

    # 3. Assemble report
    score_change = curr - prev
    change_arrow = "↑" if score_change > 0 else "↓" if score_change < 0 else "→"
    change_str = f"+{score_change}" if score_change > 0 else str(score_change)

    report_text = f"""{'='*60}
MONTHLY SECURITY REPORT
{company}
{date.today().strftime('%B %Y')}
{'='*60}

SECURITY SCORE: {curr}/100 ({change_arrow} {change_str} from last month)
Previous: {prev}/100 → Current: {curr}/100

{'─'*60}
EXECUTIVE NARRATIVE
{'─'*60}

{narrative}

{'─'*60}
SCORE CHANGE ANALYSIS
{'─'*60}

{score_analysis}

{'─'*60}
METRICS SNAPSHOT
{'─'*60}

  Findings resolved this month:  {client_data.get('resolved_count', 0)}
  New findings detected:         {client_data.get('new_findings_count', 0)}
  Open findings:                 {client_data.get('open_findings_count', 0)} ({client_data.get('critical_open', 0)} critical)
  Compliance:                    {client_data.get('prev_compliance_pct', 0)}% → {client_data.get('compliance_pct', 0)}%
  Phishing:                      {client_data.get('phishing_results', 'No campaign this month')}
  Vendors assessed:              {client_data.get('vendor_results', 'None this month')}

{'─'*60}
KEY EVENTS
{'─'*60}

  {client_data.get('key_events', 'Routine monitoring — no incidents')}

{'='*60}
Generated by CyberComply Report Engine
{datetime.now().strftime('%Y-%m-%d %H:%M')}
{'='*60}
"""

    report_path.write_text(report_text)
    print(f"\n  ✅ Report saved: {report_path}")

    # Cost summary
    cost_info = get_total_cost()
    print(f"  AI cost: ${cost_info['total_cost']:.4f} for {cost_info['total_calls']} calls")

    return report_path


def _load_client_data(data_path: str) -> dict:
    """Load client data from JSON file."""
    path = Path(data_path)
    if not path.exists():
        raise FileNotFoundError(f"Client data file not found: {data_path}")
    return json.loads(path.read_text())


def _build_sample_data(company_name: str, industry: str = "cpa",
                       prev_score: int = 45, curr_score: int = 58) -> dict:
    """Build sample client data for testing or first-time use."""
    return {
        "company_name": company_name,
        "industry": industry,
        "tier": "Professional",
        "months_active": 3,
        "previous_score": prev_score,
        "current_score": curr_score,
        "resolved_count": 3,
        "new_findings_count": 1,
        "open_findings_count": 5,
        "critical_open": 0,
        "prev_compliance_pct": 62,
        "compliance_pct": 71,
        "phishing_results": "12% click rate (down from 20% last month)",
        "vendor_results": "2 vendors assessed, 1 flagged for follow-up",
        "threat_highlights": "New IRS phishing campaign targeting CPA firms detected by CISA",
        "key_events": "DMARC implemented, MFA enabled for all users",
        "resolved_items_detail": "DMARC record added, SSL certificate renewed, MFA enabled",
        "new_items_detail": "Outdated WordPress plugin detected",
        "external_changes": "IRS issued new guidance on WISP requirements",
    }


# ═══════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberComply Report Engine")
    subparsers = parser.add_subparsers(dest="command")

    # Monthly report
    monthly = subparsers.add_parser("monthly", help="Generate monthly retainer report")
    monthly.add_argument("company", help="Client company name")
    monthly.add_argument("--data", "-d", help="Path to client data JSON file")
    monthly.add_argument("--industry", "-i", default="cpa")
    monthly.add_argument("--prev-score", type=int, default=45, help="Previous month score")
    monthly.add_argument("--curr-score", type=int, default=58, help="Current month score")
    monthly.add_argument("--output", "-o", help="Output directory")

    # Score change analysis only
    score = subparsers.add_parser("score-change", help="Generate score change explanation")
    score.add_argument("company", help="Client company name")
    score.add_argument("--prev", type=int, required=True, help="Previous score")
    score.add_argument("--curr", type=int, required=True, help="Current score")
    score.add_argument("--resolved", type=str, default="", help="Resolved items description")
    score.add_argument("--new", type=str, default="", help="New findings description")

    args = parser.parse_args()

    if args.command == "monthly":
        if args.data:
            client_data = _load_client_data(args.data)
        else:
            client_data = _build_sample_data(
                args.company, args.industry, args.prev_score, args.curr_score
            )

        output_dir = Path(args.output) if args.output else None
        generate_monthly_report(client_data, output_dir)

    elif args.command == "score-change":
        analysis = generate_score_analysis(
            args.company, args.prev, args.curr,
            resolved_items=args.resolved,
            new_items=args.new,
        )
        print(f"\nScore Change Analysis for {args.company}:")
        print(f"  {args.prev} → {args.curr} ({'+' if args.curr > args.prev else ''}{args.curr - args.prev})")
        print(f"\n{analysis}")

    else:
        print("CyberComply Report Engine")
        print("=" * 40)
        print("Usage:")
        print("  python report_engine.py monthly 'Smith CPA'                    # Monthly report with defaults")
        print("  python report_engine.py monthly 'Smith CPA' -d client.json     # Monthly report from data file")
        print("  python report_engine.py monthly 'Smith CPA' --prev-score 45 --curr-score 67")
        print("  python report_engine.py score-change 'Smith CPA' --prev 45 --curr 67")
        print("")
        print("Client data JSON format:")
        sample = _build_sample_data("Example Corp")
        print(json.dumps(sample, indent=2))
