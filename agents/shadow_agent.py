"""
SHADOW — Dark Web & Credential Intelligence Agent
"I find your secrets before criminals do."

Scans breach databases for leaked credentials associated with a domain.
Uses: Have I Been Pwned API (paid $3.50/mo) + free breach databases.

Usage:
    shadow = ShadowAgent(hibp_api_key="your-key")
    results = shadow.scan("targetcompany.com", ["ceo@targetcompany.com", "admin@targetcompany.com"])
    print(results)
"""

from __future__ import annotations

import requests
import json
import time
import hashlib
import os
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class BreachResult:
    email: str
    breach_name: str
    breach_date: str
    data_exposed: list
    description: str
    is_verified: bool
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    severity_reason: str


@dataclass 
class ScanSummary:
    domain: str
    scan_date: str
    total_emails_checked: int
    total_exposed: int
    critical: int
    high: int
    medium: int
    low: int
    exposure_rate: str
    breaches: list
    password_check_results: list


class ShadowAgent:
    """
    Dark Web Intelligence Agent.
    Checks breach databases for leaked credentials.
    """

    AGENT_NAME = "SHADOW"
    AGENT_TAGLINE = "I find your secrets before criminals do."

    def __init__(self, hibp_api_key: Optional[str] = None):
        self.hibp_key = hibp_api_key or os.getenv("HIBP_API_KEY")
        self.hibp_base = "https://haveibeenpwned.com/api/v3"
        self.headers = {
            "hibp-api-key": self.hibp_key or "",
            "user-agent": "CyberComply-Shadow-Agent-v1"
        }
        self.rate_limit_delay = 1.6  # HIBP requires 1.5s between requests

    # ─── CORE SCANNING ───────────────────────────────────────

    def check_email_breaches(self, email: str) -> list:
        """Check a single email against all known breaches."""
        if not self.hibp_key:
            return self._check_email_free(email)

        url = f"{self.hibp_base}/breachedaccount/{email}"
        params = {"truncateResponse": "false"}

        try:
            response = requests.get(
                url, headers=self.headers, params=params, timeout=10
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return []  # No breaches found
            elif response.status_code == 429:
                # Rate limited — wait and retry
                time.sleep(2)
                return self.check_email_breaches(email)
            else:
                print(f"[SHADOW] HIBP returned {response.status_code} for {email}")
                return []
        except requests.exceptions.RequestException as e:
            print(f"[SHADOW] Error checking {email}: {e}")
            return []

    def _check_email_free(self, email: str) -> list:
        """Free fallback: Check email against public breach databases."""
        breaches = []

        # Method 1: Check haveibeenpwned.com (password check is free)
        # The breach check requires API key, but we can still check passwords
        
        # Method 2: Use free breach notification services
        # BreachDirectory.org has a free API
        try:
            resp = requests.get(
                f"https://breachdirectory.org/api/search?term={email}",
                timeout=10,
                headers={"User-Agent": "CyberComply-Shadow-Agent"}
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("found"):
                    for source in data.get("sources", []):
                        breaches.append({
                            "Name": source,
                            "BreachDate": "Unknown",
                            "DataClasses": ["Email addresses", "Passwords"],
                            "Description": f"Found in {source} breach database",
                            "IsVerified": False,
                            "Domain": "breachdirectory.org"
                        })
        except Exception:
            pass

        return breaches

    def check_password_pwned(self, password: str) -> int:
        """
        Check if a password has been seen in breaches.
        Uses k-anonymity model — only sends first 5 chars of SHA1 hash.
        THIS IS FREE — no API key needed.
        """
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        try:
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                timeout=10
            )
            if response.status_code == 200:
                for line in response.text.splitlines():
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return int(count)
        except Exception:
            pass
        return 0

    # ─── DOMAIN SCANNING ─────────────────────────────────────

    def scan(self, domain: str, employee_emails: list) -> ScanSummary:
        """
        Full domain scan — checks all employee emails against breach databases.
        
        Args:
            domain: Company domain (e.g., "smithcpa.com")
            employee_emails: List of email addresses to check
            
        Returns:
            ScanSummary with all findings
        """
        print(f"\n[SHADOW] Starting dark web scan for {domain}")
        print(f"[SHADOW] Checking {len(employee_emails)} email addresses...\n")

        all_breaches = []
        password_checks = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for i, email in enumerate(employee_emails):
            print(f"[SHADOW] [{i+1}/{len(employee_emails)}] Scanning {email}...")

            # Check breaches
            breaches = self.check_email_breaches(email)
            time.sleep(self.rate_limit_delay)  # Rate limiting

            if breaches:
                for breach in breaches:
                    severity, reason = self._assess_severity(email, breach)
                    severity_counts[severity] += 1

                    result = BreachResult(
                        email=email,
                        breach_name=breach.get("Name", "Unknown"),
                        breach_date=breach.get("BreachDate", "Unknown"),
                        data_exposed=breach.get("DataClasses", []),
                        description=breach.get("Description", ""),
                        is_verified=breach.get("IsVerified", False),
                        severity=severity,
                        severity_reason=reason
                    )
                    all_breaches.append(result)

                print(f"    ⚠️  Found in {len(breaches)} breach(es)!")
            else:
                print(f"    ✅ Clean — no breaches found")

        total_exposed = len(set(b.email for b in all_breaches))
        
        summary = ScanSummary(
            domain=domain,
            scan_date=datetime.utcnow().isoformat() + "Z",
            total_emails_checked=len(employee_emails),
            total_exposed=total_exposed,
            critical=severity_counts["CRITICAL"],
            high=severity_counts["HIGH"],
            medium=severity_counts["MEDIUM"],
            low=severity_counts["LOW"],
            exposure_rate=f"{total_exposed/max(len(employee_emails),1)*100:.1f}%",
            breaches=[asdict(b) for b in all_breaches],
            password_check_results=password_checks
        )

        self._print_summary(summary)
        return summary

    # ─── SEVERITY ASSESSMENT ─────────────────────────────────

    def _assess_severity(self, email: str, breach: dict) -> tuple:
        """Assess severity of a breach finding."""
        data_classes = breach.get("DataClasses", [])
        breach_date = breach.get("BreachDate", "2000-01-01")
        is_verified = breach.get("IsVerified", False)

        # CRITICAL: Recent breach with passwords in plaintext
        if any(d in data_classes for d in ["Passwords", "Password hints"]):
            if breach_date >= "2023-01-01":
                return "CRITICAL", "Recent breach with password data — likely still active"
            elif breach_date >= "2021-01-01":
                return "HIGH", "Password exposed in breach — may still be in use"
            else:
                return "MEDIUM", "Older password exposure — should still be changed"

        # HIGH: Sensitive personal data exposed
        if any(d in data_classes for d in [
            "Credit cards", "Bank account numbers",
            "Social security numbers", "Government issued IDs",
            "Security questions and answers"
        ]):
            return "HIGH", "Sensitive financial/identity data exposed"

        # HIGH: Admin/executive email
        if any(prefix in email.split('@')[0].lower() for prefix in [
            'admin', 'ceo', 'cfo', 'cto', 'owner', 'partner',
            'managing', 'director', 'president', 'it'
        ]):
            return "HIGH", "Executive/admin account found in breach"

        # MEDIUM: Multiple breaches or recent
        if is_verified and breach_date >= "2022-01-01":
            return "MEDIUM", "Verified recent breach with personal data"

        # LOW: Older or unverified
        return "LOW", "Older breach with limited data exposure"

    # ─── REPORTING ────────────────────────────────────────────

    def _print_summary(self, summary: ScanSummary):
        """Print a console summary of scan results."""
        print(f"\n{'='*60}")
        print(f"  SHADOW SCAN RESULTS — {summary.domain}")
        print(f"{'='*60}")
        print(f"  Scan date:        {summary.scan_date}")
        print(f"  Emails checked:   {summary.total_emails_checked}")
        print(f"  Emails exposed:   {summary.total_exposed}")
        print(f"  Exposure rate:    {summary.exposure_rate}")
        print(f"")
        print(f"  🔴 CRITICAL:  {summary.critical}")
        print(f"  🟠 HIGH:      {summary.high}")
        print(f"  🟡 MEDIUM:    {summary.medium}")
        print(f"  ⚪ LOW:       {summary.low}")
        print(f"{'='*60}")

        if summary.breaches:
            print(f"\n  FINDINGS:")
            for b in summary.breaches:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
                print(f"  {icon.get(b['severity'], '⚪')} {b['email']}")
                print(f"     Breach: {b['breach_name']} ({b['breach_date']})")
                print(f"     Exposed: {', '.join(b['data_exposed'][:5])}")
                print(f"     Severity: {b['severity']} — {b['severity_reason']}")
                print()

    def to_json(self, summary: ScanSummary) -> str:
        """Export scan results as JSON."""
        return json.dumps(asdict(summary), indent=2, default=str)

    def to_dict(self, summary: ScanSummary) -> dict:
        """Export scan results as dictionary."""
        return asdict(summary)

    def generate_alert(self, breach: dict, company_name: str, industry: str = "cpa",
                       employee_access: str = "email and file access") -> str:
        """
        Generate AI-powered dark web alert via P54 for a specific breach finding.
        Transforms raw breach data into an urgent, actionable alert with 4 steps.

        Returns alert text (150-200 words).
        """
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from prompt_engine import call_prompt, get_industry_context

        ctx = get_industry_context(industry)

        # Determine password type from data classes
        data_classes = breach.get("data_exposed", breach.get("DataClasses", []))
        if "Passwords" in data_classes:
            password_type = "plaintext password"
        elif "Password hints" in data_classes:
            password_type = "password hints"
        else:
            password_type = "no password (email and personal data only)"

        alert = call_prompt(
            "P54_DARK_WEB_ALERT",
            client_name=company_name,
            company_name=company_name,
            industry=ctx.get("label", industry),
            email_platform=ctx.get("tech_environment", "Microsoft 365"),
            data_types=ctx.get("data_types", "business data"),
            exposed_email=breach.get("email", "unknown@domain.com"),
            employee_name=breach.get("email", "").split("@")[0].replace(".", " ").title(),
            employee_access=employee_access,
            breach_source=breach.get("breach_name", breach.get("Name", "Unknown")),
            breach_date=breach.get("breach_date", breach.get("BreachDate", "Unknown")),
            password_type=password_type,
            total_domain_breaches=str(breach.get("total_domain_breaches", 1)),
        )

        return alert

    def generate_alerts(self, summary: ScanSummary, company_name: str,
                        industry: str = "cpa") -> list:
        """
        Generate AI alerts for all CRITICAL and HIGH severity breaches.
        Returns list of (breach_dict, alert_text) tuples.
        """
        alerts = []
        for breach in summary.breaches:
            if breach.get("severity") in ("CRITICAL", "HIGH"):
                breach["total_domain_breaches"] = summary.total_exposed
                try:
                    alert_text = self.generate_alert(breach, company_name, industry)
                    alerts.append((breach, alert_text))
                    print(f"  [SHADOW] Alert generated for {breach.get('email', 'unknown')}")
                except Exception as e:
                    print(f"  [SHADOW] Alert failed for {breach.get('email', 'unknown')}: {e}")

        return alerts

    def save_alerts(self, alerts: list, company_name: str, output_dir: Path = None) -> Path:
        """Save generated alerts to disk."""
        company_safe = company_name.replace(" ", "_").replace("&", "and")
        if output_dir is None:
            output_dir = Path("client-deliverables") / company_safe
        alert_dir = output_dir / "alerts"
        alert_dir.mkdir(parents=True, exist_ok=True)

        for i, (breach, alert_text) in enumerate(alerts):
            email_safe = breach.get("email", "unknown").replace("@", "_at_")
            alert_path = alert_dir / f"alert_{email_safe}_{datetime.now().strftime('%Y%m%d')}.txt"
            alert_path.write_text(alert_text)

        if alerts:
            print(f"  [SHADOW] {len(alerts)} alerts saved to {alert_dir}/")
        return alert_dir if alerts else None


# ─── DEMO / TESTING ──────────────────────────────────────────

if __name__ == "__main__":
    # Demo mode — works without API key using free methods
    shadow = ShadowAgent()

    # Test with a known breached email (test@example.com is safe to test)
    print("[SHADOW] Running demo scan...")
    print("[SHADOW] Note: For production use, set HIBP_API_KEY env variable")
    print("[SHADOW]       Get your key at: https://haveibeenpwned.com/API/Key")
    print()

    # Password check demo (always free)
    test_passwords = ["password123", "Summer2024!", "correcthorsebatterystaple"]
    for pwd in test_passwords:
        count = shadow.check_password_pwned(pwd)
        if count > 0:
            print(f"  ⚠️  Password '{pwd}' found {count:,} times in breaches!")
        else:
            print(f"  ✅ Password '{pwd}' not found in breaches")
