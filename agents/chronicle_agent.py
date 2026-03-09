"""
CHRONICLE — Reporting & Intelligence Engine
"I tell the story of your security journey."

Aggregates data from all agents and produces every client-facing report,
dashboard metric, and executive summary. CHRONICLE is what the client
actually reads — and what keeps them paying every month.

Current: 9-page assessment PDF (via ReportLab)
Planned: Monthly reports, quarterly board reports, annual reviews,
         cyber insurance application packages.
"""

from datetime import datetime
from agents.report_generator import generate_report


class ChronicleAgent:
    AGENT_NAME = "CHRONICLE"
    AGENT_TAGLINE = "I tell the story of your security journey."

    def generate_assessment_report(self, scan_data: dict, output_path: str) -> str:
        """
        Generate the branded 9-page security assessment PDF.

        Args:
            scan_data: Dict with keys: domain, company_name, archer, spectre,
                       forge_profile, compliance
            output_path: Where to save the PDF

        Returns:
            Path to generated PDF
        """
        return generate_report(scan_data, output_path)

    def generate_monthly_report(self, client_id: str, scan_data: dict,
                                previous_scan: dict = None, alerts: list = None,
                                compliance_data: dict = None) -> dict:
        """Generate monthly security report using P46 prompt."""
        from prompt_engine import call_prompt
        from datetime import date
        import json

        company = scan_data.get("company_name", "Client")
        score = scan_data.get("score", 0)
        grade = scan_data.get("grade", "N/A")
        findings = scan_data.get("archer", {}).get("findings", [])

        prev_score = previous_scan.get("score", 0) if previous_scan else score
        score_delta = score - prev_score

        new_alerts = len(alerts) if alerts else 0
        resolved_count = sum(1 for f in findings if f.get("status") == "resolved")

        try:
            narrative = call_prompt(
                "P46_MONTHLY_SECURITY_REPORT",
                client_name=company,
                current_score=str(score),
                previous_score=str(prev_score),
                score_delta=str(score_delta),
                grade=grade,
                findings_count=str(len(findings)),
                critical_findings=str(sum(1 for f in findings if f.get("severity") == "CRITICAL")),
                high_findings=str(sum(1 for f in findings if f.get("severity") == "HIGH")),
                resolved_count=str(resolved_count),
                new_alerts=str(new_alerts),
                top_findings=json.dumps(findings[:5], indent=2) if findings else "None",
            )
        except Exception as e:
            narrative = f"Monthly report generation pending. Score: {score}/{grade}. Findings: {len(findings)}."

        return {
            "type": "monthly_report",
            "date": date.today().isoformat(),
            "company": company,
            "score": score,
            "grade": grade,
            "score_delta": score_delta,
            "narrative": narrative,
            "findings_summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
                "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
                "resolved": resolved_count,
            },
            "alerts_count": new_alerts,
        }

    def generate_quarterly_report(self, client_data: dict, output_path: str) -> dict:
        """
        Generate quarterly board/executive report. (Phase 2)

        Will include: strategic risk assessment, YoY maturity improvement,
        budget ROI, industry benchmarks, regulatory status, threat landscape.
        """
        return {
            "status": "planned",
            "agent": self.AGENT_NAME,
            "note": "Quarterly board report available in Phase 2",
        }

    def generate_insurance_package(self, client_data: dict, output_path: str) -> dict:
        """
        Generate cyber insurance application evidence package. (Phase 2)

        Will include: pre-filled questionnaire responses, MFA evidence,
        endpoint protection proof, backup verification, IR plan reference.
        """
        return {
            "status": "planned",
            "agent": self.AGENT_NAME,
            "note": "Insurance package generation available in Phase 2",
        }
