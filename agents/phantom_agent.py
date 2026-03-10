"""
PHANTOM — Phishing Simulation & Security Awareness Agent
"I test your people before hackers do."

Integrates with GoPhish (open source) for sending + tracking.
Uses Claude API to generate industry-specific phishing templates.

GoPhish Setup:
    docker pull gophish/gophish
    docker run -d -p 3333:3333 -p 8080:8080 gophish/gophish
    
    Default admin: https://localhost:3333
    API key: Found on first login
"""

import requests
import json
import os
from datetime import datetime
from typing import Optional


# ─── PHISHING TEMPLATE LIBRARY ───────────────────────────────
# Pre-built templates by industry (no AI needed for basic campaigns)

PHISHING_TEMPLATES = {
    "cpa_irs_notice": {
        "name": "IRS E-Filing System Update",
        "industry": ["Accounting / CPA"],
        "difficulty": "medium",
        "subject": "Action Required: IRS E-Filing Portal Update for Tax Season {{.Year}}",
        "html_body": """
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #003366; padding: 20px; text-align: center;">
        <img src="https://www.irs.gov/pub/image/irs_sitelogo.png" alt="IRS" style="height: 50px;">
    </div>
    <div style="padding: 30px; background-color: #ffffff;">
        <p>Dear Tax Professional,</p>
        <p>The IRS has updated the e-filing portal security requirements effective immediately. 
        All authorized e-file providers must verify their Electronic Filing Identification Number (EFIN) 
        by <strong>{{.DeadlineDate}}</strong> to maintain filing privileges.</p>
        <p>Failure to complete verification will result in temporary suspension of your e-filing credentials.</p>
        <p style="text-align: center; margin: 30px 0;">
            <a href="{{.URL}}" style="background-color: #003366; color: white; padding: 12px 30px; 
            text-decoration: none; border-radius: 4px; font-weight: bold;">Verify Your EFIN Now</a>
        </p>
        <p style="font-size: 12px; color: #666;">This is an automated message from the IRS Modernized 
        e-File (MeF) system. Reference: MeF-SEC-2026-{{.ReferenceNum}}</p>
    </div>
</div>
""",
        "red_flags": [
            "IRS never sends login links via email",
            "Creates artificial urgency with deadline",
            "Threatens credential suspension",
            "Generic greeting instead of your name"
        ]
    },
    "cpa_client_doc": {
        "name": "Client Document Share",
        "industry": ["Accounting / CPA"],
        "difficulty": "hard",
        "subject": "Re: {{.ClientName}} - Updated W-2 and 1099 Documents",
        "html_body": """
<div style="font-family: Calibri, sans-serif; max-width: 600px;">
    <p>Hi {{.FirstName}},</p>
    <p>As discussed, I've uploaded the corrected W-2 and 1099 forms to our secure portal. 
    Can you review before we file the amended return?</p>
    <p><a href="{{.URL}}">📎 Download: {{.ClientName}}_W2_1099_Corrected.pdf</a></p>
    <p>Need these filed by end of week if possible.</p>
    <p>Thanks,<br>{{.SenderName}}<br>{{.SenderTitle}}</p>
    <div style="font-size: 11px; color: #999; border-top: 1px solid #eee; padding-top: 10px;">
        Sent from my iPhone
    </div>
</div>
""",
        "red_flags": [
            "External link pretending to be document download",
            "Urgency pressure (end of week)",
            "Appears to be from a known person",
            "'Sent from my iPhone' creates false sense of legitimacy"
        ]
    },
    "generic_password_reset": {
        "name": "Microsoft 365 Password Expiry",
        "industry": ["All"],
        "difficulty": "easy",
        "subject": "Your Microsoft 365 password expires in 24 hours",
        "html_body": """
<div style="font-family: 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #0078d4; padding: 20px; text-align: center;">
        <span style="color: white; font-size: 24px;">Microsoft</span>
    </div>
    <div style="padding: 30px; background-color: #f5f5f5;">
        <h2 style="color: #333;">Password Expiration Notice</h2>
        <p>Your Microsoft 365 password for <strong>{{.Email}}</strong> will expire in 24 hours.</p>
        <p>To avoid being locked out of your account, please update your password now.</p>
        <p style="text-align: center; margin: 30px 0;">
            <a href="{{.URL}}" style="background-color: #0078d4; color: white; padding: 12px 30px; 
            text-decoration: none; border-radius: 4px;">Update Password</a>
        </p>
        <p style="font-size: 12px; color: #999;">Microsoft Corporation, One Microsoft Way, Redmond, WA</p>
    </div>
</div>
""",
        "red_flags": [
            "Microsoft never sends password expiry emails with links",
            "Creates urgency (24 hours)",
            "Generic - no personal details beyond email",
            "Check the actual sender email address"
        ]
    },
    "generic_voicemail": {
        "name": "Missed Voicemail Notification",
        "industry": ["All"],
        "difficulty": "medium",
        "subject": "You have 1 new voicemail from ({{.PhoneNumber}})",
        "html_body": """
<div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;">
    <table style="width: 100%; border: 1px solid #ddd; border-radius: 8px;">
        <tr style="background-color: #f8f8f8;">
            <td style="padding: 15px;">
                <strong>🎤 New Voicemail</strong>
            </td>
        </tr>
        <tr>
            <td style="padding: 20px;">
                <p><strong>From:</strong> {{.PhoneNumber}}</p>
                <p><strong>Duration:</strong> 0:47</p>
                <p><strong>Date:</strong> {{.Date}} {{.Time}}</p>
                <p style="text-align: center; margin: 20px 0;">
                    <a href="{{.URL}}" style="background-color: #28a745; color: white; padding: 10px 25px; 
                    text-decoration: none; border-radius: 4px;">▶ Play Voicemail</a>
                </p>
            </td>
        </tr>
    </table>
    <p style="font-size: 11px; color: #aaa; text-align: center;">
        Unified Messaging Service — Do not reply to this email
    </p>
</div>
""",
        "red_flags": [
            "Voicemail links should go to your phone system, not external URLs",
            "Vague sender info",
            "Generic 'Unified Messaging Service'",
            "Hover over the Play button to see the real URL"
        ]
    },
    "healthcare_hipaa": {
        "name": "HIPAA Compliance Training Due",
        "industry": ["Healthcare"],
        "difficulty": "medium",
        "subject": "URGENT: Annual HIPAA Training Overdue - Complete by {{.Deadline}}",
        "html_body": """
<div style="font-family: Arial, sans-serif; max-width: 600px;">
    <div style="background-color: #c62828; padding: 10px 20px;">
        <span style="color: white; font-weight: bold;">⚠️ HIPAA Compliance Alert</span>
    </div>
    <div style="padding: 20px; background: #fff;">
        <p>Dear {{.FirstName}},</p>
        <p>Our records indicate you have not completed your mandatory annual HIPAA Security 
        Awareness Training. This training is <strong>overdue</strong> and must be completed 
        by {{.Deadline}} to maintain compliance.</p>
        <p><strong>Failure to complete may result in:</strong></p>
        <ul>
            <li>Suspension of system access</li>
            <li>Compliance violation on record</li>
        </ul>
        <p style="text-align: center;">
            <a href="{{.URL}}" style="background-color: #1565c0; color: white; padding: 12px 30px; 
            text-decoration: none; border-radius: 4px;">Complete Training Now</a>
        </p>
        <p style="font-size: 12px; color: #666;">Compliance Department | Do not reply</p>
    </div>
</div>
""",
        "red_flags": [
            "Creates urgency with threats of suspension",
            "External link for 'training' — real training comes through your LMS",
            "Red banner designed to trigger anxiety",
            "Check sender address — is this really from your compliance team?"
        ]
    },
    "financial_wire": {
        "name": "Urgent Wire Transfer Request",
        "industry": ["Financial Services", "Accounting / CPA", "Legal"],
        "difficulty": "hard",
        "subject": "Urgent: Wire Transfer Needed Today - Confidential",
        "html_body": """
<div style="font-family: Calibri, sans-serif; max-width: 600px;">
    <p>Hi {{.FirstName}},</p>
    <p>I need you to process an urgent wire transfer today. I'm in a meeting and can't call 
    but this needs to go out before 3 PM EST.</p>
    <p><strong>Amount:</strong> ${{.Amount}}<br>
    <strong>Recipient:</strong> {{.RecipientName}}<br>
    <strong>Reference:</strong> Invoice {{.InvoiceNum}}</p>
    <p>Please confirm once sent. I'll provide the bank details through our 
    <a href="{{.URL}}">secure portal</a>.</p>
    <p>Thanks — sorry for the rush.<br>
    {{.CEOName}}<br>
    <span style="color: #666; font-size: 12px;">Sent from mobile</span></p>
</div>
""",
        "red_flags": [
            "CLASSIC BEC attack - CEO impersonation",
            "Urgency + secrecy ('confidential', 'can't call')",
            "Wire transfer requests should ALWAYS be verified by phone",
            "Check the actual sender email - not just the display name"
        ]
    }
}


# ─── TRAINING PAGE TEMPLATE ──────────────────────────────────

TRAINING_PAGE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Awareness Training</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 700px; margin: 50px auto; padding: 20px; }
        .alert { background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .alert h2 { color: #856404; margin-top: 0; }
        .red-flag { background: #f8f8f8; border-left: 4px solid #dc3545; padding: 10px 15px; margin: 10px 0; }
        .tip { background: #d4edda; border-left: 4px solid #28a745; padding: 10px 15px; margin: 10px 0; }
        .btn { background: #007bff; color: white; padding: 12px 30px; border: none; border-radius: 4px; 
               cursor: pointer; font-size: 16px; text-decoration: none; display: inline-block; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="alert">
        <h2>⚠️ This Was a Security Test</h2>
        <p>You clicked on a simulated phishing email sent by your company's security team. 
        <strong>Don't worry — no harm was done.</strong> This is part of your company's ongoing 
        security awareness program powered by CyberComply.</p>
    </div>
    
    <h3>What You Should Have Noticed:</h3>
    {red_flags}
    
    <h3>How to Protect Yourself:</h3>
    <div class="tip">
        <strong>1. Check the sender's email address</strong> — not just the display name. 
        Hover over it to see the actual address.
    </div>
    <div class="tip">
        <strong>2. Hover before you click</strong> — look at where links actually go 
        before clicking them.
    </div>
    <div class="tip">
        <strong>3. When in doubt, verify</strong> — call the sender directly using a 
        known phone number (not one from the email).
    </div>
    <div class="tip">
        <strong>4. Report suspicious emails</strong> — forward to your IT team or use 
        the "Report Phishing" button in Outlook.
    </div>
    
    <p>This training moment has been recorded. Your next test will be more challenging. 
    Stay vigilant!</p>
    
    <p style="color: #666; font-size: 12px;">Powered by CyberComply — PHANTOM Agent</p>
</body>
</html>
"""


class PhantomAgent:
    """
    AI Phishing Simulation Agent.
    Manages campaigns through GoPhish API.
    """

    AGENT_NAME = "PHANTOM"
    AGENT_TAGLINE = "I test your people before hackers do."

    def __init__(self, gophish_url: str = None, gophish_api_key: str = None):
        self.gophish_url = gophish_url or os.getenv("GOPHISH_URL", "https://localhost:3333")
        self.gophish_key = gophish_api_key or os.getenv("GOPHISH_API_KEY", "")
        self.templates = PHISHING_TEMPLATES

    def get_templates_for_industry(self, industry: str) -> list:
        """Get phishing templates applicable to a specific industry."""
        applicable = []
        for key, template in self.templates.items():
            if industry in template["industry"] or "All" in template["industry"]:
                applicable.append({
                    "key": key,
                    "name": template["name"],
                    "difficulty": template["difficulty"],
                    "subject": template["subject"],
                    "red_flags": template["red_flags"]
                })
        return applicable

    def create_campaign(self, campaign_name: str, template_key: str,
                        employee_emails: list, send_date: str = None) -> dict:
        """Create a phishing campaign via GoPhish API."""
        template = self.templates.get(template_key)
        if not template:
            return {"error": f"Template '{template_key}' not found"}

        if not self.gophish_key:
            return {"status": "prepared", "template": template_key,
                    "targets": len(employee_emails),
                    "note": "GoPhish not connected — set GOPHISH_URL and GOPHISH_API_KEY"}

        headers = {"Authorization": f"Bearer {self.gophish_key}"}
        base = self.gophish_url

        try:
            # 1. Create or reuse sending profile
            smtp_name = "CyberComply SMTP"
            smtp_data = {
                "name": smtp_name,
                "host": os.getenv("SMTP_HOST", "smtp.gmail.com:587"),
                "from_address": os.getenv("SMTP_FROM", "security@cybercomply.io"),
                "username": os.getenv("SMTP_USER", ""),
                "password": os.getenv("SMTP_PASS", ""),
                "ignore_cert_errors": True,
            }
            resp = requests.post(f"{base}/api/smtp/", headers=headers, json=smtp_data, verify=False, timeout=10)
            smtp_id = resp.json().get("id")
            if not smtp_id:
                existing = requests.get(f"{base}/api/smtp/", headers=headers, verify=False, timeout=10).json()
                smtp_id = next((s["id"] for s in existing if s.get("name") == smtp_name), None)

            # 2. Create email template
            tmpl_data = {
                "name": f"{campaign_name}_template",
                "subject": template["subject"],
                "html": template["html_body"],
            }
            resp = requests.post(f"{base}/api/templates/", headers=headers, json=tmpl_data, verify=False, timeout=10)
            tmpl_id = resp.json().get("id")

            # 3. Create landing page
            page_data = {
                "name": f"{campaign_name}_page",
                "html": self.generate_training_page(template_key),
                "capture_credentials": False,
                "redirect_url": "",
            }
            resp = requests.post(f"{base}/api/pages/", headers=headers, json=page_data, verify=False, timeout=10)
            page_id = resp.json().get("id")

            # 4. Create target group
            targets = [{"email": e, "first_name": e.split("@")[0]} for e in employee_emails]
            group_data = {"name": f"{campaign_name}_targets", "targets": targets}
            resp = requests.post(f"{base}/api/groups/", headers=headers, json=group_data, verify=False, timeout=10)
            group_id = resp.json().get("id")

            # 5. Launch campaign
            campaign_data = {
                "name": campaign_name,
                "template": {"id": tmpl_id},
                "page": {"id": page_id},
                "smtp": {"id": smtp_id},
                "groups": [{"id": group_id}],
                "launch_date": send_date or datetime.utcnow().isoformat() + "Z",
            }
            resp = requests.post(f"{base}/api/campaigns/", headers=headers, json=campaign_data, verify=False, timeout=10)
            result = resp.json()

            return {
                "status": "launched",
                "campaign_id": result.get("id"),
                "name": campaign_name,
                "targets": len(employee_emails),
                "template": template_key,
            }

        except Exception as e:
            return {"status": "error", "error": str(e),
                    "note": "GoPhish API call failed. Check GOPHISH_URL and GOPHISH_API_KEY."}

    def get_campaign_results(self, campaign_id: int) -> dict:
        """Get results from a GoPhish campaign."""
        if self.gophish_key:
            try:
                resp = requests.get(
                    f"{self.gophish_url}/api/campaigns/{campaign_id}/results",
                    headers={"Authorization": f"Bearer {self.gophish_key}"},
                    verify=False, timeout=10
                )
                return resp.json()
            except Exception as e:
                return {"error": str(e)}
        return {"error": "GoPhish not connected"}

    def generate_training_page(self, template_key: str) -> str:
        """Generate the training page shown when someone clicks a phishing link."""
        template = self.templates.get(template_key, {})
        red_flags = template.get("red_flags", [])
        
        flags_html = ""
        for flag in red_flags:
            flags_html += f'<div class="red-flag">🚩 <strong>{flag}</strong></div>\n'
        
        return TRAINING_PAGE_HTML.replace("{red_flags}", flags_html)

    def calculate_metrics(self, results: dict) -> dict:
        """Calculate campaign metrics from GoPhish results."""
        total = results.get("total", 0)
        opened = results.get("opened", 0)
        clicked = results.get("clicked", 0)
        submitted = results.get("submitted_data", 0)
        reported = results.get("reported", 0)

        return {
            "total_targets": total,
            "emails_opened": opened,
            "open_rate": f"{opened/max(total,1)*100:.1f}%",
            "links_clicked": clicked,
            "click_rate": f"{clicked/max(total,1)*100:.1f}%",
            "credentials_submitted": submitted,
            "submission_rate": f"{submitted/max(total,1)*100:.1f}%",
            "reported_as_phishing": reported,
            "report_rate": f"{reported/max(total,1)*100:.1f}%",
        }


if __name__ == "__main__":
    phantom = PhantomAgent()
    
    print("[PHANTOM] Available phishing templates for CPA firms:")
    templates = phantom.get_templates_for_industry("Accounting / CPA")
    for t in templates:
        print(f"\n  📧 {t['name']} (Difficulty: {t['difficulty']})")
        print(f"     Subject: {t['subject']}")
        print(f"     Red flags: {', '.join(t['red_flags'][:2])}")
    
    print(f"\n[PHANTOM] Total templates available: {len(PHISHING_TEMPLATES)}")
    print(f"[PHANTOM] GoPhish required for sending campaigns")
    print(f"[PHANTOM] Install: docker pull gophish/gophish")
