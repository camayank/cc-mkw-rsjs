"""
CyberComply — 9-Page Security Assessment Report Generator
Generates a professional branded PDF from SHADOW + RECON + GUARDIAN scan data.
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus.flowables import Flowable
from datetime import datetime
import json, os, sys

# ─── BRAND COLORS ─────────────────────────────────────────
DARK = HexColor('#0a0a0f')
CARD = HexColor('#1a1a2e')
ACCENT = HexColor('#00b8d4')
ACCENT2 = HexColor('#7c4dff')
RED = HexColor('#e53935')
ORANGE = HexColor('#ff9100')
YELLOW = HexColor('#ffd600')
GREEN = HexColor('#00c853')
WHITE = HexColor('#ffffff')
LIGHT_GRAY = HexColor('#e0e0e0')
MID_GRAY = HexColor('#9e9e9e')
DARK_GRAY = HexColor('#333340')
BG_LIGHT = HexColor('#f5f5fa')


class ScoreCircle(Flowable):
    """Draw a circular score indicator."""
    def __init__(self, score, size=80):
        Flowable.__init__(self)
        self.score = score
        self.size = size
        self.width = size
        self.height = size

    def draw(self):
        c = self.canv
        r = self.size / 2
        cx, cy = r, r

        if self.score < 35:
            ring_color, label = RED, "CRITICAL"
        elif self.score < 50:
            ring_color, label = ORANGE, "POOR"
        elif self.score < 65:
            ring_color, label = YELLOW, "FAIR"
        elif self.score < 80:
            ring_color, label = GREEN, "GOOD"
        else:
            ring_color, label = GREEN, "STRONG"

        c.setStrokeColor(ring_color)
        c.setLineWidth(4)
        c.circle(cx, cy, r - 4)
        c.setFont("Helvetica-Bold", 24)
        c.setFillColor(ring_color)
        c.drawCentredString(cx, cy + 4, str(self.score))
        c.setFont("Helvetica", 8)
        c.drawCentredString(cx, cy - 12, f"/100")


class BarChart(Flowable):
    """Draw a horizontal bar for score breakdown."""
    def __init__(self, label, score, max_score, width=400, height=28):
        Flowable.__init__(self)
        self.label = label
        self.score = score
        self.max_score = max_score
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        pct = self.score / max(self.max_score, 1)
        bar_w = 220
        bar_h = 12
        bar_x = 150
        bar_y = 8

        # Label
        c.setFont("Helvetica", 9)
        c.setFillColor(DARK_GRAY)
        c.drawString(0, bar_y + 1, self.label)

        # Background bar
        c.setFillColor(HexColor('#e8e8f0'))
        c.roundRect(bar_x, bar_y, bar_w, bar_h, 3, fill=1, stroke=0)

        # Fill bar
        if pct > 0.7:
            fill_color = GREEN
        elif pct > 0.4:
            fill_color = ORANGE
        else:
            fill_color = RED
        c.setFillColor(fill_color)
        c.roundRect(bar_x, bar_y, bar_w * pct, bar_h, 3, fill=1, stroke=0)

        # Score text
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(DARK_GRAY)
        c.drawString(bar_x + bar_w + 10, bar_y + 1, f"{self.score}/{self.max_score}")


def create_styles():
    """Create custom paragraph styles."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        'CoverTitle', fontName='Helvetica-Bold', fontSize=28,
        textColor=DARK, alignment=TA_CENTER, spaceAfter=12, leading=34
    ))
    styles.add(ParagraphStyle(
        'CoverSub', fontName='Helvetica', fontSize=14,
        textColor=MID_GRAY, alignment=TA_CENTER, spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        'SectionHead', fontName='Helvetica-Bold', fontSize=18,
        textColor=DARK, spaceAfter=12, spaceBefore=20, leading=22
    ))
    styles.add(ParagraphStyle(
        'SubHead', fontName='Helvetica-Bold', fontSize=13,
        textColor=DARK_GRAY, spaceAfter=8, spaceBefore=12
    ))
    styles.add(ParagraphStyle(
        'Body', fontName='Helvetica', fontSize=10,
        textColor=DARK_GRAY, spaceAfter=6, leading=14
    ))
    styles.add(ParagraphStyle(
        'BodySmall', fontName='Helvetica', fontSize=9,
        textColor=MID_GRAY, spaceAfter=4, leading=12
    ))
    styles.add(ParagraphStyle(
        'AccentText', fontName='Helvetica-Bold', fontSize=10,
        textColor=ACCENT, spaceAfter=4
    ))
    styles.add(ParagraphStyle(
        'CriticalText', fontName='Helvetica-Bold', fontSize=10,
        textColor=RED, spaceAfter=4
    ))
    styles.add(ParagraphStyle(
        'Footer', fontName='Helvetica', fontSize=7,
        textColor=MID_GRAY, alignment=TA_CENTER
    ))
    return styles


def header_footer(canvas, doc):
    """Add header and footer to each page."""
    canvas.saveState()
    w, h = letter

    # Header line
    canvas.setStrokeColor(ACCENT)
    canvas.setLineWidth(2)
    canvas.line(40, h - 40, w - 40, h - 40)

    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(ACCENT)
    canvas.drawString(40, h - 36, "CYBERCOMPLY")

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MID_GRAY)
    canvas.drawRightString(w - 40, h - 36, "CONFIDENTIAL")

    # Footer
    canvas.setStrokeColor(LIGHT_GRAY)
    canvas.setLineWidth(0.5)
    canvas.line(40, 36, w - 40, 36)

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MID_GRAY)
    canvas.drawString(40, 24, "CyberComply — 11 AI Agents. Always On. Always Watching.")
    canvas.drawRightString(w - 40, 24, f"Page {doc.page}")

    canvas.restoreState()


def generate_report(scan_data: dict, output_path: str = "security_report.pdf"):
    """
    Generate the complete 9-page security assessment PDF.

    scan_data should contain:
    - domain: str
    - company_name: str (optional)
    - archer: dict (from ReconAgent.scan())
    - spectre: dict (from ShadowAgent.scan(), optional)
    - forge_profile: dict (from GuardianAgent.process_questionnaire(), optional)
    - compliance: dict (from GuardianAgent.get_compliance_status(), optional)
    """
    domain = scan_data.get("domain", "unknown.com")
    company = scan_data.get("company_name", domain.split('.')[0].title())
    archer = scan_data.get("archer", {})
    spectre = scan_data.get("spectre", {})
    profile = scan_data.get("forge_profile", {})
    compliance = scan_data.get("compliance", {})

    score_data = archer.get("score", {})
    score = score_data.get("total", 0)
    grade = score_data.get("grade", "F")
    label = score_data.get("label", "NOT ASSESSED")
    findings = archer.get("findings", [])
    breakdown = score_data.get("breakdown", {})
    executive_summary_ai = scan_data.get("executive_summary")

    CATEGORY_LABELS = {
        'email_security': 'Email Security',
        'ssl_tls': 'SSL / TLS',
        'security_headers': 'Security Headers',
        'network_exposure': 'Network Exposure',
        'technology': 'Technology',
        'dns_security': 'DNS Security',
    }

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=60, bottomMargin=50,
        leftMargin=50, rightMargin=50
    )
    styles = create_styles()
    story = []

    # ═══ PAGE 1: COVER ═══
    story.append(Spacer(1, 120))
    story.append(Paragraph("CYBERSECURITY", styles['CoverSub']))
    story.append(Paragraph("HEALTH ASSESSMENT", styles['CoverTitle']))
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="40%", thickness=2, color=ACCENT, spaceAfter=16))
    story.append(Paragraph(f"Prepared for: <b>{company}</b>", styles['CoverSub']))
    story.append(Paragraph(f"Domain: {domain}", styles['CoverSub']))
    story.append(Paragraph(f"Date: {datetime.now().strftime('%B %d, %Y')}", styles['CoverSub']))
    story.append(Spacer(1, 40))

    # Score on cover
    story.append(ScoreCircle(score, size=100))
    story.append(Spacer(1, 8))
    sev_color = RED if score < 35 else ORANGE if score < 50 else YELLOW if score < 65 else GREEN
    story.append(Paragraph(
        f'<font color="#{sev_color.hexval()[2:]}">{label}</font>',
        ParagraphStyle('ScoreLabel', fontName='Helvetica-Bold', fontSize=16,
                       alignment=TA_CENTER, textColor=sev_color)
    ))
    story.append(Spacer(1, 60))
    story.append(Paragraph("Prepared by CyberComply", styles['CoverSub']))
    story.append(Paragraph("11 AI Agents. Always On. Always Watching.", styles['BodySmall']))
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        '<font color="#e53935"><b>CONFIDENTIAL</b></font> — This report contains sensitive security information.',
        ParagraphStyle('Conf', fontName='Helvetica', fontSize=8, alignment=TA_CENTER, textColor=RED)
    ))
    story.append(PageBreak())

    # ═══ PAGE 2: EXECUTIVE SUMMARY ═══
    story.append(Paragraph("EXECUTIVE SUMMARY", styles['SectionHead']))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=12))

    if executive_summary_ai:
        summary_text = executive_summary_ai
    else:
        summary_text = (
            f"Our AI security agents (SHADOW and RECON) conducted a comprehensive assessment of "
            f"{company}'s external security posture on {datetime.now().strftime('%B %d, %Y')}. The assessment covered "
            f"email security configuration, SSL/TLS certificates, network exposure, web security headers, "
            f"technology stack analysis, and DNS security."
        )
    story.append(Paragraph(summary_text, styles['Body']))
    story.append(Spacer(1, 12))

    # Score + breakdown
    story.append(Paragraph("SECURITY SCORE", styles['SubHead']))
    story.append(ScoreCircle(score, size=80))
    story.append(Spacer(1, 8))

    for cat_name, cat_data in breakdown.items():
        display_name = CATEGORY_LABELS.get(cat_name, cat_name.replace('_', ' ').title())
        story.append(BarChart(display_name, cat_data['score'], cat_data['max']))
        story.append(Spacer(1, 4))

    story.append(Spacer(1, 12))

    # Key findings summary
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')

    summary_table = Table([
        ['Total Findings', str(len(findings))],
        ['Critical', str(critical)],
        ['High', str(high)],
        ['Medium', str(medium)],
    ], colWidths=[200, 100])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), DARK_GRAY),
        ('TEXTCOLOR', (1, 1), (1, 1), RED),
        ('TEXTCOLOR', (1, 2), (1, 2), ORANGE),
        ('TEXTCOLOR', (1, 3), (1, 3), YELLOW),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, LIGHT_GRAY),
    ]))
    story.append(summary_table)
    story.append(PageBreak())

    # ═══ PAGE 3: DARK WEB FINDINGS ═══
    story.append(Paragraph("DARK WEB FINDINGS", styles['SectionHead']))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=12))
    story.append(Paragraph("Agent: SHADOW — Dark Web & Credential Intelligence", styles['AccentText']))

    breaches = spectre.get("breaches", [])
    if breaches:
        story.append(Paragraph(
            f'<font color="#e53935"><b>{spectre.get("total_exposed", 0)} employee email(s)</b></font> found in known data breaches.',
            styles['Body']
        ))
        story.append(Spacer(1, 8))

        for b in breaches[:10]:
            sev_icon = "CRITICAL" if b.get("severity") == "CRITICAL" else b.get("severity", "MEDIUM")
            sev_c = RED if sev_icon == "CRITICAL" else ORANGE if sev_icon == "HIGH" else YELLOW
            story.append(Paragraph(
                f'<font color="#{sev_c.hexval()[2:]}"><b>[{sev_icon}]</b></font> '
                f'<b>{b.get("email", "unknown")}</b>',
                styles['Body']
            ))
            story.append(Paragraph(
                f'Breach: {b.get("breach_name", "Unknown")} ({b.get("breach_date", "Unknown")}) — '
                f'Exposed: {", ".join(b.get("data_exposed", [])[:4])}',
                styles['BodySmall']
            ))
            story.append(Paragraph(f'{b.get("severity_reason", "")}', styles['BodySmall']))
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph(
            "No breached credentials were found in this scan. However, new breaches are discovered daily. "
            "SHADOW monitors continuously to catch new exposures as they appear.",
            styles['Body']
        ))
        story.append(Paragraph(
            "<i>Note: Full dark web scanning requires the HIBP API integration. "
            "Contact us to activate continuous monitoring.</i>",
            styles['BodySmall']
        ))

    story.append(PageBreak())

    # ═══ PAGE 4: EMAIL SECURITY ═══
    story.append(Paragraph("EMAIL SECURITY ANALYSIS", styles['SectionHead']))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=12))
    story.append(Paragraph("Agent: RECON — External Attack Surface Scanner", styles['AccentText']))

    email = archer.get("email_security", {})

    for check_name, check_data in [("SPF (Sender Policy Framework)", email.get("spf", {})),
                                     ("DMARC (Domain-based Message Authentication)", email.get("dmarc", {})),
                                     ("DKIM (DomainKeys Identified Mail)", email.get("dkim", {}))]:
        status = check_data.get("status", "FAIL")
        status_color = GREEN if status == "PASS" else ORANGE if status == "WARN" else RED
        story.append(Paragraph(
            f'{check_name}: <font color="#{status_color.hexval()[2:]}"><b>{status}</b></font>',
            styles['SubHead']
        ))
        if check_data.get("issue"):
            story.append(Paragraph(check_data["issue"], styles['Body']))
        if check_data.get("record"):
            story.append(Paragraph(
                f'<font name="Courier" size="8">{check_data["record"][:100]}</font>',
                styles['BodySmall']
            ))
        story.append(Spacer(1, 8))

    if not email.get("dmarc", {}).get("exists"):
        story.append(Paragraph(
            '<font color="#e53935"><b>IMPACT:</b></font> Without DMARC, a hacker could send an email as '
            f'anyone@{domain} asking a client to wire money to a fraudulent account. '
            'The email would pass most spam filters and appear completely legitimate.',
            styles['Body']
        ))

    story.append(PageBreak())

    # ═══ PAGE 5: NETWORK & SSL ═══
    story.append(Paragraph("NETWORK EXPOSURE & SSL", styles['SectionHead']))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=12))

    # SSL
    ssl_data = archer.get("ssl", {})
    story.append(Paragraph("SSL/TLS Certificate", styles['SubHead']))
    if ssl_data.get("valid"):
        story.append(Paragraph(
            f'Issuer: {ssl_data.get("issuer", "Unknown")} | '
            f'Expires: {ssl_data.get("expires", "Unknown")} | '
            f'Protocol: {ssl_data.get("protocol", "Unknown")}',
            styles['Body']
        ))
    if ssl_data.get("issue"):
        story.append(Paragraph(ssl_data["issue"], styles['CriticalText']))
    story.append(Spacer(1, 12))

    # Open Ports
    ports = archer.get("ports", {})
    story.append(Paragraph("Open Ports", styles['SubHead']))
    if ports.get("ports"):
        port_data = [['Port', 'Service', 'Risk']]
        for p in ports["ports"][:15]:
            risk_color = RED if p["risk"] == "CRITICAL" else ORANGE if p["risk"] == "HIGH" else MID_GRAY
            port_data.append([str(p["port"]), p["service"], p["risk"]])

        port_table = Table(port_data, colWidths=[60, 120, 80])
        port_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0), CARD),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, LIGHT_GRAY),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(port_table)
    else:
        story.append(Paragraph("No concerning open ports detected.", styles['Body']))

    story.append(PageBreak())

    # ═══ PAGE 6: SECURITY HEADERS & TECH ═══
    story.append(Paragraph("WEB SECURITY & TECHNOLOGY", styles['SectionHead']))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=12))

    headers = archer.get("headers", {})
    story.append(Paragraph("HTTP Security Headers", styles['SubHead']))

    if headers.get("checks"):
        header_data = [['Header', 'Status']]
        for hname, hinfo in headers["checks"].items():
            status = "Present" if hinfo.get("present") else "MISSING"
            header_data.append([hname, status])
        h_table = Table(header_data, colWidths=[280, 80])
        h_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 0), (-1, 0), CARD),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, LIGHT_GRAY),
        ]))
        story.append(h_table)
    story.append(Spacer(1, 12))

    # Technology
    tech = archer.get("technology", {})
    if tech.get("detected"):
        story.append(Paragraph("Technology Detected", styles['SubHead']))
        for t in tech["detected"]:
            risk_note = f' — <font color="#e53935">{t["risk"]}</font>' if t.get("risk") else ""
            story.append(Paragraph(f'{t["name"]}{risk_note}', styles['Body']))

    story.append(PageBreak())

    # ═══ PAGE 7: SECURITY SCORECARD ═══
    story.append(Paragraph("SECURITY SCORECARD", styles['SectionHead']))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=12))

    story.append(Paragraph(
        f'Overall Score: <font color="#{sev_color.hexval()[2:]}"><b>{score}/100 — {label}</b></font>',
        ParagraphStyle('BigScore', fontName='Helvetica-Bold', fontSize=18,
                       textColor=DARK, spaceAfter=16)
    ))

    for cat_name, cat_data in breakdown.items():
        display_name = CATEGORY_LABELS.get(cat_name, cat_name.replace('_', ' ').title())
        story.append(BarChart(display_name, cat_data['score'], cat_data['max']))
        story.append(Spacer(1, 6))

    story.append(Spacer(1, 20))

    # Compliance snapshot
    if compliance:
        story.append(Paragraph("COMPLIANCE SNAPSHOT", styles['SubHead']))
        for fw_id, fw_data in compliance.items():
            if not isinstance(fw_data, dict):
                continue
            pct = fw_data.get("compliance_percentage", 0)
            story.append(Paragraph(
                f'{fw_data.get("framework_name", fw_id)}: <b>{pct}%</b> compliant '
                f'({fw_data.get("met", 0)} met / {fw_data.get("total_controls", 0)} total)',
                styles['Body']
            ))

    story.append(PageBreak())

    # ═══ PAGE 8: REMEDIATION PLAN ═══
    story.append(Paragraph("REMEDIATION PLAN", styles['SectionHead']))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=12))

    priority_groups = {
        'THIS WEEK (Priority 1)': [f for f in findings if f.get('severity') in ['CRITICAL']],
        'THIS MONTH (Priority 2)': [f for f in findings if f.get('severity') in ['HIGH']],
        'THIS QUARTER (Priority 3)': [f for f in findings if f.get('severity') in ['MEDIUM', 'LOW']],
    }

    for group_name, group_findings in priority_groups.items():
        if group_findings:
            story.append(Paragraph(group_name, styles['SubHead']))
            for f in group_findings:
                sev_c = RED if f["severity"] == "CRITICAL" else ORANGE if f["severity"] == "HIGH" else YELLOW
                story.append(Paragraph(
                    f'<font color="#{sev_c.hexval()[2:]}"><b>[{f["severity"]}]</b></font> {f["title"]}',
                    styles['Body']
                ))
                # Use AI narrative if available, otherwise fall back to raw description
                if f.get("narrative"):
                    story.append(Paragraph(f.get("narrative", ""), styles['Body']))
                else:
                    story.append(Paragraph(f'{f.get("description", "")[:150]}', styles['BodySmall']))
                story.append(Paragraph(
                    f'<b>Fix:</b> {f.get("fix", "N/A")} | '
                    f'<b>Effort:</b> {f.get("effort", "N/A")} | '
                    f'<b>Cost:</b> {f.get("cost", "N/A")}',
                    styles['BodySmall']
                ))
                story.append(Spacer(1, 6))

    story.append(PageBreak())

    # ═══ PAGE 9: ABOUT + NEXT STEPS ═══
    story.append(Paragraph("NEXT STEPS", styles['SectionHead']))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=12))

    story.append(Paragraph(
        "This assessment identified several areas requiring immediate attention. "
        "CyberComply's 11 AI agents can address all findings automatically — "
        "from continuous dark web monitoring to policy generation, compliance tracking, "
        "employee phishing tests, and 24/7 security event monitoring.",
        styles['Body']
    ))
    story.append(Spacer(1, 16))

    story.append(Paragraph("YOUR 11 AI AGENTS", styles['SubHead']))
    agents_info = [
        ['Agent', 'Role', 'What It Does For You'],
        ['RECON', 'Attack Surface', 'External vulnerability scanning & scoring'],
        ['SHADOW', 'Dark Web', 'Continuous credential & breach monitoring'],
        ['GUARDIAN', 'Virtual CISO', 'Policies, risk register, compliance roadmap'],
        ['COMPLY', 'Compliance', 'Multi-framework control mapping'],
        ['PHANTOM', 'Phishing', 'Employee phishing simulations & training'],
        ['VIGIL', 'SOC Monitor', '24/7 monitoring of security events'],
        ['SENTINEL', 'Vendor Risk', 'Third-party vendor risk management'],
        ['DISPATCH', 'Incident', 'Automated incident response playbooks'],
        ['FALCON', 'Threat Intel', 'Industry-specific threat monitoring'],
        ['VANGUARD', 'Orchestrator', 'Task management & workflow automation'],
        ['CHRONICLE', 'Reporting', 'Executive reports & compliance evidence'],
    ]
    a_table = Table(agents_info, colWidths=[65, 75, 270])
    a_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 0), (-1, 0), CARD),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 1), (0, -1), ACCENT),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, LIGHT_GRAY),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(a_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("READY TO ACTIVATE YOUR SHIELD?", styles['SubHead']))
    story.append(Paragraph(
        "Book a free 15-minute call to review these findings with our team. "
        "No obligation. No pressure. Just answers.",
        styles['Body']
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        '<b>Schedule:</b> https://calendly.com/security-cybercomply/30min', styles['AccentText']
    ))
    story.append(Paragraph(
        '<b>Email:</b> security@cybercomply.io', styles['AccentText']
    ))
    story.append(Paragraph(
        '<b>Website:</b> https://cybercomply.io', styles['AccentText']
    ))
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="100%", thickness=1, color=LIGHT_GRAY, spaceAfter=8))
    story.append(Paragraph(
        "CyberComply — 11 AI Agents. Always On. Always Watching.",
        styles['Footer']
    ))
    story.append(Paragraph(
        f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} | "
        f"Assessment ID: DCS-{datetime.now().strftime('%Y%m%d')}-{hash(domain) % 10000:04d}",
        styles['Footer']
    ))

    # BUILD PDF
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    return output_path


# ─── MAIN: GENERATE REPORT FROM LIVE SCAN ────────────────

if __name__ == "__main__":
    # Run actual scans and generate report
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from agents.recon_agent import ReconAgent
    from agents.guardian_agent import GuardianAgent

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"[REPORT] Scanning {target} and generating PDF report...")

    # Run RECON scan
    recon_agent = ReconAgent()
    archer_results = recon_agent.scan(target)

    # Create GUARDIAN profile (simulated questionnaire)
    guardian_agent = GuardianAgent()
    profile = guardian_agent.process_questionnaire({
        "q1": target.split('.')[0].title() + " Inc.",
        "q2": "Technology / SaaS",
        "q3": "26-50",
        "q6": "Microsoft 365",
        "q7": "Yes — for some users",
        "q12": ["Client Financial Data"],
        "q15": "No", "q16": "No", "q17": "Never",
        "q18": "No", "q20": "No",
        "q21": ["SOC 2"],
    })
    compliance = guardian_agent.get_compliance_status(profile)

    # Generate report
    scan_data = {
        "domain": target,
        "company_name": target.split('.')[0].title() + " Inc.",
        "archer": archer_results,
        "spectre": {"total_exposed": 0, "breaches": []},
        "forge_profile": profile,
        "compliance": compliance,
    }

    output = f"CyberComply_Security_Report_{target.replace('.', '_')}.pdf"
    generate_report(scan_data, output)
    print(f"\n[REPORT] PDF generated: {output}")
