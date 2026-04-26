"""
Premium client qualification.

Evaluates a 15-field intake form and returns one of:
  qualified | needs_review | disqualified | waitlist

Customer-facing copy is intentionally soft. Internal `flags` and `reasons`
are operator-only and never surfaced to the customer.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any


# ─── Reference data ────────────────────────────────────────────

# Tier 1 + Tier 2 markets only. Anything else routes to waitlist (partner channel).
SUPPORTED_COUNTRIES = {
    # Tier 1
    "US", "CA", "GB", "UK", "IE", "AU", "NZ", "SG", "HK",
    # Tier 2
    "DE", "FR", "NL", "ES", "IT", "BE", "SE", "DK", "FI", "PL",
    "CH", "NO", "IS", "AE", "SA", "IL", "IN", "ZA",
}

# OFAC + sanctioned + jurisdictions we will not service.
BLOCKED_COUNTRIES = {"RU", "BY", "IR", "KP", "CU", "SY", "VE", "MM", "CN"}

# Industries we will not onboard regardless of revenue.
PROHIBITED_INDUSTRIES = {
    "adult", "gambling", "crypto_exchange", "weapons",
    "surveillance_tech", "political_campaign", "cannabis_unlicensed",
    "payday_lending", "mlm", "shell_company",
}

# Industries we welcome and have vertical templates for.
PREFERRED_INDUSTRIES = {
    "cpa", "accounting", "tax", "healthcare", "medical_practice",
    "rcm", "legal", "law_firm", "saas", "vertical_saas",
    "fintech", "wealth_management", "ria", "insurance_brokerage",
    "msp", "title_escrow", "real_estate",
}

# Revenue band ordering (lowest to highest).
REVENUE_BANDS = [
    "under_1m",
    "1m_5m",
    "5m_10m",
    "10m_25m",
    "25m_50m",
    "50m_100m",
    "100m_250m",
    "over_250m",
]

# Employee band ordering.
EMPLOYEE_BANDS = [
    "under_10",
    "10_24",
    "25_49",
    "50_99",
    "100_249",
    "250_499",
    "500_plus",
]

# Compliance drivers we recognize as legitimate.
VALID_COMPLIANCE_DRIVERS = {
    "audit_upcoming", "rfp_requirement", "insurance_renewal",
    "client_due_diligence", "regulatory_deadline", "breach_response",
    "board_mandate", "investor_due_diligence", "vendor_questionnaire",
    "contract_clause", "state_law_deadline",
}

# Frameworks we have built-in mapping for.
SUPPORTED_FRAMEWORKS = {
    "soc2", "hipaa", "ftc_safeguards", "irs_4557", "nist_csf",
    "iso_27001", "pci_dss", "nis2", "dora", "gdpr", "uk_gdpr",
    "essential_eight", "cyber_essentials", "pdpa", "lgpd", "dpdp",
    "popia", "appi", "ncc_ecc",
}

# Decision-maker titles we accept for paid onboarding.
EXECUTIVE_TITLES = {
    "ceo", "founder", "owner", "managing_partner", "partner",
    "president", "coo", "cfo", "cto", "ciso", "cio",
    "vp", "head_of", "director_finance", "director_it",
    "director_compliance", "director_security", "general_counsel",
}

# Titles too junior to authorize a paid retainer alone.
JUNIOR_TITLES = {
    "analyst", "intern", "associate", "specialist",
    "coordinator", "junior", "consultant_external",
}

# Cyber insurance status.
INSURANCE_STATES = {"in_force", "renewing_soon", "denied", "none", "unknown"}

# Internal security maturity self-rating.
MATURITY_LEVELS = {"none", "basic", "developing", "established", "mature"}


# ─── Result builder ────────────────────────────────────────────

def _result(
    status: str,
    headline: str,
    customer_message: str,
    next_step: str,
    flags: list[str],
    reasons: list[str],
    score: int,
) -> dict[str, Any]:
    return {
        "status": status,
        "headline": headline,                 # safe to show customer
        "customer_message": customer_message, # safe to show customer
        "next_step": next_step,               # safe to show customer
        "flags": flags,                       # OPERATOR ONLY
        "reasons": reasons,                   # OPERATOR ONLY
        "score": score,                       # OPERATOR ONLY
        "evaluated_at": datetime.utcnow().isoformat(),
    }


# ─── Evaluator ────────────────────────────────────────────────

def evaluate(answers: dict[str, Any]) -> dict[str, Any]:
    """
    Evaluate a qualification submission.

    Required answer keys (all strings unless noted):
      legal_name, domain, country, industry, revenue_band,
      employee_band, compliance_driver, framework, dm_title,
      urgency, insurance_status, maturity, has_internal_ciso (bool),
      domain_ownership_confirmed (bool), prohibited_self_attest (bool)

    Returns a dict with status + customer-safe copy + operator-only flags.
    """
    flags: list[str] = []
    reasons: list[str] = []
    score = 0

    legal_name = (answers.get("legal_name") or "").strip()
    domain = (answers.get("domain") or "").strip().lower()
    country = (answers.get("country") or "").upper().strip()
    industry = (answers.get("industry") or "").lower().strip()
    revenue = (answers.get("revenue_band") or "").lower().strip()
    employees = (answers.get("employee_band") or "").lower().strip()
    driver = (answers.get("compliance_driver") or "").lower().strip()
    framework = (answers.get("framework") or "").lower().strip()
    dm_title = (answers.get("dm_title") or "").lower().strip()
    urgency = (answers.get("urgency") or "").lower().strip()
    insurance = (answers.get("insurance_status") or "").lower().strip()
    maturity = (answers.get("maturity") or "").lower().strip()
    has_internal_ciso = bool(answers.get("has_internal_ciso", False))
    domain_owner_ok = bool(answers.get("domain_ownership_confirmed", False))
    prohibited_attest = bool(answers.get("prohibited_self_attest", False))

    # ── Hard blockers (disqualified) ──
    if not legal_name or not domain:
        flags.append("missing_required_fields")
        reasons.append("Legal name or domain not provided.")
        return _result(
            status="needs_review",
            headline="We need a few more details",
            customer_message=(
                "Thanks for your interest. Please complete the company name "
                "and primary domain so we can prepare your proposal."
            ),
            next_step="return_to_form",
            flags=flags, reasons=reasons, score=0,
        )

    if country in BLOCKED_COUNTRIES:
        flags.append("blocked_jurisdiction")
        reasons.append(f"Country {country} is on our restricted list (sanctions / data residency).")
        return _result(
            status="disqualified",
            headline="We're not able to onboard clients in your region right now",
            customer_message=(
                "Thank you for considering CyberComply. We currently cannot offer "
                "service in your region. We'll let you know if that changes."
            ),
            next_step="end",
            flags=flags, reasons=reasons, score=0,
        )

    if industry in PROHIBITED_INDUSTRIES:
        flags.append("prohibited_industry")
        reasons.append(f"Industry '{industry}' is outside our service scope.")
        return _result(
            status="disqualified",
            headline="Your industry is outside our current service scope",
            customer_message=(
                "Thanks for reaching out. The industries we serve today don't "
                "include yours. We'd recommend a specialist provider — we're "
                "happy to make an introduction if helpful."
            ),
            next_step="referral",
            flags=flags, reasons=reasons, score=0,
        )

    if not domain_owner_ok:
        flags.append("domain_ownership_unconfirmed")
        reasons.append("Customer did not confirm authority over the domain.")
        # Soft handling — we just route to needs_review.

    # ── Country support ──
    if country not in SUPPORTED_COUNTRIES:
        flags.append("country_not_in_direct_market")
        reasons.append(f"Country {country} is outside our direct-sales region; partner channel.")
        return _result(
            status="waitlist",
            headline="We'd love to support you through a partner",
            customer_message=(
                "We're not yet onboarding direct clients in your region, but we "
                "work with trusted partners who can deliver the same outcomes. "
                "Add yourself to our priority list and we'll connect you with "
                "the right partner."
            ),
            next_step="partner_referral",
            flags=flags, reasons=reasons, score=0,
        )

    # ── Soft filters (combine to Qualified / Needs review / Waitlist) ──

    # Revenue floor
    revenue_idx = REVENUE_BANDS.index(revenue) if revenue in REVENUE_BANDS else -1
    if revenue_idx >= 0 and revenue_idx <= 1:  # under $5M
        flags.append("below_revenue_floor")
        reasons.append("Revenue band below $5M ARR threshold.")
    elif revenue_idx >= 2:
        score += 20

    # Employee floor
    emp_idx = EMPLOYEE_BANDS.index(employees) if employees in EMPLOYEE_BANDS else -1
    if emp_idx >= 0 and emp_idx <= 1:  # under 25
        flags.append("below_employee_floor")
        reasons.append("Headcount below 25 FTE threshold.")
    elif emp_idx >= 2:
        score += 15

    # Compliance driver
    if not driver or driver not in VALID_COMPLIANCE_DRIVERS:
        flags.append("no_compliance_driver")
        reasons.append("No clear compliance forcing function articulated.")
    else:
        score += 20

    # Framework
    if framework and framework in SUPPORTED_FRAMEWORKS:
        score += 10
    else:
        flags.append("framework_unmapped")
        reasons.append("Framework not in built-in mapping library.")

    # Decision-maker
    if dm_title in JUNIOR_TITLES:
        flags.append("non_decision_maker_contact")
        reasons.append("Primary contact is below typical buyer authority.")
    elif dm_title in EXECUTIVE_TITLES:
        score += 20
    else:
        flags.append("dm_title_unclassified")
        reasons.append("Contact title not recognized as decision-maker.")

    # Urgency
    if urgency in ("immediate", "30_days"):
        score += 15
    elif urgency in ("90_days", "this_quarter"):
        score += 8
    elif urgency in ("exploring", "no_timeline"):
        flags.append("no_urgency")
        reasons.append("No stated timeline or forcing event.")

    # Cyber insurance
    if insurance == "denied":
        flags.append("insurance_denied")
        reasons.append("Insurance was denied — high-touch remediation likely required.")
        score += 5  # still buying motion
    elif insurance == "renewing_soon":
        score += 10  # strong forcing function
    elif insurance not in INSURANCE_STATES:
        flags.append("insurance_status_unknown")
        reasons.append("Insurance status not provided.")

    # Internal security maturity — high maturity is NOT our ICP
    if has_internal_ciso:
        flags.append("has_internal_ciso")
        reasons.append("Internal CISO present — buyer typically wants best-of-breed point tools.")
    if maturity == "mature":
        flags.append("internal_security_mature")
        reasons.append("Self-reported mature security program — best fit is partner channel or co-sell.")
    elif maturity in ("none", "basic", "developing"):
        score += 10

    # Prohibited self-attest (false attest = customer didn't confirm clean industry)
    if not prohibited_attest:
        flags.append("prohibited_attest_missing")
        reasons.append("Customer did not attest they are not in a prohibited industry.")

    # ── Decide status from flags + score ──

    hard_review_flags = {
        "below_revenue_floor", "below_employee_floor",
        "no_compliance_driver", "non_decision_maker_contact",
        "domain_ownership_unconfirmed", "prohibited_attest_missing",
    }
    not_ideal_flags = {"has_internal_ciso", "internal_security_mature"}

    has_hard_review = bool(set(flags) & hard_review_flags)
    has_not_ideal = bool(set(flags) & not_ideal_flags)

    # Mature internal security team → waitlist / partner
    if has_not_ideal and not has_hard_review:
        return _result(
            status="waitlist",
            headline="It looks like you've already built strong internal security",
            customer_message=(
                "Companies with an established in-house security team typically "
                "get better value from us through our partner channel or specific "
                "co-sell engagements. We'd love to introduce you to the right fit."
            ),
            next_step="partner_referral",
            flags=flags, reasons=reasons, score=score,
        )

    # Below floors / no driver / junior contact → needs review
    if has_hard_review:
        return _result(
            status="needs_review",
            headline="Let's set up a quick call to scope this properly",
            customer_message=(
                "Based on what you shared, our team would like to learn a bit "
                "more about your goals before recommending the right plan. "
                "We'll be in touch within one business day to schedule a brief "
                "fit call."
            ),
            next_step="schedule_intro_call",
            flags=flags, reasons=reasons, score=score,
        )

    # High score, no blockers → qualified
    if score >= 60:
        return _result(
            status="qualified",
            headline="You're a great fit — let's get started",
            customer_message=(
                "Based on your responses, we can move directly to onboarding. "
                "You'll receive a proposal and engagement letter for review, "
                "and your named advisor will reach out to schedule kickoff."
            ),
            next_step="proposal",
            flags=flags, reasons=reasons, score=score,
        )

    # Default soft path
    return _result(
        status="needs_review",
        headline="Thanks — we'll be in touch shortly",
        customer_message=(
            "Your responses are with our team. A named advisor will reach out "
            "within one business day to confirm fit and walk you through next steps."
        ),
        next_step="schedule_intro_call",
        flags=flags, reasons=reasons, score=score,
    )
