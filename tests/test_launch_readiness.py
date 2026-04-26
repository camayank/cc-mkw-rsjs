"""Final launch-readiness checks.

These assertions cover the items a first-paying-customer due-diligence
review will look at, beyond what sell_readiness.py already covers:

  - Legal entity attribution present on every customer-facing surface
  - .env.example and README.md exist so an operator can deploy
  - Lead-capture flow does not silently imply email delivery
  - No "TODO/FIXME/lorem" placeholder copy in shipped templates
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PRODUCT_ENTITY = "DigComply"
PRODUCT_ASSOCIATION = "CA4CPA"


CUSTOMER_FACING_TEMPLATES = [
    "templates/landing.html",
    "templates/scan.html",
    "templates/report.html",
    "templates/advisory_report.html",
    "templates/portal.html",
]


@pytest.mark.parametrize("path", CUSTOMER_FACING_TEMPLATES)
def test_legal_entity_attribution_present(path):
    with open(path) as f:
        text = f.read()
    assert PRODUCT_ENTITY in text, (
        f"{path}: missing DigComply attribution — first paying customer's "
        f"invoice and disclaimers must reference the issuing legal entity."
    )
    assert PRODUCT_ASSOCIATION in text, (
        f"{path}: missing CA4CPA association"
    )


def test_advisory_report_disclaimers_attribute_to_legal_entity():
    if "advisory_report" in sys.modules:
        del sys.modules["advisory_report"]
    import advisory_report as ar
    titles = [d["title"] for d in ar.DISCLAIMERS]
    bodies = [d["body"] for d in ar.DISCLAIMERS]
    assert "Issuing entity" in titles, "Advisory report disclaimers missing 'Issuing entity'"
    issuing_body = next(b for d in ar.DISCLAIMERS for b in [d["body"]]
                        if d["title"] == "Issuing entity")
    assert PRODUCT_ENTITY in issuing_body
    assert PRODUCT_ASSOCIATION in issuing_body


def test_env_example_documents_required_variables():
    with open(".env.example") as f:
        text = f.read()
    required_keys = [
        "DATA_DIR", "JWT_SECRET", "DASHBOARD_PASSWORD",
        "BASE_URL", "RESET_TOKEN_SECRET",
    ]
    for k in required_keys:
        assert k in text, f".env.example missing required variable: {k}"

    optional_integration_keys = [
        "HIBP_API_KEY", "GOPHISH_API_KEY", "MS_TENANT_ID",
        "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET",
        "SMTP_HOST", "OPERATOR_MFA_SECRET", "APEX_BIN",
    ]
    for k in optional_integration_keys:
        assert k in text, f".env.example missing optional integration: {k}"


def test_env_example_warns_about_test_only_bypasses():
    with open(".env.example") as f:
        text = f.read()
    # Both bypass flags should appear with explicit "do not set in production" warning.
    assert "BYPASS_PASSWORD_POLICY" in text
    assert "OPERATOR_MFA_DISABLED" in text
    assert "DO NOT SET in production" in text or "Never set this in production" in text


def test_readme_present_with_required_sections():
    with open("README.md") as f:
        text = f.read()
    for section in [
        PRODUCT_ENTITY, PRODUCT_ASSOCIATION,
        "Operator first-time setup", "Customer onboarding flow",
        "Advisor delivery flow", "Audit log",
        "Backup / restore", "Manual business / legal steps",
    ]:
        assert section in text, f"README.md missing section: {section}"


def test_no_placeholder_or_internal_text_in_customer_templates():
    forbidden = [
        "lorem ipsum", "TODO:", "FIXME", "XXX:", "TBD",
        "placeholder text", "fake data", "demo only — remove before launch",
    ]
    for tmpl in CUSTOMER_FACING_TEMPLATES + [
        "templates/portal_login.html", "templates/portal_setup.html",
        "templates/portal_forgot.html", "templates/portal_reset.html",
        "templates/qualify.html",
    ]:
        with open(tmpl) as f:
            text = f.read().lower()
        for phrase in forbidden:
            assert phrase.lower() not in text, (
                f"{tmpl}: contains placeholder/internal phrase '{phrase}'"
            )


def test_lead_capture_does_not_falsely_claim_email_delivery():
    """The success state must not say 'sent' / 'delivered' — it has to be
    contingent on actual SMTP configuration to avoid false promises."""
    with open("templates/scan.html") as f:
        text = f.read()
    # The honest copy is in place ("when email is configured" or "shortly").
    # Forbid bare promises like "Report sent" / "Email delivered".
    forbidden = [
        "Email delivered",
        "Your report has been sent",
        "Email sent successfully",
    ]
    for phrase in forbidden:
        assert phrase not in text, (
            f"scan.html: lead success contains false delivery claim: '{phrase}'"
        )


def test_portal_sidebar_attributes_to_legal_entity():
    with open("templates/portal.html") as f:
        text = f.read()
    # The footer of the sidebar should attribute to the issuing entity so
    # a customer screenshot taken anywhere in the portal carries it.
    assert PRODUCT_ENTITY in text
    assert PRODUCT_ASSOCIATION in text
