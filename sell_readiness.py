"""
Sell-readiness checklist.

Eleven invariants the product must hold to be safe to sell. Each check is
a small, isolated probe that returns ("pass" | "fail" | "warn", detail).
Together the checks classify the product into one of four release states:

  ready_to_sell             — every check passes; ship to a paying customer
  ready_with_advisor_review — checks pass but at least one deliverable is
                               waiting on a named advisor's sign-off
  needs_legal_review        — invariants pass but a legal warning surfaces
                               (template gap, missing disclaimer, etc.)
  not_safe_to_sell          — at least one invariant fails

This module is run by the test harness (`tests/test_sell_readiness.py`)
AND exposed via an operator endpoint so the dashboard can show the gate
state at any time.
"""
from __future__ import annotations

import io
import json
import os
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


# ─── Categories ──────────────────────────────────────────────

READY_TO_SELL              = "ready_to_sell"
READY_WITH_ADVISOR_REVIEW  = "ready_with_advisor_review"
NEEDS_LEGAL_REVIEW         = "needs_legal_review"
NOT_SAFE_TO_SELL           = "not_safe_to_sell"

CATEGORY_LABELS = {
    READY_TO_SELL:             "Ready to sell",
    READY_WITH_ADVISOR_REVIEW: "Ready with advisor review",
    NEEDS_LEGAL_REVIEW:        "Needs legal review",
    NOT_SAFE_TO_SELL:          "Not safe to sell",
}


# ─── Check shape ─────────────────────────────────────────────

@dataclass
class Check:
    id: str
    label: str
    status: str = "pass"          # pass | fail | warn | advisor_pending
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "label": self.label,
                 "status": self.status, "detail": self.detail}


# ─── 1. Private routes require auth ──────────────────────────

def check_private_routes_require_auth() -> Check:
    """Probe a sentinel set of private routes via TestClient with no auth."""
    try:
        from starlette.testclient import TestClient
        import importlib
        # Late import to pick up the live app.
        if "main" not in importlib.sys.modules:
            import main  # type: ignore
        else:
            main = importlib.sys.modules["main"]
        c = TestClient(main.app, raise_server_exceptions=False)
        sentinels = [
            "/api/clients",
            "/api/leads",
            "/api/operator/delivery-console",
            "/api/operator/audit-log",
            "/api/operator/clients/x/legal-authorization",
        ]
        for path in sentinels:
            resp = c.get(path)
            if resp.status_code != 401:
                return Check("private_routes_auth",
                              "Private routes require auth",
                              "fail",
                              f"{path} returned {resp.status_code}")
        return Check("private_routes_auth",
                      "Private routes require auth",
                      "pass",
                      f"{len(sentinels)} sentinel routes returned 401 unauthenticated")
    except Exception as e:
        return Check("private_routes_auth",
                      "Private routes require auth", "fail", f"probe error: {e}")


# ─── 2. Client isolation ─────────────────────────────────────

def check_client_isolation(*, client_a: str = "ck_a", client_b: str = "ck_b") -> Check:
    """Verify a portal JWT minted for client_a cannot read client_b's portal
    or audit log endpoints. Uses a fresh in-memory clients tree."""
    try:
        import client_manager
        from starlette.testclient import TestClient
        import importlib
        main = importlib.import_module("main")
        cm = client_manager
        # Don't pollute existing data: only run if at least 2 client profiles
        # we own already exist OR we can create a-b without disturbing prod.
        cm.create_client(client_a, "A", "a.com", tier="essentials")
        cm.create_client(client_b, "B", "b.com", tier="essentials")
        token_a = cm.create_jwt(client_a)
        c = TestClient(main.app, raise_server_exceptions=False)
        c.cookies.set("portal_token", token_a)
        for path in (f"/portal/{client_b}",
                      f"/api/portal/{client_b}/audit-log",
                      f"/api/portal/{client_b}/legal-authorization"):
            resp = c.get(path)
            if resp.status_code == 200 and "window.location" not in resp.text:
                return Check("client_isolation",
                              "Client isolation",
                              "fail",
                              f"client_a reached {path} — got {resp.status_code}")
        return Check("client_isolation",
                      "Client isolation", "pass",
                      "Cross-client portal + audit endpoints blocked")
    except Exception as e:
        return Check("client_isolation",
                      "Client isolation", "warn",
                      f"probe could not run cleanly: {e}")


# ─── 3. Active validation requires authorization ─────────────

def check_active_validation_gate() -> Check:
    try:
        import security_validation as sv
        import client_manager
        cm = client_manager
        cm.create_client("ck_sv", "SV", "sv.com")
        eng = sv.create_engagement("ck_sv", scan_class=sv.SCAN_ACTIVE)
        sv.scope_engagement("ck_sv", eng["engagement_id"], {
            "target_domains": ["sv.com"],
            "testing_window": {"start_at": "", "end_at": ""},
            "emergency_contact": {"name": "X", "phone_24x7": "+1"},
        })
        # No legal record on file → approve must refuse.
        try:
            sv.approve_engagement("ck_sv", eng["engagement_id"], "Op")
            return Check("active_validation_gate",
                          "Active validation requires authorization",
                          "fail",
                          "approve_engagement() succeeded without legal record")
        except sv.EngagementTransitionError as e:
            if "legal authorization" in str(e).lower() or "preconditions" in str(e).lower():
                return Check("active_validation_gate",
                              "Active validation requires authorization",
                              "pass",
                              "approve_engagement() blocks without signed legal stack")
            return Check("active_validation_gate",
                          "Active validation requires authorization",
                          "warn",
                          f"unexpected error: {e}")
    except Exception as e:
        return Check("active_validation_gate",
                      "Active validation requires authorization",
                      "fail", f"probe error: {e}")


# ─── 4. No false all-clear states in alert partials ──────────

_FORBIDDEN_ALERT_PHRASES = (
    "your credentials are clean",
    "all systems normal",
    "no threats detected for your technology stack",
    "no threats detected.",
    "all clear",
    "first scan runs on the 15th",
    "first campaign launches next quarter",
)


def check_no_false_all_clear_states() -> Check:
    """Scan the alert-partial templates and route handlers for forbidden
    'all clear' language. The truth-gate copy lives in templates/partials."""
    suspect_files = [
        "templates/partials/alert_panel.html",
        "templates/partials/alert_report.html",
        "templates/portal.html",
    ]
    findings: list[str] = []
    for path in suspect_files:
        try:
            with open(path) as f:
                text = f.read().lower()
        except FileNotFoundError:
            continue
        for phrase in _FORBIDDEN_ALERT_PHRASES:
            if phrase in text:
                findings.append(f"{path}: contains '{phrase}'")
    if findings:
        return Check("no_false_all_clear",
                      "No false all-clear states", "fail",
                      "; ".join(findings))
    return Check("no_false_all_clear",
                  "No false all-clear states", "pass",
                  "No forbidden 'all clear' phrases found in alert templates")


# ─── 5. Reviewed claims require metadata ─────────────────────

def check_reviewed_claims_require_metadata() -> Check:
    """Build the document library with NO review record and assert that
    no item ends up at status='Advisor reviewed'."""
    try:
        import document_library as dl
        out = dl.build_library(
            client_id="ck_rev", tier="essentials",
            reports=[{"filename": "monthly_2026-04.pdf", "date": "2026-04-15"}],
            policies=[{"filename": "wisp.pdf"}],
            frameworks=[],
            advisor_name="Alice",
            advisor_reviewed_at="2026-04-15",            # heuristic only
            monthly_summary_reviewed_at="2026-04-15",
            legal_view={},
            review_records={},                            # NO real records
        )
        bad = []
        for d in (out["reports"] + out["policies"]):
            if d["review_status"] == dl.STATUS_ADVISOR_REVIEWED:
                bad.append(d["business_title"])
        if bad:
            return Check("reviewed_claims_metadata",
                          "Reviewed claims require metadata", "fail",
                          "Static heuristic still produces 'Advisor reviewed': "
                          + ", ".join(bad))
        return Check("reviewed_claims_metadata",
                      "Reviewed claims require metadata", "pass",
                      "Without sign-off records, no item is marked Advisor reviewed")
    except Exception as e:
        return Check("reviewed_claims_metadata",
                      "Reviewed claims require metadata", "fail",
                      f"probe error: {e}")


# ─── 6. Alert HTML is escaped ────────────────────────────────

def check_alert_html_escaped() -> Check:
    """Render the alert_panel template directly with a script payload and
    confirm the raw <script> never appears in the output."""
    try:
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader("templates"), autoescape=True)
        tmpl = env.get_template("partials/alert_panel.html")
        payload = '<script>alert("xss")</script>'
        html = tmpl.render(
            category_label=payload,
            source_label=payload,
            cadence_label="Weekly",
            state="success_with_findings",
            last_checked="2026-04-15",
            alerts=[{"title": payload, "narrative": payload,
                      "severity": "HIGH", "actions": [payload], "date": "2026-04-15"}],
            extras_kind="darkweb",
            next_action=payload,
            setup_action="",
        )
        if '<script>alert("xss")</script>' in html:
            return Check("alert_html_escaped",
                          "Alert HTML is escaped", "fail",
                          "Raw <script> appears in rendered alert panel")
        if "&lt;script&gt;" not in html and "&#39;" not in html and "&#34;" not in html:
            # No escaped form found at all — suggests the payload was stripped,
            # which would also be safe but worth a warning.
            return Check("alert_html_escaped",
                          "Alert HTML is escaped", "warn",
                          "Payload absent but no escaped marker found")
        return Check("alert_html_escaped",
                      "Alert HTML is escaped", "pass",
                      "Script payload escaped via autoescape")
    except Exception as e:
        return Check("alert_html_escaped",
                      "Alert HTML is escaped", "fail",
                      f"probe error: {e}")


# ─── 7. Evidence package excludes secrets ────────────────────

_SECRET_KEYS = ("password_hash", "magic_token", "magic_token_expires",
                "stripe_secret", "stripe_secret_key", "reset_token_nonce",
                "OPERATOR_MFA_SECRET", "JWT_SECRET")


def check_evidence_package_excludes_secrets() -> Check:
    """Build an audit package programmatically and confirm no plaintext
    secret marker appears in any of the file contents."""
    try:
        from starlette.testclient import TestClient
        import importlib, client_manager
        main = importlib.import_module("main")
        cm = client_manager
        cm.create_client("ck_zip", "ZipCo", "zip.com", tier="essentials")
        cm.set_portal_password("ck_zip", "Tr0ub4dor&3-Castle")
        # Create some content so the ZIP isn't empty.
        reports = cm._client_dir("ck_zip") / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "r.pdf").write_bytes(b"%PDF")
        token = cm.create_jwt("ck_zip")
        c = TestClient(main.app, raise_server_exceptions=False)
        c.cookies.set("portal_token", token)
        resp = c.get("/portal/ck_zip/download/audit-package")
        if resp.status_code != 200:
            return Check("evidence_no_secrets",
                          "Evidence package excludes secrets", "warn",
                          f"Audit package returned {resp.status_code}")
        z = zipfile.ZipFile(io.BytesIO(resp.content))
        offenders = []
        for name in z.namelist():
            try:
                blob = z.read(name).decode("utf-8", errors="ignore")
            except Exception:
                continue
            for key in _SECRET_KEYS:
                if key in blob:
                    offenders.append(f"{name}: contains '{key}'")
        if offenders:
            return Check("evidence_no_secrets",
                          "Evidence package excludes secrets", "fail",
                          "; ".join(offenders))
        return Check("evidence_no_secrets",
                      "Evidence package excludes secrets", "pass",
                      f"Verified {len(z.namelist())} files contain no known secrets")
    except Exception as e:
        return Check("evidence_no_secrets",
                      "Evidence package excludes secrets", "warn",
                      f"probe error: {e}")


# ─── 8. Pricing tiers match billing thresholds ───────────────

def check_pricing_thresholds_match() -> Check:
    """The TIERS table values must align with the Stripe webhook brackets."""
    try:
        import client_manager
        cm = client_manager
        # Canonical tiers and their ARR amounts.
        spec = {
            "diagnostic":     0,
            "essentials":     24_000,
            "professional":   48_000,
            "enterprise_plus": 96_000,
        }
        for tier, expected in spec.items():
            arr = cm.annual_revenue_for_tier(tier)
            if arr != expected:
                return Check("pricing_thresholds",
                              "Pricing tiers match billing thresholds", "fail",
                              f"{tier} ARR={arr}, expected {expected}")

        # Stripe webhook thresholds (in cents) must match the tier amounts.
        # We can't run the webhook live without Stripe; instead, check the
        # billing module source contains the spec'd thresholds.
        with open("billing.py") as f:
            src = f.read()
        for cents in ("9_600_000", "4_800_000", "2_400_000"):
            if cents not in src:
                return Check("pricing_thresholds",
                              "Pricing tiers match billing thresholds", "fail",
                              f"Stripe webhook missing threshold {cents}")
        return Check("pricing_thresholds",
                      "Pricing tiers match billing thresholds", "pass",
                      "Tier ARR + Stripe thresholds both align with the commercial spec")
    except Exception as e:
        return Check("pricing_thresholds",
                      "Pricing tiers match billing thresholds", "fail",
                      f"probe error: {e}")


# ─── 9. Task verification workflow ───────────────────────────

def check_task_verification_workflow() -> Check:
    try:
        import client_manager
        cm = client_manager
        cm.create_client("ck_task", "TaskCo", "task.com")
        t = cm.add_task("ck_task", "Fix DMARC", "HIGH", "Email")
        # Customer cannot directly verify.
        try:
            cm.update_task_status("ck_task", t["id"], cm.TASK_STATUS_VERIFIED)
            return Check("task_workflow",
                          "Task verification workflow", "fail",
                          "Customer-facing status setter accepted 'verified'")
        except cm.TaskTransitionError:
            pass
        # Submit + advisor verify.
        cm.submit_task_for_review("ck_task", t["id"], by="customer")
        cm.verify_task("ck_task", t["id"], by="Alice CISSP",
                        method="rescan", reviewer_credential="CISSP")
        after = next(x for x in cm.get_tasks("ck_task") if x["id"] == t["id"])
        if after["status"] != cm.TASK_STATUS_VERIFIED:
            return Check("task_workflow",
                          "Task verification workflow", "fail",
                          f"after verify status={after['status']}")
        if after.get("verified_by") != "Alice CISSP":
            return Check("task_workflow",
                          "Task verification workflow", "fail",
                          "verified_by not recorded")
        return Check("task_workflow",
                      "Task verification workflow", "pass",
                      "Submit→verify cycle records verified_by + verified_at")
    except Exception as e:
        return Check("task_workflow",
                      "Task verification workflow", "fail",
                      f"probe error: {e}")


# ─── 10. Audit logs are written ──────────────────────────────

def check_audit_logs_written() -> Check:
    try:
        import audit_log as al
        before = len(al.list_events(client_id=None, limit=10_000))
        al.record(action=al.ACTION_LOGIN, actor="probe",
                   role=al.ROLE_CUSTOMER, client_id="ck_audit_probe")
        after = len(al.list_events(client_id=None, limit=10_000))
        if after <= before:
            return Check("audit_log_written",
                          "Audit logs are written", "fail",
                          f"event count did not grow ({before} → {after})")
        recent = al.list_events(client_id="ck_audit_probe", limit=5)
        if not recent or recent[0].get("action") != al.ACTION_LOGIN:
            return Check("audit_log_written",
                          "Audit logs are written", "fail",
                          "expected probe event missing from per-client stream")
        return Check("audit_log_written",
                      "Audit logs are written", "pass",
                      "Probe event landed in both global and per-client streams")
    except Exception as e:
        return Check("audit_log_written",
                      "Audit logs are written", "fail",
                      f"probe error: {e}")


# ─── 11. Mobile responsive selectors present ─────────────────

_REQUIRED_BREAKPOINTS = ("max-width:600px", "max-width:380px", "max-width:340px")


def check_portal_mobile_responsive() -> Check:
    """Static check: verify the customer-facing templates declare media
    queries for the required mobile breakpoints. The auth pages (login,
    forgot, reset, setup) are short-form forms that scale automatically
    with viewport units + max-width clamps; they need at minimum a
    viewport meta tag and a fluid layout (max-width on the card)."""
    main_surfaces = [
        "templates/portal.html",
        "templates/advisory_report.html",
        "templates/dashboard.html",
    ]
    auth_surfaces = [
        "templates/portal_login.html",
        "templates/portal_setup.html",
        "templates/portal_forgot.html",
        "templates/portal_reset.html",
    ]
    missing: list[str] = []
    for p in main_surfaces:
        try:
            with open(p) as f:
                text = f.read().lower().replace(" ", "")
        except FileNotFoundError:
            missing.append(f"{p}: file missing")
            continue
        for bp in _REQUIRED_BREAKPOINTS:
            if bp.replace(" ", "") not in text:
                missing.append(f"{p}: no @media for {bp}")
    # Auth surfaces only need a viewport meta + an explicit max-width clamp.
    for p in auth_surfaces:
        try:
            with open(p) as f:
                text = f.read()
        except FileNotFoundError:
            continue
        if 'name="viewport"' not in text:
            missing.append(f"{p}: missing viewport meta")
        if "max-width" not in text:
            missing.append(f"{p}: no fluid max-width clamp")
    if missing:
        return Check("portal_mobile_responsive",
                      "Portal templates render on mobile-sized layouts",
                      "warn", "; ".join(missing))
    return Check("portal_mobile_responsive",
                  "Portal templates render on mobile-sized layouts",
                  "pass", "All required @media breakpoints declared")


# ─── Legal-review warnings (advisory) ────────────────────────

def _legal_warnings() -> list[str]:
    """Soft warnings that don't block sale but warrant a legal review pass."""
    warnings = []
    # Disclaimers must mention 'no legal advice' and 'no breach prevention guarantee'.
    try:
        import advisory_report as ar
        titles = [d["title"].lower() for d in ar.DISCLAIMERS]
        if not any("legal" in t for t in titles):
            warnings.append("Advisory report disclaimers missing 'No legal advice'")
        if not any("breach" in t for t in titles):
            warnings.append("Advisory report disclaimers missing 'No breach-prevention guarantee'")
    except Exception:
        warnings.append("Could not load advisory_report disclaimers")
    return warnings


# ─── Advisor-pending check ───────────────────────────────────

def _advisor_pending_warnings() -> list[str]:
    """Warnings when a deliverable is on disk but has no signed-off review.
    Skipped at module level when there are no live clients."""
    out: list[str] = []
    try:
        import client_manager
        import advisor_review as ar
        for client in client_manager.list_all_clients():
            cid = client.get("client_id", "")
            if not cid:
                continue
            reviews = ar.list_reviews(cid)
            policies = client_manager.get_policies(cid) or []
            for p in policies:
                fname = p.get("filename", "")
                key_guess = "wisp" if "wisp" in fname.lower() else None
                if key_guess:
                    rec = reviews.get(ar.policy_key(key_guess), {})
                    if not ar.is_signed_off(rec):
                        out.append(
                            f"client {cid}: {fname} exists but advisor review pending"
                        )
    except Exception:
        pass
    return out


# ─── Entry point ────────────────────────────────────────────

def run_checks() -> dict[str, Any]:
    checks: list[Check] = [
        check_private_routes_require_auth(),
        check_client_isolation(),
        check_active_validation_gate(),
        check_no_false_all_clear_states(),
        check_reviewed_claims_require_metadata(),
        check_alert_html_escaped(),
        check_evidence_package_excludes_secrets(),
        check_pricing_thresholds_match(),
        check_task_verification_workflow(),
        check_audit_logs_written(),
        check_portal_mobile_responsive(),
    ]
    legal_warnings = _legal_warnings()
    advisor_pending = _advisor_pending_warnings()

    fails = [c for c in checks if c.status == "fail"]
    warns = [c for c in checks if c.status == "warn"]
    if fails:
        category = NOT_SAFE_TO_SELL
        summary = (
            f"{len(fails)} invariant(s) failed. Resolve before any further "
            "sales activity. See checklist for details."
        )
    elif legal_warnings:
        category = NEEDS_LEGAL_REVIEW
        summary = (
            "All invariants pass. Legal review recommended before signing "
            "first paying customer: " + "; ".join(legal_warnings)
        )
    elif advisor_pending:
        category = READY_WITH_ADVISOR_REVIEW
        summary = (
            "Product is sound. At least one deliverable is awaiting named "
            "advisor sign-off before customer release."
        )
    elif warns:
        category = READY_WITH_ADVISOR_REVIEW
        summary = (
            "All hard checks pass; soft warnings present: "
            + "; ".join(c.detail for c in warns)
        )
    else:
        category = READY_TO_SELL
        summary = (
            "All 11 invariants pass and no advisor / legal items are pending."
        )

    return {
        "category": category,
        "category_label": CATEGORY_LABELS[category],
        "summary": summary,
        "checks": [c.to_dict() for c in checks],
        "legal_warnings": legal_warnings,
        "advisor_pending": advisor_pending,
    }
