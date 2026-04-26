"""Auth/security primitives tests.

Proves:
  - Password policy: 12-char minimum, 3-of-4 character classes, common-password block
  - TOTP: matches across the 30s window, drift tolerance, rejects bad codes
  - Reset tokens: signed, time-bounded, client-bound, single-use
  - Operator MFA gate: required when OPERATOR_MFA_SECRET is set
  - /portal/forgot returns generic success (no enumeration)
  - /portal/reset enforces the policy + invalidates the nonce on success
  - Login page surfaces company context, support, and the MFA roadmap label
  - We never claim MFA is enforced for customers
"""
from __future__ import annotations

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Password policy ─────────────────────────────────────────


def test_password_policy_rejects_too_short(monkeypatch):
    monkeypatch.delenv("BYPASS_PASSWORD_POLICY", raising=False)
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    with pytest.raises(_as.PasswordPolicyError):
        _as.validate_password("Short1!")


def test_password_policy_rejects_one_class():
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    with pytest.raises(_as.PasswordPolicyError):
        _as.validate_password("aaaaaaaaaaaa")


def test_password_policy_rejects_common():
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    with pytest.raises(_as.PasswordPolicyError):
        _as.validate_password("Password123!")


def test_password_policy_accepts_strong():
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    _as.validate_password("Tr0ub4dor&3-Castle")


def test_password_strength_report():
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    weak = _as.password_strength("a")
    strong = _as.password_strength("Tr0ub4dor&3-Castle")
    assert weak["meets_policy"] is False
    assert strong["meets_policy"] is True
    assert strong["classes"] == 4


def test_set_portal_password_enforces_policy_in_production(fresh_client_manager,
                                                          monkeypatch):
    """When BYPASS_PASSWORD_POLICY is unset, the production rule applies."""
    monkeypatch.delenv("BYPASS_PASSWORD_POLICY", raising=False)
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    with pytest.raises(_as.PasswordPolicyError):
        cm.set_portal_password("c1", "Pass123!")  # too short
    cm.set_portal_password("c1", "Tr0ub4dor&3-Castle")  # OK


# ─── TOTP ────────────────────────────────────────────────────


def test_totp_secret_generation_is_base32():
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    s = _as.generate_totp_secret()
    # Base32 alphabet only
    assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" for c in s)
    assert len(s) >= 24


def test_totp_round_trip():
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    secret = _as.generate_totp_secret()
    code = _as.totp_now(secret)
    assert _as.verify_totp(secret, code) is True


def test_totp_drift_tolerated():
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    secret = _as.generate_totp_secret()
    # Code from 25 seconds ago (within ±1 step / ±30s) must verify.
    past = _as.totp_now(secret, t=int(time.time()) - 25)
    assert _as.verify_totp(secret, past) is True


def test_totp_rejects_far_drift():
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    secret = _as.generate_totp_secret()
    far = _as.totp_now(secret, t=int(time.time()) - 600)
    assert _as.verify_totp(secret, far) is False


def test_totp_rejects_garbage():
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    secret = _as.generate_totp_secret()
    assert _as.verify_totp(secret, "abc") is False
    assert _as.verify_totp(secret, "") is False
    assert _as.verify_totp(secret, "12345") is False  # wrong length


def test_totp_otpauth_uri_format():
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    secret = _as.generate_totp_secret()
    uri = _as.otpauth_uri(secret=secret, account="operator")
    assert uri.startswith("otpauth://totp/")
    assert "issuer=CyberComply" in uri
    assert "digits=6" in uri
    assert "period=30" in uri


# ─── Operator MFA gate ───────────────────────────────────────


def test_operator_mfa_required_when_secret_set(monkeypatch):
    monkeypatch.delenv("OPERATOR_MFA_DISABLED", raising=False)
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    monkeypatch.setenv("OPERATOR_MFA_SECRET", _as.generate_totp_secret())
    assert _as.operator_mfa_required() is True


def test_operator_mfa_disabled_via_test_flag(monkeypatch):
    monkeypatch.setenv("OPERATOR_MFA_DISABLED", "1")
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    monkeypatch.setenv("OPERATOR_MFA_SECRET", _as.generate_totp_secret())
    assert _as.operator_mfa_required() is False


def test_dashboard_login_blocked_without_mfa_when_required(test_app, monkeypatch):
    """When MFA is configured, password alone must NOT pass auth."""
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    monkeypatch.setenv("OPERATOR_MFA_SECRET", _as.generate_totp_secret())
    monkeypatch.delenv("OPERATOR_MFA_DISABLED", raising=False)
    from starlette.testclient import TestClient
    c = TestClient(test_app, raise_server_exceptions=False)
    # No MFA code → 401 from any operator endpoint.
    resp = c.get("/api/operator/delivery-console", params={"password": "testpass"})
    assert resp.status_code == 401


def test_dashboard_login_succeeds_with_valid_mfa(test_app, monkeypatch):
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    secret = _as.generate_totp_secret()
    monkeypatch.setenv("OPERATOR_MFA_SECRET", secret)
    monkeypatch.delenv("OPERATOR_MFA_DISABLED", raising=False)
    code = _as.totp_now(secret)
    from starlette.testclient import TestClient
    c = TestClient(test_app, raise_server_exceptions=False)
    resp = c.get("/api/operator/delivery-console",
                  params={"password": "testpass", "mfa": code})
    assert resp.status_code == 200


def test_mfa_setup_endpoint_returns_secret_and_uri(test_app):
    from starlette.testclient import TestClient
    c = TestClient(test_app, raise_server_exceptions=False)
    resp = c.post("/api/operator/mfa/setup-secret",
                   params={"password": "testpass"})
    assert resp.status_code == 200
    body = resp.json()
    assert "secret" in body and len(body["secret"]) >= 24
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert "instructions" in body


def test_mfa_setup_requires_password(test_app):
    from starlette.testclient import TestClient
    c = TestClient(test_app, raise_server_exceptions=False)
    resp = c.post("/api/operator/mfa/setup-secret")
    assert resp.status_code == 401


def test_mfa_status_endpoint_reports_state(test_app, monkeypatch):
    monkeypatch.setenv("OPERATOR_MFA_DISABLED", "1")
    monkeypatch.delenv("OPERATOR_MFA_SECRET", raising=False)
    from starlette.testclient import TestClient
    c = TestClient(test_app, raise_server_exceptions=False)
    resp = c.get("/api/operator/mfa/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["mfa_required"] is False
    assert body["configured"] is False


# ─── Reset tokens ────────────────────────────────────────────


def test_reset_token_round_trip(monkeypatch):
    monkeypatch.setenv("RESET_TOKEN_SECRET", "test-secret")
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    tok = _as.create_reset_token("c1")
    valid, nonce = _as.verify_reset_token(tok, "c1")
    assert valid is True
    assert nonce


def test_reset_token_wrong_client_rejected(monkeypatch):
    monkeypatch.setenv("RESET_TOKEN_SECRET", "test-secret")
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    tok = _as.create_reset_token("c1")
    valid, _ = _as.verify_reset_token(tok, "c2")
    assert valid is False


def test_reset_token_tampered_signature_rejected(monkeypatch):
    monkeypatch.setenv("RESET_TOKEN_SECRET", "test-secret")
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    tok = _as.create_reset_token("c1")
    bad = tok[:-4] + "ffff"
    valid, _ = _as.verify_reset_token(bad, "c1")
    assert valid is False


def test_reset_token_expired(monkeypatch):
    monkeypatch.setenv("RESET_TOKEN_SECRET", "test-secret")
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    tok = _as.create_reset_token("c1", ttl=-1)  # already expired
    valid, _ = _as.verify_reset_token(tok, "c1")
    assert valid is False


# ─── /portal/forgot + /portal/reset routes ────────────────────


def test_portal_forgot_returns_generic_success_for_unknown_client(test_client):
    resp = test_client.post("/portal/forgot",
                             json={"client_id": "definitely-not-here"})
    assert resp.status_code == 200
    assert "If an account exists" in resp.json()["message"]


def test_portal_forgot_returns_generic_success_for_known_client(
    test_client, fresh_client_manager,
):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.set_portal_password("c1", "Tr0ub4dor&3-Castle")
    resp = test_client.post("/portal/forgot",
                             json={"client_id": "c1", "email": "ceo@co.com"})
    assert resp.status_code == 200
    # Same opaque message for both branches — no enumeration.
    assert "If an account exists" in resp.json()["message"]


def test_portal_reset_completes_password_change(test_client, fresh_client_manager,
                                                monkeypatch):
    monkeypatch.setenv("RESET_TOKEN_SECRET", "test-secret")
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    cm.set_portal_password("c1", "OldStrongPass123!")

    # Begin the reset flow.
    test_client.post("/portal/forgot", json={"client_id": "c1"})

    # Mint a token directly so we can use it without inspecting the email.
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    token = _as.create_reset_token("c1")
    parts = token.split(".")
    cm.store_reset_token_nonce("c1", parts[1], int(parts[2]))

    resp = test_client.post("/portal/reset", json={
        "client_id": "c1", "token": token, "new_password": "Tr0ub4dor&3-Castle",
    })
    assert resp.status_code == 200
    # Old password no longer works; new one does.
    assert cm.verify_password("c1", "OldStrongPass123!") is False
    assert cm.verify_password("c1", "Tr0ub4dor&3-Castle") is True


def test_portal_reset_rejects_bad_password(test_client, fresh_client_manager,
                                          monkeypatch):
    monkeypatch.setenv("RESET_TOKEN_SECRET", "test-secret")
    monkeypatch.delenv("BYPASS_PASSWORD_POLICY", raising=False)
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    token = _as.create_reset_token("c1")
    parts = token.split(".")
    cm.store_reset_token_nonce("c1", parts[1], int(parts[2]))

    resp = test_client.post("/portal/reset", json={
        "client_id": "c1", "token": token, "new_password": "short",
    })
    assert resp.status_code == 400


def test_portal_reset_rejects_reused_token(test_client, fresh_client_manager,
                                          monkeypatch):
    monkeypatch.setenv("RESET_TOKEN_SECRET", "test-secret")
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    if "auth_security" in sys.modules: del sys.modules["auth_security"]
    import auth_security as _as
    token = _as.create_reset_token("c1")
    parts = token.split(".")
    cm.store_reset_token_nonce("c1", parts[1], int(parts[2]))

    body = {"client_id": "c1", "token": token,
             "new_password": "Tr0ub4dor&3-Castle"}
    first = test_client.post("/portal/reset", json=body)
    assert first.status_code == 200
    second = test_client.post("/portal/reset", json=body)
    assert second.status_code == 400


def test_portal_reset_rejects_invalid_token(test_client, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Co", "co.com")
    resp = test_client.post("/portal/reset", json={
        "client_id": "c1", "token": "garbage",
        "new_password": "Tr0ub4dor&3-Castle",
    })
    assert resp.status_code == 400


# ─── Login page UX ───────────────────────────────────────────


def test_login_page_renders_company_context(test_client, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Acme Corp", "acme.com")
    resp = test_client.get("/portal/login", params={"client": "c1"})
    assert resp.status_code == 200
    assert "Acme Corp" in resp.text
    # Support contact present.
    assert "support" in resp.text.lower()
    # MFA roadmap label present, NOT a claim of enforcement.
    assert "MFA on roadmap" in resp.text
    assert "MFA enforced" not in resp.text
    assert "Multi-factor enabled" not in resp.text


def test_login_page_shows_session_expired_banner_via_query():
    """Just verify the banner string is in the template; client side flips it on."""
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader("templates"), autoescape=True)
    html = env.get_template("portal_login.html").render(
        error="", client_id="", company="",
        support_email="support@cybercomply.io", calendly_link="",
    )
    assert "Your session expired" in html
    assert "expired" in html  # the JS query-string check


def test_setup_page_strict_password_policy_visible(test_client, fresh_client_manager):
    cm = fresh_client_manager
    cm.create_client("c1", "Acme", "acme.com")
    token = cm.generate_magic_link("c1")
    resp = test_client.get("/portal/login", params={"client": "c1", "token": token})
    assert resp.status_code == 200
    assert "At least 12 characters" in resp.text
    # Customer MFA disclosed honestly: roadmap, not enforced.
    assert "Customer multi-factor authentication is on our roadmap" in resp.text


def test_setup_page_renders_company():
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader("templates"), autoescape=True)
    html = env.get_template("portal_setup.html").render(
        client_id="c1", token="t", company="Acme Corp", min_password_length=12,
        error="",
    )
    assert "Acme Corp" in html


# ─── No false MFA claims ────────────────────────────────────


def test_no_template_claims_customer_mfa_is_enforced():
    """The product never claims customer MFA is enforced in the UI until built."""
    forbidden = [
        "MFA enabled by default",
        "Multi-factor required",
        "MFA enforced",
        "Two-factor authentication enabled",
    ]
    for tmpl_name in ["portal_login.html", "portal_setup.html",
                       "portal_forgot.html", "portal_reset.html"]:
        with open(f"templates/{tmpl_name}") as f:
            text = f.read()
        for phrase in forbidden:
            assert phrase not in text, f"{tmpl_name} contains forbidden claim: {phrase!r}"
