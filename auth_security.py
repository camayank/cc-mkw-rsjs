"""
Authentication & account-trust primitives.

Implements:
  - Password strength validator (minimum 12 chars, 3 of 4 character classes)
  - RFC 6238 TOTP (time-based one-time password) — used for mandatory
    operator MFA. No external dependencies.
  - Single-use, time-bounded password-reset tokens
  - Helpers for the operator MFA setup flow

Client-side MFA is *not* implemented yet — the portal exposes a clearly
labeled roadmap placeholder. We never claim MFA is enforced for customers.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from datetime import datetime, timezone, timedelta
from typing import Optional


# ─── Password rules ──────────────────────────────────────────

MIN_PASSWORD_LENGTH = 12

# Common-password blocklist (very short — paid deployments should plug in HIBP).
_COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "p@ssword",
    "qwerty", "qwerty123", "letmein", "welcome", "welcome1",
    "admin", "admin123", "changeme", "iloveyou", "1q2w3e4r5t",
}


class PasswordPolicyError(ValueError):
    """Raised when a password does not satisfy the policy."""


def password_strength(pw: str) -> dict:
    """Return a structured strength report. Used by the UI for the bar."""
    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ])
    long_enough = len(pw) >= MIN_PASSWORD_LENGTH
    common = pw.lower() in _COMMON_PASSWORDS
    score = 0
    if long_enough:
        score += 1
    score += classes  # 0..4
    if not common and long_enough and classes >= 3:
        score += 1
    label = ["Very weak", "Weak", "Fair", "Good", "Strong", "Excellent"][min(score, 5)]
    return {
        "score": score,
        "label": label,
        "meets_policy": long_enough and classes >= 3 and not common,
        "length": len(pw),
        "classes": classes,
        "is_common": common,
    }


def validate_password(pw: str) -> None:
    """Raise PasswordPolicyError when the password violates the policy."""
    if len(pw) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ])
    if classes < 3:
        raise PasswordPolicyError(
            "Password must include at least 3 of: lowercase, uppercase, "
            "digit, special character"
        )
    # Compare against the common-password list both as-typed and with
    # punctuation stripped, so trivial variations like "Password123!" are
    # caught alongside "password123".
    pw_lower = pw.lower()
    pw_stripped = "".join(c for c in pw_lower if c.isalnum())
    if pw_lower in _COMMON_PASSWORDS or pw_stripped in _COMMON_PASSWORDS:
        raise PasswordPolicyError(
            "This password is on the common-passwords list — please choose another"
        )


# ─── TOTP (RFC 6238) ─────────────────────────────────────────

_TOTP_PERIOD_SECONDS = 30
_TOTP_DIGITS = 6
_TOTP_DRIFT_STEPS = 1   # accept ±1 step (≈30s) for clock drift


def generate_totp_secret() -> str:
    """Return a base32-encoded 20-byte secret suitable for an authenticator app."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    secret = (secret or "").strip().replace(" ", "").upper()
    if not secret:
        raise ValueError("Empty TOTP secret")
    # Re-pad to multiple of 8.
    pad = (-len(secret)) % 8
    return base64.b32decode(secret + "=" * pad)


def totp_now(secret: str, *, t: Optional[int] = None,
             period: int = _TOTP_PERIOD_SECONDS,
             digits: int = _TOTP_DIGITS) -> str:
    """Compute the TOTP code for the current step (or `t`)."""
    counter = (t if t is not None else int(time.time())) // period
    key = _decode_secret(secret)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret: str, code: str, *,
                drift_steps: int = _TOTP_DRIFT_STEPS) -> bool:
    """Constant-time TOTP verification with ±1-step clock-drift tolerance."""
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if len(code) != _TOTP_DIGITS or not code.isdigit():
        return False
    now_t = int(time.time())
    for offset in range(-drift_steps, drift_steps + 1):
        candidate = totp_now(secret, t=now_t + offset * _TOTP_PERIOD_SECONDS)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def otpauth_uri(*, secret: str, account: str, issuer: str = "CyberComply") -> str:
    """Build the otpauth:// URI for a QR code in an authenticator app."""
    from urllib.parse import quote
    label = quote(f"{issuer}:{account}", safe="")
    qs = (
        f"secret={secret}"
        f"&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={_TOTP_DIGITS}&period={_TOTP_PERIOD_SECONDS}"
    )
    return f"otpauth://totp/{label}?{qs}"


# ─── Operator MFA configuration ──────────────────────────────

def operator_mfa_secret() -> str:
    """Return the operator's stored TOTP secret, or empty string when not set."""
    return (os.getenv("OPERATOR_MFA_SECRET") or "").strip()


def operator_mfa_required() -> bool:
    """Operator MFA is mandatory for production. We treat the presence of
    OPERATOR_MFA_SECRET as proof that MFA is set up; until then the dashboard
    surfaces a strong banner urging setup.

    Tests can opt out via OPERATOR_MFA_DISABLED=1 (used only by the test
    harness — never set this in production)."""
    if os.getenv("OPERATOR_MFA_DISABLED", "").lower() in ("1", "true", "yes"):
        return False
    return bool(operator_mfa_secret())


def verify_operator_mfa(code: str) -> bool:
    """Verify the supplied TOTP code against the configured operator secret."""
    secret = operator_mfa_secret()
    if not secret:
        return False
    return verify_totp(secret, code)


# ─── Password reset tokens ───────────────────────────────────

# Single-use, signed, time-bounded reset tokens.
# Format: "{client_id}.{nonce}.{expiry_epoch}.{hmac}"

_RESET_TTL_SECONDS = 30 * 60   # 30 minutes


def _signing_key() -> bytes:
    secret = os.getenv("RESET_TOKEN_SECRET") or os.getenv("JWT_SECRET", "")
    if not secret:
        # Last-resort fallback so the module still works in dev. Not safe to
        # rely on — set RESET_TOKEN_SECRET (or JWT_SECRET) in production.
        secret = "dev-only-reset-secret-set-RESET_TOKEN_SECRET"
    return secret.encode()


def create_reset_token(client_id: str, *, ttl: int = _RESET_TTL_SECONDS) -> str:
    """Create a signed, time-bounded password-reset token. The caller can
    keep the token nonce on the profile so it can be invalidated server-side
    after a successful reset (single-use)."""
    nonce = secrets.token_urlsafe(12)
    expiry = int(time.time()) + ttl
    payload = f"{client_id}.{nonce}.{expiry}"
    sig = hmac.new(_signing_key(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}.{sig}"


def verify_reset_token(token: str, client_id: str) -> tuple[bool, str]:
    """Returns (valid, nonce). The caller is responsible for tracking the
    nonce on the client profile and refusing reuse."""
    if not token:
        return (False, "")
    parts = token.split(".")
    if len(parts) != 4:
        return (False, "")
    payload_cid, nonce, expiry_s, sig = parts
    if payload_cid != client_id:
        return (False, "")
    try:
        expiry = int(expiry_s)
    except ValueError:
        return (False, "")
    if int(time.time()) > expiry:
        return (False, "")
    expected = hmac.new(
        _signing_key(),
        f"{payload_cid}.{nonce}.{expiry}".encode(),
        hashlib.sha256,
    ).hexdigest()[:32]
    if not hmac.compare_digest(expected, sig):
        return (False, "")
    return (True, nonce)


# ─── Time helpers ────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
