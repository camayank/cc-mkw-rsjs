"""
Legal & authorization controls for managed cyber-compliance and security validation.

Defines the document/acknowledgment models, valid statuses, and the hard gate
that any active security validation (Apex / authenticated scanning / exploit
attempt / pentest-class run) must pass before execution.

Customer-facing labels:
  Active, Pending setup, Not connected, Included, Not included,
  Review pending, Advisor reviewed, Approved, Expired, Withdrawn.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


# ─── Document statuses ────────────────────────────────────────

# Lifecycle for any legal document (MSA, SOW, NDA, DPA).
DOCUMENT_STATUSES = (
    "not_started",     # never sent
    "draft",           # operator drafted, not sent
    "sent",            # delivered to customer
    "in_review",       # customer is reviewing
    "signed",          # signed by both parties
    "countersigned",   # alias-friendly
    "expired",         # past validity
    "withdrawn",       # revoked
)

DOCUMENT_REQUIRED_FOR_ACTIVE = ("signed", "countersigned")

# Authorization-form lifecycle (passive scan + active validation).
AUTHORIZATION_STATUSES = (
    "not_required",
    "draft",
    "pending_customer_signature",
    "pending_operator_review",
    "approved",        # only state that passes the active gate
    "expired",
    "withdrawn",
    "rejected",
)

# Acknowledgment status (booleans we capture explicitly).
ACK_STATUSES = ("not_acknowledged", "acknowledged")


# ─── Models ───────────────────────────────────────────────────

@dataclass
class LegalDocument:
    name: str                               # "MSA" / "SOW" / "NDA" / "DPA"
    status: str = "not_started"
    sent_at: str = ""
    signed_at: str = ""
    signed_by_name: str = ""
    signed_by_title: str = ""
    signed_by_email: str = ""
    document_url: str = ""                  # link to e-sign envelope or PDF
    envelope_id: str = ""                   # DocuSign / equivalent id
    expires_at: str = ""
    notes: str = ""

    def is_signed(self) -> bool:
        return self.status in DOCUMENT_REQUIRED_FOR_ACTIVE


@dataclass
class AuthorizedRepresentative:
    full_name: str = ""
    title: str = ""
    email: str = ""
    phone: str = ""
    company_legal_name: str = ""
    verified_at: str = ""                   # set when operator confirms identity
    verification_method: str = ""           # "email_domain_match" | "video_call" | "docusign"


@dataclass
class OwnershipConfirmation:
    domains_owned: list[str] = field(default_factory=list)
    confirmed_by_name: str = ""
    confirmed_by_title: str = ""
    confirmed_at: str = ""
    proof_method: str = ""                  # "dns_txt" | "html_meta" | "email_domain" | "attestation"
    proof_artifact: str = ""                # token / file / id


@dataclass
class TestingWindow:
    start_at: str = ""                      # ISO8601
    end_at: str = ""
    timezone: str = "UTC"
    blackout_periods: list[dict] = field(default_factory=list)
    notes: str = ""


@dataclass
class RateLimits:
    max_requests_per_second: int = 5
    max_concurrent_targets: int = 1
    max_total_requests: int = 100_000
    abort_on_5xx_threshold: int = 50
    abort_on_4xx_threshold: int = 1_000


@dataclass
class EmergencyContact:
    name: str = ""
    title: str = ""
    phone_24x7: str = ""
    email: str = ""
    backup_name: str = ""
    backup_phone: str = ""


@dataclass
class Acknowledgments:
    client_responsibility: bool = False
    no_legal_advice: bool = False
    no_breach_prevention_guarantee: bool = False
    third_party_platforms_excluded: bool = False
    data_handling_agreed: bool = False
    acknowledged_at: str = ""
    acknowledged_by: str = ""

    def all_required(self) -> bool:
        return all([
            self.client_responsibility,
            self.no_legal_advice,
            self.no_breach_prevention_guarantee,
        ])


@dataclass
class PassiveScanAuthorization:
    status: str = "not_required"            # passive scans default not_required
    domains: list[str] = field(default_factory=list)
    authorized_at: str = ""
    authorized_by_name: str = ""
    authorized_by_title: str = ""
    expires_at: str = ""


@dataclass
class ActiveValidationAuthorization:
    """Authorization for any active testing class: Apex pentest, authenticated
    scans, exploit verification, intrusive vulnerability scanning, etc."""
    status: str = "not_required"
    scope_summary: str = ""
    target_domains: list[str] = field(default_factory=list)
    target_ips: list[str] = field(default_factory=list)        # individual IPs
    target_cidrs: list[str] = field(default_factory=list)      # CIDR ranges
    excluded_systems: list[str] = field(default_factory=list)
    excluded_techniques: list[str] = field(default_factory=list)
    testing_window: TestingWindow = field(default_factory=TestingWindow)
    rate_limits: RateLimits = field(default_factory=RateLimits)
    emergency_contact: EmergencyContact = field(default_factory=EmergencyContact)
    authorized_at: str = ""
    authorized_by_name: str = ""
    authorized_by_title: str = ""
    authorized_by_email: str = ""
    operator_approved_at: str = ""
    operator_approved_by: str = ""
    expires_at: str = ""                    # active auths must always have expiry
    revoked_at: str = ""
    revocation_reason: str = ""
    docusign_envelope_id: str = ""

    def is_within_window(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        try:
            start = datetime.fromisoformat(self.testing_window.start_at.replace("Z", "+00:00"))
            end = datetime.fromisoformat(self.testing_window.end_at.replace("Z", "+00:00"))
        except Exception:
            return False
        return start <= now <= end

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if not self.expires_at:
            return True
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except Exception:
            return True
        return (now or datetime.now(timezone.utc)) > exp


@dataclass
class LegalAuthorizationRecord:
    """The full per-client legal + authorization snapshot."""
    client_id: str
    msa: LegalDocument = field(default_factory=lambda: LegalDocument(name="MSA"))
    sow: LegalDocument = field(default_factory=lambda: LegalDocument(name="SOW"))
    nda: LegalDocument = field(default_factory=lambda: LegalDocument(name="NDA"))
    dpa: LegalDocument = field(default_factory=lambda: LegalDocument(name="DPA"))
    authorized_representative: AuthorizedRepresentative = field(default_factory=AuthorizedRepresentative)
    ownership: OwnershipConfirmation = field(default_factory=OwnershipConfirmation)
    passive_scan: PassiveScanAuthorization = field(default_factory=PassiveScanAuthorization)
    active_validation: ActiveValidationAuthorization = field(default_factory=ActiveValidationAuthorization)
    acknowledgments: Acknowledgments = field(default_factory=Acknowledgments)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── Validation helpers ───────────────────────────────────────

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


def validate_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match((domain or "").strip()))


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr.strip(), strict=False)
        return True
    except ValueError:
        return False


# ─── The gate ─────────────────────────────────────────────────

# Domains we will never run active validation against without explicit
# carrier approval (third-party platforms / shared hosts).
PROTECTED_PLATFORM_SUFFIXES = (
    ".myshopify.com", ".herokuapp.com", ".azurewebsites.net",
    ".cloudfront.net", ".s3.amazonaws.com", ".appspot.com",
    ".firebaseapp.com", ".netlify.app", ".vercel.app",
    ".github.io", ".pages.dev", ".wpengine.com",
    ".salesforce.com", ".force.com", ".hubspot.com",
)


def authorization_gate(
    record: LegalAuthorizationRecord,
    *,
    require_active: bool = True,
    target_hint: Optional[str] = None,
) -> dict[str, Any]:
    """
    Enforce the hard precondition for any active security validation run
    (Apex pentest, authenticated scan, exploit verification, intrusive scan).

    Returns:
        {
          "allowed": bool,
          "reason": str | None,        # operator-facing reason (never returned to customer)
          "blockers": list[str],       # operator-facing list of failed checks
          "checked_at": iso8601,
        }

    A run is allowed only when ALL of the following hold:
      - MSA signed
      - SOW signed
      - NDA signed
      - DPA signed
      - Authorized representative recorded + verified
      - Domain/system ownership confirmed
      - Passive scan authorized for the relevant domains
      - Active validation authorization status == "approved"
      - Testing window is active (now between start_at and end_at)
      - Active authorization is not expired
      - Required acknowledgments captured
      - Target hint (when provided) lies inside scoped targets and outside excluded
        systems and protected platform suffixes
    """
    blockers: list[str] = []

    # Documents
    for doc, label in (
        (record.msa, "MSA"),
        (record.sow, "SOW"),
        (record.nda, "NDA"),
        (record.dpa, "DPA"),
    ):
        if not doc.is_signed():
            blockers.append(f"{label} not signed (status={doc.status or 'not_started'})")

    # Authorized representative
    rep = record.authorized_representative
    if not (rep.full_name and rep.title and rep.email):
        blockers.append("Authorized representative incomplete")
    if not rep.verified_at:
        blockers.append("Authorized representative not verified")

    # Ownership
    own = record.ownership
    if not (own.domains_owned and own.confirmed_at and own.proof_method):
        blockers.append("Domain/system ownership not confirmed")

    # Acknowledgments
    if not record.acknowledgments.all_required():
        blockers.append("Client responsibility / no-legal-advice / "
                        "no-breach-prevention-guarantee acknowledgments missing")

    # Passive scan auth (always required if any scanning at all)
    if record.passive_scan.status not in ("approved", "not_required"):
        blockers.append(f"Passive scan authorization not approved "
                        f"(status={record.passive_scan.status})")

    # Active validation
    if require_active:
        active = record.active_validation
        if active.status != "approved":
            blockers.append(f"Active validation authorization not approved "
                            f"(status={active.status})")
        else:
            if active.is_expired():
                blockers.append("Active validation authorization expired")
            if not active.is_within_window():
                blockers.append("Outside the agreed testing window")
            if not active.authorized_at or not active.authorized_by_name:
                blockers.append("Customer signature missing on active authorization")
            if not active.operator_approved_at or not active.operator_approved_by:
                blockers.append("Operator counter-approval missing on active authorization")
            if not (active.target_domains or active.target_ips or active.target_cidrs):
                blockers.append("No targets defined in scope")
            if not active.emergency_contact.phone_24x7:
                blockers.append("24x7 emergency contact phone missing")
            # Validate scope syntactically
            for d in active.target_domains:
                if not validate_domain(d):
                    blockers.append(f"Invalid domain in target list: {d}")
                if d.lower().endswith(PROTECTED_PLATFORM_SUFFIXES):
                    blockers.append(f"Target {d} is on a protected third-party platform")
            for ip in active.target_ips:
                if not validate_ip(ip):
                    blockers.append(f"Invalid IP in target list: {ip}")
            for cidr in active.target_cidrs:
                if not validate_cidr(cidr):
                    blockers.append(f"Invalid CIDR in target list: {cidr}")

            # Per-target hint check
            if target_hint:
                if not _target_in_scope(target_hint, active):
                    blockers.append(f"Target '{target_hint}' is not inside the approved scope")
                if _target_excluded(target_hint, active):
                    blockers.append(f"Target '{target_hint}' is on the excluded list")
                if target_hint.lower().endswith(PROTECTED_PLATFORM_SUFFIXES):
                    blockers.append(f"Target '{target_hint}' is on a protected third-party platform")

    return {
        "allowed": len(blockers) == 0,
        "reason": None if not blockers else "; ".join(blockers),
        "blockers": blockers,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _target_in_scope(target: str, active: ActiveValidationAuthorization) -> bool:
    t = target.strip().lower()
    # Domain match
    for d in active.target_domains:
        if t == d.lower() or t.endswith("." + d.lower()):
            return True
    # IP match
    if validate_ip(t):
        if t in (ip.strip() for ip in active.target_ips):
            return True
        try:
            tip = ipaddress.ip_address(t)
            for cidr in active.target_cidrs:
                if tip in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            pass
    return False


def _target_excluded(target: str, active: ActiveValidationAuthorization) -> bool:
    t = target.strip().lower()
    for ex in active.excluded_systems:
        e = ex.strip().lower()
        if not e:
            continue
        if t == e or t.endswith("." + e):
            return True
    return False


# ─── Customer-safe view ───────────────────────────────────────

def to_customer_view(record: LegalAuthorizationRecord) -> dict[str, Any]:
    """Customer-safe summary using soft labels — no operator-only fields."""
    def doc_label(d: LegalDocument) -> str:
        if d.status in DOCUMENT_REQUIRED_FOR_ACTIVE:
            return "Signed"
        if d.status in ("sent", "in_review"):
            return "Review pending"
        if d.status == "expired":
            return "Expired"
        if d.status == "withdrawn":
            return "Withdrawn"
        return "Pending setup"

    def auth_label(status: str) -> str:
        return {
            "not_required": "Not included",
            "draft": "Pending setup",
            "pending_customer_signature": "Review pending",
            "pending_operator_review": "Review pending",
            "approved": "Approved",
            "expired": "Expired",
            "withdrawn": "Withdrawn",
            "rejected": "Pending setup",
        }.get(status, "Pending setup")

    return {
        "documents": {
            "msa": doc_label(record.msa),
            "sow": doc_label(record.sow),
            "nda": doc_label(record.nda),
            "dpa": doc_label(record.dpa),
        },
        "authorized_representative_recorded": bool(
            record.authorized_representative.full_name
            and record.authorized_representative.email
        ),
        "ownership_confirmed": bool(
            record.ownership.domains_owned and record.ownership.confirmed_at
        ),
        "passive_scan": auth_label(record.passive_scan.status),
        "active_validation": auth_label(record.active_validation.status),
        "acknowledgments_complete": record.acknowledgments.all_required(),
    }


# ─── Construction helper ──────────────────────────────────────

def from_dict(d: dict[str, Any]) -> LegalAuthorizationRecord:
    """Rebuild a record from persisted JSON."""
    if not d:
        return LegalAuthorizationRecord(client_id="")
    rec = LegalAuthorizationRecord(client_id=d.get("client_id", ""))
    for k in ("msa", "sow", "nda", "dpa"):
        v = d.get(k) or {}
        setattr(rec, k, LegalDocument(**{f.name: v.get(f.name, getattr(getattr(rec, k), f.name))
                                         for f in LegalDocument.__dataclass_fields__.values()}))
    if d.get("authorized_representative"):
        rec.authorized_representative = AuthorizedRepresentative(**{
            f.name: d["authorized_representative"].get(f.name, "")
            for f in AuthorizedRepresentative.__dataclass_fields__.values()
        })
    if d.get("ownership"):
        rec.ownership = OwnershipConfirmation(**{
            f.name: d["ownership"].get(f.name, getattr(rec.ownership, f.name))
            for f in OwnershipConfirmation.__dataclass_fields__.values()
        })
    if d.get("passive_scan"):
        rec.passive_scan = PassiveScanAuthorization(**{
            f.name: d["passive_scan"].get(f.name, getattr(rec.passive_scan, f.name))
            for f in PassiveScanAuthorization.__dataclass_fields__.values()
        })
    if d.get("active_validation"):
        av = d["active_validation"]
        rec.active_validation = ActiveValidationAuthorization(
            status=av.get("status", "not_required"),
            scope_summary=av.get("scope_summary", ""),
            target_domains=list(av.get("target_domains", [])),
            target_ips=list(av.get("target_ips", [])),
            target_cidrs=list(av.get("target_cidrs", [])),
            excluded_systems=list(av.get("excluded_systems", [])),
            excluded_techniques=list(av.get("excluded_techniques", [])),
            testing_window=TestingWindow(**{
                f.name: (av.get("testing_window") or {}).get(f.name, getattr(TestingWindow(), f.name))
                for f in TestingWindow.__dataclass_fields__.values()
            }),
            rate_limits=RateLimits(**{
                f.name: (av.get("rate_limits") or {}).get(f.name, getattr(RateLimits(), f.name))
                for f in RateLimits.__dataclass_fields__.values()
            }),
            emergency_contact=EmergencyContact(**{
                f.name: (av.get("emergency_contact") or {}).get(f.name, getattr(EmergencyContact(), f.name))
                for f in EmergencyContact.__dataclass_fields__.values()
            }),
            authorized_at=av.get("authorized_at", ""),
            authorized_by_name=av.get("authorized_by_name", ""),
            authorized_by_title=av.get("authorized_by_title", ""),
            authorized_by_email=av.get("authorized_by_email", ""),
            operator_approved_at=av.get("operator_approved_at", ""),
            operator_approved_by=av.get("operator_approved_by", ""),
            expires_at=av.get("expires_at", ""),
            revoked_at=av.get("revoked_at", ""),
            revocation_reason=av.get("revocation_reason", ""),
            docusign_envelope_id=av.get("docusign_envelope_id", ""),
        )
    if d.get("acknowledgments"):
        rec.acknowledgments = Acknowledgments(**{
            f.name: d["acknowledgments"].get(f.name, getattr(rec.acknowledgments, f.name))
            for f in Acknowledgments.__dataclass_fields__.values()
        })
    rec.created_at = d.get("created_at", "")
    rec.updated_at = d.get("updated_at", "")
    return rec
