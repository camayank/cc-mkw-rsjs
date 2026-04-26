"""
Advisor-review metadata across the product.

A single record schema applied to every reviewable subject (report, policy,
monthly summary, evidence package, security-validation finding, task
verification, audit package). The record is the only source of truth for
"reviewed" claims in the UI — the templates must never show a static
"Advisor reviewed" badge unless the corresponding record exists *and*
its review_status is APPROVED.

Storage: clients/{client_id}/reviews.json
  { subject_key (str): ReviewRecord-as-dict, ... }

Subject key convention (so we never collide across artifact types):
  report:{key}                # canonical reports from document_library
  policy:{key}                # canonical policies from document_library
  monthly_summary:{YYYY-MM}
  evidence_package:{YYYY-MM}
  audit_package:{YYYY-MM}
  validation_finding:{finding_id}
  task:{task_id}              # written by verify_task; mirrored here

Customer view:
  Internal operator notes are removed before any payload reaches the
  customer portal. The `customer_view()` helper enforces this.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ─── Statuses ─────────────────────────────────────────────────

REVIEW_PENDING = "pending"            # not yet reviewed
REVIEW_IN_REVIEW = "in_review"        # advisor actively reviewing
REVIEW_APPROVED = "approved"          # signed off — only this state may render "Advisor reviewed"
REVIEW_REJECTED = "rejected"          # advisor rejected; needs rework
REVIEW_WITHDRAWN = "withdrawn"        # obsolete or revoked

ALL_STATUSES = (REVIEW_PENDING, REVIEW_IN_REVIEW, REVIEW_APPROVED,
                REVIEW_REJECTED, REVIEW_WITHDRAWN)

STATUS_LABELS = {
    REVIEW_PENDING: "Review pending",
    REVIEW_IN_REVIEW: "Review pending",
    REVIEW_APPROVED: "Advisor reviewed",
    REVIEW_REJECTED: "Returned for rework",
    REVIEW_WITHDRAWN: "Withdrawn",
}

# Allowed reviewer credentials. Anything else is rejected by set_review().
RECOGNIZED_CREDENTIALS = {
    "CISSP", "CISA", "CISM", "CRISC", "CCSP", "GIAC", "OSCP", "CEH",
    "CIPP/US", "CIPP/E", "CIPM", "QSA", "PCI ISA",
}


# ─── Subject-key helpers ──────────────────────────────────────

def report_key(report_key_: str) -> str:
    return f"report:{report_key_}"

def policy_key(policy_key_: str) -> str:
    return f"policy:{policy_key_}"

def monthly_summary_key(yyyy_mm: str) -> str:
    return f"monthly_summary:{yyyy_mm}"

def evidence_package_key(yyyy_mm: str) -> str:
    return f"evidence_package:{yyyy_mm}"

def audit_package_key(yyyy_mm: str) -> str:
    return f"audit_package:{yyyy_mm}"

def validation_finding_key(finding_id: str) -> str:
    return f"validation_finding:{finding_id}"

def task_key(task_id: str) -> str:
    return f"task:{task_id}"


# ─── Record schema ────────────────────────────────────────────

@dataclass
class ReviewRecord:
    """The 9 fields required by the spec, plus identity fields."""
    subject_key: str = ""
    prepared_by: str = ""                       # e.g. "System" / "Advisor — Alice"
    reviewed_by: str = ""                       # advisor name (only when reviewed)
    reviewed_on: str = ""                       # ISO date (only when reviewed)
    review_status: str = REVIEW_PENDING
    advisor_notes: str = ""                     # advisor-facing rationale, customer-visible
    client_facing_recommendation: str = ""      # one-line takeaway for the customer
    internal_operator_notes: str = ""           # OPERATOR ONLY — never customer-visible
    reviewer_credential: str = ""               # e.g. "CISSP" — only when actually held
    sign_off_timestamp: str = ""                # ISO timestamp of final approval

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── Persistence ──────────────────────────────────────────────

def _data_root() -> Path:
    return Path(os.getenv("DATA_DIR", ".")) / "clients"


def _reviews_path(client_id: str) -> Path:
    p = _data_root() / client_id
    p.mkdir(parents=True, exist_ok=True)
    return p / "reviews.json"


def _load(client_id: str) -> dict[str, dict[str, Any]]:
    p = _reviews_path(client_id)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _save(client_id: str, blob: dict[str, dict[str, Any]]) -> None:
    _reviews_path(client_id).write_text(json.dumps(blob, indent=2, default=str))


# ─── Public API ───────────────────────────────────────────────

def get_review(client_id: str, subject_key: str) -> dict[str, Any]:
    """Return the review record (operator view, includes internal notes) or
    an empty dict if no record exists. Callers heading to the customer must
    use customer_view() before rendering."""
    return dict(_load(client_id).get(subject_key, {}))


def list_reviews(client_id: str) -> dict[str, dict[str, Any]]:
    return _load(client_id)


def set_review(
    client_id: str,
    subject_key: str,
    *,
    prepared_by: Optional[str] = None,
    reviewed_by: Optional[str] = None,
    reviewed_on: Optional[str] = None,
    review_status: Optional[str] = None,
    advisor_notes: Optional[str] = None,
    client_facing_recommendation: Optional[str] = None,
    internal_operator_notes: Optional[str] = None,
    reviewer_credential: Optional[str] = None,
    sign_off_timestamp: Optional[str] = None,
) -> dict[str, Any]:
    """Create or update a review record. Only fields explicitly supplied are
    written; absent fields are left untouched. Status transitions to APPROVED
    require a non-empty reviewed_by, reviewed_on, and sign_off_timestamp.

    Returns the new record (operator view).
    """
    if not subject_key:
        raise ValueError("subject_key required")

    if review_status is not None and review_status not in ALL_STATUSES:
        raise ValueError(f"Invalid review_status: {review_status}")

    if reviewer_credential and reviewer_credential not in RECOGNIZED_CREDENTIALS:
        raise ValueError(
            f"Unrecognized reviewer_credential: {reviewer_credential}. "
            f"Allowed: {sorted(RECOGNIZED_CREDENTIALS)}"
        )

    blob = _load(client_id)
    existing = blob.get(subject_key, {})
    rec = ReviewRecord(
        subject_key=subject_key,
        prepared_by=existing.get("prepared_by", ""),
        reviewed_by=existing.get("reviewed_by", ""),
        reviewed_on=existing.get("reviewed_on", ""),
        review_status=existing.get("review_status", REVIEW_PENDING),
        advisor_notes=existing.get("advisor_notes", ""),
        client_facing_recommendation=existing.get("client_facing_recommendation", ""),
        internal_operator_notes=existing.get("internal_operator_notes", ""),
        reviewer_credential=existing.get("reviewer_credential", ""),
        sign_off_timestamp=existing.get("sign_off_timestamp", ""),
    )

    if prepared_by is not None:                  rec.prepared_by = prepared_by
    if reviewed_by is not None:                  rec.reviewed_by = reviewed_by
    if reviewed_on is not None:                  rec.reviewed_on = reviewed_on
    if review_status is not None:                rec.review_status = review_status
    if advisor_notes is not None:                rec.advisor_notes = advisor_notes
    if client_facing_recommendation is not None:
        rec.client_facing_recommendation = client_facing_recommendation
    if internal_operator_notes is not None:
        rec.internal_operator_notes = internal_operator_notes
    if reviewer_credential is not None:          rec.reviewer_credential = reviewer_credential
    if sign_off_timestamp is not None:           rec.sign_off_timestamp = sign_off_timestamp

    # Hard rule: APPROVED requires complete sign-off identity.
    if rec.review_status == REVIEW_APPROVED:
        if not (rec.reviewed_by and rec.reviewed_on and rec.sign_off_timestamp):
            raise ValueError(
                "Approved status requires reviewed_by, reviewed_on, and sign_off_timestamp"
            )

    blob[subject_key] = rec.to_dict()
    _save(client_id, blob)
    return blob[subject_key]


def is_signed_off(record: dict[str, Any]) -> bool:
    """True iff this record represents a real, complete advisor sign-off."""
    if not record:
        return False
    return (
        record.get("review_status") == REVIEW_APPROVED
        and bool(record.get("reviewed_by"))
        and bool(record.get("reviewed_on"))
        and bool(record.get("sign_off_timestamp"))
    )


def display_status(record: dict[str, Any]) -> str:
    """Customer-safe status label. Falls back to 'Review pending' when the
    record is missing or incomplete. The 'Advisor reviewed' label is only
    returned for fully-signed-off records — never for status='approved'
    without complete sign-off identity."""
    if is_signed_off(record):
        return STATUS_LABELS[REVIEW_APPROVED]
    if not record:
        return "Review pending"
    status = record.get("review_status", REVIEW_PENDING)
    if status == REVIEW_APPROVED:
        # Approved without sign-off identity → not really reviewed.
        return "Review pending"
    return STATUS_LABELS.get(status, "Review pending")


def customer_view(record: dict[str, Any]) -> dict[str, Any]:
    """Return the record stripped of operator-only fields. Empty dict in,
    empty dict out (caller should use display_status() to render the label)."""
    if not record:
        return {}
    safe = dict(record)
    safe.pop("internal_operator_notes", None)
    # Replace status with a customer-safe label.
    safe["status_label"] = display_status(record)
    return safe


def annotate(item: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """Stamp review metadata onto an existing item (report, policy, vault row,
    etc.). The item is mutated in place AND returned for chaining. Customer-
    safe only: internal_operator_notes is never written onto the item."""
    if not is_signed_off(record):
        # No sign-off → never claim reviewed.
        item.setdefault("reviewed_by", "")
        item.setdefault("reviewed_on", "")
        item.setdefault("reviewer_credential", "")
        item.setdefault("sign_off_timestamp", "")
        item["review_status_label"] = display_status(record)
        # Preserve any client-facing recommendation written during in-review.
        item.setdefault("client_facing_recommendation",
                        (record or {}).get("client_facing_recommendation", ""))
        item.setdefault("advisor_notes", (record or {}).get("advisor_notes", ""))
        item.setdefault("prepared_by", (record or {}).get("prepared_by", ""))
        return item
    item["reviewed_by"] = record.get("reviewed_by", "")
    item["reviewed_on"] = record.get("reviewed_on", "")
    item["reviewer_credential"] = record.get("reviewer_credential", "")
    item["sign_off_timestamp"] = record.get("sign_off_timestamp", "")
    item["client_facing_recommendation"] = record.get("client_facing_recommendation", "")
    item["advisor_notes"] = record.get("advisor_notes", "")
    item["prepared_by"] = record.get("prepared_by", "")
    item["review_status_label"] = STATUS_LABELS[REVIEW_APPROVED]
    return item


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
