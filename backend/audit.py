"""Tamper-evident audit logging service using SHA-256 hash chaining."""

from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.models import AuditLog
from backend.security import compute_audit_hash

GENESIS_PREVIOUS_HASH = "0" * 64

# Action Constants
ACTION_UPLOAD = "UPLOAD"
ACTION_DOWNLOAD = "DOWNLOAD"
ACTION_EDIT = "EDIT"
ACTION_DELETE = "DELETE"
ACTION_PERMISSION_GRANT = "PERMISSION_GRANT"
ACTION_PERMISSION_REVOKE = "PERMISSION_REVOKE"
ACTION_ACCESS_DENIED = "ACCESS_DENIED"
ACTION_LOGIN_SUCCESS = "LOGIN_SUCCESS"
ACTION_LOGIN_FAILED = "LOGIN_FAILED"
ACTION_USER_REGISTER = "USER_REGISTER"
ACTION_ROLE_CHANGE = "ROLE_CHANGE"
ACTION_STATUS_CHANGE = "STATUS_CHANGE"


def format_audit_timestamp(dt: datetime) -> str:
    """Formats datetime to standard MySQL DATETIME precision (seconds)."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def record_audit_event(
    db: Session,
    action: str,
    actor_id: Optional[int] = None,
    document_id: Optional[int] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None
) -> AuditLog:
    """
    Records an immutable audit event in the database with SHA-256 hash chaining.
    The new entry incorporates the cryptographic hash of the latest preceding record.
    """
    # Fetch the latest audit log entry to establish the cryptographic link
    latest_entry = db.query(AuditLog).order_by(desc(AuditLog.id)).first()
    previous_hash = latest_entry.entry_hash if latest_entry else GENESIS_PREVIOUS_HASH

    # Truncate microsecond to match MySQL DATETIME column precision
    now = datetime.utcnow().replace(microsecond=0)
    created_at_str = format_audit_timestamp(now)

    entry_hash = compute_audit_hash(
        previous_hash=previous_hash,
        actor_id=actor_id,
        document_id=document_id,
        action=action,
        details=details,
        ip_address=ip_address,
        created_at_iso=created_at_str
    )

    log_entry = AuditLog(
        actor_id=actor_id,
        document_id=document_id,
        action=action,
        details=details,
        ip_address=ip_address,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
        created_at=now
    )

    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    return log_entry


def verify_audit_chain(db: Session) -> Dict[str, Any]:
    """
    Cryptographically verifies the SHA-256 hash chain of all audit log records.
    Detects if any record was modified, injected, removed, or out of sequence.
    """
    logs: List[AuditLog] = db.query(AuditLog).order_by(AuditLog.id.asc()).all()

    if not logs:
        return {
            "is_valid": True,
            "total_records": 0,
            "broken_at_id": None,
            "details": "Audit log is empty. No records to verify."
        }

    expected_previous_hash = GENESIS_PREVIOUS_HASH

    for idx, log in enumerate(logs):
        # 1. Verify previous_hash linkage
        stored_prev = log.previous_hash or GENESIS_PREVIOUS_HASH
        if stored_prev != expected_previous_hash:
            return {
                "is_valid": False,
                "total_records": len(logs),
                "broken_at_id": log.id,
                "details": (
                    f"Chain break at record #{log.id} (action: {log.action}): "
                    f"previous_hash '{stored_prev[:16]}...' does not match expected "
                    f"preceding hash '{expected_previous_hash[:16]}...'."
                )
            }

        # 2. Recompute entry_hash to verify data integrity
        created_at_str = format_audit_timestamp(log.created_at)
        recomputed_hash = compute_audit_hash(
            previous_hash=stored_prev,
            actor_id=log.actor_id,
            document_id=log.document_id,
            action=log.action,
            details=log.details,
            ip_address=log.ip_address,
            created_at_iso=created_at_str
        )

        if recomputed_hash != log.entry_hash:
            return {
                "is_valid": False,
                "total_records": len(logs),
                "broken_at_id": log.id,
                "details": (
                    f"Tamper detected at record #{log.id} (action: {log.action}): "
                    f"Stored entry_hash does not match recomputed data hash."
                )
            }

        expected_previous_hash = log.entry_hash

    return {
        "is_valid": True,
        "total_records": len(logs),
        "broken_at_id": None,
        "details": f"Audit log verified successfully. All {len(logs)} records in the SHA-256 hash chain are valid and intact."
    }
