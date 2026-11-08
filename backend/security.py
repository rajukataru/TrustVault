"""Security, Cryptography, Argon2, JWT, and SHA-256 Tamper-Evident Audit Logging."""

import os
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, BinaryIO, Dict, Any, List
from dotenv import load_dotenv
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy import desc

# Find .env in project root
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"
load_dotenv(ENV_FILE, override=True)

SECRET_KEY = os.getenv("SECRET_KEY") or os.getenv("JWT_SECRET")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError("A strong SECRET_KEY (at least 32 characters) must be configured in .env")

ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
try:
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
except ValueError:
    ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ---------------------------------------------------------
# Password Hashing with Argon2id
# ---------------------------------------------------------
password_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    return password_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2 hash."""
    return password_context.verify(password, hashed_password)


# ---------------------------------------------------------
# JWT Token Operations
# ---------------------------------------------------------
def create_access_token(
    user_id: int,
    role: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Generates a signed JWT token containing subject ID and role."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decodes and validates a signed JWT token."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


# ---------------------------------------------------------
# SHA-256 File Integrity Checksums
# ---------------------------------------------------------
def compute_sha256_bytes(data: bytes) -> str:
    """Computes SHA-256 hexadecimal digest for raw bytes."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def compute_sha256_stream(stream: BinaryIO, chunk_size: int = 65536) -> str:
    """Computes SHA-256 digest for an open stream, restoring seek position."""
    hasher = hashlib.sha256()
    pos = stream.tell() if hasattr(stream, "tell") else None

    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)

    if pos is not None and hasattr(stream, "seek"):
        stream.seek(pos)

    return hasher.hexdigest()


# ---------------------------------------------------------
# Tamper-Evident SHA-256 Audit Log Chaining
# ---------------------------------------------------------
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


def compute_audit_hash(
    previous_hash: Optional[str],
    actor_id: Optional[int],
    document_id: Optional[int],
    action: str,
    details: Optional[str],
    ip_address: Optional[str],
    created_at_iso: str
) -> str:
    """
    Computes deterministic SHA-256 entry hash for audit log hash chaining.
    Format: previous_hash|actor_id|document_id|action|details|ip_address|created_at_iso
    """
    p_hash = previous_hash or GENESIS_PREVIOUS_HASH
    actor_str = str(actor_id) if actor_id is not None else "NONE"
    doc_str = str(document_id) if document_id is not None else "NONE"
    details_str = details or ""
    ip_str = ip_address or "UNKNOWN"

    canonical = (
        f"{p_hash}|{actor_str}|{doc_str}|{action.strip()}|"
        f"{details_str.strip()}|{ip_str.strip()}|{created_at_iso.strip()}"
    )

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def record_audit_event(
    db: Session,
    action: str,
    actor_id: Optional[int] = None,
    document_id: Optional[int] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = None
):
    """Records an immutable audit event in the database with SHA-256 hash chaining."""
    from backend.models import AuditLog

    latest_entry = db.query(AuditLog).order_by(desc(AuditLog.id)).first()
    previous_hash = latest_entry.entry_hash if latest_entry else GENESIS_PREVIOUS_HASH

    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
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
    from backend.models import AuditLog

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
