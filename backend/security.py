"""Security, cryptographic operations, Argon2 password hashing, and JWT tokens."""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, BinaryIO

from jose import jwt, JWTError
from passlib.context import CryptContext

from backend.config import (
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)

# Password hashing configuration using Argon2id
password_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)


def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2."""
    return password_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2 hash."""
    return password_context.verify(password, hashed_password)


def create_access_token(
    user_id: int,
    role: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Generates a signed JWT access token containing subject ID and role."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )

    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decodes and validates a signed JWT access token."""
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM]
    )


def compute_sha256_bytes(data: bytes) -> str:
    """Computes SHA-256 hexadecimal digest for raw bytes."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def compute_sha256_stream(stream: BinaryIO, chunk_size: int = 65536) -> str:
    """Computes SHA-256 digest for an open binary stream, resetting seek afterwards."""
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
    Format:
    previous_hash|actor_id|document_id|action|details|ip_address|created_at_iso
    """
    p_hash = previous_hash or ("0" * 64)
    actor_str = str(actor_id) if actor_id is not None else "NONE"
    doc_str = str(document_id) if document_id is not None else "NONE"
    details_str = details or ""
    ip_str = ip_address or "UNKNOWN"

    canonical = (
        f"{p_hash}|{actor_str}|{doc_str}|{action.strip()}|"
        f"{details_str.strip()}|{ip_str.strip()}|{created_at_iso.strip()}"
    )

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
