"""FastAPI dependencies for JWT authentication, RBAC, and document authorization."""

from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError

from backend.database import get_db
from backend.models import User, Document, DocumentPermission
from backend.security import decode_access_token
from backend.audit import record_audit_event, ACTION_ACCESS_DENIED

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_client_ip(request: Request) -> str:
    """Extracts client IP address from request headers or client host."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "UNKNOWN"


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Validates JWT access token and returns the authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid, expired, or missing authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(token)
        user_id_str = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception
        user_id = int(user_id_str)
    except (JWTError, ValueError, TypeError):
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account has been deactivated"
        )

    return user


def require_roles(*allowed_roles: str):
    """Dependency factory ensuring current user has one of the specified roles."""
    def role_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Required role '{allowed_roles}', but your role is '{current_user.role}'"
            )
        return current_user

    return role_checker


def get_effective_permission(
    db: Session,
    user: User,
    document: Document
) -> Optional[str]:
    """
    Computes effective permission for a user on a given document:
    Returns 'admin', 'owner', 'edit', 'read', or None.
    """
    if user.role == "admin":
        return "admin"
    if document.owner_id == user.id:
        return "owner"

    perm = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == document.id,
        DocumentPermission.user_id == user.id
    ).first()

    if perm:
        return perm.access_level

    return None


def verify_document_access(
    document_id: int,
    required_level: str,  # 'read', 'edit', 'owner_or_admin'
    current_user: User,
    db: Session,
    request: Request
) -> tuple[Document, str]:
    """
    Verifies user has the required permission level on the document.
    Logs an ACTION_ACCESS_DENIED audit event on failure.
    Returns (document, effective_permission).
    """
    document = db.query(Document).filter(
        Document.id == document_id,
        Document.is_deleted == False
    ).first()

    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found or has been deleted"
        )

    effective_perm = get_effective_permission(db, current_user, document)
    client_ip = get_client_ip(request)

    # Permission check logic
    has_access = False
    if effective_perm in ("admin", "owner"):
        has_access = True
    elif required_level == "read" and effective_perm in ("read", "edit"):
        has_access = True
    elif required_level == "edit" and effective_perm == "edit":
        has_access = True

    if not has_access:
        # Audit log the denied access attempt
        record_audit_event(
            db=db,
            action=ACTION_ACCESS_DENIED,
            actor_id=current_user.id,
            document_id=document.id,
            details=(
                f"Access denied for user '{current_user.email}' (role: {current_user.role}). "
                f"Required permission: '{required_level}', effective permission: '{effective_perm}'."
            ),
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to perform this action on this document"
        )

    return document, effective_perm
