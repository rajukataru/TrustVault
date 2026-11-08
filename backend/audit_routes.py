"""FastAPI API routes for Audit Logging and Tamper Verification."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models import User, AuditLog, Document
from backend.schemas import AuditLogResponse, AuditVerificationResponse
from backend.dependencies import get_current_user, require_roles
from backend.audit import verify_audit_chain

router = APIRouter(
    prefix="/audit",
    tags=["Audit & Tamper Verification"]
)


@router.get(
    "/logs",
    response_model=List[AuditLogResponse],
    summary="Retrieve system audit logs"
)
def get_audit_logs(
    action: Optional[str] = Query(None, description="Filter by event action"),
    document_id: Optional[int] = Query(None, description="Filter by document ID"),
    actor_id: Optional[int] = Query(None, description="Filter by actor user ID"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves audit logs according to role:
    - Admin: Can inspect complete audit history across all documents and users.
    - Owner: Can inspect events relating to their documents or actions performed by themselves.
    - Viewer: Can only inspect events performed by themselves.
    """
    query = db.query(AuditLog)

    if current_user.role == "admin":
        # Admin can view all logs, with optional filters
        if action:
            query = query.filter(AuditLog.action == action)
        if document_id:
            query = query.filter(AuditLog.document_id == document_id)
        if actor_id:
            query = query.filter(AuditLog.actor_id == actor_id)

    elif current_user.role == "owner":
        # Owner can view actions on their owned documents or actions by themselves
        owned_doc_ids = [
            doc.id for doc in db.query(Document.id).filter(
                Document.owner_id == current_user.id
            ).all()
        ]
        query = query.filter(
            (AuditLog.actor_id == current_user.id) |
            (AuditLog.document_id.in_(owned_doc_ids))
        )
        if action:
            query = query.filter(AuditLog.action == action)
        if document_id:
            if document_id in owned_doc_ids:
                query = query.filter(AuditLog.document_id == document_id)
            else:
                return []

    else:
        # Viewer only sees their own actions
        query = query.filter(AuditLog.actor_id == current_user.id)
        if action:
            query = query.filter(AuditLog.action == action)

    logs = query.order_by(desc(AuditLog.id)).offset(offset).limit(limit).all()

    # Populate response with actor and document metadata
    response = []
    for log in logs:
        actor_name = log.actor.name if log.actor else None
        actor_email = log.actor.email if log.actor else None
        doc_name = log.document.original_filename if log.document else None

        response.append(
            AuditLogResponse(
                id=log.id,
                actor_id=log.actor_id,
                actor_name=actor_name,
                actor_email=actor_email,
                document_id=log.document_id,
                document_filename=doc_name,
                action=log.action,
                details=log.details,
                ip_address=log.ip_address,
                previous_hash=log.previous_hash,
                entry_hash=log.entry_hash,
                created_at=log.created_at
            )
        )

    return response


@router.get(
    "/verify",
    response_model=AuditVerificationResponse,
    summary="Cryptographically verify SHA-256 audit log hash chain"
)
def verify_hash_chain(
    current_user: User = Depends(require_roles("admin", "owner")),
    db: Session = Depends(get_db)
):
    """
    Verifies that the entire audit log hash chain is untampered.
    Recalculates every SHA-256 entry hash and tests continuity with previous_hash.
    """
    result = verify_audit_chain(db)
    return AuditVerificationResponse(
        is_valid=result["is_valid"],
        total_records=result["total_records"],
        broken_at_id=result["broken_at_id"],
        details=result["details"]
    )
