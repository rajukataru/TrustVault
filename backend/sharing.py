"""Document sharing and permission management API endpoints."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User, Document, DocumentPermission
from backend.schemas import PermissionGrant, PermissionResponse
from backend.dependencies import (
    get_current_user,
    get_client_ip,
    verify_document_access
)
from backend.audit import (
    record_audit_event,
    ACTION_PERMISSION_GRANT,
    ACTION_PERMISSION_REVOKE
)

router = APIRouter(
    prefix="/documents",
    tags=["Sharing & Access Control"]
)


@router.post(
    "/{document_id}/permissions",
    response_model=PermissionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Share document with a user (grant read or edit access)"
)
def share_document(
    document_id: int,
    grant: PermissionGrant,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Grants read or edit permission to a registered user:
    - Only Document Owner or Admin can grant permissions.
    - Validates target recipient exists.
    - Prevents granting permission to the owner themselves.
    - Upserts permission record (creates or modifies existing).
    - Records tamper-evident PERMISSION_GRANT audit event.
    """
    # Verify owner or admin access
    doc, eff_perm = verify_document_access(
        document_id=document_id,
        required_level="owner_or_admin",
        current_user=current_user,
        db=db,
        request=request
    )

    # Find target user by email
    target_email = grant.user_email.strip().lower()
    target_user = db.query(User).filter(User.email == target_email).first()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with email '{target_email}' does not exist"
        )

    if target_user.id == doc.owner_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot grant sharing permissions to the document owner"
        )

    # Check if permission already exists
    permission = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc.id,
        DocumentPermission.user_id == target_user.id
    ).first()

    if permission:
        old_level = permission.access_level
        permission.access_level = grant.access_level
        permission.granted_by = current_user.id
        db.commit()
        db.refresh(permission)
        detail_msg = (
            f"Updated permission for user '{target_user.email}' on document '{doc.original_filename}' "
            f"from '{old_level}' to '{grant.access_level}'."
        )
    else:
        permission = DocumentPermission(
            document_id=doc.id,
            user_id=target_user.id,
            access_level=grant.access_level,
            granted_by=current_user.id
        )
        db.add(permission)
        db.commit()
        db.refresh(permission)
        detail_msg = (
            f"Granted '{grant.access_level}' permission for user '{target_user.email}' "
            f"on document '{doc.original_filename}'."
        )

    # Record audit log
    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_PERMISSION_GRANT,
        actor_id=current_user.id,
        document_id=doc.id,
        details=detail_msg,
        ip_address=client_ip
    )

    return PermissionResponse(
        id=permission.id,
        document_id=permission.document_id,
        user_id=permission.user_id,
        user_name=target_user.name,
        user_email=target_user.email,
        access_level=permission.access_level,
        granted_by=permission.granted_by,
        granted_by_name=current_user.name,
        created_at=permission.created_at
    )


@router.get(
    "/{document_id}/permissions",
    response_model=List[PermissionResponse],
    summary="List collaborators and permissions for a document"
)
def list_document_permissions(
    document_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lists all users who have access to this document:
    - Accessible to Owner, Admin, or users with edit access.
    """
    doc, eff_perm = verify_document_access(
        document_id=document_id,
        required_level="edit",
        current_user=current_user,
        db=db,
        request=request
    )

    perms = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc.id
    ).all()

    response = []
    for p in perms:
        response.append(
            PermissionResponse(
                id=p.id,
                document_id=p.document_id,
                user_id=p.user_id,
                user_name=p.user.name if p.user else None,
                user_email=p.user.email if p.user else None,
                access_level=p.access_level,
                granted_by=p.granted_by,
                granted_by_name=p.granter.name if p.granter else None,
                created_at=p.created_at
            )
        )

    return response


@router.delete(
    "/{document_id}/permissions/{user_id}",
    summary="Revoke document access from a user"
)
def revoke_document_permission(
    document_id: int,
    user_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Revokes access permission from a collaborator:
    - Only Document Owner or Admin can revoke permissions.
    - Records tamper-evident PERMISSION_REVOKE audit event.
    """
    doc, eff_perm = verify_document_access(
        document_id=document_id,
        required_level="owner_or_admin",
        current_user=current_user,
        db=db,
        request=request
    )

    permission = db.query(DocumentPermission).filter(
        DocumentPermission.document_id == doc.id,
        DocumentPermission.user_id == user_id
    ).first()

    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No sharing permission found for this user on the document"
        )

    target_email = permission.user.email if permission.user else f"User ID {user_id}"
    revoked_level = permission.access_level

    db.delete(permission)
    db.commit()

    # Record audit log
    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_PERMISSION_REVOKE,
        actor_id=current_user.id,
        document_id=doc.id,
        details=(
            f"Revoked '{revoked_level}' access from user '{target_email}' "
            f"for document '{doc.original_filename}'."
        ),
        ip_address=client_ip
    )

    return {"message": f"Successfully revoked access for {target_email}"}
