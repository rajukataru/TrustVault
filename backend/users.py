"""User management and discovery API endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.database import get_db
from backend.models import User
from backend.schemas import UserResponse, UserRoleUpdate, UserStatusUpdate
from backend.dependencies import (
    get_current_user,
    require_roles,
    get_client_ip
)
from backend.audit import (
    record_audit_event,
    ACTION_ROLE_CHANGE,
    ACTION_STATUS_CHANGE
)

router = APIRouter(
    prefix="/users",
    tags=["User Management"]
)


@router.get(
    "",
    response_model=List[UserResponse],
    summary="List all users (Admin only)"
)
def list_users(
    query: Optional[str] = Query(None, description="Search by name or email"),
    role: Optional[str] = Query(None, description="Filter by role"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db)
):
    """Admin-only endpoint to inspect all platform users."""
    q = db.query(User)
    if query:
        filter_str = f"%{query}%"
        q = q.filter(
            or_(
                User.name.ilike(filter_str),
                User.email.ilike(filter_str)
            )
        )
    if role:
        q = q.filter(User.role == role)

    return q.order_by(User.id.asc()).offset(offset).limit(limit).all()


@router.get(
    "/search",
    response_model=List[UserResponse],
    summary="Search users for collaboration and sharing"
)
def search_collaborators(
    query: str = Query(..., min_length=1, description="Search term for name or email"),
    limit: int = Query(10, ge=1, le=50),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Allows authenticated users to search other users to share documents with."""
    filter_str = f"%{query}%"
    users = db.query(User).filter(
        User.id != current_user.id,
        User.is_active == True,
        or_(
            User.name.ilike(filter_str),
            User.email.ilike(filter_str)
        )
    ).limit(limit).all()

    return users


@router.patch(
    "/{user_id}/role",
    response_model=UserResponse,
    summary="Change user role (Admin only)"
)
def update_user_role(
    user_id: int,
    role_update: UserRoleUpdate,
    request: Request,
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db)
):
    """Admin-only endpoint to promote or demote user roles."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    old_role = target_user.role
    target_user.role = role_update.role
    db.commit()
    db.refresh(target_user)

    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_ROLE_CHANGE,
        actor_id=current_user.id,
        details=f"Admin {current_user.email} changed role of {target_user.email} from '{old_role}' to '{target_user.role}'.",
        ip_address=client_ip
    )

    return target_user


@router.patch(
    "/{user_id}/status",
    response_model=UserResponse,
    summary="Activate or deactivate user account (Admin only)"
)
def update_user_status(
    user_id: int,
    status_update: UserStatusUpdate,
    request: Request,
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db)
):
    """Admin-only endpoint to activate or deactivate user accounts."""
    if user_id == current_user.id and not status_update.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admins cannot deactivate their own account"
        )

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    target_user.is_active = status_update.is_active
    db.commit()
    db.refresh(target_user)

    client_ip = get_client_ip(request)
    action_str = "activated" if target_user.is_active else "deactivated"
    record_audit_event(
        db=db,
        action=ACTION_STATUS_CHANGE,
        actor_id=current_user.id,
        details=f"Admin {current_user.email} {action_str} account of {target_user.email}.",
        ip_address=client_ip
    )

    return target_user
