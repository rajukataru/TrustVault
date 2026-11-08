"""Authentication and User Management routes for TrustVault."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.database import get_db
from backend.models import User
from backend.schemas import (
    UserRegister,
    UserLogin,
    UserResponse,
    TokenResponse,
    UserRoleUpdate,
    UserStatusUpdate
)
from backend.security import (
    hash_password,
    verify_password,
    create_access_token,
    record_audit_event,
    ACTION_USER_REGISTER,
    ACTION_LOGIN_SUCCESS,
    ACTION_LOGIN_FAILED,
    ACTION_ROLE_CHANGE,
    ACTION_STATUS_CHANGE
)
from backend.dependencies import (
    get_current_user,
    require_roles,
    get_client_ip
)

# Authentication Router
auth_router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

# User Management Router
users_router = APIRouter(
    prefix="/users",
    tags=["User Management"]
)


# ---------------------------------------------------------
# Authentication Endpoints
# ---------------------------------------------------------
@auth_router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account"
)
def register_user(
    user_data: UserRegister,
    request: Request,
    db: Session = Depends(get_db)
):
    """Registers a new user account with unique email and Argon2id password hash."""
    email = str(user_data.email).strip().lower()

    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address is already registered"
        )

    user_count = db.query(User).count()
    assigned_role = "admin" if user_count == 0 else (user_data.role or "viewer")

    new_user = User(
        name=user_data.name.strip(),
        email=email,
        password_hash=hash_password(user_data.password),
        role=assigned_role,
        is_active=True
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_USER_REGISTER,
        actor_id=new_user.id,
        details=f"User registered with email '{email}' and role '{assigned_role}'.",
        ip_address=client_ip
    )

    return new_user


def _authenticate_and_issue_token(email: str, password: str, request: Request, db: Session) -> TokenResponse:
    clean_email = email.strip().lower()
    client_ip = get_client_ip(request)

    user = db.query(User).filter(User.email == clean_email).first()

    if not user or not verify_password(password, user.password_hash):
        record_audit_event(
            db=db,
            action=ACTION_LOGIN_FAILED,
            actor_id=user.id if user else None,
            details=f"Failed login attempt for email '{clean_email}'. Invalid credentials.",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        record_audit_event(
            db=db,
            action=ACTION_LOGIN_FAILED,
            actor_id=user.id,
            details=f"Failed login attempt for deactivated account '{clean_email}'.",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated. Please contact an administrator."
        )

    access_token = create_access_token(user_id=user.id, role=user.role)

    record_audit_event(
        db=db,
        action=ACTION_LOGIN_SUCCESS,
        actor_id=user.id,
        details=f"Successful login for user '{clean_email}' (role: {user.role}).",
        ip_address=client_ip
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        role=user.role,
        user_id=user.id,
        name=user.name,
        email=user.email
    )


@auth_router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login with JSON credentials"
)
def login_json(
    credentials: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    return _authenticate_and_issue_token(
        email=credentials.email,
        password=credentials.password,
        request=request,
        db=db
    )


@auth_router.post(
    "/token",
    response_model=TokenResponse,
    summary="Login via OAuth2 password form (Swagger UI support)"
)
def login_form(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    return _authenticate_and_issue_token(
        email=form_data.username,
        password=form_data.password,
        request=request,
        db=db
    )


@auth_router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile"
)
def get_my_profile(current_user: User = Depends(get_current_user)):
    return current_user


# ---------------------------------------------------------
# User Management Endpoints (Admin & Collaborator Search)
# ---------------------------------------------------------
@users_router.get(
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
    q = db.query(User)
    if query:
        filter_str = f"%{query}%"
        q = q.filter(or_(User.name.ilike(filter_str), User.email.ilike(filter_str)))
    if role:
        q = q.filter(User.role == role)

    return q.order_by(User.id.asc()).offset(offset).limit(limit).all()


@users_router.get(
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
    filter_str = f"%{query}%"
    return db.query(User).filter(
        User.id != current_user.id,
        User.is_active == True,
        or_(User.name.ilike(filter_str), User.email.ilike(filter_str))
    ).limit(limit).all()


@users_router.patch(
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
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

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


@users_router.patch(
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
    if user_id == current_user.id and not status_update.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admins cannot deactivate their own account"
        )

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

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
