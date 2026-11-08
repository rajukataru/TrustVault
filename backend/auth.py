"""Authentication routes: Registration, Login, Token generation, and Profile."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User
from backend.schemas import UserRegister, UserLogin, UserResponse, TokenResponse
from backend.security import (
    hash_password,
    verify_password,
    create_access_token
)
from backend.dependencies import get_current_user, get_client_ip
from backend.audit import (
    record_audit_event,
    ACTION_USER_REGISTER,
    ACTION_LOGIN_SUCCESS,
    ACTION_LOGIN_FAILED
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


@router.post(
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
    """
    Registers a new user:
    - Enforces unique email (case-insensitive).
    - Hashes password using Argon2id.
    - If this is the very first user registered on the system, promotes to 'admin' automatically.
    - Records tamper-evident USER_REGISTER audit event.
    """
    email = str(user_data.email).strip().lower()

    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address is already registered"
        )

    # First user automatically becomes admin, otherwise default to requested role or viewer
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


def _authenticate_and_issue_token(
    email: str,
    password: str,
    request: Request,
    db: Session
) -> TokenResponse:
    """Helper method for authenticating credentials, auditing, and issuing JWT tokens."""
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

    # Generate JWT token
    access_token = create_access_token(
        user_id=user.id,
        role=user.role
    )

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


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login with JSON credentials"
)
def login_json(
    credentials: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    """Authenticates using JSON payload, returning JWT bearer token."""
    return _authenticate_and_issue_token(
        email=credentials.email,
        password=credentials.password,
        request=request,
        db=db
    )


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Login via OAuth2 password form (Swagger UI support)"
)
def login_form(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Authenticates using standard OAuth2 form data (for Swagger UI /docs)."""
    return _authenticate_and_issue_token(
        email=form_data.username,
        password=form_data.password,
        request=request,
        db=db
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile"
)
def get_my_profile(
    current_user: User = Depends(get_current_user)
):
    """Retrieves profile of the currently authenticated user."""
    return current_user
