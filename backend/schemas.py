"""Pydantic data validation schemas for TrustVault API."""

from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, EmailStr, Field, ConfigDict


# ---------------------------------------------------------
# User Schemas
# ---------------------------------------------------------
class UserRegister(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password: str = Field(..., min_length=8, max_length=128, description="Strong password")
    role: Optional[Literal["admin", "owner", "viewer"]] = Field(
        default="viewer",
        description="Desired role (defaults to viewer; first user can be admin)"
    )


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime


class UserRoleUpdate(BaseModel):
    role: Literal["admin", "owner", "viewer"]


class UserStatusUpdate(BaseModel):
    is_active: bool


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: int
    name: str
    email: EmailStr


# ---------------------------------------------------------
# Document Schemas
# ---------------------------------------------------------
class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    owner_id: int
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    original_filename: str
    category: Optional[str] = None
    content_type: str
    size_bytes: int
    checksum_sha256: str
    created_at: datetime
    updated_at: datetime
    is_deleted: bool
    effective_permission: Optional[str] = None


class DocumentMetadataUpdate(BaseModel):
    original_filename: Optional[str] = Field(None, min_length=1, max_length=255)
    category: Optional[str] = Field(None, max_length=100)


# ---------------------------------------------------------
# Document Sharing & Permission Schemas
# ---------------------------------------------------------
class PermissionGrant(BaseModel):
    user_email: EmailStr
    access_level: Literal["read", "edit"]


class PermissionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    document_id: int
    user_id: int
    user_name: Optional[str] = None
    user_email: Optional[str] = None
    access_level: str
    granted_by: int
    granted_by_name: Optional[str] = None
    created_at: datetime


# ---------------------------------------------------------
# Audit Log Schemas
# ---------------------------------------------------------
class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_id: Optional[int] = None
    actor_name: Optional[str] = None
    actor_email: Optional[str] = None
    document_id: Optional[int] = None
    document_filename: Optional[str] = None
    action: str
    details: Optional[str] = None
    ip_address: Optional[str] = None
    previous_hash: Optional[str] = None
    entry_hash: str
    created_at: datetime


class AuditVerificationResponse(BaseModel):
    is_valid: bool
    total_records: int
    broken_at_id: Optional[int] = None
    details: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
