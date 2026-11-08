"""SQLAlchemy data models for TrustVault."""

from datetime import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    BigInteger,
    Text,
    UniqueConstraint,
    CheckConstraint,
    Index,
)
from sqlalchemy.orm import relationship

from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)

    role = Column(String(20), nullable=False, default="viewer")
    is_active = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "role IN ('admin', 'owner', 'viewer')",
            name="check_user_role",
        ),
    )

    # Relationships
    owned_documents = relationship(
        "Document",
        back_populates="owner",
        cascade="all, delete-orphan",
        foreign_keys="[Document.owner_id]"
    )
    permissions_received = relationship(
        "DocumentPermission",
        back_populates="user",
        foreign_keys="[DocumentPermission.user_id]"
    )
    permissions_granted = relationship(
        "DocumentPermission",
        back_populates="granter",
        foreign_keys="[DocumentPermission.granted_by]"
    )
    audit_events = relationship(
        "AuditLog",
        back_populates="actor",
        foreign_keys="[AuditLog.actor_id]"
    )


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)

    owner_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    original_filename = Column(String(255), nullable=False)
    storage_key = Column(String(100), unique=True, nullable=False)

    category = Column(String(100), nullable=True)
    content_type = Column(String(100), nullable=False)
    size_bytes = Column(BigInteger, nullable=False)
    checksum_sha256 = Column(String(64), nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    is_deleted = Column(Boolean, default=False, nullable=False)

    # Relationships
    owner = relationship(
        "User",
        back_populates="owned_documents",
        foreign_keys=[owner_id]
    )
    permissions = relationship(
        "DocumentPermission",
        back_populates="document",
        cascade="all, delete-orphan",
        foreign_keys="[DocumentPermission.document_id]"
    )
    audit_logs = relationship(
        "AuditLog",
        back_populates="document",
        foreign_keys="[AuditLog.document_id]"
    )


class DocumentPermission(Base):
    __tablename__ = "document_permissions"

    id = Column(Integer, primary_key=True, index=True)

    document_id = Column(
        Integer,
        ForeignKey("documents.id"),
        nullable=False,
        index=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    access_level = Column(String(10), nullable=False)

    granted_by = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
    )

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "document_id",
            "user_id",
            name="unique_document_user_permission",
        ),
        CheckConstraint(
            "access_level IN ('read', 'edit')",
            name="check_permission_level",
        ),
    )

    # Relationships
    document = relationship(
        "Document",
        back_populates="permissions",
        foreign_keys=[document_id]
    )
    user = relationship(
        "User",
        back_populates="permissions_received",
        foreign_keys=[user_id]
    )
    granter = relationship(
        "User",
        back_populates="permissions_granted",
        foreign_keys=[granted_by]
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    actor_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
    )

    document_id = Column(
        Integer,
        ForeignKey("documents.id", ondelete="SET NULL"),
        nullable=True,
    )

    action = Column(String(50), nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)

    previous_hash = Column(String(64), nullable=True)
    entry_hash = Column(String(64), nullable=False, unique=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("idx_audit_document", "document_id"),
        Index("idx_audit_actor", "actor_id"),
        Index("idx_audit_created", "created_at"),
    )

    # Relationships
    actor = relationship(
        "User",
        back_populates="audit_events",
        foreign_keys=[actor_id]
    )
    document = relationship(
        "Document",
        back_populates="audit_logs",
        foreign_keys=[document_id]
    )
