"""Database connection, storage configuration, and seeder for TrustVault."""

import os
import uuid
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Project root directory
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"

# Load environment configuration
load_dotenv(ENV_FILE, override=True)

# ---------------------------------------------------------------------------
# Database Configuration
# DATABASE_URL must be set as an environment variable — no insecure fallback.
# Example: mysql+pymysql://user:password@host:3306/dbname
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is required but not set.\n"
        "Set it in your .env file (local dev) or as a Render environment variable (production).\n"
        "Example: mysql+pymysql://user:password@host:3306/trustvault"
    )

# Storage Configuration
STORAGE_PATH_STR = os.getenv("STORAGE_PATH", "storage/private")
STORAGE_DIR = Path(STORAGE_PATH_STR)
if not STORAGE_DIR.is_absolute():
    STORAGE_DIR = BASE_DIR / STORAGE_DIR

# Ensure private storage directory exists
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

try:
    MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "10"))
except ValueError:
    MAX_FILE_SIZE_MB = 10

MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

# ---------------------------------------------------------------------------
# SQLAlchemy Engine & Session Setup
#
# SSL support for Aiven (or any cloud MySQL that requires TLS):
# Set MYSQL_SSL_CA to the path of your downloaded CA certificate.
# On Render, upload the .pem file as a Secret File and set MYSQL_SSL_CA to
# its mounted path, e.g. /etc/secrets/aiven-ca.pem
# If MYSQL_SSL_CA is not set, the engine connects without explicit SSL args
# (suitable for local development).
# ---------------------------------------------------------------------------
MYSQL_SSL_CA = os.getenv("MYSQL_SSL_CA")  # e.g. "/etc/secrets/aiven-ca.pem"

_connect_args: dict = {}
if MYSQL_SSL_CA:
    if not Path(MYSQL_SSL_CA).is_file():
        raise RuntimeError(
            f"MYSQL_SSL_CA is set to '{MYSQL_SSL_CA}' but the file was not found. "
            "Ensure the CA certificate file exists at the specified path."
        )
    _connect_args["ssl"] = {"ca": MYSQL_SSL_CA}

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=1800,
    echo=False,
    connect_args=_connect_args
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db():
    """Dependency for providing a transactional database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Initializes all database tables defined in models."""
    from backend import models
    Base.metadata.create_all(bind=engine)


def seed_database(create_sample_doc: bool = True):
    """Populates initial demo accounts and optional sample document."""
    from backend import models
    from backend import security

    # Ensure tables exist
    create_tables()

    demo_users = [
        {
            "name": "Security Administrator",
            "email": "admin@trustvault.com",
            "password": "TrustVaultAdmin2026!",
            "role": "admin"
        },
        {
            "name": "Sarah Connor (Document Owner)",
            "email": "owner@trustvault.com",
            "password": "TrustVaultOwner2026!",
            "role": "owner"
        },
        {
            "name": "John Doe (Document Viewer)",
            "email": "viewer@trustvault.com",
            "password": "TrustVaultViewer2026!",
            "role": "viewer"
        }
    ]

    db = SessionLocal()
    try:
        created_users = {}
        for u in demo_users:
            existing = db.query(models.User).filter(models.User.email == u["email"]).first()
            if not existing:
                new_user = models.User(
                    name=u["name"],
                    email=u["email"],
                    password_hash=security.hash_password(u["password"]),
                    role=u["role"],
                    is_active=True
                )
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                created_users[u["role"]] = new_user

                security.record_audit_event(
                    db=db,
                    action=security.ACTION_USER_REGISTER,
                    actor_id=new_user.id,
                    details=f"Demo account created: {u['email']} (role: {u['role']})",
                    ip_address="127.0.0.1"
                )
            else:
                created_users[u["role"]] = existing

        # Create sample document if owner exists and no documents exist
        doc_count = db.query(models.Document).count()
        if create_sample_doc and doc_count == 0 and "owner" in created_users:
            owner = created_users["owner"]
            viewer = created_users.get("viewer")

            sample_content = (
                b"TrustVault Cryptographic Security Specification\n\n"
                b"1. Password Hashing: Argon2id (memory-hard, resistant to GPU attacks)\n"
                b"2. Authentication: Signed JWT tokens with HS256\n"
                b"3. File Storage: UUID-keyed files isolated outside web root with SHA-256 integrity verification\n"
                b"4. Audit Trail: Tamper-evident hash-chained logs with continuous SHA-256 verification\n"
            )
            storage_key = f"{uuid.uuid4().hex}.vault"
            file_path = STORAGE_DIR / storage_key
            with open(file_path, "wb") as f:
                f.write(sample_content)

            with open(file_path, "rb") as f:
                checksum = security.compute_sha256_stream(f)

            sample_doc = models.Document(
                owner_id=owner.id,
                original_filename="TrustVault_Security_Spec.txt",
                storage_key=storage_key,
                category="Confidential",
                content_type="text/plain",
                size_bytes=len(sample_content),
                checksum_sha256=checksum,
                is_deleted=False
            )
            db.add(sample_doc)
            db.commit()
            db.refresh(sample_doc)

            security.record_audit_event(
                db=db,
                action=security.ACTION_UPLOAD,
                actor_id=owner.id,
                document_id=sample_doc.id,
                details=f"Demo document created: '{sample_doc.original_filename}'. SHA-256: {checksum}",
                ip_address="127.0.0.1"
            )

            # Share with viewer
            if viewer:
                perm = models.DocumentPermission(
                    document_id=sample_doc.id,
                    user_id=viewer.id,
                    access_level="read",
                    granted_by=owner.id
                )
                db.add(perm)
                db.commit()

                security.record_audit_event(
                    db=db,
                    action=security.ACTION_PERMISSION_GRANT,
                    actor_id=owner.id,
                    document_id=sample_doc.id,
                    details=f"Shared '{sample_doc.original_filename}' with '{viewer.email}' (access: read)",
                    ip_address="127.0.0.1"
                )

        print("[*] Database initialization & seeding verified.")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
