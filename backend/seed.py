"""Database seeder script for TrustVault demonstration and evaluation."""

import sys
import uuid
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy.orm import Session
from backend.database import SessionLocal, engine, Base
from backend.models import User, Document, DocumentPermission
from backend.security import hash_password, compute_sha256_stream
from backend.config import STORAGE_DIR
from backend.audit import (
    record_audit_event,
    ACTION_USER_REGISTER,
    ACTION_UPLOAD,
    ACTION_PERMISSION_GRANT
)


DEMO_USERS = [
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


def seed_database(create_sample_doc: bool = True):
    """Populates initial demo accounts and optional sample document."""
    # Ensure tables exist
    Base.metadata.create_all(bind=engine)

    db: Session = SessionLocal()
    try:
        created_users = {}
        for u in DEMO_USERS:
            existing = db.query(User).filter(User.email == u["email"]).first()
            if not existing:
                new_user = User(
                    name=u["name"],
                    email=u["email"],
                    password_hash=hash_password(u["password"]),
                    role=u["role"],
                    is_active=True
                )
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                created_users[u["role"]] = new_user

                record_audit_event(
                    db=db,
                    action=ACTION_USER_REGISTER,
                    actor_id=new_user.id,
                    details=f"Demo account created: {u['email']} (role: {u['role']})",
                    ip_address="127.0.0.1"
                )
                print(f"Created demo account: {u['email']} ({u['role']})")
            else:
                created_users[u["role"]] = existing
                print(f"Demo account already exists: {u['email']}")

        # Optionally create a sample document if owner exists and no docs exist
        doc_count = db.query(Document).count()
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
                checksum = compute_sha256_stream(f)

            sample_doc = Document(
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

            record_audit_event(
                db=db,
                action=ACTION_UPLOAD,
                actor_id=owner.id,
                document_id=sample_doc.id,
                details=f"Demo document created: '{sample_doc.original_filename}'. SHA-256: {checksum}",
                ip_address="127.0.0.1"
            )
            print(f"Created sample document: {sample_doc.original_filename}")

            # Share with viewer
            if viewer:
                perm = DocumentPermission(
                    document_id=sample_doc.id,
                    user_id=viewer.id,
                    access_level="read",
                    granted_by=owner.id
                )
                db.add(perm)
                db.commit()

                record_audit_event(
                    db=db,
                    action=ACTION_PERMISSION_GRANT,
                    actor_id=owner.id,
                    document_id=sample_doc.id,
                    details=f"Shared '{sample_doc.original_filename}' with '{viewer.email}' (access: read)",
                    ip_address="127.0.0.1"
                )
                print(f"Shared sample document with {viewer.email}")

        print("\nSeeding complete!")
        print("-" * 50)
        print("Demo Credentials:")
        print("  Admin:  admin@trustvault.com  / TrustVaultAdmin2026!")
        print("  Owner:  owner@trustvault.com  / TrustVaultOwner2026!")
        print("  Viewer: viewer@trustvault.com / TrustVaultViewer2026!")
        print("-" * 50)

    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
