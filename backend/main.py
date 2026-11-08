"""FastAPI Application Entrypoint and Route Orchestrator for TrustVault."""

import uuid
import shutil
from pathlib import Path
from typing import List, Optional
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    Query,
    Request,
    status
)
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text, or_, desc

from backend.database import (
    engine,
    SessionLocal,
    get_db,
    STORAGE_DIR,
    MAX_FILE_SIZE_BYTES,
    MAX_FILE_SIZE_MB
)
from backend.models import User, Document, DocumentPermission, AuditLog
from backend.schemas import (
    DocumentResponse,
    DocumentMetadataUpdate,
    PermissionGrant,
    PermissionResponse,
    AuditLogResponse,
    AuditVerificationResponse
)
from backend.security import (
    compute_sha256_stream,
    record_audit_event,
    verify_audit_chain,
    ACTION_UPLOAD,
    ACTION_DOWNLOAD,
    ACTION_EDIT,
    ACTION_DELETE,
    ACTION_PERMISSION_GRANT,
    ACTION_PERMISSION_REVOKE,
    ACTION_ACCESS_DENIED
)
from backend.dependencies import (
    get_current_user,
    require_roles,
    get_client_ip,
    get_effective_permission,
    verify_document_access
)
from backend.auth import auth_router, users_router

app = FastAPI(
    title="TrustVault API",
    description=(
        "Enterprise-grade Secure Document Sharing Platform featuring "
        "Argon2 password hashing, JWT authentication, Role-Based Access Control "
        "(Admin, Owner, Viewer), and Tamper-Evident SHA-256 Hash Chained Audit Logs."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for Streamlit and external clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers from auth.py
app.include_router(auth_router)
app.include_router(users_router)


# ---------------------------------------------------------
# General Health and Info Endpoints
# ---------------------------------------------------------
@app.get("/", tags=["General"], summary="Root Welcome endpoint")
def root():
    return {
        "platform": "TrustVault",
        "description": "Secure Document Sharing Platform",
        "version": "1.0.0",
        "documentation": "/docs",
        "status": "Operational"
    }


@app.get("/health", tags=["General"], summary="System and Database Health Check")
def health_check():
    """Performs deep health checks on database, storage, and audit chain."""
    health_status = {
        "api": "Online",
        "database": "Disconnected",
        "storage": "Unavailable",
        "audit_chain": "Unknown"
    }

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        health_status["database"] = "Connected"
    except Exception as e:
        health_status["database"] = f"Error: {str(e)}"
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=health_status)

    if STORAGE_DIR.exists() and STORAGE_DIR.is_dir():
        health_status["storage"] = "Accessible"
    else:
        health_status["storage"] = "Missing"

    db = SessionLocal()
    try:
        verification = verify_audit_chain(db)
        health_status["audit_chain"] = "Valid" if verification["is_valid"] else "TAMPER_DETECTED"
    except Exception:
        health_status["audit_chain"] = "Error checking"
    finally:
        db.close()

    return health_status


# ---------------------------------------------------------
# Document Management Endpoints
# ---------------------------------------------------------
def _build_doc_response(doc: Document, effective_permission: Optional[str]) -> DocumentResponse:
    return DocumentResponse(
        id=doc.id,
        owner_id=doc.owner_id,
        owner_name=doc.owner.name if doc.owner else None,
        owner_email=doc.owner.email if doc.owner else None,
        original_filename=doc.original_filename,
        category=doc.category,
        content_type=doc.content_type,
        size_bytes=doc.size_bytes,
        checksum_sha256=doc.checksum_sha256,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        is_deleted=doc.is_deleted,
        effective_permission=effective_permission
    )


@app.post(
    "/documents/upload",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Documents"],
    summary="Securely upload a new document"
)
async def upload_document(
    request: Request,
    file: UploadFile = File(..., description="Document file to upload (max 10MB)"),
    category: Optional[str] = Form(None, description="Optional category"),
    current_user: User = Depends(require_roles("admin", "owner")),
    db: Session = Depends(get_db)
):
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Filename is required")

    original_filename = Path(file.filename).name
    storage_key = f"{uuid.uuid4().hex}.vault"
    destination_path = STORAGE_DIR / storage_key

    size_bytes = 0
    try:
        with open(destination_path, "wb") as buffer:
            while chunk := await file.read(65536):
                size_bytes += len(chunk)
                if size_bytes > MAX_FILE_SIZE_BYTES:
                    buffer.close()
                    if destination_path.exists():
                        destination_path.unlink()
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE_MB}MB"
                    )
                buffer.write(chunk)
    except Exception as e:
        if destination_path.exists():
            destination_path.unlink()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    if size_bytes == 0:
        if destination_path.exists():
            destination_path.unlink()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot upload an empty file")

    with open(destination_path, "rb") as f:
        checksum_sha256 = compute_sha256_stream(f)

    doc = Document(
        owner_id=current_user.id,
        original_filename=original_filename,
        storage_key=storage_key,
        category=category.strip() if category else None,
        content_type=file.content_type or "application/octet-stream",
        size_bytes=size_bytes,
        checksum_sha256=checksum_sha256,
        is_deleted=False
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_UPLOAD,
        actor_id=current_user.id,
        document_id=doc.id,
        details=f"Uploaded document '{original_filename}' ({size_bytes} bytes). SHA256: {checksum_sha256}",
        ip_address=client_ip
    )

    effective_perm = "owner" if current_user.role != "admin" else "admin"
    return _build_doc_response(doc, effective_perm)


@app.get("/documents", response_model=List[DocumentResponse], tags=["Documents"], summary="List accessible documents")
def list_documents(
    query: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    scope: str = Query("all"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    base_query = db.query(Document).filter(Document.is_deleted == False)

    if current_user.role == "admin":
        if scope == "owned":
            base_query = base_query.filter(Document.owner_id == current_user.id)
        elif scope == "shared":
            shared_ids = [p.document_id for p in db.query(DocumentPermission.document_id).filter(DocumentPermission.user_id == current_user.id).all()]
            base_query = base_query.filter(Document.id.in_(shared_ids))
    elif current_user.role == "owner":
        shared_ids = [p.document_id for p in db.query(DocumentPermission.document_id).filter(DocumentPermission.user_id == current_user.id).all()]
        if scope == "owned":
            base_query = base_query.filter(Document.owner_id == current_user.id)
        elif scope == "shared":
            base_query = base_query.filter(Document.id.in_(shared_ids))
        else:
            base_query = base_query.filter(or_(Document.owner_id == current_user.id, Document.id.in_(shared_ids)))
    else:
        shared_ids = [p.document_id for p in db.query(DocumentPermission.document_id).filter(DocumentPermission.user_id == current_user.id).all()]
        base_query = base_query.filter(Document.id.in_(shared_ids))

    if query:
        search_filter = f"%{query}%"
        base_query = base_query.filter(or_(Document.original_filename.ilike(search_filter), Document.category.ilike(search_filter)))

    if category:
        base_query = base_query.filter(Document.category == category)

    docs = base_query.order_by(desc(Document.updated_at)).offset(offset).limit(limit).all()
    return [_build_doc_response(doc, get_effective_permission(db, current_user, doc)) for doc in docs]


@app.get("/documents/{document_id}", response_model=DocumentResponse, tags=["Documents"], summary="Get document details")
def get_document_details(document_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc, eff_perm = verify_document_access(document_id, "read", current_user, db, request)
    return _build_doc_response(doc, eff_perm)


@app.get("/documents/{document_id}/download", tags=["Documents"], summary="Securely download document with integrity check")
def download_document(document_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc, eff_perm = verify_document_access(document_id, "read", current_user, db, request)
    file_path = STORAGE_DIR / doc.storage_key

    if not file_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File was not found in storage")

    with open(file_path, "rb") as f:
        disk_checksum = compute_sha256_stream(f)

    if disk_checksum != doc.checksum_sha256:
        client_ip = get_client_ip(request)
        record_audit_event(
            db=db,
            action=ACTION_ACCESS_DENIED,
            actor_id=current_user.id,
            document_id=doc.id,
            details=f"INTEGRITY VIOLATION DETECTED: File '{doc.original_filename}' checksum mismatch.",
            ip_address=client_ip
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Security error: File integrity verification failed.")

    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_DOWNLOAD,
        actor_id=current_user.id,
        document_id=doc.id,
        details=f"Downloaded '{doc.original_filename}'. Checksum verified.",
        ip_address=client_ip
    )

    return FileResponse(path=file_path, media_type=doc.content_type, filename=doc.original_filename)


@app.put("/documents/{document_id}", response_model=DocumentResponse, tags=["Documents"], summary="Update document metadata")
def update_document_metadata(document_id: int, metadata: DocumentMetadataUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc, eff_perm = verify_document_access(document_id, "edit", current_user, db, request)
    changes = []
    if metadata.original_filename and metadata.original_filename != doc.original_filename:
        old_name = doc.original_filename
        doc.original_filename = Path(metadata.original_filename).name
        changes.append(f"renamed from '{old_name}' to '{doc.original_filename}'")
    if metadata.category is not None and metadata.category != doc.category:
        old_cat = doc.category
        doc.category = metadata.category.strip() if metadata.category else None
        changes.append(f"category changed from '{old_cat}' to '{doc.category}'")

    if changes:
        db.commit()
        db.refresh(doc)
        client_ip = get_client_ip(request)
        record_audit_event(
            db=db,
            action=ACTION_EDIT,
            actor_id=current_user.id,
            document_id=doc.id,
            details=f"Updated document metadata: {', '.join(changes)}.",
            ip_address=client_ip
        )

    return _build_doc_response(doc, eff_perm)


@app.put("/documents/{document_id}/content", response_model=DocumentResponse, tags=["Documents"], summary="Replace document content")
async def update_document_content(document_id: int, request: Request, file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc, eff_perm = verify_document_access(document_id, "edit", current_user, db, request)
    file_path = STORAGE_DIR / doc.storage_key
    backup_path = STORAGE_DIR / f"{doc.storage_key}.bak"
    if file_path.exists():
        shutil.copyfile(file_path, backup_path)

    size_bytes = 0
    try:
        with open(file_path, "wb") as buffer:
            while chunk := await file.read(65536):
                size_bytes += len(chunk)
                if size_bytes > MAX_FILE_SIZE_BYTES:
                    buffer.close()
                    if backup_path.exists():
                        shutil.copyfile(backup_path, file_path)
                    raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File exceeds limit")
                buffer.write(chunk)
    except Exception as e:
        if backup_path.exists():
            shutil.copyfile(backup_path, file_path)
            backup_path.unlink()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))

    if backup_path.exists():
        backup_path.unlink()

    with open(file_path, "rb") as f:
        new_checksum = compute_sha256_stream(f)

    doc.size_bytes = size_bytes
    doc.checksum_sha256 = new_checksum
    if file.content_type:
        doc.content_type = file.content_type
    db.commit()
    db.refresh(doc)

    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_EDIT,
        actor_id=current_user.id,
        document_id=doc.id,
        details=f"Updated file content ({size_bytes} bytes). New checksum: {new_checksum[:16]}...",
        ip_address=client_ip
    )
    return _build_doc_response(doc, eff_perm)


@app.delete("/documents/{document_id}", tags=["Documents"], summary="Soft-delete document")
def delete_document(document_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc, eff_perm = verify_document_access(document_id, "owner_or_admin", current_user, db, request)
    doc.is_deleted = True
    db.commit()

    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_DELETE,
        actor_id=current_user.id,
        document_id=doc.id,
        details=f"Document '{doc.original_filename}' soft-deleted by {current_user.email}.",
        ip_address=client_ip
    )
    return {"message": f"Document '{doc.original_filename}' deleted successfully"}


# ---------------------------------------------------------
# Sharing and Permission Endpoints
# ---------------------------------------------------------
@app.post("/documents/{document_id}/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED, tags=["Sharing & Access Control"], summary="Share document with user")
def share_document(document_id: int, grant: PermissionGrant, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc, eff_perm = verify_document_access(document_id, "owner_or_admin", current_user, db, request)
    target_email = grant.user_email.strip().lower()
    target_user = db.query(User).filter(User.email == target_email).first()

    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User with email '{target_email}' does not exist")
    if target_user.id == doc.owner_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot grant sharing permissions to the document owner")

    permission = db.query(DocumentPermission).filter(DocumentPermission.document_id == doc.id, DocumentPermission.user_id == target_user.id).first()
    if permission:
        old_level = permission.access_level
        permission.access_level = grant.access_level
        permission.granted_by = current_user.id
        db.commit()
        db.refresh(permission)
        detail_msg = f"Updated permission for '{target_user.email}' on '{doc.original_filename}' to '{grant.access_level}'."
    else:
        permission = DocumentPermission(document_id=doc.id, user_id=target_user.id, access_level=grant.access_level, granted_by=current_user.id)
        db.add(permission)
        db.commit()
        db.refresh(permission)
        detail_msg = f"Granted '{grant.access_level}' access to '{target_user.email}' on '{doc.original_filename}'."

    client_ip = get_client_ip(request)
    record_audit_event(db=db, action=ACTION_PERMISSION_GRANT, actor_id=current_user.id, document_id=doc.id, details=detail_msg, ip_address=client_ip)

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


@app.get("/documents/{document_id}/permissions", response_model=List[PermissionResponse], tags=["Sharing & Access Control"], summary="List document collaborators")
def list_document_permissions(document_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc, eff_perm = verify_document_access(document_id, "edit", current_user, db, request)
    perms = db.query(DocumentPermission).filter(DocumentPermission.document_id == doc.id).all()
    return [
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
        for p in perms
    ]


@app.delete("/documents/{document_id}/permissions/{user_id}", tags=["Sharing & Access Control"], summary="Revoke collaborator access")
def revoke_document_permission(document_id: int, user_id: int, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc, eff_perm = verify_document_access(document_id, "owner_or_admin", current_user, db, request)
    permission = db.query(DocumentPermission).filter(DocumentPermission.document_id == doc.id, DocumentPermission.user_id == user_id).first()

    if not permission:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No sharing permission found for this user")

    target_email = permission.user.email if permission.user else f"User ID {user_id}"
    revoked_level = permission.access_level
    db.delete(permission)
    db.commit()

    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_PERMISSION_REVOKE,
        actor_id=current_user.id,
        document_id=doc.id,
        details=f"Revoked '{revoked_level}' access from '{target_email}' on '{doc.original_filename}'.",
        ip_address=client_ip
    )
    return {"message": f"Successfully revoked access for {target_email}"}


# ---------------------------------------------------------
# Audit Log and Tamper Verification Endpoints
# ---------------------------------------------------------
@app.get("/audit/logs", response_model=List[AuditLogResponse], tags=["Audit & Tamper Verification"], summary="Retrieve audit logs")
def get_audit_logs(
    action: Optional[str] = Query(None),
    document_id: Optional[int] = Query(None),
    actor_id: Optional[int] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(AuditLog)
    if current_user.role == "admin":
        if action:
            query = query.filter(AuditLog.action == action)
        if document_id:
            query = query.filter(AuditLog.document_id == document_id)
        if actor_id:
            query = query.filter(AuditLog.actor_id == actor_id)
    elif current_user.role == "owner":
        owned_doc_ids = [d.id for d in db.query(Document.id).filter(Document.owner_id == current_user.id).all()]
        query = query.filter(or_(AuditLog.actor_id == current_user.id, AuditLog.document_id.in_(owned_doc_ids)))
        if action:
            query = query.filter(AuditLog.action == action)
        if document_id:
            if document_id in owned_doc_ids:
                query = query.filter(AuditLog.document_id == document_id)
            else:
                return []
    else:
        query = query.filter(AuditLog.actor_id == current_user.id)
        if action:
            query = query.filter(AuditLog.action == action)

    logs = query.order_by(desc(AuditLog.id)).offset(offset).limit(limit).all()
    return [
        AuditLogResponse(
            id=l.id,
            actor_id=l.actor_id,
            actor_name=l.actor.name if l.actor else None,
            actor_email=l.actor.email if l.actor else None,
            document_id=l.document_id,
            document_filename=l.document.original_filename if l.document else None,
            action=l.action,
            details=l.details,
            ip_address=l.ip_address,
            previous_hash=l.previous_hash,
            entry_hash=l.entry_hash,
            created_at=l.created_at
        )
        for l in logs
    ]


@app.get("/audit/verify", response_model=AuditVerificationResponse, tags=["Audit & Tamper Verification"], summary="Verify SHA-256 hash chain")
def verify_hash_chain(current_user: User = Depends(require_roles("admin", "owner")), db: Session = Depends(get_db)):
    result = verify_audit_chain(db)
    return AuditVerificationResponse(
        is_valid=result["is_valid"],
        total_records=result["total_records"],
        broken_at_id=result["broken_at_id"],
        details=result["details"]
    )
