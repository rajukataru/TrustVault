"""Document management API endpoints: Upload, Search, Download, Update, Delete."""

import uuid
import shutil
from pathlib import Path
from typing import List, Optional
from fastapi import (
    APIRouter,
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
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from backend.database import get_db
from backend.models import User, Document, DocumentPermission
from backend.schemas import DocumentResponse, DocumentMetadataUpdate
from backend.config import STORAGE_DIR, MAX_FILE_SIZE_BYTES, MAX_FILE_SIZE_MB
from backend.security import compute_sha256_stream
from backend.dependencies import (
    get_current_user,
    require_roles,
    get_client_ip,
    get_effective_permission,
    verify_document_access
)
from backend.audit import (
    record_audit_event,
    ACTION_UPLOAD,
    ACTION_DOWNLOAD,
    ACTION_EDIT,
    ACTION_DELETE
)

router = APIRouter(
    prefix="/documents",
    tags=["Documents"]
)


def build_document_response(doc: Document, effective_permission: Optional[str]) -> DocumentResponse:
    """Helper to convert Document ORM model to Pydantic DocumentResponse."""
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


@router.post(
    "/upload",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Securely upload a new document"
)
async def upload_document(
    request: Request,
    file: UploadFile = File(..., description="Document file to upload (max 10MB)"),
    category: Optional[str] = Form(None, description="Optional document category tag"),
    current_user: User = Depends(require_roles("admin", "owner")),
    db: Session = Depends(get_db)
):
    """
    Secure document upload:
    - Restricts upload to Admin and Owner roles.
    - Validates file size against MAX_FILE_SIZE_MB limit (10MB).
    - Stores file outside web root using a secure UUID storage key.
    - Computes and registers cryptographic SHA-256 checksum.
    - Records immutable UPLOAD audit event with SHA-256 hash chaining.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required"
        )

    # Sanitize original filename (remove directory path components)
    original_filename = Path(file.filename).name
    storage_key = f"{uuid.uuid4().hex}.vault"
    destination_path = STORAGE_DIR / storage_key

    # Stream file to disk while validating size and computing SHA-256
    size_bytes = 0
    try:
        with open(destination_path, "wb") as buffer:
            while chunk := await file.read(65536):
                size_bytes += len(chunk)
                if size_bytes > MAX_FILE_SIZE_BYTES:
                    # File exceeds limit - abort and remove partial file
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to securely write document: {str(e)}"
        )

    if size_bytes == 0:
        if destination_path.exists():
            destination_path.unlink()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot upload an empty file"
        )

    # Compute SHA-256 checksum of saved file
    with open(destination_path, "rb") as f:
        checksum_sha256 = compute_sha256_stream(f)

    # Create document record
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

    # Record tamper-evident audit log
    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_UPLOAD,
        actor_id=current_user.id,
        document_id=doc.id,
        details=(
            f"Uploaded document '{original_filename}' ({size_bytes} bytes). "
            f"Category: '{doc.category or 'None'}'. SHA256: {checksum_sha256}"
        ),
        ip_address=client_ip
    )

    effective_perm = "owner" if current_user.role != "admin" else "admin"
    return build_document_response(doc, effective_perm)


@router.get(
    "",
    response_model=List[DocumentResponse],
    summary="Search and list accessible documents"
)
def list_documents(
    query: Optional[str] = Query(None, description="Search term for filename or category"),
    category: Optional[str] = Query(None, description="Filter by category"),
    scope: str = Query("all", description="Scope: 'all', 'owned', or 'shared'"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Search and retrieve documents accessible to current user:
    - Admin: can inspect all active documents.
    - Owner: can see owned documents and documents shared with them.
    - Viewer: can only see documents explicitly shared with them.
    """
    base_query = db.query(Document).filter(Document.is_deleted == False)

    # Role-based access scoping
    if current_user.role == "admin":
        if scope == "owned":
            base_query = base_query.filter(Document.owner_id == current_user.id)
        elif scope == "shared":
            shared_ids = [
                p.document_id for p in db.query(DocumentPermission.document_id).filter(
                    DocumentPermission.user_id == current_user.id
                ).all()
            ]
            base_query = base_query.filter(Document.id.in_(shared_ids))

    elif current_user.role == "owner":
        shared_ids = [
            p.document_id for p in db.query(DocumentPermission.document_id).filter(
                DocumentPermission.user_id == current_user.id
            ).all()
        ]
        if scope == "owned":
            base_query = base_query.filter(Document.owner_id == current_user.id)
        elif scope == "shared":
            base_query = base_query.filter(Document.id.in_(shared_ids))
        else:
            base_query = base_query.filter(
                or_(
                    Document.owner_id == current_user.id,
                    Document.id.in_(shared_ids)
                )
            )

    else:  # Viewer
        shared_ids = [
            p.document_id for p in db.query(DocumentPermission.document_id).filter(
                DocumentPermission.user_id == current_user.id
            ).all()
        ]
        base_query = base_query.filter(Document.id.in_(shared_ids))

    # Apply search query
    if query:
        search_filter = f"%{query}%"
        base_query = base_query.filter(
            or_(
                Document.original_filename.ilike(search_filter),
                Document.category.ilike(search_filter)
            )
        )

    # Apply category filter
    if category:
        base_query = base_query.filter(Document.category == category)

    docs = base_query.order_by(desc(Document.updated_at)).offset(offset).limit(limit).all()

    response = []
    for doc in docs:
        eff_perm = get_effective_permission(db, current_user, doc)
        response.append(build_document_response(doc, eff_perm))

    return response


@router.get(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Get document metadata and effective permissions"
)
def get_document_details(
    document_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves document details if user has read permission."""
    doc, eff_perm = verify_document_access(
        document_id=document_id,
        required_level="read",
        current_user=current_user,
        db=db,
        request=request
    )
    return build_document_response(doc, eff_perm)


@router.get(
    "/{document_id}/download",
    summary="Securely download document with cryptographic integrity verification"
)
def download_document(
    document_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Secure document download:
    - Verifies user authorization (Owner, Admin, or shared user).
    - Verifies file presence on disk.
    - Recalculates SHA-256 checksum to ensure file was not corrupted or tampered on disk.
    - Streams file safely with appropriate Content-Disposition header.
    - Records tamper-evident DOWNLOAD audit event.
    """
    doc, eff_perm = verify_document_access(
        document_id=document_id,
        required_level="read",
        current_user=current_user,
        db=db,
        request=request
    )

    file_path = STORAGE_DIR / doc.storage_key
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The requested file was not found in storage"
        )

    # Pre-download SHA-256 integrity verification
    with open(file_path, "rb") as f:
        disk_checksum = compute_sha256_stream(f)

    if disk_checksum != doc.checksum_sha256:
        # Integrity breach detected on disk!
        client_ip = get_client_ip(request)
        record_audit_event(
            db=db,
            action=ACTION_ACCESS_DENIED,
            actor_id=current_user.id,
            document_id=doc.id,
            details=(
                f"INTEGRITY VIOLATION DETECTED: File '{doc.original_filename}' storage checksum "
                f"'{disk_checksum}' does not match registered checksum '{doc.checksum_sha256}'."
            ),
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security error: Cryptographic file integrity check failed. The file on disk has been corrupted or tampered."
        )

    # Record download audit event
    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_DOWNLOAD,
        actor_id=current_user.id,
        document_id=doc.id,
        details=f"Downloaded file '{doc.original_filename}' ({doc.size_bytes} bytes). Integrity verified (SHA-256: {doc.checksum_sha256[:16]}...).",
        ip_address=client_ip
    )

    return FileResponse(
        path=file_path,
        media_type=doc.content_type,
        filename=doc.original_filename
    )


@router.put(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Update document metadata (filename, category)"
)
def update_document_metadata(
    document_id: int,
    metadata: DocumentMetadataUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Updates document metadata:
    - Requires Owner, Admin, or collaborator with 'edit' access.
    - Records EDIT audit log entry.
    """
    doc, eff_perm = verify_document_access(
        document_id=document_id,
        required_level="edit",
        current_user=current_user,
        db=db,
        request=request
    )

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

    return build_document_response(doc, eff_perm)


@router.put(
    "/{document_id}/content",
    response_model=DocumentResponse,
    summary="Replace document file content (version update)"
)
async def update_document_content(
    document_id: int,
    request: Request,
    file: UploadFile = File(..., description="Replacement document file (max 10MB)"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Replaces existing file content for a document:
    - Requires Owner, Admin, or collaborator with 'edit' access.
    - Replaces file on disk and recomputes SHA-256 checksum.
    - Records EDIT audit log entry.
    """
    doc, eff_perm = verify_document_access(
        document_id=document_id,
        required_level="edit",
        current_user=current_user,
        db=db,
        request=request
    )

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
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE_MB}MB"
                    )
                buffer.write(chunk)
    except Exception as e:
        if backup_path.exists():
            shutil.copyfile(backup_path, file_path)
            backup_path.unlink()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update document content: {str(e)}"
        )

    if backup_path.exists():
        backup_path.unlink()

    # Compute new checksum
    with open(file_path, "rb") as f:
        new_checksum = compute_sha256_stream(f)

    old_checksum = doc.checksum_sha256
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
        details=(
            f"Updated file content ({size_bytes} bytes). "
            f"Checksum updated from {old_checksum[:16]}... to {new_checksum[:16]}..."
        ),
        ip_address=client_ip
    )

    return build_document_response(doc, eff_perm)


@router.delete(
    "/{document_id}",
    summary="Soft-delete document"
)
def delete_document(
    document_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Soft-deletes a document:
    - Only Document Owner or Admin can delete.
    - Retains audit history and marks is_deleted=True.
    - Records DELETE audit event.
    """
    doc, eff_perm = verify_document_access(
        document_id=document_id,
        required_level="owner_or_admin",
        current_user=current_user,
        db=db,
        request=request
    )

    doc.is_deleted = True
    db.commit()

    client_ip = get_client_ip(request)
    record_audit_event(
        db=db,
        action=ACTION_DELETE,
        actor_id=current_user.id,
        document_id=doc.id,
        details=f"Document '{doc.original_filename}' (ID: {doc.id}) soft-deleted by {current_user.email}.",
        ip_address=client_ip
    )

    return {"message": f"Document '{doc.original_filename}' deleted successfully"}
