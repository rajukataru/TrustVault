"""Tests for Document upload, download, metadata search, and management."""

import io
import pytest


def test_document_upload_success(client, owner_headers):
    """Verify document upload saves file, calculates SHA-256, and returns metadata."""
    file_content = b"Financial Q4 Report - TrustVault Confidential Data"
    files = {
        "file": ("financial_q4.txt", io.BytesIO(file_content), "text/plain")
    }
    data = {"category": "Finance"}

    response = client.post(
        "/documents/upload",
        files=files,
        data=data,
        headers=owner_headers
    )
    assert response.status_code == 201
    doc = response.json()
    assert doc["original_filename"] == "financial_q4.txt"
    assert doc["category"] == "Finance"
    assert doc["size_bytes"] == len(file_content)
    assert len(doc["checksum_sha256"]) == 64
    assert doc["effective_permission"] == "owner"


def test_document_upload_empty_file_rejected(client, owner_headers):
    """Verify that uploading an empty file is rejected with 400 Bad Request."""
    files = {
        "file": ("empty.txt", io.BytesIO(b""), "text/plain")
    }
    response = client.post("/documents/upload", files=files, headers=owner_headers)
    assert response.status_code == 400
    assert "empty file" in response.json()["detail"].lower()


def test_list_documents_rbac_filtering(client, owner_headers, viewer_headers, admin_headers):
    """Verify list documents filters correctly based on user roles and permissions."""
    # Admin sees all documents
    admin_res = client.get("/documents", headers=admin_headers)
    assert admin_res.status_code == 200
    admin_docs = admin_res.json()
    assert len(admin_docs) >= 1

    # Owner sees their documents
    owner_res = client.get("/documents", headers=owner_headers)
    assert owner_res.status_code == 200
    owner_docs = owner_res.json()
    assert len(owner_docs) >= 1

    # Viewer sees only shared documents
    viewer_res = client.get("/documents", headers=viewer_headers)
    assert viewer_res.status_code == 200
    viewer_docs = viewer_res.json()
    assert all(d["effective_permission"] in ("read", "edit") for d in viewer_docs)


def test_document_search_by_category_and_name(client, owner_headers):
    """Verify document search filters by filename and category."""
    response = client.get("/documents?query=Security&category=Confidential", headers=owner_headers)
    assert response.status_code == 200
    docs = response.json()
    for d in docs:
        assert "security" in d["original_filename"].lower() or d["category"] == "Confidential"


def test_document_download_success(client, owner_headers):
    """Verify downloading a document returns file content and correct headers."""
    # Find a document owned by owner
    list_res = client.get("/documents?scope=owned", headers=owner_headers)
    assert list_res.status_code == 200
    docs = list_res.json()
    assert len(docs) > 0
    doc_id = docs[0]["id"]

    download_res = client.get(f"/documents/{doc_id}/download", headers=owner_headers)
    assert download_res.status_code == 200
    assert len(download_res.content) == docs[0]["size_bytes"]


def test_document_metadata_update(client, owner_headers):
    """Verify updating document metadata (filename, category)."""
    list_res = client.get("/documents?scope=owned", headers=owner_headers)
    doc_id = list_res.json()[0]["id"]

    update_payload = {
        "original_filename": "Updated_Document_Title.txt",
        "category": "UpdatedCategory"
    }
    put_res = client.put(f"/documents/{doc_id}", json=update_payload, headers=owner_headers)
    assert put_res.status_code == 200
    updated_doc = put_res.json()
    assert updated_doc["original_filename"] == "Updated_Document_Title.txt"
    assert updated_doc["category"] == "UpdatedCategory"
