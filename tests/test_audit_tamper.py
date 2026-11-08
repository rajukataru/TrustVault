"""Tests for Audit Logging and SHA-256 Hash Chain Tamper-Evidence."""

import io
import pytest
from backend.models import AuditLog
from backend.audit import verify_audit_chain


def test_audit_logs_contain_key_actions(client, admin_headers):
    """Verify audit log records critical platform operations."""
    response = client.get("/audit/logs", headers=admin_headers)
    assert response.status_code == 200
    logs = response.json()
    assert len(logs) > 0

    actions = {log["action"] for log in logs}
    assert "USER_REGISTER" in actions or "LOGIN_SUCCESS" in actions
    for log in logs:
        assert len(log["entry_hash"]) == 64
        assert "created_at" in log


def test_access_denied_generates_audit_event(client, owner_headers, viewer_headers, admin_headers):
    """Verify unauthorized attempts produce an ACCESS_DENIED audit entry."""
    # 1. Owner creates a strictly private document
    files = {
        "file": ("top_secret_vault.txt", io.BytesIO(b"Confidential Executive Briefing"), "text/plain")
    }
    up_res = client.post("/documents/upload", files=files, headers=owner_headers)
    assert up_res.status_code == 201
    private_doc_id = up_res.json()["id"]

    # 2. Viewer attempts to access private document without permission
    denied_res = client.get(f"/documents/{private_doc_id}", headers=viewer_headers)
    assert denied_res.status_code == 403

    # 3. Check that ACCESS_DENIED is logged in the audit trail
    res = client.get(f"/audit/logs?action=ACCESS_DENIED&document_id={private_doc_id}", headers=admin_headers)
    assert res.status_code == 200
    denied_logs = res.json()
    assert len(denied_logs) >= 1
    assert denied_logs[0]["action"] == "ACCESS_DENIED"
    assert "access denied" in denied_logs[0]["details"].lower()


def test_audit_hash_chain_verification_endpoint(client, admin_headers):
    """Verify GET /audit/verify reports that the current SHA-256 chain is intact."""
    response = client.get("/audit/verify", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is True
    assert data["total_records"] > 0
    assert data["broken_at_id"] is None
    assert "verified successfully" in data["details"].lower()


def test_tamper_detection_on_database_modification(client, admin_headers, db_session):
    """
    CRITICAL CRYPTOGRAPHIC PROOF:
    Directly alters a row in MySQL audit_logs table without updating its SHA-256 hash.
    Proves that the tamper-evident hash chaining system detects the modification immediately!
    """
    # 1. Verify chain is initially valid
    initial_verify = client.get("/audit/verify", headers=admin_headers).json()
    assert initial_verify["is_valid"] is True

    # 2. Pick the latest audit log entry and tamper with it
    target_log = db_session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    assert target_log is not None
    original_details = target_log.details
    tampered_id = target_log.id

    try:
        # Simulate malicious database tampering by an attacker
        target_log.details = "MALICIOUSLY TAMPERED AUDIT LOG ENTRY!"
        db_session.commit()

        # 3. Verify that the tamper-evident check catches this modification
        tamper_verify = client.get("/audit/verify", headers=admin_headers).json()
        assert tamper_verify["is_valid"] is False, "Tampered log was NOT detected!"
        assert tamper_verify["broken_at_id"] == tampered_id
        assert "tamper detected" in tamper_verify["details"].lower()

    finally:
        # 4. Restore original log content to restore chain integrity
        target_log.details = original_details
        db_session.commit()

    # 5. Verify chain is valid again
    restored_verify = client.get("/audit/verify", headers=admin_headers).json()
    assert restored_verify["is_valid"] is True
