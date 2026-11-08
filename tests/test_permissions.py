"""Tests for Granular Permissions, Sharing, Revocation, and RBAC enforcement."""

import io
import pytest


def test_viewer_upload_forbidden(client, viewer_headers):
    """Verify viewers cannot upload documents directly (enforces RBAC)."""
    files = {
        "file": ("unauthorized.txt", io.BytesIO(b"Unauthorized data"), "text/plain")
    }
    response = client.post("/documents/upload", files=files, headers=viewer_headers)
    assert response.status_code == 403
    assert "access denied" in response.json()["detail"].lower()


def test_share_document_with_viewer(client, owner_headers, viewer_headers):
    """Verify owner can share a document with viewer and viewer can access it."""
    # 1. Owner uploads a new test document
    files = {
        "file": ("contract_agreement.txt", io.BytesIO(b"Signed NDA Agreement 2026"), "text/plain")
    }
    up_res = client.post("/documents/upload", files=files, headers=owner_headers)
    assert up_res.status_code == 201
    doc_id = up_res.json()["id"]

    # 2. Before sharing, viewer cannot access the document
    get_before = client.get(f"/documents/{doc_id}", headers=viewer_headers)
    assert get_before.status_code == 403

    # 3. Owner shares document with viewer (read permission)
    share_payload = {
        "user_email": "viewer@trustvault.com",
        "access_level": "read"
    }
    share_res = client.post(
        f"/documents/{doc_id}/permissions",
        json=share_payload,
        headers=owner_headers
    )
    assert share_res.status_code == 201
    perm_data = share_res.json()
    assert perm_data["access_level"] == "read"
    assert perm_data["user_email"] == "viewer@trustvault.com"

    # 4. Now viewer can read and download
    get_after = client.get(f"/documents/{doc_id}", headers=viewer_headers)
    assert get_after.status_code == 200
    assert get_after.json()["effective_permission"] == "read"

    dl_res = client.get(f"/documents/{doc_id}/download", headers=viewer_headers)
    assert dl_res.status_code == 200
    assert dl_res.content == b"Signed NDA Agreement 2026"

    # 5. Viewer cannot edit since they only have 'read' permission
    edit_res = client.put(
        f"/documents/{doc_id}",
        json={"original_filename": "Malicious_Rename.txt"},
        headers=viewer_headers
    )
    assert edit_res.status_code == 403

    # 6. Owner upgrades permission to 'edit'
    upgrade_res = client.post(
        f"/documents/{doc_id}/permissions",
        json={"user_email": "viewer@trustvault.com", "access_level": "edit"},
        headers=owner_headers
    )
    assert upgrade_res.status_code == 201
    assert upgrade_res.json()["access_level"] == "edit"

    # 7. Viewer can now edit
    edit_res2 = client.put(
        f"/documents/{doc_id}",
        json={"original_filename": "Authorized_Edit_By_Viewer.txt"},
        headers=viewer_headers
    )
    assert edit_res2.status_code == 200
    assert edit_res2.json()["original_filename"] == "Authorized_Edit_By_Viewer.txt"

    # 8. Owner revokes viewer permission
    list_perms = client.get(f"/documents/{doc_id}/permissions", headers=owner_headers)
    # Find viewer's permission entry
    viewer_perms = [p for p in list_perms.json() if p["user_email"] == "viewer@trustvault.com"]
    assert len(viewer_perms) > 0
    viewer_user_id = viewer_perms[0]["user_id"]

    revoke_res = client.delete(
        f"/documents/{doc_id}/permissions/{viewer_user_id}",
        headers=owner_headers
    )
    assert revoke_res.status_code == 200

    # 9. Viewer is now blocked again
    final_get = client.get(f"/documents/{doc_id}", headers=viewer_headers)
    assert final_get.status_code == 403


def test_cannot_share_with_self(client, owner_headers):
    """Verify owner cannot grant sharing permission to themselves."""
    list_res = client.get("/documents?scope=owned", headers=owner_headers)
    doc_id = list_res.json()[0]["id"]

    res = client.post(
        f"/documents/{doc_id}/permissions",
        json={"user_email": "owner@trustvault.com", "access_level": "read"},
        headers=owner_headers
    )
    assert res.status_code == 400
    assert "owner" in res.json()["detail"].lower()
