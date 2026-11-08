"""Pytest fixtures and configuration for TrustVault test suite."""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.main import app
from backend.database import SessionLocal, seed_database
from backend.models import User, Document, DocumentPermission, AuditLog


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Ensures database has demo users and sample document seeded before tests run."""
    seed_database(create_sample_doc=True)
    yield


@pytest.fixture(scope="function")
def db_session():
    """Provides a fresh database session for a test function."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def client():
    """Provides a FastAPI test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def admin_token(client):
    """Logs in as admin and returns JWT Bearer token."""
    response = client.post(
        "/auth/login",
        json={"email": "admin@trustvault.com", "password": "TrustVaultAdmin2026!"}
    )
    assert response.status_code == 200, f"Admin login failed: {response.text}"
    return response.json()["access_token"]


@pytest.fixture(scope="module")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="module")
def owner_token(client):
    """Logs in as owner and returns JWT Bearer token."""
    response = client.post(
        "/auth/login",
        json={"email": "owner@trustvault.com", "password": "TrustVaultOwner2026!"}
    )
    assert response.status_code == 200, f"Owner login failed: {response.text}"
    return response.json()["access_token"]


@pytest.fixture(scope="module")
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture(scope="module")
def viewer_token(client):
    """Logs in as viewer and returns JWT Bearer token."""
    response = client.post(
        "/auth/login",
        json={"email": "viewer@trustvault.com", "password": "TrustVaultViewer2026!"}
    )
    assert response.status_code == 200, f"Viewer login failed: {response.text}"
    return response.json()["access_token"]


@pytest.fixture(scope="module")
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}
