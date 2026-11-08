"""Tests for Authentication, Password Hashing, and JWT operations."""

import uuid
import pytest
from backend.security import hash_password, verify_password, decode_access_token


def test_argon2_password_hashing():
    """Verify that Argon2 hashing creates a valid salted hash and verifies correctly."""
    raw_password = "SuperSecretPassword2026!"
    hashed = hash_password(raw_password)

    assert hashed.startswith("$argon2"), f"Hash does not use Argon2: {hashed}"
    assert verify_password(raw_password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_user_registration_success(client):
    """Verify successful user registration with valid credentials."""
    unique_email = f"testuser_{uuid.uuid4().hex[:8]}@example.com"
    payload = {
        "name": "Test Candidate",
        "email": unique_email,
        "password": "ValidPassword2026!",
        "role": "viewer"
    }

    response = client.post("/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == unique_email
    assert data["name"] == "Test Candidate"
    assert data["role"] == "viewer"
    assert data["is_active"] is True
    assert "id" in data


def test_user_registration_duplicate_email(client):
    """Verify that registering with an existing email returns 409 Conflict."""
    payload = {
        "name": "Duplicate Admin",
        "email": "admin@trustvault.com",
        "password": "Password123456!",
        "role": "viewer"
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 409
    assert "already registered" in response.json()["detail"].lower()


def test_login_success(client):
    """Verify JSON authentication returns a valid JWT token."""
    response = client.post(
        "/auth/login",
        json={"email": "admin@trustvault.com", "password": "TrustVaultAdmin2026!"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "admin"

    # Decode and verify claims
    payload = decode_access_token(data["access_token"])
    assert payload["role"] == "admin"
    assert "sub" in payload
    assert "exp" in payload


def test_login_invalid_password(client):
    """Verify login failure with incorrect credentials returns 401."""
    response = client.post(
        "/auth/login",
        json={"email": "admin@trustvault.com", "password": "TotallyWrongPassword!"}
    )
    assert response.status_code == 401
    assert "invalid email or password" in response.json()["detail"].lower()


def test_get_current_user_profile(client, owner_headers):
    """Verify /auth/me returns current authenticated user details."""
    response = client.get("/auth/me", headers=owner_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "owner@trustvault.com"
    assert data["role"] == "owner"


def test_unauthenticated_request_rejected(client):
    """Verify endpoints requiring authentication reject unauthenticated requests."""
    response = client.get("/auth/me")
    assert response.status_code == 401
