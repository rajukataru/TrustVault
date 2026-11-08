# 🔒 TrustVault — Secure Document-Sharing Platform

**Snovasys Fresher Hiring Challenge 2026**

TrustVault is an enterprise-grade, secure document-sharing platform engineered in Python with **FastAPI**, **Streamlit**, **MySQL**, **SQLAlchemy**, and cryptographic security best practices.

TrustVault guarantees document confidentiality, role-based access control (RBAC), file integrity verification, granular permission delegation, and **tamper-evident audit logging using SHA-256 cryptographic hash chaining**.

---

## 🌟 Key Highlights & Security Features

| Feature | Implementation | Security Benefit |
| :--- | :--- | :--- |
| **Password Hashing** | **Argon2id** (`argon2-cffi`, `passlib`) | State-of-the-art memory-hard hashing resistant to GPU/ASIC brute-force attacks |
| **Authentication** | **JWT (JSON Web Tokens)** with **HS256** | Stateless, signed bearer tokens with configurable expiration |
| **Access Control (RBAC)** | **Admin**, **Owner**, **Viewer** | Strict role-based permission checks on every API route and UI component |
| **Secure Storage** | UUID key isolation in `storage/private` | Prevents directory traversal attacks; original filenames never touch the disk |
| **File Integrity** | Streaming **SHA-256 checksums** | Verified upon upload and re-verified **before every download** to detect file tampering |
| **Granular Sharing** | Per-document **Read** / **Edit** grants | Document owners can grant or revoke collaborator access with 1 click |
| **Tamper-Evident Audit** | **SHA-256 Hash Chaining** | Blockchain-style sequential hash links guarantee non-repudiation and instant tamper detection |
| **Access Denial Logging** | Automatic `ACCESS_DENIED` audits | Every unauthorized read, edit, or download attempt is logged with IP and actor identity |
| **Interactive UI** | **Streamlit** multi-tab dashboard | Modern interface with quick demo logins, real-time vault stats, and hash chain visualizer |
| **OpenAPI Documentation**| **FastAPI Swagger UI** (`/docs`) | Complete interactive REST API playground with schema definitions and auth support |

---

## 🏛️ Architecture Overview

```
                      +-----------------------------+
                      |     Streamlit Frontend      |
                      |    (http://localhost:8501)  |
                      +--------------+--------------+
                                     |
                         HTTP REST API (JWT Bearer)
                                     |
                      +--------------v--------------+
                      |       FastAPI Backend       |
                      |    (http://localhost:8000)  |
                      +--------------+--------------+
                                     |
          +--------------------------+--------------------------+
          |                          |                          |
+---------v---------+      +---------v---------+      +---------v---------+
|   MySQL Database  |      |   Secure Storage  |      |  Cryptographic    |
| (Users, Metadata, |      | `storage/private` |      |   SHA-256 Chain   |
|   Permissions)    |      | (UUID keyed files)|      |   (Audit Logs)    |
+-------------------+      +-------------------+      +-------------------+
```

---

## 📁 Project Structure

```
TrustVault/
├── backend/
│   ├── __init__.py
│   ├── config.py              # Centralized environment configuration
│   ├── database.py            # SQLAlchemy engine, session maker, get_db dependency
│   ├── models.py              # User, Document, DocumentPermission, AuditLog ORM models
│   ├── schemas.py             # Pydantic request/response validation models
│   ├── security.py            # Argon2 password hashing, JWT creation/decoding, SHA-256 helpers
│   ├── audit.py               # SHA-256 hash chaining engine & integrity verification
│   ├── dependencies.py        # OAuth2 token authentication, RBAC, access-denied logging
│   ├── auth.py                # Registration, JSON/Form login, profile endpoints
│   ├── documents.py           # Upload (10MB limit), search, download, edit, delete
│   ├── sharing.py             # Granular permission grants, collaborator listing, revocation
│   ├── users.py               # Admin user management and collaborator lookup
│   ├── audit_routes.py        # Audit log explorer and cryptographic chain verification
│   ├── main.py                # FastAPI application entrypoint with CORS & health checks
│   └── seed.py                # Database seeder for demo accounts and sample document
├── frontend/
│   ├── __init__.py
│   ├── app.py                 # Streamlit multi-tab application
│   └── styles.py              # Custom CSS components, role badges, metric cards
├── storage/
│   └── private/               # Isolated storage for UUID-named documents
├── tests/
│   ├── __init__.py
│   ├── conftest.py            # Pytest test client and authentication fixtures
│   ├── test_auth.py           # Registration, Argon2 verification, JWT token tests
│   ├── test_documents.py      # Upload, search, download integrity, metadata edit tests
│   ├── test_permissions.py    # RBAC enforcement, sharing, edit access, revocation tests
│   └── test_audit_tamper.py   # Audit logging, SHA-256 chaining, simulated tamper detection
├── run.py                     # Unified platform launcher (CLI arguments supported)
├── requirements.txt           # Production dependencies list
├── README.md                  # Comprehensive platform documentation
├── THREATS.md                 # STRIDE threat model & security mitigation analysis
├── PROMPTS.md                 # Development journey & AI prompt log
├── .env.example               # Configuration template without secrets
└── .gitignore                 # Version control rules excluding secrets and virtual environments
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Python 3.11+** (Tested on Python 3.12)
- **MySQL Server 8.0+** running locally on port 3306

### 2. Database Setup (MySQL)
Log into your MySQL server as `root` and execute:

```sql
CREATE DATABASE IF NOT EXISTS trustvault CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'trustvault_app'@'localhost' IDENTIFIED BY 'TrustVault2026!';
GRANT ALL PRIVILEGES ON trustvault.* TO 'trustvault_app'@'localhost';
FLUSH PRIVILEGES;
```

### 3. Environment Configuration
Create a `.env` file in the project root:

```ini
DATABASE_URL=mysql+pymysql://trustvault_app:TrustVault2026@localhost:3306/trustvault
SECRET_KEY=OEMFYSP9aXVe2AAq8YcT5PRN3IzCRFs03jPWqsFHwn2Aoe15whwTdHQNGBf2PAQc
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
STORAGE_PATH=storage/private
MAX_FILE_SIZE_MB=10
API_URL=http://127.0.0.1:8000
```

### 4. Install Dependencies
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 5. Seed Demo Accounts
Run the database seeder to initialize the tables and seed evaluation accounts:

```powershell
python -m backend.seed
```

---

## 🔑 Demo Credentials

| Role | Email | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@trustvault.com` | `TrustVaultAdmin2026!` | Superuser: manage all documents, promote/demote users, view all audit logs, verify SHA-256 chain |
| **Owner** | `owner@trustvault.com` | `TrustVaultOwner2026!` | Upload files, manage owned documents, share with read/edit access, revoke permissions |
| **Viewer** | `viewer@trustvault.com` | `TrustVaultViewer2026!` | View and download documents shared with them; edit only if granted `edit` access |

> ⚡ **Tip**: In the Streamlit UI, use the **⚡ Quick Demo Login** tab to sign in with any of these roles with a single click!

---

## 🖥️ Running TrustVault

### Option 1: Unified Launcher (Recommended)
Launches the FastAPI backend and Streamlit frontend concurrently:

```powershell
python run.py
```
- **Streamlit Frontend**: [http://127.0.0.1:8501](http://127.0.0.1:8501)
- **FastAPI Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **FastAPI ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### Option 2: Individual Launchers
Run the backend only:
```powershell
python run.py --backend
```

Run the frontend only:
```powershell
python run.py --frontend
```

---

## 🧪 Automated Testing

TrustVault includes a comprehensive automated test suite with **20 unit and integration tests** covering all security features:

```powershell
pytest -v tests
```

### Test Coverage Highlights:
- **Argon2 Password Hashing**: Verifies salt uniqueness and verification rejection of wrong passwords.
- **Authentication**: User registration, duplicate email rejection (409), JWT creation, profile checks.
- **Document Management**: File upload with 10MB limit enforcement, pre-download SHA-256 verification, metadata updates.
- **Granular RBAC**: Viewer upload prohibition, document sharing with `read` permission, edit restriction, permission upgrade to `edit`, and revocation.
- **Audit Logging**: Uploads, downloads, edits, deletions, and `ACCESS_DENIED` security events.
- **Tamper-Evident Hash Chain**: Cryptographically tests that intentionally modifying an audit row in the database breaks the chain and is flagged as `TAMPER_DETECTED`.

---

## 🛡️ Tamper-Evident Audit Logging (Technical Specification)

TrustVault implements sequential cryptographic hash chaining:

1. **Genesis Entry**: The very first log record uses `previous_hash = "0" * 64`.
2. **Subsequent Entries**: Each new entry retrieves the `entry_hash` of the immediately preceding record as its `previous_hash`.
3. **Hash Calculation**:
   $$\text{entry\_hash} = \text{SHA256}(\text{previous\_hash} \parallel \text{actor\_id} \parallel \text{document\_id} \parallel \text{action} \parallel \text{details} \parallel \text{ip\_address} \parallel \text{created\_at})$$
4. **Verification Algorithm**:
   - Traverses the entire audit log in ascending sequence (`id ASC`).
   - Asserts that `record[i].previous_hash == record[i-1].entry_hash`.
   - Recomputes the SHA-256 digest from the record data and asserts equality with `record[i].entry_hash`.
   - If any discrepancy is found, returns the exact record ID where tampering occurred.

---

## 📜 License
Developed for the **Snovasys Fresher Hiring Challenge 2026**. All rights reserved.
