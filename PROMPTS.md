# 📝 Development Journey & Prompts Log

**Project:** TrustVault — Secure Document-Sharing Platform  
**Challenge:** Snovasys Fresher Hiring Challenge 2026  
**Developer:** Antigravity AI Pair Programmer & Candidate  

---

## 1. Project Goal & Requirements Analysis

The objective was to engineer an enterprise-grade document sharing platform satisfying strict functional and security requirements:
- Python 3, FastAPI, Streamlit, MySQL, SQLAlchemy.
- Argon2 password hashing, JWT Bearer tokens.
- Three RBAC roles: Admin, Owner, and Viewer.
- Secure document upload, download, search, editing, and soft-deletion.
- Granular per-document sharing with `read` and `edit` permissions, plus instant revocation.
- Authorization verification on every route with automatic `ACCESS_DENIED` audit logging.
- Tamper-evident audit logging using SHA-256 sequential hash chaining.
- Professional Streamlit frontend & interactive FastAPI Swagger documentation.
- Automated test suite validating all security features.

---

## 2. Iterative Development & Prompt Engineering Log

### Phase 1: Environment & Codebase Inspection
- **User Prompt:** Inspect the existing TrustVault project without deleting working files or dropping database tables.
- **Key Inspection Findings:**
  - Database `trustvault` with 4 tables (`users`, `documents`, `document_permissions`, `audit_logs`) was initialized.
  - Core dependencies (`fastapi`, `uvicorn`, `streamlit`, `argon2-cffi`, `python-jose`, `passlib`, `pymysql`) were present in the virtual environment.
  - Discovered a critical import order dependency: importing `backend.security` directly failed with `RuntimeError: Set a strong SECRET_KEY in your .env file` because `load_dotenv` was only invoked inside `database.py`.
- **Architectural Solution:** Designed a centralized `backend/config.py` module responsible for validating and exporting all settings (`DATABASE_URL`, `SECRET_KEY`, `STORAGE_DIR`, `MAX_FILE_SIZE_BYTES`).

### Phase 2: Cryptographic Tamper-Evident Hash Chaining
- **Challenge:** Creating an unbroken, deterministic SHA-256 hash chain in a relational database.
- **Encountered Edge Case:** Microsecond mismatch between Python `datetime.utcnow()` and MySQL's default `DATETIME` column type. In Python, timestamps had fractional microseconds (e.g. `.123456`), but MySQL stored them with second precision (`.000000`). When reading records back to verify the chain, recomputed hashes differed!
- **Engineering Fix:** Truncated timestamps to second precision (`now = datetime.utcnow().replace(microsecond=0)`) and standardized formatting via `strftime("%Y-%m-%d %H:%M:%S")`.
- **Result:** 100% deterministic hash generation and verification across all database reads and writes.

### Phase 3: Granular RBAC & Document Management
- **Prompt:** Implement secure document upload, download, search, sharing, and revocation.
- **Key Engineering Decisions:**
  - Files are saved outside the web root in `storage/private` with random UUID names (`{uuid4().hex}.vault`). The original filename is kept solely in database metadata.
  - Size validation: Enforces `MAX_FILE_SIZE_MB = 10` during stream reading. If exceeded, the stream terminates and any partial buffer is immediately unlinked.
  - Pre-download integrity check: Recalculates SHA-256 before serving any file. If a file was tampered with on disk, download is halted with an integrity alert.
  - Authorization check on every document route: Reusable `verify_document_access()` function verifies role, ownership, or permission in `document_permissions`. If unauthorized, records an `ACCESS_DENIED` audit event with the caller's IP and raises HTTP 403.

### Phase 4: Automated Testing & Edge Cases
- **Prompt:** Create automated tests for all important features, run tests, and fix errors.
- **Test Discovery:**
  - Pytest initial run caught an issue: Pydantic's `EmailStr` (backed by `email-validator`) rejected `@trustvault.local` because `.local` is a reserved special-use top-level domain (RFC 6761).
  - Solution: Standardized all demo accounts and test fixtures to `@trustvault.com`.
- **Final Test Run:** 20 out of 20 tests passed cleanly in 2.32s, including tests proving that tampering with database records breaks the cryptographic hash chain.

### Phase 5: Professional Streamlit Frontend
- **Prompt:** Build a professional Streamlit frontend.
- **UI Architecture:**
  - Sleek modern styling with dark header banner and role-specific color badges.
  - Quick 1-Click Demo Login buttons for Admin, Owner, and Viewer roles.
  - Live metric cards (accessible documents, storage used, audit event count, hash chain integrity).
  - Document vault with search by filename and category filtering.
  - Drag-and-drop secure upload with instant SHA-256 display.
  - Collaborator and permission manager (grant read/edit, revoke).
  - Cryptographic hash chain verification panel with visual green/red status indicators.
  - Admin user management with role switching and activation toggle.

---

## 3. Key Decisions & Rationale Summary

| Decision | Rationale |
| :--- | :--- |
| **Centralized `backend/config.py`** | Eliminates order-dependent imports and guarantees consistent environment settings. |
| **Argon2id for Password Hashing** | Modern, memory-hard hashing resistant to GPU/ASIC attacks, far superior to plain SHA-256 or bcrypt. |
| **UUID Storage Keys** | Eliminates directory traversal (`../../`) and filename collision attacks. |
| **Pre-Download File Checksum** | Guarantees that documents served to users have not been altered on disk. |
| **Sequential SHA-256 Audit Chaining** | Provides mathematical tamper-evidence and non-repudiation for audit logs. |
| **Unified `run.py` Launcher** | Simplifies startup for recruiters and evaluators with a single command. |
