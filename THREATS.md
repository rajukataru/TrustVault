# 🛡️ TrustVault Security Architecture & Threat Model (STRIDE)

This document outlines the comprehensive threat modeling and security mitigations implemented in **TrustVault**, structured according to the industry-standard **STRIDE** methodology (developed by Microsoft).

---

## 1. Threat Modeling Matrix (STRIDE)

| Threat Category | Potential Threat Vector | Severity | TrustVault Security Controls & Mitigations |
| :--- | :--- | :---: | :--- |
| **Spoofing** | Credential stuffing, dictionary attacks, stolen JWT tokens | **Critical** | - **Argon2id password hashing**: Memory-hard key derivation resistant to GPU/ASIC brute forcing.<br>- **JWT Tokens with HS256**: Cryptographically signed using a 64+ byte secret key; short 30-minute expiration.<br>- **Active account verification**: Immediate token rejection if an account is disabled. |
| **Tampering** | Modifying stored documents on disk | **High** | - **Pre-download SHA-256 verification**: The backend calculates the file's hash before streaming. If bytes on disk were tampered, the download is aborted with an integrity alert.<br>- **UUID Storage Keys**: File paths on disk use random UUIDv4 names isolated in `storage/private`, completely detached from client filenames. |
| **Tampering** | Altering, injecting, or deleting database audit logs | **Critical** | - **Tamper-Evident SHA-256 Hash Chaining**: Every log entry contains the cryptographic hash of the previous log and its own data.<br>- **One-Click & Automated Chain Verification**: Detects any altered row, missing sequence, or hash mismatch, identifying the exact record ID where tampering occurred. |
| **Repudiation** | Actor denies uploading, downloading, editing, or deleting a document | **High** | - **Immutable Comprehensive Audit Logging**: Every upload, download, metadata change, content replacement, permission grant, and deletion records the actor ID, target document ID, timestamp, and client IP.<br>- **Access Denied Auditing**: Even unauthorized access attempts are logged with client IP and attempted action. |
| **Information Disclosure** | Insecure direct object references (IDOR), unauthorized file access, path traversal | **Critical** | - **Rigid Path Traversal Guards**: Filenames are sanitized with `Path(filename).name`; all files are written strictly inside `storage/private` using UUID keys.<br>- **Strict Authorization on Every Document Route**: Every access requires ownership, admin privileges, or explicit row entry in `document_permissions`.<br>- **Role Scoping**: Viewers cannot list documents that have not been shared with them. |
| **Denial of Service** | Uploading massive files to exhaust server disk space | **Medium** | - **Streaming Size Limit Enforcement**: Upload stream inspects chunk sizes and terminates immediately if the file exceeds `MAX_FILE_SIZE_MB` (10MB), unlinking any partial file buffers.<br>- **Empty File Rejection**: 0-byte uploads are rejected. |
| **Elevation of Privilege** | Viewers attempting to upload files, share documents, or alter user roles | **Critical** | - **Role-Based Access Control (RBAC)**: Role checks (`admin`, `owner`, `viewer`) are enforced at the router dependency layer before business logic executes.<br>- **Access Level Separation**: `read` permission cannot modify document metadata or replace content; only `edit` permission or ownership permits updates.<br>- **Admin-Only Guard**: Only administrators can modify roles or deactivate accounts. |

---

## 2. In-Depth Cryptographic Analysis

### A. Argon2id Password Hashing
TrustVault utilizes **Argon2id** (via `passlib.context.CryptContext(schemes=["argon2"])`):
- **Why Argon2id?** Unlike legacy algorithms (MD5, SHA-1, SHA-256 without key stretching) or older KDFs (PBKDF2), Argon2 was the winner of the Password Hashing Competition (PHC). Argon2id provides hybrid defense against both side-channel cache attacks and memory-hard resistance against GPU/ASIC parallel password cracking.
- **Salting**: Generates unique, cryptographically random salts per password hash automatically.

### B. Pre-Download File Integrity Verification
A common vulnerability in document-sharing systems is file corruption or silent offline tampering by an attacker with filesystem access.
- Upon upload, TrustVault computes the streaming SHA-256 hash of the received bytes and stores it in `documents.checksum_sha256`.
- Prior to serving any download via `GET /documents/{id}/download`:
  1. The server reads the stored file in 64KB chunks.
  2. Computes the live SHA-256 checksum of the file on disk.
  3. Asserts `live_checksum == document.checksum_sha256`.
  4. If a mismatch occurs, streaming is blocked, an `ACCESS_DENIED` security alert is written to the audit log, and an HTTP 500 error is returned.

### C. Tamper-Evident SHA-256 Audit Hash Chaining
Audit logs are frequently targeted by malicious actors attempting to cover their tracks. TrustVault eliminates this vulnerability by chaining records sequentially:

$$\text{Record } 0: \quad \text{previous\_hash} = 0000000000000000000000000000000000000000000000000000000000000000$$
$$\text{Record } n: \quad \text{previous\_hash}_n = \text{entry\_hash}_{n-1}$$
$$\text{entry\_hash}_n = \text{SHA256}(\text{previous\_hash}_n \parallel \text{actor}_n \parallel \text{doc}_n \parallel \text{action}_n \parallel \text{details}_n \parallel \text{ip}_n \parallel \text{timestamp}_n)$$

#### Cryptographic Guarantee:
Because SHA-256 is collision-resistant and preimage-resistant:
1. Modifying any detail, timestamp, or actor in record $k$ alters $\text{entry\_hash}_k$.
2. This immediately breaks the linkage with $\text{previous\_hash}_{k+1}$.
3. Even if an attacker recomputes $\text{entry\_hash}_k$, they must recompute all subsequent hashes up to the tip of the chain—which will fail if signed external witnesses or immutable snapshots are used.
4. TrustVault's `verify_audit_chain()` verifies this chain from Genesis to tip in $O(N)$ time.

---

## 3. Defense-in-Depth Implementation Checklist

- [x] **No Hardcoded Secrets**: Secrets and database credentials loaded via `.env` with fallback prevention.
- [x] **Safe Git Inclusion**: Comprehensive `.gitignore` protecting `.env`, `venv/`, and `storage/private/*`.
- [x] **Parameterized Queries**: SQLAlchemy 2.0 ORM prevents SQL injection across all database interactions.
- [x] **Input Validation**: Pydantic v2 schemas strictly validate emails, string bounds, and enum literals.
- [x] **Path Traversal Protection**: Stored files never use user-supplied names or relative path tokens.
- [x] **CORS Configuration**: Explicitly configured for local frontend communication.
- [x] **Automated Regression Testing**: 20 automated pytest tests including simulated database tampering.
