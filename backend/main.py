"""FastAPI Application entrypoint for TrustVault."""

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from backend.database import engine, SessionLocal
from backend.config import STORAGE_DIR
from backend.audit import verify_audit_chain
from backend.auth import router as auth_router
from backend.documents import router as documents_router
from backend.sharing import router as sharing_router
from backend.users import router as users_router
from backend.audit_routes import router as audit_router

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

# Enable CORS for frontend clients (Streamlit, React, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth_router)
app.include_router(documents_router)
app.include_router(sharing_router)
app.include_router(users_router)
app.include_router(audit_router)


@app.get(
    "/",
    tags=["General"],
    summary="Root Welcome endpoint"
)
def root():
    return {
        "platform": "TrustVault",
        "description": "Secure Document Sharing Platform",
        "version": "1.0.0",
        "documentation": "/docs",
        "status": "Operational"
    }


@app.get(
    "/health",
    tags=["General"],
    summary="System and Database Health Check"
)
def health_check():
    """Performs deep health checks: MySQL connectivity, storage system, and audit integrity."""
    health_status = {
        "api": "Online",
        "database": "Disconnected",
        "storage": "Unavailable",
        "audit_chain": "Unknown"
    }

    # 1. Database Check
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        health_status["database"] = "Connected"
    except Exception as e:
        health_status["database"] = f"Error: {str(e)}"
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=health_status
        )

    # 2. Storage Directory Check
    if STORAGE_DIR.exists() and STORAGE_DIR.is_dir():
        health_status["storage"] = "Accessible"
    else:
        health_status["storage"] = "Missing"

    # 3. Audit Log Chain Quick Integrity Check
    db = SessionLocal()
    try:
        verification = verify_audit_chain(db)
        health_status["audit_chain"] = "Valid" if verification["is_valid"] else "TAMPER_DETECTED"
    except Exception:
        health_status["audit_chain"] = "Error checking"
    finally:
        db.close()

    return health_status
