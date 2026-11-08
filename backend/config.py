import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory for the project (C:\Users\katar\TrustVault)
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"

# Load environment variables from .env
load_dotenv(ENV_FILE, override=True)

# Database Configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "mysql+pymysql://trustvault_app:TrustVault2026@localhost:3306/trustvault"
)

# Cryptographic and JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY") or os.getenv("JWT_SECRET")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        f"A strong SECRET_KEY (at least 32 characters) must be configured in {ENV_FILE}"
    )

ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
try:
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
except ValueError:
    ACCESS_TOKEN_EXPIRE_MINUTES = 30

# File Storage Configuration
STORAGE_PATH_STR = os.getenv("STORAGE_PATH", "storage/private")
STORAGE_DIR = Path(STORAGE_PATH_STR)
if not STORAGE_DIR.is_absolute():
    STORAGE_DIR = BASE_DIR / STORAGE_DIR

# Ensure storage directory exists
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

try:
    MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "10"))
except ValueError:
    MAX_FILE_SIZE_MB = 10

MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")
