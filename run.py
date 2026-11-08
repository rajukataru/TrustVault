"""TrustVault Unified Platform Launcher.

Supports running FastAPI Backend, Streamlit Frontend, automated tests, and database seeding.

Usage:
    python run.py             # Launches both Backend and Streamlit Frontend
    python run.py --backend   # Launches FastAPI backend only (port 8000)
    python run.py --frontend  # Launches Streamlit frontend only (port 8501)
    python run.py --seed      # Seeds demo users and sample document
    python run.py --test      # Runs full pytest test suite
"""

import sys
import os
import time
import subprocess
import webbrowser
import argparse
from pathlib import Path

# Safe Unicode output on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

PYTHON_EXEC = sys.executable


def run_seed():
    """Runs database seeder."""
    print("[*] Running TrustVault database seeder...")
    subprocess.run([PYTHON_EXEC, "-m", "backend.seed"], cwd=str(PROJECT_ROOT))


def run_tests():
    """Runs automated pytest suite."""
    print("[*] Running automated test suite with pytest...")
    subprocess.run([PYTHON_EXEC, "-m", "pytest", "-v", "tests"], cwd=str(PROJECT_ROOT))


def run_backend(port: int = 8000):
    """Runs FastAPI backend with uvicorn."""
    import uvicorn
    print(f"[*] Launching TrustVault FastAPI backend on http://127.0.0.1:{port}...")
    print(f"[*] Swagger Documentation: http://127.0.0.1:{port}/docs")
    uvicorn.run("backend.main:app", host="127.0.0.1", port=port, reload=False)


def run_frontend(port: int = 8501):
    """Runs Streamlit frontend."""
    frontend_app = PROJECT_ROOT / "frontend" / "app.py"
    print(f"[*] Launching TrustVault Streamlit frontend on http://127.0.0.1:{port}...")
    subprocess.run(
        [
            PYTHON_EXEC,
            "-m",
            "streamlit",
            "run",
            str(frontend_app),
            "--server.port",
            str(port),
            "--server.headless",
            "false"
        ],
        cwd=str(PROJECT_ROOT)
    )


def run_all():
    """Launches both backend and frontend concurrently."""
    print("=" * 60)
    print("TrustVault - Secure Document Sharing Platform")
    print("=" * 60)

    # Launch Backend as subprocess
    backend_proc = subprocess.Popen(
        [
            PYTHON_EXEC,
            "-m",
            "uvicorn",
            "backend.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000"
        ],
        cwd=str(PROJECT_ROOT)
    )

    time.sleep(2)

    # Open Swagger Docs and Streamlit Frontend
    def open_browser():
        time.sleep(2)
        webbrowser.open("http://127.0.0.1:8501")
        webbrowser.open("http://127.0.0.1:8000/docs")

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    try:
        run_frontend(port=8501)
    finally:
        print("\nStopping backend server...")
        backend_proc.terminate()
        backend_proc.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TrustVault Platform Launcher")
    parser.add_argument("--backend", action="store_true", help="Launch FastAPI backend only")
    parser.add_argument("--frontend", action="store_true", help="Launch Streamlit frontend only")
    parser.add_argument("--seed", action="store_true", help="Seed database with demo accounts")
    parser.add_argument("--test", action="store_true", help="Run automated test suite")
    args = parser.parse_args()

    if args.seed:
        run_seed()
    elif args.test:
        run_tests()
    elif args.backend:
        run_backend()
    elif args.frontend:
        run_frontend()
    else:
        run_all()
