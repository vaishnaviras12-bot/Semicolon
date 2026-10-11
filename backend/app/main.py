"""
FastAPI Main Application Entry Point
====================================
Configures CORS middleware, initializes database schemas, registers API routers,
and exposes OpenAPI documentation.
"""

import os
import sys
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse

# Add PakkaSemicolon root directory to sys.path
_ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
if _ROOT_PATH not in sys.path:
    sys.path.insert(0, _ROOT_PATH)

from backend.app.config import settings
from backend.app.database.connection import engine, Base
from backend.app.database.migrations import run_schema_migrations
from backend.app.api.router import api_router

import logging
from sqlalchemy import text

logger = logging.getLogger("ecdat.main")

# Initialize Database Schema & Migrations
Base.metadata.create_all(bind=engine)
run_schema_migrations(engine, Base)

def _log_pqc_startup_status():
    try:
        from backend.app.services.pqc_prototype_service import get_pqc_environment_diagnostics
        diag = get_pqc_environment_diagnostics()
        if diag.get("oqs_available"):
            logger.info(
                f"[ECDAT PQC Readiness] liboqs native library is READY: "
                f"ML-DSA-65={diag.get('ml_dsa_65_supported')}, "
                f"ML-KEM-768={diag.get('ml_kem_768_supported')}, "
                f"Enabled Signatures={len(diag.get('enabled_signature_mechanisms', []))}, "
                f"Enabled KEMs={len(diag.get('enabled_kem_mechanisms', []))} "
                f"({diag.get('operating_system')} {diag.get('cpu_architecture')})"
            )
        else:
            logger.warning(
                f"[ECDAT PQC Readiness] liboqs native library is UNAVAILABLE: "
                f"{diag.get('unavailability_reason')}. "
                f"Set OQS_INSTALL_PATH or compile native liboqs."
            )
    except Exception as e:
        logger.warning(f"[ECDAT PQC Readiness] Failed to inspect liboqs status: {e}")

_log_pqc_startup_status()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Comprehensive Cryptographic Bill of Materials (CBOM) & Post-Quantum Cryptography Readiness Engine",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers under /api/v1 and /api for compatibility
app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(api_router, prefix="/api")

# Determine path to production React dist folder
_FRONTEND_DIST_DIR = os.path.abspath(os.path.join(_ROOT_PATH, "ecdat-app-final-original-video-fixit/dist"))

if os.path.exists(os.path.join(_FRONTEND_DIST_DIR, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(_FRONTEND_DIST_DIR, "assets")), name="assets")

@app.get("/{full_path:path}")
async def serve_spa_or_static(full_path: str):
    # 1. Allow API routes, docs, redoc, openapi to return JSON 404 if unhandled
    clean_path = full_path.lstrip("/")
    if clean_path == "api" or clean_path.startswith("api/") or full_path in ("docs", "redoc", "openapi.json"):
        raise HTTPException(status_code=404, detail="API route not found")
    
    # 2. Secure static file resolving & path traversal prevention
    real_dist = os.path.realpath(_FRONTEND_DIST_DIR)
    
    if full_path:
        requested_target = os.path.join(_FRONTEND_DIST_DIR, full_path)
        real_target = os.path.realpath(requested_target)
        
        # Verify real_target is strictly inside real_dist directory
        try:
            is_inside = os.path.commonpath([real_target, real_dist]) == real_dist
        except ValueError:
            is_inside = False

        # Check for dotfiles / hidden files in relative path
        rel_path = os.path.relpath(real_target, real_dist)
        has_dotfile = any(part.startswith(".") for part in rel_path.split(os.sep))
        
        if is_inside and not has_dotfile and os.path.isfile(real_target):
            return FileResponse(real_target)
    
    # 3. SPA Fallback: Return React index.html for all frontend routes (/dashboard, /scanner, /reports, /remediator, etc.)
    index_file = os.path.join(_FRONTEND_DIST_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    
    return HTMLResponse(
        "<h1>ECDAT CBOM Platform</h1>"
        "<p>Frontend build not found. Please run <code>npm run build</code> in ecdat-app-final-original-video-fixit.</p>"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
