"""
Health & System Capability Endpoints
====================================
Provides system capability parameters, health checks, and detector statuses.
"""

from fastapi import APIRouter
from backend.app.database.connection import mongo_db
from backend.app.schemas.scan import SystemInfo

router = APIRouter(tags=["health"])

@router.get("/health")
def health_check():
    return {"status": "ok", "service": "ECDAT PQC CBOM Engine"}

@router.get("/system/info", response_model=SystemInfo)
def system_info():
    return SystemInfo(
        version="1.0.0",
        status="healthy",
        scanners_available=[
            "python", "java", "javascript", "c_cpp", "tree_sitter", "semgrep",
            "certificate", "protocol", "docker", "container", "binary", "dependency",
            "cloud_iac", "hardware_hsm"
        ],
        tree_sitter_enabled=True,
        docker_enabled=False,
        postgres_connected=True,
        mongodb_connected=mongo_db is not None,
    )
