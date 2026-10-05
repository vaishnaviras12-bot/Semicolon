"""
API v1 Router Entry Point
=========================
Aggregates health, scans, and system info routers under /api/v1.
"""

from fastapi import APIRouter
from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.scans import router as scans_router
from backend.app.api.v1.auth import router as auth_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(scans_router)
api_router.include_router(auth_router)
