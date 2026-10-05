"""
Backend Configuration Settings
==============================
Manages environment parameters, database URIs, file upload boundaries, CORS origins,
and PQC planning horizon settings via Pydantic Settings.
"""

import os
from typing import List
from pydantic_settings import BaseSettings

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

def _resolve_database_url() -> str:
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        if env_url.startswith("sqlite:///"):
            path_part = env_url[len("sqlite:///"):].strip()
            if not os.path.isabs(path_part.lstrip("./").lstrip(".\\")):
                db_name = os.path.basename(path_part) or "ecdat_pqc.db"
                abs_db_path = os.path.abspath(os.path.join(_PROJECT_ROOT, db_name)).replace("\\", "/")
                return f"sqlite:///{abs_db_path}"
        return env_url
    default_abs_db = os.path.abspath(os.path.join(_PROJECT_ROOT, "ecdat_pqc.db")).replace("\\", "/")
    return f"sqlite:///{default_abs_db}"

class Settings(BaseSettings):
    PROJECT_NAME: str = "ECDAT PQC CBOM Engine"
    API_V1_STR: str = "/api/v1"
    
    # Database URIs
    DATABASE_URL: str = _resolve_database_url()
    MONGODB_URL: str = os.getenv("MONGO_URI", os.getenv("MONGODB_URL", "mongodb://localhost:27017"))
    MONGODB_DATABASE: str = os.getenv("MONGODB_DATABASE", "ecdat_cbom")

    # Security & File Limits
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "./workspace_scans")
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "200"))
    
    JWT_SECRET: str = os.getenv("JWT_SECRET", "ecdat-pqc-cbom-secret-key-2026-super-secure-32bytes")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_HOURS: int = 24
    
    # CORS Origins
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000"
    ]

    # Mosca & Risk Planning Horizons
    REFERENCE_YEAR: int = int(os.getenv("REFERENCE_YEAR", "2026"))
    Q_DAY_PLANNING_YEAR: int = int(os.getenv("Q_DAY_PLANNING_YEAR", "2035"))
    QDAY_P25: int = int(os.getenv("QDAY_P25", "8"))
    QDAY_P50: int = int(os.getenv("QDAY_P50", "13"))
    QDAY_P75: int = int(os.getenv("QDAY_P75", "21"))

    # SMTP & Password Reset Settings
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: str | None = os.getenv("SMTP_USERNAME", None)
    SMTP_PASSWORD: str | None = os.getenv("SMTP_PASSWORD", None)
    SMTP_FROM: str | None = os.getenv("SMTP_FROM", None)
    FRONTEND_BASE_URL: str = os.getenv("FRONTEND_BASE_URL", "http://localhost:8000")
    PASSWORD_RESET_EXPIRE_MINUTES: int = int(os.getenv("PASSWORD_RESET_EXPIRE_MINUTES", "10"))
    PASSWORD_RESET_MAX_ATTEMPTS: int = int(os.getenv("PASSWORD_RESET_MAX_ATTEMPTS", "5"))
    PASSWORD_RESET_RESEND_COOLDOWN_SECONDS: int = int(os.getenv("PASSWORD_RESET_RESEND_COOLDOWN_SECONDS", "60"))

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
