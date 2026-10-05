"""
Pydantic Schemas for API Contracts
===================================
Defines strongly typed input/output validation models for scan creation, status,
cryptographic inventory, risk engine outputs, Mosca parameters, recommendations, and reports.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_serializer

def serialize_utc_datetime(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class ScanCreate(BaseModel):
    project_name: Optional[str] = "Default Project"
    target_name: Optional[str] = "Uploaded Target"

class ScanStatus(BaseModel):
    scan_id: str
    status: str # queued | extracting | scanning | completed | failed
    stage: str
    progress_percentage: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    artifact_count: int = 0
    errors: Optional[List[str]] = None

    @field_serializer('created_at', 'completed_at', mode='plain')
    def serialize_dates(self, dt: Optional[datetime], _info) -> Optional[str]:
        return serialize_utc_datetime(dt)

class CryptoArtifact(BaseModel):
    id: str
    artifact_type: str
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    purpose: Optional[str] = None
    protocol: Optional[str] = None
    library: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    detection_method: str = "static_analysis"
    confidence: float = 0.8
    purpose_confidence: Optional[float] = 0.5
    resolution_status: Optional[str] = "resolved"
    detection_sources: Optional[List[str]] = None
    
    layer: str = "in_use"
    sensitivity: str = "moderate"
    exposure_type: str = "internal"
    
    shor_vulnerable: bool = False
    quantum_class: str = "unresolved"
    classically_weak: bool = False
    
    risk_score: float = 0.0
    risk_band: str = "safe"
    
    mosca_x: float = 5.0
    mosca_y: float = 0.5
    mosca_z: float = 9.0
    mosca_margin: float = 3.5
    mosca_status: str = "SAFE"
    hndl_relevant: bool = False
    
    migration_effort_hours: float = 16.0
    migration_effort_years: float = 0.1
    effort_level: str = "Medium"
    breaking_change_risk: str = "low"
    
    recommendation: Optional[Any] = None
    evidence: Optional[Any] = None

class ScanSummary(BaseModel):
    total_artifacts: int = 0
    shor_count: int = 0
    readiness_score: int = 100
    top_risk_band: str = "safe"
    band_counts: Dict[str, int] = Field(default_factory=lambda: {"critical": 0, "high": 0, "moderate": 0, "low": 0, "safe": 0})
    layer_counts: Dict[str, int] = Field(default_factory=lambda: {"in_transit": 0, "in_use": 0, "at_rest": 0})
    portfolio_mosca: Dict[str, Any] = Field(default_factory=dict)
    total_effort_hours: float = 0.0

class ScanResponse(BaseModel):
    scan_id: str
    project_name: str
    target_name: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    stage: str
    summary: ScanSummary

    @field_serializer('created_at', 'completed_at', mode='plain')
    def serialize_dates(self, dt: Optional[datetime], _info) -> Optional[str]:
        return serialize_utc_datetime(dt)

class RemediationStatusUpdate(BaseModel):
    status: str # pending | pr-drafted | merged
    choice: Optional[str] = "bridge" # bridge | full

class ReminderAckRequest(BaseModel):
    acknowledged: bool = True

class RemediationResponse(BaseModel):
    scan_id: str
    remediations: Dict[str, Dict[str, Any]]

class CBOMResponse(BaseModel):
    scan_id: str
    cbom: Dict[str, Any]

class SystemInfo(BaseModel):
    version: str = "1.0.0"
    status: str = "healthy"
    scanners_available: List[str] = [
        "python", "java", "javascript", "c_cpp", "tree_sitter", "semgrep",
        "certificate", "protocol", "docker", "container", "binary", "dependency",
        "cloud_iac", "hardware_hsm"
    ]
    tree_sitter_enabled: bool = True
    docker_enabled: bool = False
    postgres_connected: bool = True
    mongodb_connected: bool = False
