"""
SQLAlchemy Database Models for ECDAT CBOM & PQC Risk Engine
============================================================
Defines relational system of record tables for scans, findings, risk assessments,
migration evaluations, Mosca analysis, PQC recommendations, and remediation tracking.
"""

from datetime import datetime
import uuid
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.app.database.connection import Base

def generate_uuid():
    return str(uuid.uuid4())

class UserModel(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("ScanModel", back_populates="user", cascade="all, delete-orphan")


class ScanModel(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    project_name = Column(String(255), default="Default Project")
    target_name = Column(String(255), nullable=False)
    target_type = Column(String(100), default="repository")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(50), default="queued") # queued | extracting | scanning | completed | failed
    stage = Column(String(100), default="Queued for scanning")
    progress_percentage = Column(Integer, default=0)
    
    artifact_count = Column(Integer, default=0)
    shor_count = Column(Integer, default=0)
    readiness_score = Column(Integer, default=100)
    top_risk_band = Column(String(50), default="safe")
    mosca_status = Column(String(50), default="SAFE")
    
    summary_json = Column(JSON, nullable=True)
    scanner_errors = Column(JSON, nullable=True)

    user = relationship("UserModel", back_populates="scans")
    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")
    cbom = relationship("CBOMModel", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    remediations = relationship("RemediationModel", back_populates="scan", cascade="all, delete-orphan")


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    
    artifact_type = Column(String(100), nullable=False)
    algorithm = Column(String(100), nullable=True)
    key_size = Column(Integer, nullable=True)
    purpose = Column(String(100), nullable=True)
    protocol = Column(String(100), nullable=True)
    library = Column(String(150), nullable=True)
    
    file_path = Column(Text, nullable=True)
    line_number = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    detection_method = Column(String(100), default="static_analysis")
    confidence = Column(Float, default=0.8)
    purpose_confidence = Column(Float, nullable=True, default=0.5)
    resolution_status = Column(String(50), nullable=True, default="resolved")
    detection_sources_json = Column(Text, nullable=True)

    layer = Column(String(50), default="in_use") # in_transit | in_use | at_rest
    sensitivity = Column(String(50), default="moderate")
    exposure_type = Column(String(50), default="internal") # internal | external
    
    shor_vulnerable = Column(Boolean, default=False)
    quantum_class = Column(String(50), default="unresolved") # shor | grover | classical_weak | unresolved
    classically_weak = Column(Boolean, default=False)
    
    risk_score = Column(Float, default=0.0)
    risk_band = Column(String(50), default="safe") # safe | low | moderate | high | critical
    
    mosca_x = Column(Float, default=5.0)
    mosca_y = Column(Float, default=0.5)
    mosca_z = Column(Float, default=9.0)
    mosca_margin = Column(Float, default=3.5)
    mosca_status = Column(String(50), default="SAFE")
    hndl_relevant = Column(Boolean, default=False)
    
    migration_effort_hours = Column(Float, default=16.0)
    migration_effort_years = Column(Float, default=0.1)
    effort_level = Column(String(50), default="Medium")
    breaking_change_risk = Column(String(50), default="low")

    recommendation_json = Column(JSON, nullable=True)
    evidence_json = Column(JSON, nullable=True)

    scan = relationship("ScanModel", back_populates="findings")


class CBOMModel(Base):
    __tablename__ = "cbom_documents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    cbom_json = Column(JSON, nullable=False)
    cyclonedx_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanModel", back_populates="cbom")


class RemediationModel(Base):
    __tablename__ = "remediation_items"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    finding_id = Column(String(64), nullable=False)
    patch_choice = Column(String(50), default="bridge") # bridge | full
    status = Column(String(50), default="pending") # pending | pr-drafted | merged
    updated_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanModel", back_populates="remediations")


class PasswordResetTokenModel(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    attempts = Column(Integer, nullable=False, default=0)  # wrong-OTP counter
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("UserModel")


class ReminderAcknowledgementModel(Base):
    __tablename__ = "reminder_acknowledgements"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    finding_id = Column(String(64), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    acknowledged = Column(Boolean, default=True)
    acknowledged_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanModel")

