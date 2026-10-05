"""
Scan Lifecycle & Persistence Service
====================================
Orchestrates async background scan processing, status updates, database persistence
(PostgreSQL SQLAlchemy models & MongoDB document store), and query handling.
"""

from datetime import datetime
import json
import os
import shutil
import zipfile
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from backend.app.database.connection import SessionLocal, mongo_db
from backend.app.models.scan import ScanModel, FindingModel, CBOMModel, RemediationModel
from backend.app.services.scanner_orchestrator import ScannerOrchestrator

logger = logging.getLogger("ecdat.scan_service")

class ScanService:
    def __init__(self):
        self.orchestrator = ScannerOrchestrator()

    def process_scan_background(self, scan_id: str, target_path: str, is_archive: bool = False):
        db: Session = SessionLocal()
        try:
            scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            if not scan:
                logger.error(f"Scan {scan_id} not found in database.")
                return

            scan.status = "extracting"
            scan.stage = "Extracting upload target workspace"
            scan.progress_percentage = 10
            db.commit()

            # Extract archive if target is ZIP
            is_temp_extract = False
            extract_dir = target_path

            if is_archive and zipfile.is_zipfile(target_path):
                is_temp_extract = True
                extract_dir = os.path.join(os.path.dirname(target_path), f"extracted_{scan_id}")
                os.makedirs(extract_dir, exist_ok=True)
                
                MAX_FILES = 10000
                MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024 # 500 MB
                total_size = 0

                with zipfile.ZipFile(target_path, 'r') as zip_ref:
                    infos = zip_ref.infolist()
                    if len(infos) > MAX_FILES:
                        raise ValueError(f"ZIP archive contains too many files ({len(infos)} > max {MAX_FILES}).")

                    for info in infos:
                        # 1. Symlink detection (mode & S_IFLNK)
                        mode = info.external_attr >> 16
                        if mode & 0o120000 == 0o120000:
                            logger.warning(f"Skipping symlink in ZIP entry: {info.filename}")
                            continue

                        # 2. Path Traversal & Absolute Path check
                        norm_name = os.path.normpath(info.filename)
                        if norm_name.startswith("..") or os.path.isabs(norm_name):
                            raise ValueError(f"Path traversal detected in ZIP entry: {info.filename}")

                        target_file = os.path.abspath(os.path.join(extract_dir, info.filename))
                        abs_extract = os.path.abspath(extract_dir)
                        if not (target_file.startswith(abs_extract + os.sep) or target_file == abs_extract):
                            raise ValueError(f"Zip Slip path traversal attack detected: {info.filename}")

                        # 3. Exclude node_modules and .git directories
                        parts = norm_name.split(os.sep)
                        if 'node_modules' in parts or '.git' in parts:
                            continue

                        # 4. Total uncompressed size limit
                        total_size += info.file_size
                        if total_size > MAX_UNCOMPRESSED_BYTES:
                            raise ValueError("ZIP uncompressed content exceeds 500MB safety limit.")

                        # Extract single safe member
                        zip_ref.extract(info, extract_dir)

            scan.status = "scanning"
            scan.stage = "Discovering cryptographic assets & running detectors"
            scan.progress_percentage = 30
            db.commit()

            # Execute full scanner & risk pipeline
            result = self.orchestrator.run_full_scan(extract_dir, scan_id=scan_id)

            scan.stage = "Generating CBOM & calculating risk score"
            scan.progress_percentage = 70
            db.commit()

            # Persist findings to PostgreSQL
            scan.artifact_count = result["artifact_count"]
            scan.shor_count = result["shor_count"]
            scan.readiness_score = result["readiness_score"]
            scan.top_risk_band = result["top_risk_band"]
            scan.mosca_status = result["portfolio_mosca"].get("portfolio_status", "SAFE")
            scan.summary_json = {
                "band_counts": result["band_counts"],
                "portfolio_mosca": result["portfolio_mosca"],
                "total_effort_hours": result["total_effort_hours"],
                "compliance": result.get("compliance"),
            }

            for f in result["findings"]:
                finding_db = FindingModel(
                    id=f["id"],
                    scan_id=scan_id,
                    artifact_type=f["artifact_type"],
                    algorithm=f["algorithm"],
                    key_size=f["key_size"],
                    purpose=f["purpose"],
                    protocol=f["protocol"],
                    library=f["library"],
                    file_path=f["file_path"],
                    line_number=f["line_number"],
                    code_snippet=f["code_snippet"],
                    detection_method=f["detection_method"],
                    confidence=f["confidence"],
                    purpose_confidence=f.get("purpose_confidence"),
                    resolution_status=f.get("resolution_status"),
                    detection_sources_json=json.dumps(f.get("detection_sources")) if f.get("detection_sources") else None,
                    layer=f["layer"],
                    sensitivity=f["sensitivity"],
                    exposure_type=f["exposure_type"],
                    shor_vulnerable=f["shor_vulnerable"],
                    quantum_class=f["quantum_class"],
                    classically_weak=f["classically_weak"],
                    risk_score=f["risk_score"],
                    risk_band=f["risk_band"],
                    mosca_x=f["mosca_x"],
                    mosca_y=f["mosca_y"],
                    mosca_z=f["mosca_z"],
                    mosca_margin=f["mosca_margin"],
                    mosca_status=f["mosca_status"],
                    hndl_relevant=f["hndl_relevant"],
                    migration_effort_hours=f["migration_effort_hours"],
                    migration_effort_years=f["migration_effort_years"],
                    effort_level=f["effort_level"],
                    breaking_change_risk=f["breaking_change_risk"],
                    recommendation_json=f["recommendation"],
                    evidence_json=f["evidence"],
                )
                db.add(finding_db)

            # Persist CBOM document
            cbom_db = CBOMModel(
                scan_id=scan_id,
                cbom_json=result["cbom"],
                cyclonedx_json=result["cyclonedx"],
            )
            db.add(cbom_db)

            # Persist to MongoDB if connected
            if mongo_db is not None:
                try:
                    mongo_db["scan_evidence"].insert_one({
                        "scan_id": scan_id,
                        "user_id": scan.user_id,
                        "created_at": datetime.utcnow(),
                        "result": result
                    })
                    mongo_db["scans"].update_one(
                        {"id": scan_id},
                        {"$set": {
                            "id": scan_id,
                            "user_id": scan.user_id,
                            "project_name": scan.project_name,
                            "target_name": scan.target_name,
                            "status": "completed",
                            "created_at": scan.created_at,
                            "completed_at": datetime.utcnow(),
                            "artifact_count": scan.artifact_count,
                            "summary_json": scan.summary_json
                        }},
                        upsert=True
                    )
                    mongo_db["scans"].create_index([("user_id", 1), ("created_at", -1)])
                except Exception as me:
                    logger.warning(f"Failed to store scan in MongoDB: {me}")

            scan.status = "completed"
            scan.stage = "Scan completed successfully"
            scan.progress_percentage = 100
            scan.completed_at = datetime.utcnow()
            db.commit()

        except Exception as e:
            logger.error(f"Error processing scan {scan_id}: {e}", exc_info=True)
            db.rollback()
            scan = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.stage = f"Scan failed: {str(e)}"
                scan.scanner_errors = [str(e)]
                db.commit()
        finally:
            if is_temp_extract and extract_dir and os.path.exists(extract_dir):
                try:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                except Exception as ce:
                    logger.warning(f"Error removing temp extraction dir {extract_dir}: {ce}")
            db.close()
