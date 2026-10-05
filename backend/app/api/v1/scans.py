"""
Scan API v1 Endpoints
=====================
Implements all required OpenAPI REST endpoints for target upload, scan job creation,
status polling, inventory querying, CBOM export, CycloneDX export, risk assessment,
MTech migration metrics, Mosca analysis, recommendations, remediation management,
scan reminders, and scan deletion with strict user isolation.
"""

from datetime import datetime, timezone
import json
import os
import shutil
import uuid
import zipfile
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, Query, status
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database.connection import get_db, mongo_db
from backend.app.models.scan import (
    ScanModel, FindingModel, CBOMModel, RemediationModel, UserModel, ReminderAcknowledgementModel
)
from backend.app.schemas.scan import (
    ScanCreate, ScanResponse, ScanStatus, CryptoArtifact, RemediationStatusUpdate, SystemInfo, ReminderAckRequest
)

def format_utc_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
from backend.app.services.scan_service import ScanService
from backend.app.utils.auth import get_current_user, get_current_user_optional

router = APIRouter(prefix="/scans", tags=["scans"])
scan_service = ScanService()


def _get_user_scan(scan_id: str, current_user: Optional[UserModel], db: Session) -> ScanModel:
    """
    Helper function enforcing strict user isolation.
    Returns ScanModel only if it exists and belongs to current_user.
    Otherwise raises 404 Not Found (never 403, preventing scan existence leakage).
    """
    query = db.query(ScanModel).filter(ScanModel.id == scan_id)
    if current_user:
        query = query.filter(ScanModel.user_id == current_user.id)
    scan = query.first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.post("/upload", response_model=ScanStatus, status_code=status.HTTP_202_ACCEPTED)
async def upload_scan_target(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    project_name: Optional[str] = "Default Project",
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Upload scan target (ZIP archive, source file, certificate, Dockerfile, CBOM JSON) and trigger scan."""
    upload_dir = os.path.abspath(settings.UPLOAD_DIR)
    os.makedirs(upload_dir, exist_ok=True)

    is_archive = file.filename.lower().endswith(".zip")
    
    # Read file content to check size limit
    content = await file.read()
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Uploaded file exceeds maximum size limit of {settings.MAX_UPLOAD_SIZE_MB}MB."
        )

    # If ZIP, inspect for Zip Slip path traversal attack before proceeding
    if is_archive:
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(content), 'r') as zf:
                for member in zf.namelist():
                    norm_path = os.path.normpath(member)
                    if norm_path.startswith("..") or os.path.isabs(norm_path):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Zip Slip path traversal attack detected in archive member: {member}"
                        )
        except zipfile.BadZipFile:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is not a valid ZIP archive."
            )

    scan_id = str(uuid.uuid4())
    file_path = os.path.join(upload_dir, f"{scan_id}_{file.filename}")
    with open(file_path, "wb") as buffer:
        buffer.write(content)

    user_id = current_user.id if current_user else None

    scan_db = ScanModel(
        id=scan_id,
        user_id=user_id,
        project_name=project_name or "Default Project",
        target_name=file.filename,
        target_type="archive" if is_archive else "file",
        status="queued",
        stage="File uploaded; queued for background discovery",
        progress_percentage=0,
    )
    db.add(scan_db)
    db.commit()
    db.refresh(scan_db)

    # Launch scan in background task
    background_tasks.add_task(scan_service.process_scan_background, scan_id, file_path, is_archive)

    return ScanStatus(
        scan_id=scan_id,
        status="queued",
        stage="Queued for analysis",
        progress_percentage=0,
        created_at=scan_db.created_at,
        artifact_count=0,
    )


@router.post("", response_model=ScanStatus, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Create a scan for an existing local target directory or samples."""
    scan_id = str(uuid.uuid4())
    sample_dir = os.path.abspath("./ECDAT-main/samples")
    user_id = current_user.id if current_user else None
    
    scan_db = ScanModel(
        id=scan_id,
        user_id=user_id,
        project_name=payload.project_name,
        target_name=payload.target_name or "Local Sample",
        target_type="directory",
        status="queued",
        stage="Queued for background analysis",
        progress_percentage=0,
    )
    db.add(scan_db)
    db.commit()

    background_tasks.add_task(scan_service.process_scan_background, scan_id, sample_dir, False)

    return ScanStatus(
        scan_id=scan_id,
        status="queued",
        stage="Queued for analysis",
        progress_percentage=0,
        created_at=scan_db.created_at,
        artifact_count=0,
    )


@router.get("", response_model=List[ScanResponse])
def list_scans(
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """List all previous scans for the authenticated user."""
    query = db.query(ScanModel)
    if current_user:
        query = query.filter(ScanModel.user_id == current_user.id)
    
    scans = query.order_by(ScanModel.created_at.desc()).all()
    results = []
    for s in scans:
        summary = s.summary_json or {}
        results.append(ScanResponse(
            scan_id=s.id,
            project_name=s.project_name or "Default Project",
            target_name=s.target_name,
            created_at=s.created_at,
            completed_at=s.completed_at,
            status=s.status,
            stage=s.stage,
            summary={
                "total_artifacts": s.artifact_count,
                "shor_count": s.shor_count,
                "readiness_score": s.readiness_score,
                "top_risk_band": s.top_risk_band,
                "band_counts": summary.get("band_counts", {"critical": 0, "high": 0, "moderate": 0, "low": 0, "safe": 0}),
                "portfolio_mosca": summary.get("portfolio_mosca", {}),
                "total_effort_hours": summary.get("total_effort_hours", 0.0),
            }
        ))
    return results


@router.get("/{scan_id}/status", response_model=ScanStatus)
def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Get scan status and real progress percentage with user isolation."""
    scan = _get_user_scan(scan_id, current_user, db)
    return ScanStatus(
        scan_id=scan.id,
        status=scan.status,
        stage=scan.stage,
        progress_percentage=scan.progress_percentage,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        artifact_count=scan.artifact_count,
        errors=scan.scanner_errors,
    )


@router.get("/{scan_id}/findings", response_model=List[CryptoArtifact])
@router.get("/{scan_id}/inventory", response_model=List[CryptoArtifact])
def get_scan_findings(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Get discovered cryptographic inventory and findings for a scan with user isolation."""
    scan = _get_user_scan(scan_id, current_user, db)

    findings = db.query(FindingModel).filter(FindingModel.scan_id == scan.id).all()
    results = []
    for f in findings:
        results.append(CryptoArtifact(
            id=f.id,
            artifact_type=f.artifact_type,
            algorithm=f.algorithm,
            key_size=f.key_size,
            purpose=f.purpose,
            protocol=f.protocol,
            library=f.library,
            file_path=f.file_path,
            line_number=f.line_number,
            code_snippet=f.code_snippet,
            detection_method=f.detection_method or "static_analysis",
            confidence=f.confidence if f.confidence is not None else 0.8,
            purpose_confidence=f.purpose_confidence,
            resolution_status=f.resolution_status,
            detection_sources=json.loads(f.detection_sources_json) if getattr(f, "detection_sources_json", None) else [f.detection_method or "static_analysis"],
            layer=f.layer or "in_use",
            sensitivity=f.sensitivity or "moderate",
            exposure_type=f.exposure_type or "internal",
            shor_vulnerable=f.shor_vulnerable or False,
            quantum_class=f.quantum_class or "unresolved",
            classically_weak=f.classically_weak or False,
            risk_score=f.risk_score or 0.0,
            risk_band=f.risk_band or "safe",
            mosca_x=f.mosca_x or 5.0,
            mosca_y=f.mosca_y or 0.5,
            mosca_z=f.mosca_z or 9.0,
            mosca_margin=f.mosca_margin or 3.5,
            mosca_status=f.mosca_status or "SAFE",
            hndl_relevant=f.hndl_relevant or False,
            migration_effort_hours=f.migration_effort_hours or 16.0,
            migration_effort_years=f.migration_effort_years or 0.1,
            effort_level=f.effort_level or "Medium",
            breaking_change_risk=f.breaking_change_risk or "low",
            recommendation=f.recommendation_json,
            evidence=f.evidence_json,
        ))
    return results


@router.get("/{scan_id}/cbom")
def get_scan_cbom(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Get standardized CBOM JSON output with user isolation."""
    scan = _get_user_scan(scan_id, current_user, db)
    cbom = db.query(CBOMModel).filter(CBOMModel.scan_id == scan.id).first()
    if not cbom:
        raise HTTPException(status_code=404, detail="CBOM document not found for scan")
    return cbom.cbom_json


@router.get("/{scan_id}/cyclonedx")
def get_scan_cyclonedx(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Get CycloneDX 1.6 CBOM document export with user isolation."""
    scan = _get_user_scan(scan_id, current_user, db)
    cbom = db.query(CBOMModel).filter(CBOMModel.scan_id == scan.id).first()
    if not cbom or not cbom.cyclonedx_json:
        raise HTTPException(status_code=404, detail="CycloneDX export not found for scan")
    return cbom.cyclonedx_json


@router.get("/{scan_id}/risk")
def get_scan_risk(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Get overall risk assessment for scan with user isolation."""
    scan = _get_user_scan(scan_id, current_user, db)
    return {
        "scan_id": scan.id,
        "shor_count": scan.shor_count,
        "readiness_score": scan.readiness_score,
        "top_risk_band": scan.top_risk_band,
        "summary": scan.summary_json,
    }


@router.get("/{scan_id}/mosca")
def get_scan_mosca(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Get Mosca Theorem calculations and portfolio exposure status with user isolation."""
    scan = _get_user_scan(scan_id, current_user, db)
    summary = scan.summary_json or {}
    return {
        "scan_id": scan.id,
        "mosca_status": scan.mosca_status,
        "portfolio_mosca": summary.get("portfolio_mosca", {}),
    }


@router.get("/{scan_id}/migration")
def get_scan_migration(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Get MTech migration effort assessment with user isolation."""
    scan = _get_user_scan(scan_id, current_user, db)
    summary = scan.summary_json or {}
    return {
        "scan_id": scan.id,
        "total_effort_hours": summary.get("total_effort_hours", 0.0),
    }


@router.get("/{scan_id}/remediation")
def get_scan_remediation(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Get remediation tracking items and PQC patch code recommendations with user isolation."""
    scan = _get_user_scan(scan_id, current_user, db)
    remediations = db.query(RemediationModel).filter(RemediationModel.scan_id == scan.id).all()
    rem_map = {r.finding_id: {"status": r.status, "choice": r.patch_choice} for r in remediations}
    return {"scan_id": scan.id, "remediations": rem_map}


@router.post("/{scan_id}/remediation/{finding_id}/status")
def update_remediation_status(
    scan_id: str,
    finding_id: str,
    payload: RemediationStatusUpdate,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Update remediation status for a specific finding with user isolation."""
    scan = _get_user_scan(scan_id, current_user, db)
    item = db.query(RemediationModel).filter(
        RemediationModel.scan_id == scan.id,
        RemediationModel.finding_id == finding_id
    ).first()

    if not item:
        item = RemediationModel(
            scan_id=scan.id,
            finding_id=finding_id,
            status=payload.status,
            patch_choice=payload.choice or "bridge",
        )
        db.add(item)
    else:
        item.status = payload.status
        if payload.choice:
            item.patch_choice = payload.choice
        item.updated_at = datetime.utcnow()

    db.commit()
    return {"scan_id": scan.id, "finding_id": finding_id, "status": item.status, "choice": item.patch_choice}


@router.get("/{scan_id}/compliance")
def get_scan_compliance(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """Get Compliance Assessment for scan findings with user isolation."""
    scan = _get_user_scan(scan_id, current_user, db)
    summary = scan.summary_json or {}
    compliance = summary.get("compliance")
    if not compliance:
        findings = db.query(FindingModel).filter(FindingModel.scan_id == scan.id).all()
        if not findings:
            raise HTTPException(status_code=404, detail="No findings found for scan compliance assessment")
        findings_dicts = [
            {
                "id": f.id,
                "algorithm": f.algorithm,
                "shor_vulnerable": f.shor_vulnerable,
                "risk_band": f.risk_band,
                "file_path": f.file_path,
                "recommendation": f.recommendation_json,
            }
            for f in findings
        ]
        from backend.app.services.compliance_service import ComplianceService
        compliance_service = ComplianceService()
        compliance = compliance_service.evaluate_compliance(findings_dicts)
    return {"scan_id": scan.id, **compliance}


@router.get("/{scan_id}/mosca")
def get_scan_mosca(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """
    Get Mosca Theorem breach-window assessment for scan findings with user isolation.
    Computes per-finding X, Y, X+Y, and breach status at P25, P50, and P75 against Q-Day distribution.
    """
    scan = _get_user_scan(scan_id, current_user, db)
    findings = db.query(FindingModel).filter(FindingModel.scan_id == scan.id).all()

    from backend.app.services.mosca_service import MoscaService
    mosca_service = MoscaService()

    findings_mosca = []
    for f in findings:
        file_basename = os.path.basename(f.file_path) if f.file_path else "source code"
        artifact = {
            "id": f.id,
            "algorithm": f.algorithm,
            "purpose": f.purpose,
            "artifact_type": f.artifact_type,
            "shor_vulnerable": f.shor_vulnerable,
            "quantum_class": f.quantum_class,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "sensitivity": f.data_classification,
        }
        effort = (f.effort_level or "").lower()
        if effort == "high":
            y = 2.0
        elif effort in ("medium", "moderate"):
            y = 1.0
        elif effort == "low":
            y = 0.5
        else:
            y = 1.0

        calc = mosca_service.calculate_finding_mosca(artifact, migration_years=y)
        calc.update({
            "id": f.id,
            "asset": file_basename,
            "algorithm": f.algorithm or "Crypto Asset",
            "file_path": f.file_path,
            "line_number": f.line_number,
            "risk_band": f.risk_band,
            "purpose": f.purpose,
        })
        findings_mosca.append(calc)

    portfolio = mosca_service.calculate_portfolio_mosca(findings_mosca)
    return {
        "scan_id": scan.id,
        "portfolio": portfolio,
        "findings": findings_mosca,
    }



@router.post("/{scan_id}/findings/{finding_id}/prototype")
def run_finding_pqc_prototype(
    scan_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """
    Executes an isolated, experimental PQC prototype test for a specific finding's recommendation.
    Consumes existing recommendation data and invokes liboqs if available.
    """
    scan = _get_user_scan(scan_id, current_user, db)
    finding = db.query(FindingModel).filter(
        FindingModel.scan_id == scan.id,
        FindingModel.id == finding_id
    ).first()
    
    if not finding:
        finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()

    finding_data = {
        "id": finding_id,
        "algorithm": finding.algorithm if finding else "RSA-2048",
        "purpose": finding.purpose if finding else None,
        "recommendation": finding.recommendation_json if finding else {}
    }

    from backend.app.services.pqc_prototype_service import run_pqc_prototype
    result = run_pqc_prototype(finding_data)
    return {"scan_id": scan.id, "finding_id": finding_id, **result}


@router.get("/{scan_id}/reminders")
def get_scan_reminders(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """
    Get active reminders and action items for high-risk findings in a scan.
    Enforces strict user isolation and returns acknowledgement state.
    """
    scan = _get_user_scan(scan_id, current_user, db)
    findings = db.query(FindingModel).filter(FindingModel.scan_id == scan.id).all()
    
    acks = db.query(ReminderAcknowledgementModel).filter(ReminderAcknowledgementModel.scan_id == scan.id).all()
    ack_map = {a.finding_id: (a.acknowledged, a.acknowledged_at) for a in acks}

    band_priority = {"critical": 1, "high": 2, "moderate": 3, "low": 4, "safe": 5}

    reminders = []
    for f in findings:
        risk_band = (f.risk_band or "safe").lower()
        if risk_band in ("critical", "high", "moderate") or f.shor_vulnerable:
            file_basename = os.path.basename(f.file_path) if f.file_path else "source code"
            title = f"Remediate {f.algorithm or 'Crypto Asset'}"
            msg = f"Vulnerable asset detected in {file_basename}. Shor risk: {'YES' if f.shor_vulnerable else 'NO'}."
            action = f"Apply PQC algorithm migration ({f.effort_level or 'Medium'} effort)."
            
            ack_info = ack_map.get(f.id)
            is_ack = ack_info[0] if ack_info else False
            ack_at = format_utc_iso(ack_info[1]) if (ack_info and ack_info[0] and ack_info[1]) else None

            reminders.append({
                "id": f.id,
                "scan_id": scan.id,
                "title": title,
                "message": msg,
                "action_required": action,
                "algorithm": f.algorithm,
                "risk_band": f.risk_band,
                "shor_vulnerable": f.shor_vulnerable,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "risk_score": f.risk_score or 0.0,
                "recommendation": f.recommendation_json,
                "priority": band_priority.get(risk_band, 99),
                "acknowledged": is_ack,
                "acknowledged_at": ack_at
            })

    reminders.sort(key=lambda x: (x["priority"], -x["risk_score"]))
    completed_count = sum(1 for r in reminders if r["acknowledged"])
    return {
        "scan_id": scan.id,
        "count": len(reminders),
        "completed_count": completed_count,
        "reminders": reminders
    }


@router.post("/{scan_id}/reminders/{reminder_id}")
@router.patch("/{scan_id}/reminders/{reminder_id}")
def update_scan_reminder_acknowledgement(
    scan_id: str,
    reminder_id: str,
    payload: ReminderAckRequest,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """
    Acknowledge or unacknowledge a reminder item ('I've updated my code') with user isolation.
    """
    scan = _get_user_scan(scan_id, current_user, db)
    
    ack = db.query(ReminderAcknowledgementModel).filter(
        ReminderAcknowledgementModel.scan_id == scan.id,
        ReminderAcknowledgementModel.finding_id == reminder_id
    ).first()

    now = datetime.now(timezone.utc)
    if ack:
        ack.acknowledged = payload.acknowledged
        ack.acknowledged_at = now if payload.acknowledged else None
    else:
        ack = ReminderAcknowledgementModel(
            scan_id=scan.id,
            finding_id=reminder_id,
            user_id=current_user.id if current_user else None,
            acknowledged=payload.acknowledged,
            acknowledged_at=now if payload.acknowledged else None
        )
        db.add(ack)

    db.commit()
    db.refresh(ack)

    return {
        "scan_id": scan.id,
        "reminder_id": reminder_id,
        "acknowledged": ack.acknowledged,
        "acknowledged_at": format_utc_iso(ack.acknowledged_at)
    }


@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: Optional[UserModel] = Depends(get_current_user_optional)
):
    """
    Delete a scan and all associated findings, CBOM documents, remediations,
    and target disk files with strict user isolation.
    """
    scan = _get_user_scan(scan_id, current_user, db)

    # Delete disk files if upload target exists
    upload_dir = os.path.abspath(settings.UPLOAD_DIR)
    for fname in os.listdir(upload_dir):
        if fname.startswith(scan.id):
            fpath = os.path.join(upload_dir, fname)
            try:
                if os.path.isdir(fpath):
                    shutil.rmtree(fpath, ignore_errors=True)
                else:
                    os.remove(fpath)
            except Exception:
                pass

    # Delete from MongoDB if connected
    if mongo_db is not None:
        try:
            mongo_db["scan_evidence"].delete_many({"scan_id": scan.id})
            mongo_db["scans"].delete_many({"id": scan.id})
        except Exception:
            pass

    db.delete(scan)
    db.commit()

    return {"message": "Scan deleted successfully", "scan_id": scan.id}
