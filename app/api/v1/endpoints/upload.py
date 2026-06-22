from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path
import uuid
from typing import List
import traceback

from app.database import get_db
from app.config import settings
from app.schemas.scan import ScanResponse, ScanCreate
from app.services.apk_validator import APKValidator
from app.services.hash_service import HashService
from app.services.scan_service import ScanService
from app.services.apk_analyzer import APKAnalyzer
from app.services.threat_scoring import ThreatScoring
from app.services.attack_mapper import AttackMapper
from app.services.intelligence_engine import IntelligenceEngine
from app.services.analyst_workflow import AnalystWorkflow
from app.utils.file_handler import FileHandler
from app.api.v1.endpoints.cases import get_user_id
import json

router = APIRouter()


def _attack_context(analysis_result: dict, threat_assessment: dict) -> dict:
    return {
        "package_name": analysis_result.get("package_name"),
        "app_name": analysis_result.get("app_name"),
        "permissions": [p.get("name") for p in analysis_result.get("permissions", []) if isinstance(p, dict)],
        "activities": [c.get("name") for c in analysis_result.get("activities", []) if isinstance(c, dict)],
        "services": [c.get("name") for c in analysis_result.get("services", []) if isinstance(c, dict)],
        "receivers": [c.get("name") for c in analysis_result.get("receivers", []) if isinstance(c, dict)],
        "providers": [c.get("name") for c in analysis_result.get("providers", []) if isinstance(c, dict)],
        "urls": analysis_result.get("urls", []),
        "domains": analysis_result.get("domains", []),
        "heuristic_indicators": threat_assessment.get("indicators", []),
    }


def _scan_response(scan) -> ScanResponse:
    return ScanResponse(
        scan_id=scan.id,
        sha256=scan.sha256,
        filename=scan.filename,
        file_size=scan.file_size,
        status=scan.status,
        created_at=scan.created_at,
        analysis_result=json.loads(scan.analysis_result) if scan.analysis_result else None
    )


@router.post("/upload", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def upload_apk(
    file: UploadFile = File(..., description="APK file to analyze"),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """
    Upload an APK file for analysis.
    
    This endpoint:
    1. Validates the uploaded file is a valid APK
    2. Calculates SHA256 hash
    3. Checks for duplicate uploads
    4. Stores the file
    5. Creates a database record
    6. Returns scan information
    """
    
    # Validate file extension
    if not file.filename or not file.filename.lower().endswith('.apk'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .apk files are allowed"
        )
    
    # Generate temporary file path
    temp_filename = f"{uuid.uuid4()}_{file.filename}"
    temp_path = settings.upload_dir / temp_filename
    
    try:
        # Save uploaded file temporarily
        file_size = await FileHandler.save_upload_file(file, temp_path)
        
        # Check file size
        if file_size > settings.max_upload_size:
            FileHandler.delete_file(temp_path)
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File size exceeds maximum allowed size of {settings.max_upload_size} bytes"
            )
        
        # Validate APK structure
        is_valid, error_message = APKValidator.validate_apk(temp_path)
        if not is_valid:
            FileHandler.delete_file(temp_path)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message
            )
        
        # Calculate SHA256 hash
        sha256_hash = await HashService.calculate_sha256(temp_path)
        
        # Check if this APK was already uploaded
        existing_scan = await ScanService.get_scan_by_sha256(db, sha256_hash)
        if existing_scan:
            FileHandler.delete_file(temp_path)
            return _scan_response(existing_scan)
        
        # Generate permanent storage path
        storage_path = FileHandler.generate_storage_path(
            settings.storage_dir,
            sha256_hash,
            file.filename
        )
        
        # Move file to permanent storage
        FileHandler.move_file(temp_path, storage_path)
        
        # Create database record with "analyzing" status
        scan_data = ScanCreate(
            sha256=sha256_hash,
            filename=file.filename,
            file_size=file_size,
            file_path=str(storage_path),
            status="analyzing"
        )
        
        scan = await ScanService.create_scan(db, scan_data)
        
        # Perform static analysis
        try:
            analysis_result = await APKAnalyzer.analyze(storage_path)
            
            # Calculate threat score
            threat_assessment = ThreatScoring.calculate_threat_score(analysis_result)
            attack_mapping = AttackMapper().map_artifacts(
                _attack_context(analysis_result, threat_assessment)
            )
            intelligence = IntelligenceEngine.enrich(
                apk_data=analysis_result,
                threat_assessment=threat_assessment,
                attack_mapping=attack_mapping,
            )
            
            # Combine analysis and threat assessment
            combined_result = {
                **analysis_result,
                "apk_analysis": analysis_result,
                "threat_assessment": threat_assessment,
                "attack_mapping": attack_mapping,
                "intelligence": intelligence,
                **intelligence,
            }
            combined_result["top_suspicious_functions"] = AnalystWorkflow.rank_suspicious_functions(combined_result)
            
            # Store combined results
            scan.analysis_result = json.dumps(combined_result, default=str)
            scan.status = "completed" if not analysis_result.get("analysis_failed") else "failed"
            await db.commit()
            await db.refresh(scan)
            
        except Exception as e:
            # If analysis fails, mark as failed but keep the scan record
            logger_error = traceback.format_exc()
            import logging
            logging.getLogger(__name__).error(logger_error)
            logging.getLogger(__name__).error(f"[Upload] Analysis exception type: {type(e).__name__}")
            logging.getLogger(__name__).error(f"[Upload] Analysis exception message: {str(e)}")
            scan.analysis_result = json.dumps({"error": str(e), "analysis_failed": True})
            scan.status = "failed"
            await db.commit()
            await db.refresh(scan)
        
        # Return response
        return _scan_response(scan)
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Clean up on error
        FileHandler.delete_file(temp_path)
        import logging
        logging.getLogger(__name__).error(traceback.format_exc())
        logging.getLogger(__name__).error(f"[Upload] Upload exception type: {type(e).__name__}")
        logging.getLogger(__name__).error(f"[Upload] Upload exception message: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"{type(e).__name__}: {str(e)}"
        )


@router.get("/scans", response_model=List[ScanResponse])
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """List recent APK scans for the scan history view."""
    try:
        scans = await ScanService.list_scans(db, skip=skip, limit=limit)
        return [_scan_response(scan) for scan in scans]
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(traceback.format_exc())
        logging.getLogger(__name__).error(f"[Scans] List exception type: {type(e).__name__}")
        logging.getLogger(__name__).error(f"[Scans] List exception message: {str(e)}")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)}")


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """
    Retrieve scan information by scan ID.
    """
    try:
        scan = await ScanService.get_scan_by_id(db, scan_id)
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan with ID {scan_id} not found"
            )
        
        return _scan_response(scan)
    except HTTPException:
        raise
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(traceback.format_exc())
        logging.getLogger(__name__).error(f"[Scans] Get exception type: {type(e).__name__}")
        logging.getLogger(__name__).error(f"[Scans] Get exception message: {str(e)}")
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)}")
