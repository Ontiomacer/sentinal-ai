from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import json
import logging

from app.database import get_db
from app.schemas.case import EvidenceResponse
from app.services.evidence_service import EvidenceService
from app.services.case_service import CaseService
from app.services.analysis_pipeline import AnalysisPipeline
from app.services.threat_ops_service import ThreatOpsService
from app.api.v1.endpoints.cases import get_user_id

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/cases/{case_id}/evidence", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    case_id: str,
    file: UploadFile = File(...),
    notes: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Upload evidence file to case vault."""
    
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    try:
        evidence = await EvidenceService.upload_evidence(
            db=db,
            case_id=case_id,
            case_directory=case.case_directory,
            file=file,
            user_id=user_id,
            notes=notes
        )
        
        return EvidenceResponse(
            id=evidence.id,
            case_id=evidence.case_id,
            evidence_type=evidence.evidence_type,
            filename=evidence.filename,
            original_filename=evidence.original_filename,
            file_size=evidence.file_size,
            file_path=evidence.file_path,
            md5=evidence.md5,
            sha1=evidence.sha1,
            sha256=evidence.sha256,
            analysis_status=evidence.analysis_status,
            analysis_result=json.loads(evidence.analysis_result) if evidence.analysis_result else None,
            uploaded_by=evidence.uploaded_by,
            notes=evidence.notes,
            created_at=evidence.created_at,
            analyzed_at=evidence.analyzed_at
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload evidence: {str(e)}"
        )


@router.get("/cases/{case_id}/evidence", response_model=List[EvidenceResponse])
async def list_evidence(
    case_id: str,
    evidence_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """List all evidence for a case."""
    
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    evidence_list = await EvidenceService.list_evidence(db, case_id, evidence_type)
    
    return [
        EvidenceResponse(
            id=evidence.id,
            case_id=evidence.case_id,
            evidence_type=evidence.evidence_type,
            filename=evidence.filename,
            original_filename=evidence.original_filename,
            file_size=evidence.file_size,
            file_path=evidence.file_path,
            md5=evidence.md5,
            sha1=evidence.sha1,
            sha256=evidence.sha256,
            analysis_status=evidence.analysis_status,
            analysis_result=json.loads(evidence.analysis_result) if evidence.analysis_result else None,
            uploaded_by=evidence.uploaded_by,
            notes=evidence.notes,
            created_at=evidence.created_at,
            analyzed_at=evidence.analyzed_at
        )
        for evidence in evidence_list
    ]


@router.get("/cases/{case_id}/evidence/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(
    case_id: str,
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Get evidence details."""
    
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    evidence = await EvidenceService.get_evidence(db, evidence_id)
    if not evidence or evidence.case_id != case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found"
        )
    
    return EvidenceResponse(
        id=evidence.id,
        case_id=evidence.case_id,
        evidence_type=evidence.evidence_type,
        filename=evidence.filename,
        original_filename=evidence.original_filename,
        file_size=evidence.file_size,
        file_path=evidence.file_path,
        md5=evidence.md5,
        sha1=evidence.sha1,
        sha256=evidence.sha256,
        analysis_status=evidence.analysis_status,
        analysis_result=json.loads(evidence.analysis_result) if evidence.analysis_result else None,
        uploaded_by=evidence.uploaded_by,
        notes=evidence.notes,
        created_at=evidence.created_at,
        analyzed_at=evidence.analyzed_at
    )


async def _threat_ops_evidence(
    db: AsyncSession,
    case_id: str,
    evidence_id: str,
    user_id: str,
):
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    evidence = await EvidenceService.get_evidence(db, evidence_id)
    if not evidence or evidence.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    if evidence.evidence_type.lower() != "apk":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Threat-Ops investigations require APK evidence",
        )
    return evidence


@router.get("/cases/{case_id}/evidence/{evidence_id}/investigation")
async def get_threat_ops_investigation(
    case_id: str,
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id),
):
    """Reload the persisted Threat-Ops graph, timeline, evidence, and narrative."""
    await _threat_ops_evidence(db, case_id, evidence_id, user_id)
    investigation = await ThreatOpsService.get_for_evidence(db, case_id, evidence_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return ThreatOpsService.serialize(investigation)


async def _queue_threat_ops_investigation(
    background_tasks: BackgroundTasks,
    db: AsyncSession,
    case_id: str,
    evidence_id: str,
    user_id: str,
    resume: bool,
):
    evidence = await _threat_ops_evidence(db, case_id, evidence_id, user_id)
    investigation, should_start = await ThreatOpsService.prepare(
        db,
        evidence,
        user_id,
        resume=resume,
    )
    if should_start:
        background_tasks.add_task(ThreatOpsService.run_task, investigation.id)
    return ThreatOpsService.serialize(investigation)


@router.post(
    "/cases/{case_id}/evidence/{evidence_id}/investigation",
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_threat_ops_investigation(
    case_id: str,
    evidence_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id),
):
    """Start the real, non-blocking Threat-Ops APK pipeline."""
    return await _queue_threat_ops_investigation(
        background_tasks, db, case_id, evidence_id, user_id, resume=False
    )


@router.post(
    "/cases/{case_id}/evidence/{evidence_id}/investigation/resume",
    status_code=status.HTTP_202_ACCEPTED,
)
async def resume_threat_ops_investigation(
    case_id: str,
    evidence_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id),
):
    """Resume from the first failed or incomplete stage without losing completed stages."""
    return await _queue_threat_ops_investigation(
        background_tasks, db, case_id, evidence_id, user_id, resume=True
    )


@router.post("/cases/{case_id}/evidence/{evidence_id}/analyze")
async def analyze_evidence(
    case_id: str,
    evidence_id: str,
    background_tasks: BackgroundTasks,
    pipeline: str = Form(...),  # "neural_ai" or "deep_reverse_engineering"
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Start analysis pipeline for evidence."""
    
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    # Verify evidence exists
    evidence = await EvidenceService.get_evidence(db, evidence_id)
    if not evidence or evidence.case_id != case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found"
        )
    
    # Validate pipeline type
    if pipeline not in [AnalysisPipeline.PIPELINE_NEURAL, AnalysisPipeline.PIPELINE_DEEP]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid pipeline type. Must be '{AnalysisPipeline.PIPELINE_NEURAL}' or '{AnalysisPipeline.PIPELINE_DEEP}'"
        )
    
    try:
        # Update status to INDEXING immediately
        await EvidenceService.update_analysis_status(db, evidence_id, 'INDEXING')
        
        # Add analysis task to background
        background_tasks.add_task(
            AnalysisPipeline.run_analysis_task,
            evidence_id=evidence_id,
            case_id=case_id,
            user_id=user_id,
            pipeline_type=pipeline
        )
        
        return {
            "message": "Analysis started in background",
            "evidence_id": evidence_id,
            "pipeline": pipeline,
            "status": "INDEXING"
        }
    except Exception as e:
        logger.error(f"Failed to start analysis: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start analysis: {str(e)}"
        )


@router.delete("/cases/{case_id}/evidence/{evidence_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_evidence(
    case_id: str,
    evidence_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Delete evidence."""
    
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    # Verify evidence exists and belongs to case
    evidence = await EvidenceService.get_evidence(db, evidence_id)
    if not evidence or evidence.case_id != case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found"
        )
    
    success = await EvidenceService.delete_evidence(db, evidence_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete evidence"
        )
    
    return None
