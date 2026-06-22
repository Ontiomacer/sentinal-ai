from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
import json
import os
from pathlib import Path
import logging
import jwt
import traceback
from app.config import settings

from app.database import get_db
from app.models.case import CaseStatus
from app.schemas.case import (
    CaseCreate,
    CaseUpdate,
    CaseResponse,
    CaseFilesystemResponse,
    CaseTriageResponse,
    CaseReportInventoryResponse,
    CaseReportGenerateRequest,
    CaseReportItem,
    TimelineEventCreate,
    TimelineEventResponse,
    EntityCreate,
    EntityUpdate,
    EntityResponse,
    CaseNoteCreate,
    CaseNoteUpdate,
    CaseNoteResponse
)
from app.services.case_service import CaseService
from app.services.forensic_workspace_service import ForensicWorkspaceService
from app.services.timeline_service import TimelineService
from app.services.entity_service import EntityService
from app.services.note_service import NoteService

logger = logging.getLogger(__name__)

router = APIRouter()


def _log_exception(context: str, exc: BaseException) -> None:
    logger.error(traceback.format_exc())
    logger.error(f"{context} exception type: {type(exc).__name__}")
    logger.error(f"{context} exception message: {str(exc)}")


async def get_user_id(authorization: Optional[str] = Header(None)) -> str:
    """Extract and validate user ID from Clerk JWT token."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format"
        )

    token = authorization[7:]
    
    # For development/demo, allow mock tokens if DEBUG is on
    if settings.DEBUG and token.startswith("user_"):
        return token

    try:
        # For demo purposes, we decode the token to get the user ID.
        # In production, full RS256 verification via JWKS should be performed.
        payload = jwt.decode(token, options={"verify_signature": False})
        user_id = payload.get("sub")
        
        if not user_id:
            raise ValueError("Token missing 'sub' claim")
            
        return user_id

    except Exception as e:
        logger.error(traceback.format_exc())
        logger.error(f"Clerk authentication error type: {type(e).__name__}")
        logger.error(f"Clerk authentication error message: {str(e)}")
        # Fallback for development
        if settings.DEBUG:
            return "user_dev"
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )


# ============================================================================
# CASE ENDPOINTS
# ============================================================================

@router.post("/cases", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    case_data: CaseCreate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Create a new forensic investigation case."""
    case = await CaseService.create_case(db, case_data, user_id)
    
    # Get statistics
    stats = await CaseService.get_case_statistics(db, case.id, user_id)
    
    # Parse tags
    tags = json.loads(case.tags) if case.tags else None
    
    return CaseResponse(
        id=case.id,
        name=case.name,
        client_name=case.client_name,
        investigator=case.investigator,
        description=case.description,
        severity=case.severity,
        status=case.status,
        tags=tags,
        user_id=case.user_id,
        case_directory=case.case_directory,
        created_at=case.created_at,
        updated_at=case.updated_at,
        closed_at=case.closed_at,
        **stats
    )


@router.get("/cases", response_model=List[CaseResponse])
async def list_cases(
    status: Optional[CaseStatus] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """List all cases for the authenticated user."""
    cases = await CaseService.list_cases(db, user_id, status, skip, limit)
    
    result = []
    for case in cases:
        stats = await CaseService.get_case_statistics(db, case.id, user_id)
        tags = json.loads(case.tags) if case.tags else None
        
        result.append(CaseResponse(
            id=case.id,
            name=case.name,
            client_name=case.client_name,
            investigator=case.investigator,
            description=case.description,
            severity=case.severity,
            status=case.status,
            tags=tags,
            user_id=case.user_id,
            case_directory=case.case_directory,
            created_at=case.created_at,
            updated_at=case.updated_at,
            closed_at=case.closed_at,
            **stats
        ))
    
    return result


@router.get("/cases/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Get a specific case by ID."""
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    stats = await CaseService.get_case_statistics(db, case.id, user_id)
    tags = json.loads(case.tags) if case.tags else None
    
    return CaseResponse(
        id=case.id,
        name=case.name,
        client_name=case.client_name,
        investigator=case.investigator,
        description=case.description,
        severity=case.severity,
        status=case.status,
        tags=tags,
        user_id=case.user_id,
        case_directory=case.case_directory,
        created_at=case.created_at,
        updated_at=case.updated_at,
        closed_at=case.closed_at,
        **stats
    )


@router.patch("/cases/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: str,
    case_data: CaseUpdate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Update a case."""
    case = await CaseService.update_case(db, case_id, user_id, case_data)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    stats = await CaseService.get_case_statistics(db, case.id, user_id)
    tags = json.loads(case.tags) if case.tags else None
    
    return CaseResponse(
        id=case.id,
        name=case.name,
        client_name=case.client_name,
        investigator=case.investigator,
        description=case.description,
        severity=case.severity,
        status=case.status,
        tags=tags,
        user_id=case.user_id,
        case_directory=case.case_directory,
        created_at=case.created_at,
        updated_at=case.updated_at,
        closed_at=case.closed_at,
        **stats
    )


@router.post("/cases/{case_id}/archive", response_model=CaseResponse)
async def archive_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Archive a case."""
    case = await CaseService.archive_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    stats = await CaseService.get_case_statistics(db, case.id, user_id)
    tags = json.loads(case.tags) if case.tags else None
    
    return CaseResponse(
        id=case.id,
        name=case.name,
        client_name=case.client_name,
        investigator=case.investigator,
        description=case.description,
        severity=case.severity,
        status=case.status,
        tags=tags,
        user_id=case.user_id,
        case_directory=case.case_directory,
        created_at=case.created_at,
        updated_at=case.updated_at,
        closed_at=case.closed_at,
        **stats
    )


@router.delete("/cases/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Delete a case and all associated data."""
    success = await CaseService.delete_case(db, case_id, user_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    return None


# ============================================================================
# CASE FILESYSTEM, TRIAGE, AND REPORTS
# ============================================================================

@router.get("/cases/{case_id}/filesystem", response_model=CaseFilesystemResponse)
async def get_case_filesystem(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Return the real CSI-style case directory tree and storage statistics."""
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )

    return await ForensicWorkspaceService.get_filesystem(db, case)


@router.get("/cases/{case_id}/triage", response_model=CaseTriageResponse)
async def get_case_triage_drives(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Return case triage intake locations and configured forensic drive roots."""
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )

    return await ForensicWorkspaceService.get_triage_drives(case)


from pydantic import BaseModel

class TriageImportRequest(BaseModel):
    file_path: str

@router.post("/cases/{case_id}/triage/import")
async def import_triage_file(
    case_id: str,
    import_data: TriageImportRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Import a file from a triage drive directly into case evidence."""
    import shutil
    import os
    from app.services.evidence_service import EvidenceService
    
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    file_path = import_data.file_path
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Triage file not found"
        )
        
    # Check if path is within configured roots
    case_dir = Path(case.case_directory or (Path(settings.storage_dir) / "cases" / case.id))
    allowed_roots = [case_dir / "triage"]
    
    configured = os.environ.get("SENTINEL_TRIAGE_ROOTS", "")
    for val in configured.replace(";", os.pathsep).split(os.pathsep):
        if val.strip():
            allowed_roots.append(Path(val.strip()))
            
    is_allowed = False
    for root in allowed_roots:
        try:
            if path.resolve().is_relative_to(root.resolve()):
                is_allowed = True
                break
        except Exception as exc:
            _log_exception("Case triage path validation", exc)
            continue
            
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="File path is outside configured triage roots"
        )
        
    try:
        dest_dir = case_dir / "evidence"
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate unique filename in dest
        from datetime import datetime
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{path.name}"
        dest_path = dest_dir / safe_filename
        
        shutil.copy2(path, dest_path)
        
        evidence = await EvidenceService.create_evidence_from_local_file(
            db=db,
            case_id=case_id,
            file_path=dest_path,
            original_filename=path.name,
            user_id=user_id
        )
        
        return {
            "id": evidence.id,
            "case_id": evidence.case_id,
            "filename": evidence.filename,
            "original_filename": evidence.original_filename,
            "file_size": evidence.file_size,
            "file_path": evidence.file_path,
            "sha256": evidence.sha256,
            "analysis_status": evidence.analysis_status,
            "uploaded_by": evidence.uploaded_by,
            "created_at": evidence.created_at.isoformat()
        }
    except Exception as exc:
        _log_exception("Case triage import", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Import failed: {type(exc).__name__}: {str(exc)}"
        )


@router.get("/cases/{case_id}/reports/inventory", response_model=CaseReportInventoryResponse)
async def list_case_reports(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """List real generated report files for a case."""
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )

    return await ForensicWorkspaceService.list_reports(case)


@router.post("/cases/{case_id}/reports/generate", response_model=CaseReportItem)
async def generate_case_report(
    case_id: str,
    report_data: CaseReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Generate a report from real case, evidence, entity, timeline, and note data."""
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )

    try:
        return await ForensicWorkspaceService.generate_report(
            db=db,
            case=case,
            user_id=user_id,
            report_type=report_data.report_type
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get("/cases/{case_id}/reports/{report_name}/content")
async def get_report_content(
    case_id: str,
    report_name: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Get the raw text content of a generated report."""
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    case_dir = Path(case.case_directory or (Path(settings.storage_dir) / "cases" / case.id))
    report_file = case_dir / "reports" / report_name
    
    # Secure validation to avoid path traversal
    try:
        resolved_path = report_file.resolve()
        resolved_case_dir = case_dir.resolve()
        if not resolved_path.is_relative_to(resolved_case_dir):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
    except Exception as exc:
        _log_exception("Case report path validation", exc)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid path"
        )
        
    if not report_file.exists() or not report_file.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file not found"
        )
        
    try:
        content = report_file.read_text(encoding="utf-8")
        return {"content": content}
    except Exception as exc:
        _log_exception("Case report read", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read report: {type(exc).__name__}: {str(exc)}"
        )


# ============================================================================
# TIMELINE ENDPOINTS
# ============================================================================

@router.post("/cases/{case_id}/timeline", response_model=TimelineEventResponse, status_code=status.HTTP_201_CREATED)
async def create_timeline_event(
    case_id: str,
    event_data: TimelineEventCreate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Create a timeline event for a case."""
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    event = await TimelineService.create_event(db, case_id, user_id, event_data)
    
    return TimelineEventResponse(
        id=event.id,
        case_id=event.case_id,
        event_type=event.event_type,
        title=event.title,
        description=event.description,
        evidence_id=event.evidence_id,
        entity_id=event.entity_id,
        user_id=event.user_id,
        metadata=json.loads(event.event_metadata) if event.event_metadata else None,
        created_at=event.created_at
    )


@router.get("/cases/{case_id}/timeline", response_model=List[TimelineEventResponse])
async def list_timeline_events(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """List all timeline events for a case."""
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    events = await TimelineService.list_events(db, case_id)
    
    return [
        TimelineEventResponse(
            id=event.id,
            case_id=event.case_id,
            event_type=event.event_type,
            title=event.title,
            description=event.description,
            evidence_id=event.evidence_id,
            entity_id=event.entity_id,
            user_id=event.user_id,
            metadata=json.loads(event.event_metadata) if event.event_metadata else None,
            created_at=event.created_at
        )
        for event in events
    ]


# ============================================================================
# ENTITY ENDPOINTS
# ============================================================================

@router.post("/cases/{case_id}/entities", response_model=EntityResponse, status_code=status.HTTP_201_CREATED)
async def create_entity(
    case_id: str,
    entity_data: EntityCreate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Create a forensic entity for a case."""
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    entity = await EntityService.create_entity(db, case_id, entity_data)
    
    return EntityResponse(
        id=entity.id,
        case_id=entity.case_id,
        entity_type=entity.entity_type,
        name=entity.name,
        value=entity.value,
        description=entity.description,
        risk_score=entity.risk_score,
        tags=json.loads(entity.tags) if entity.tags else None,
        related_evidence=json.loads(entity.related_evidence) if entity.related_evidence else None,
        metadata=json.loads(entity.entity_metadata) if entity.entity_metadata else None,
        created_at=entity.created_at,
        updated_at=entity.updated_at
    )


@router.get("/cases/{case_id}/entities", response_model=List[EntityResponse])
async def list_entities(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """List all entities for a case."""
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    entities = await EntityService.list_entities(db, case_id)
    
    return [
        EntityResponse(
            id=entity.id,
            case_id=entity.case_id,
            entity_type=entity.entity_type,
            name=entity.name,
            value=entity.value,
            description=entity.description,
            risk_score=entity.risk_score,
            tags=json.loads(entity.tags) if entity.tags else None,
            related_evidence=json.loads(entity.related_evidence) if entity.related_evidence else None,
            metadata=json.loads(entity.entity_metadata) if entity.entity_metadata else None,
            created_at=entity.created_at,
            updated_at=entity.updated_at
        )
        for entity in entities
    ]


@router.patch("/cases/{case_id}/entities/{entity_id}", response_model=EntityResponse)
async def update_entity(
    case_id: str,
    entity_id: str,
    entity_data: EntityUpdate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Update an entity."""
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    entity = await EntityService.update_entity(db, entity_id, entity_data)
    if not entity:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Entity not found"
        )
    
    return EntityResponse(
        id=entity.id,
        case_id=entity.case_id,
        entity_type=entity.entity_type,
        name=entity.name,
        value=entity.value,
        description=entity.description,
        risk_score=entity.risk_score,
        tags=json.loads(entity.tags) if entity.tags else None,
        related_evidence=json.loads(entity.related_evidence) if entity.related_evidence else None,
        metadata=json.loads(entity.entity_metadata) if entity.entity_metadata else None,
        created_at=entity.created_at,
        updated_at=entity.updated_at
    )


# ============================================================================
# NOTE ENDPOINTS
# ============================================================================

@router.post("/cases/{case_id}/notes", response_model=CaseNoteResponse, status_code=status.HTTP_201_CREATED)
async def create_note(
    case_id: str,
    note_data: CaseNoteCreate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Create a note for a case."""
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    # Get author name (in production, fetch from Clerk)
    author_name = case.investigator
    
    note = await NoteService.create_note(db, case_id, user_id, author_name, note_data)
    
    return CaseNoteResponse(
        id=note.id,
        case_id=note.case_id,
        title=note.title,
        content=note.content,
        note_type=note.note_type,
        user_id=note.user_id,
        author_name=note.author_name,
        created_at=note.created_at,
        updated_at=note.updated_at
    )


@router.get("/cases/{case_id}/notes", response_model=List[CaseNoteResponse])
async def list_notes(
    case_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """List all notes for a case."""
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    notes = await NoteService.list_notes(db, case_id)
    
    return [
        CaseNoteResponse(
            id=note.id,
            case_id=note.case_id,
            title=note.title,
            content=note.content,
            note_type=note.note_type,
            user_id=note.user_id,
            author_name=note.author_name,
            created_at=note.created_at,
            updated_at=note.updated_at
        )
        for note in notes
    ]


@router.patch("/cases/{case_id}/notes/{note_id}", response_model=CaseNoteResponse)
async def update_note(
    case_id: str,
    note_id: str,
    note_data: CaseNoteUpdate,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Update a note."""
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    note = await NoteService.update_note(db, note_id, user_id, note_data)
    if not note:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found"
        )
    
    return CaseNoteResponse(
        id=note.id,
        case_id=note.case_id,
        title=note.title,
        content=note.content,
        note_type=note.note_type,
        user_id=note.user_id,
        author_name=note.author_name,
        created_at=note.created_at,
        updated_at=note.updated_at
    )


@router.delete("/cases/{case_id}/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_note(
    case_id: str,
    note_id: str,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_user_id)
):
    """Delete a note."""
    # Verify case access
    case = await CaseService.get_case(db, case_id, user_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found"
        )
    
    success = await NoteService.delete_note(db, note_id, user_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found"
        )
    
    return None
