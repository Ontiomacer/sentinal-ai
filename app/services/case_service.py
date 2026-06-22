import os
import json
from pathlib import Path
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from app.models.case import Case, Evidence, TimelineEvent, Entity, CaseNote, CaseStatus
from app.schemas.case import CaseCreate, CaseUpdate
from app.config import settings


class CaseService:
    """Service for managing forensic investigation cases."""
    
    CASE_SUBDIRS = [
        "evidence",
        "extracted",
        "exports",
        "reports",
        "timeline",
        "uploads",
        "ghidra",
        "jadx",
        "iocs",
        "intelligence",
        "memory",
        "network",
        "ai_findings",
        "logs",
        "triage",
        "screenshots",
        "notes",
        "timelines"
    ]
    
    @staticmethod
    async def create_case(
        db: AsyncSession,
        case_data: CaseCreate,
        user_id: str
    ) -> Case:
        """Create a new forensic case with directory structure."""
        
        # Create case instance
        case = Case(
            name=case_data.name,
            client_name=case_data.client_name,
            investigator=case_data.investigator,
            description=case_data.description,
            severity=case_data.severity,
            tags=json.dumps(case_data.tags) if case_data.tags else None,
            user_id=user_id,
            case_directory=""  # Will be set after ID generation
        )
        
        db.add(case)
        await db.flush()  # Generate ID
        
        # Create case directory structure
        case_dir = Path(settings.storage_dir) / "cases" / case.id
        case.case_directory = str(case_dir)
        
        # Create all subdirectories
        for subdir in CaseService.CASE_SUBDIRS:
            subdir_path = case_dir / subdir
            subdir_path.mkdir(parents=True, exist_ok=True)
        
        # Create case metadata file
        metadata = {
            "case_id": case.id,
            "name": case.name,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "investigator": case.investigator,
            "client": case.client_name,
            "severity": case.severity.value
        }
        
        metadata_file = case_dir / "case_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        await db.commit()
        await db.refresh(case)
        
        return case
    
    @staticmethod
    async def get_case(db: AsyncSession, case_id: str, user_id: str) -> Optional[Case]:
        """Get a case by ID (with user access check)."""
        result = await db.execute(
            select(Case).where(
                Case.id == case_id,
                Case.user_id == user_id
            )
        )
        case = result.scalar_one_or_none()
        if case:
            return case

        if settings.DEBUG and user_id != "user_dev":
            legacy_result = await db.execute(
                select(Case).where(
                    Case.id == case_id,
                    Case.user_id == "user_dev"
                )
            )
            legacy_case = legacy_result.scalar_one_or_none()
            if legacy_case:
                legacy_case.user_id = user_id
                await db.commit()
                await db.refresh(legacy_case)
                return legacy_case

        return None
    
    @staticmethod
    async def list_cases(
        db: AsyncSession,
        user_id: str,
        status: Optional[CaseStatus] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[Case]:
        """List all cases for a user."""
        query = select(Case).where(Case.user_id == user_id)
        
        if status:
            query = query.where(Case.status == status)
        
        query = query.order_by(desc(Case.created_at)).offset(skip).limit(limit)
        
        result = await db.execute(query)
        cases = result.scalars().all()
        if cases or not settings.DEBUG or user_id == "user_dev":
            return cases

        legacy_query = select(Case).where(Case.user_id == "user_dev")
        if status:
            legacy_query = legacy_query.where(Case.status == status)
        legacy_query = legacy_query.order_by(desc(Case.created_at)).offset(skip).limit(limit)

        legacy_result = await db.execute(legacy_query)
        legacy_cases = legacy_result.scalars().all()
        if not legacy_cases:
            return []

        for case in legacy_cases:
            case.user_id = user_id
        await db.commit()
        for case in legacy_cases:
            await db.refresh(case)
        return legacy_cases
    
    @staticmethod
    async def update_case(
        db: AsyncSession,
        case_id: str,
        user_id: str,
        case_data: CaseUpdate
    ) -> Optional[Case]:
        """Update a case."""
        case = await CaseService.get_case(db, case_id, user_id)
        if not case:
            return None
        
        # Update fields
        if case_data.name is not None:
            case.name = case_data.name
        if case_data.client_name is not None:
            case.client_name = case_data.client_name
        if case_data.investigator is not None:
            case.investigator = case_data.investigator
        if case_data.description is not None:
            case.description = case_data.description
        if case_data.severity is not None:
            case.severity = case_data.severity
        if case_data.status is not None:
            case.status = case_data.status
        if case_data.tags is not None:
            case.tags = json.dumps(case_data.tags)
        
        await db.commit()
        await db.refresh(case)
        
        return case
    
    @staticmethod
    async def archive_case(
        db: AsyncSession,
        case_id: str,
        user_id: str
    ) -> Optional[Case]:
        """Archive a case."""
        case = await CaseService.get_case(db, case_id, user_id)
        if not case:
            return None
        
        case.status = CaseStatus.ARCHIVED
        await db.commit()
        await db.refresh(case)
        
        return case
    
    @staticmethod
    async def delete_case(
        db: AsyncSession,
        case_id: str,
        user_id: str
    ) -> bool:
        """Delete a case and its directory structure."""
        case = await CaseService.get_case(db, case_id, user_id)
        if not case:
            return False
        
        # Delete directory structure
        case_dir = Path(case.case_directory)
        if case_dir.exists():
            import shutil
            shutil.rmtree(case_dir)
        
        await db.delete(case)
        await db.commit()
        
        return True
    
    @staticmethod
    async def get_case_statistics(
        db: AsyncSession,
        case_id: str,
        user_id: str
    ) -> dict:
        """Get case statistics."""
        case = await CaseService.get_case(db, case_id, user_id)
        if not case:
            return {}
        
        # Count evidence
        evidence_count = await db.scalar(
            select(func.count(Evidence.id)).where(Evidence.case_id == case_id)
        )
        
        # Count timeline events
        timeline_count = await db.scalar(
            select(func.count(TimelineEvent.id)).where(TimelineEvent.case_id == case_id)
        )
        
        # Count entities
        entity_count = await db.scalar(
            select(func.count(Entity.id)).where(Entity.case_id == case_id)
        )
        
        # Count notes
        note_count = await db.scalar(
            select(func.count(CaseNote.id)).where(CaseNote.case_id == case_id)
        )
        
        return {
            "evidence_count": evidence_count or 0,
            "timeline_count": timeline_count or 0,
            "entity_count": entity_count or 0,
            "note_count": note_count or 0
        }
