"""
Investigation Service — CRUD and management for investigation sessions,
notes, bookmarks, and timeline annotations.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
import uuid

from app.models.investigation import Investigation, InvestigationNote, InvestigationBookmark

logger = logging.getLogger(__name__)


class InvestigationService:
    """Manages investigation sessions and related artifacts."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Investigation CRUD
    # ------------------------------------------------------------------

    async def create_investigation(
        self,
        scan_id: str,
        title: str = "Untitled Investigation",
        description: str = "",
        analyst_name: str = "Analyst",
    ) -> Dict[str, Any]:
        """Create a new investigation session."""
        investigation = Investigation(
            id=str(uuid.uuid4()),
            scan_id=scan_id,
            title=title,
            description=description,
            analyst_name=analyst_name,
            status="active",
        )
        self.db.add(investigation)
        await self.db.commit()
        await self.db.refresh(investigation)
        return investigation.to_dict()

    async def get_investigation(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Get a single investigation by ID."""
        result = await self.db.execute(
            select(Investigation).where(Investigation.id == investigation_id)
        )
        inv = result.scalar_one_or_none()
        return inv.to_dict() if inv else None

    async def list_investigations(self, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List investigations, optionally filtered by scan_id."""
        query = select(Investigation).order_by(Investigation.updated_at.desc())
        if scan_id:
            query = query.where(Investigation.scan_id == scan_id)
        result = await self.db.execute(query)
        investigations = result.scalars().all()
        return [inv.to_dict() for inv in investigations]

    async def update_investigation(
        self,
        investigation_id: str,
        **updates: Any,
    ) -> Optional[Dict[str, Any]]:
        """Update investigation fields."""
        allowed_fields = {
            "title", "description", "status", "analyst_name",
            "threat_level", "risk_score", "malware_family",
        }
        filtered = {k: v for k, v in updates.items() if k in allowed_fields}
        if not filtered:
            return await self.get_investigation(investigation_id)

        filtered["updated_at"] = datetime.utcnow()
        await self.db.execute(
            update(Investigation)
            .where(Investigation.id == investigation_id)
            .values(**filtered)
        )
        await self.db.commit()
        return await self.get_investigation(investigation_id)

    async def delete_investigation(self, investigation_id: str) -> bool:
        """Delete an investigation and all related data."""
        result = await self.db.execute(
            delete(Investigation).where(Investigation.id == investigation_id)
        )
        await self.db.commit()
        return result.rowcount > 0

    # ------------------------------------------------------------------
    # Notes CRUD
    # ------------------------------------------------------------------

    async def add_note(
        self,
        investigation_id: str,
        content: str,
        note_type: str = "general",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add a note to an investigation."""
        note = InvestigationNote(
            id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            content=content,
            note_type=note_type,
            tags=tags or [],
        )
        self.db.add(note)
        await self.db.commit()
        await self.db.refresh(note)
        return note.to_dict()

    async def list_notes(self, investigation_id: str) -> List[Dict[str, Any]]:
        """List notes for an investigation."""
        result = await self.db.execute(
            select(InvestigationNote)
            .where(InvestigationNote.investigation_id == investigation_id)
            .order_by(InvestigationNote.created_at.desc())
        )
        notes = result.scalars().all()
        return [n.to_dict() for n in notes]

    async def delete_note(self, note_id: str) -> bool:
        """Delete a note."""
        result = await self.db.execute(
            delete(InvestigationNote).where(InvestigationNote.id == note_id)
        )
        await self.db.commit()
        return result.rowcount > 0

    # ------------------------------------------------------------------
    # Bookmarks CRUD
    # ------------------------------------------------------------------

    async def add_bookmark(
        self,
        investigation_id: str,
        target_type: str,
        target_id: str,
        label: str = "",
        notes: str = "",
        severity: str = "medium",
    ) -> Dict[str, Any]:
        """Add a bookmark to an investigation."""
        bookmark = InvestigationBookmark(
            id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            target_type=target_type,
            target_id=target_id,
            label=label,
            notes=notes,
            severity=severity,
        )
        self.db.add(bookmark)
        await self.db.commit()
        await self.db.refresh(bookmark)
        return bookmark.to_dict()

    async def list_bookmarks(self, investigation_id: str) -> List[Dict[str, Any]]:
        """List bookmarks for an investigation."""
        result = await self.db.execute(
            select(InvestigationBookmark)
            .where(InvestigationBookmark.investigation_id == investigation_id)
            .order_by(InvestigationBookmark.created_at.desc())
        )
        bookmarks = result.scalars().all()
        return [b.to_dict() for b in bookmarks]

    async def delete_bookmark(self, bookmark_id: str) -> bool:
        """Delete a bookmark."""
        result = await self.db.execute(
            delete(InvestigationBookmark).where(InvestigationBookmark.id == bookmark_id)
        )
        await self.db.commit()
        return result.rowcount > 0
