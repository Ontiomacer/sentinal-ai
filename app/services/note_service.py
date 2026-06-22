from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.models.case import CaseNote
from app.schemas.case import CaseNoteCreate, CaseNoteUpdate


class NoteService:
    """Service for managing case notes."""
    
    @staticmethod
    async def create_note(
        db: AsyncSession,
        case_id: str,
        user_id: str,
        author_name: str,
        note_data: CaseNoteCreate
    ) -> CaseNote:
        """Create a new case note."""
        note = CaseNote(
            case_id=case_id,
            title=note_data.title,
            content=note_data.content,
            note_type=note_data.note_type,
            user_id=user_id,
            author_name=author_name
        )
        
        db.add(note)
        await db.commit()
        await db.refresh(note)
        
        return note
    
    @staticmethod
    async def list_notes(
        db: AsyncSession,
        case_id: str
    ) -> List[CaseNote]:
        """List all notes for a case."""
        result = await db.execute(
            select(CaseNote)
            .where(CaseNote.case_id == case_id)
            .order_by(desc(CaseNote.created_at))
        )
        return result.scalars().all()
    
    @staticmethod
    async def get_note(
        db: AsyncSession,
        note_id: str
    ) -> Optional[CaseNote]:
        """Get a note by ID."""
        result = await db.execute(
            select(CaseNote).where(CaseNote.id == note_id)
        )
        return result.scalar_one_or_none()
    
    @staticmethod
    async def update_note(
        db: AsyncSession,
        note_id: str,
        user_id: str,
        note_data: CaseNoteUpdate
    ) -> Optional[CaseNote]:
        """Update a note (only by the author)."""
        note = await NoteService.get_note(db, note_id)
        if not note or note.user_id != user_id:
            return None
        
        if note_data.title is not None:
            note.title = note_data.title
        if note_data.content is not None:
            note.content = note_data.content
        if note_data.note_type is not None:
            note.note_type = note_data.note_type
        
        await db.commit()
        await db.refresh(note)
        
        return note
    
    @staticmethod
    async def delete_note(
        db: AsyncSession,
        note_id: str,
        user_id: str
    ) -> bool:
        """Delete a note (only by the author)."""
        note = await NoteService.get_note(db, note_id)
        if not note or note.user_id != user_id:
            return False
        
        await db.delete(note)
        await db.commit()
        
        return True
