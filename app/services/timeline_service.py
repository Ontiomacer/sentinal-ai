import json
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.models.case import TimelineEvent
from app.schemas.case import TimelineEventCreate


class TimelineService:
    """Service for managing case timeline events."""
    
    @staticmethod
    async def create_event(
        db: AsyncSession,
        case_id: str,
        user_id: str,
        event_data: TimelineEventCreate
    ) -> TimelineEvent:
        """Create a new timeline event."""
        event = TimelineEvent(
            case_id=case_id,
            event_type=event_data.event_type,
            title=event_data.title,
            description=event_data.description,
            evidence_id=event_data.evidence_id,
            entity_id=event_data.entity_id,
            user_id=user_id,
            event_metadata=json.dumps(event_data.metadata) if event_data.metadata else None
        )
        
        db.add(event)
        await db.commit()
        await db.refresh(event)
        
        return event
    
    @staticmethod
    async def list_events(
        db: AsyncSession,
        case_id: str,
        limit: int = 100
    ) -> List[TimelineEvent]:
        """List timeline events for a case."""
        result = await db.execute(
            select(TimelineEvent)
            .where(TimelineEvent.case_id == case_id)
            .order_by(desc(TimelineEvent.created_at))
            .limit(limit)
        )
        return result.scalars().all()
    
    @staticmethod
    async def create_auto_event(
        db: AsyncSession,
        case_id: str,
        user_id: str,
        event_type: str,
        title: str,
        description: str = None,
        evidence_id: str = None,
        metadata: dict = None
    ) -> TimelineEvent:
        """Create an automatic timeline event (for system actions)."""
        event = TimelineEvent(
            case_id=case_id,
            event_type=event_type,
            title=title,
            description=description,
            evidence_id=evidence_id,
            user_id=user_id,
            event_metadata=json.dumps(metadata) if metadata else None
        )
        
        db.add(event)
        await db.commit()
        await db.refresh(event)
        
        return event
