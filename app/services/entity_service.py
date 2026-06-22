import json
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.case import Entity
from app.schemas.case import EntityCreate, EntityUpdate


class EntityService:
    """Service for managing forensic entities."""
    
    @staticmethod
    async def create_entity(
        db: AsyncSession,
        case_id: str,
        entity_data: EntityCreate
    ) -> Entity:
        """Create a new entity."""
        entity = Entity(
            case_id=case_id,
            entity_type=entity_data.entity_type,
            name=entity_data.name,
            value=entity_data.value,
            description=entity_data.description,
            risk_score=entity_data.risk_score,
            tags=json.dumps(entity_data.tags) if entity_data.tags else None,
            related_evidence=json.dumps(entity_data.related_evidence) if entity_data.related_evidence else None,
            entity_metadata=json.dumps(entity_data.metadata) if entity_data.metadata else None
        )
        
        db.add(entity)
        await db.commit()
        await db.refresh(entity)
        
        return entity
    
    @staticmethod
    async def list_entities(
        db: AsyncSession,
        case_id: str
    ) -> List[Entity]:
        """List all entities for a case."""
        result = await db.execute(
            select(Entity).where(Entity.case_id == case_id)
        )
        return result.scalars().all()
    
    @staticmethod
    async def get_entity(
        db: AsyncSession,
        entity_id: str
    ) -> Optional[Entity]:
        """Get an entity by ID."""
        result = await db.execute(
            select(Entity).where(Entity.id == entity_id)
        )
        return result.scalar_one_or_none()
    
    @staticmethod
    async def update_entity(
        db: AsyncSession,
        entity_id: str,
        entity_data: EntityUpdate
    ) -> Optional[Entity]:
        """Update an entity."""
        entity = await EntityService.get_entity(db, entity_id)
        if not entity:
            return None
        
        if entity_data.name is not None:
            entity.name = entity_data.name
        if entity_data.value is not None:
            entity.value = entity_data.value
        if entity_data.description is not None:
            entity.description = entity_data.description
        if entity_data.risk_score is not None:
            entity.risk_score = entity_data.risk_score
        if entity_data.tags is not None:
            entity.tags = json.dumps(entity_data.tags)
        if entity_data.related_evidence is not None:
            entity.related_evidence = json.dumps(entity_data.related_evidence)
        if entity_data.metadata is not None:
            entity.entity_metadata = json.dumps(entity_data.metadata)
        
        await db.commit()
        await db.refresh(entity)
        
        return entity
    
    @staticmethod
    async def delete_entity(
        db: AsyncSession,
        entity_id: str
    ) -> bool:
        """Delete an entity."""
        entity = await EntityService.get_entity(db, entity_id)
        if not entity:
            return False
        
        await db.delete(entity)
        await db.commit()
        
        return True
