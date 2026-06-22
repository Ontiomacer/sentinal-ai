from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.scan import Scan
from app.schemas.scan import ScanCreate
from typing import List, Optional


class ScanService:
    """Service for managing scan records."""
    
    @staticmethod
    async def create_scan(db: AsyncSession, scan_data: ScanCreate) -> Scan:
        """
        Create a new scan record in the database.
        
        Args:
            db: Database session
            scan_data: Scan creation data
            
        Returns:
            Created Scan object
        """
        scan = Scan(
            sha256=scan_data.sha256,
            filename=scan_data.filename,
            file_size=scan_data.file_size,
            file_path=scan_data.file_path,
            status=scan_data.status
        )
        
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        return scan
    
    @staticmethod
    async def get_scan_by_id(db: AsyncSession, scan_id: str) -> Optional[Scan]:
        """
        Retrieve a scan by its ID.
        
        Args:
            db: Database session
            scan_id: Scan identifier
            
        Returns:
            Scan object or None if not found
        """
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_scan_by_sha256(db: AsyncSession, sha256: str) -> Optional[Scan]:
        """
        Retrieve a scan by SHA256 hash.
        
        Args:
            db: Database session
            sha256: SHA256 hash
            
        Returns:
            Scan object or None if not found
        """
        result = await db.execute(select(Scan).where(Scan.sha256 == sha256))
        return result.scalar_one_or_none()

    @staticmethod
    async def list_scans(db: AsyncSession, skip: int = 0, limit: int = 100) -> List[Scan]:
        """Return recent scans for real scan-history views."""
        result = await db.execute(
            select(Scan)
            .order_by(Scan.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())
