import os
import hashlib
import shutil
from pathlib import Path
from typing import Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from fastapi import UploadFile

from app.models.case import Evidence
from app.services.timeline_service import TimelineService


class EvidenceService:
    """Service for managing case evidence and file uploads."""
    
    ALLOWED_EXTENSIONS = {
        '.apk', '.dex', '.so', '.jar', '.zip', '.log', '.txt', '.json', '.xml',
        '.pcap', '.pcapng', '.png', '.jpg', '.jpeg', '.webp', '.gif', '.img', '.dd', '.raw'
    }
    MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB
    
    @staticmethod
    async def compute_hashes(file_path: Path) -> dict:
        """Compute MD5, SHA1, and SHA256 hashes for a file."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }
    
    @staticmethod
    def get_evidence_type(filename: str) -> str:
        """Determine evidence type from filename."""
        ext = Path(filename).suffix.lower()
        
        type_map = {
            '.apk': 'apk',
            '.dex': 'dex',
            '.so': 'native_library',
            '.jar': 'jar',
            '.zip': 'archive',
            '.pcap': 'packet_capture',
            '.pcapng': 'packet_capture',
            '.png': 'image',
            '.jpg': 'image',
            '.jpeg': 'image',
            '.webp': 'image',
            '.gif': 'image',
            '.img': 'disk_image',
            '.dd': 'disk_image',
            '.raw': 'disk_image',
            '.log': 'log',
            '.txt': 'text',
            '.json': 'json',
            '.xml': 'xml'
        }
        
        return type_map.get(ext, 'unknown')
    
    @staticmethod
    async def upload_evidence(
        db: AsyncSession,
        case_id: str,
        case_directory: str,
        file: UploadFile,
        user_id: str,
        notes: Optional[str] = None
    ) -> Evidence:
        """Upload evidence file to case vault."""
        
        # Validate file extension
        file_ext = Path(file.filename).suffix.lower()
        if file_ext not in EvidenceService.ALLOWED_EXTENSIONS:
            raise ValueError(f"File type {file_ext} not allowed")
        
        # Create evidence directory if it doesn't exist
        evidence_dir = Path(case_directory) / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{file.filename}"
        file_path = evidence_dir / safe_filename
        
        # Save file
        with open(file_path, 'wb') as f:
            shutil.copyfileobj(file.file, f)
        
        # Get file size
        file_size = file_path.stat().st_size
        
        # Validate file size
        if file_size > EvidenceService.MAX_FILE_SIZE:
            file_path.unlink()  # Delete file
            raise ValueError(f"File size exceeds maximum allowed size")
        
        # Compute hashes
        hashes = await EvidenceService.compute_hashes(file_path)
        
        # Determine evidence type
        evidence_type = EvidenceService.get_evidence_type(file.filename)
        
        # Create evidence record
        evidence = Evidence(
            case_id=case_id,
            evidence_type=evidence_type,
            filename=safe_filename,
            original_filename=file.filename,
            file_size=file_size,
            file_path=str(file_path),
            md5=hashes['md5'],
            sha1=hashes['sha1'],
            sha256=hashes['sha256'],
            analysis_status='ingested',
            uploaded_by=user_id,
            notes=notes
        )
        
        db.add(evidence)
        await db.flush()
        
        # Create timeline event
        await TimelineService.create_auto_event(
            db=db,
            case_id=case_id,
            user_id=user_id,
            event_type='upload',
            title=f'Evidence Uploaded: {file.filename}',
            description=f'File type: {evidence_type}, Size: {file_size} bytes',
            evidence_id=evidence.id,
            metadata={
                'filename': file.filename,
                'size': file_size,
                'type': evidence_type,
                'sha256': hashes['sha256']
            }
        )
        
        await db.commit()
        await db.refresh(evidence)
        
        return evidence
    
    @staticmethod
    async def list_evidence(
        db: AsyncSession,
        case_id: str,
        evidence_type: Optional[str] = None
    ) -> list[Evidence]:
        """List all evidence for a case."""
        query = select(Evidence).where(Evidence.case_id == case_id)
        
        if evidence_type:
            query = query.where(Evidence.evidence_type == evidence_type)
        
        query = query.order_by(desc(Evidence.created_at))
        
        result = await db.execute(query)
        return result.scalars().all()
    
    @staticmethod
    async def get_evidence(
        db: AsyncSession,
        evidence_id: str
    ) -> Optional[Evidence]:
        """Get evidence by ID."""
        result = await db.execute(
            select(Evidence).where(Evidence.id == evidence_id)
        )
        return result.scalar_one_or_none()
    
    @staticmethod
    async def update_analysis_status(
        db: AsyncSession,
        evidence_id: str,
        status: str,
        analysis_result: Optional[dict] = None
    ) -> Optional[Evidence]:
        """Update evidence analysis status."""
        evidence = await EvidenceService.get_evidence(db, evidence_id)
        if not evidence:
            return None
        
        evidence.analysis_status = status
        
        if analysis_result:
            import json
            evidence.analysis_result = json.dumps(analysis_result)
        
        if status == 'complete':
            evidence.analyzed_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(evidence)
        
        return evidence
    
    @staticmethod
    async def delete_evidence(
        db: AsyncSession,
        evidence_id: str
    ) -> bool:
        """Delete evidence and its file."""
        evidence = await EvidenceService.get_evidence(db, evidence_id)
        if not evidence:
            return False
        
        # Delete file
        file_path = Path(evidence.file_path)
        if file_path.exists():
            file_path.unlink()
        
        await db.delete(evidence)
        await db.commit()
        
        return True

    @staticmethod
    async def create_evidence_from_local_file(
        db: AsyncSession,
        case_id: str,
        file_path: Path,
        original_filename: str,
        user_id: str,
        notes: Optional[str] = None
    ) -> Evidence:
        """Create evidence entry for an already-copied local file."""
        # Get file size
        file_size = file_path.stat().st_size
        
        # Compute hashes
        hashes = await EvidenceService.compute_hashes(file_path)
        
        # Determine evidence type
        evidence_type = EvidenceService.get_evidence_type(original_filename)
        
        # Create evidence record
        evidence = Evidence(
            case_id=case_id,
            evidence_type=evidence_type,
            filename=file_path.name,
            original_filename=original_filename,
            file_size=file_size,
            file_path=str(file_path),
            md5=hashes['md5'],
            sha1=hashes['sha1'],
            sha256=hashes['sha256'],
            analysis_status='ingested',
            uploaded_by=user_id,
            notes=notes
        )
        
        db.add(evidence)
        await db.flush()
        
        # Create timeline event
        await TimelineService.create_auto_event(
            db=db,
            case_id=case_id,
            user_id=user_id,
            event_type='upload',
            title=f'Evidence Imported: {original_filename}',
            description=f'Imported from triage. Type: {evidence_type}, Size: {file_size} bytes',
            evidence_id=evidence.id,
            metadata={
                'filename': original_filename,
                'size': file_size,
                'type': evidence_type,
                'sha256': hashes['sha256']
            }
        )
        
        await db.commit()
        await db.refresh(evidence)
        
        return evidence
