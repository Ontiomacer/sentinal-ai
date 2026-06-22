from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.models.case import CaseSeverity, CaseStatus, EntityType


# Case Schemas
class CaseCreate(BaseModel):
    """Schema for creating a new case."""
    name: str = Field(..., min_length=1, max_length=255)
    client_name: Optional[str] = Field(None, max_length=255)
    investigator: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    severity: CaseSeverity = CaseSeverity.MEDIUM
    tags: Optional[List[str]] = None


class CaseUpdate(BaseModel):
    """Schema for updating a case."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    client_name: Optional[str] = Field(None, max_length=255)
    investigator: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    severity: Optional[CaseSeverity] = None
    status: Optional[CaseStatus] = None
    tags: Optional[List[str]] = None


class CaseResponse(BaseModel):
    """Schema for case response."""
    id: str
    name: str
    client_name: Optional[str]
    investigator: str
    description: Optional[str]
    severity: CaseSeverity
    status: CaseStatus
    tags: Optional[List[str]]
    user_id: str
    case_directory: str
    created_at: datetime
    updated_at: Optional[datetime]
    closed_at: Optional[datetime]
    
    # Statistics
    evidence_count: int = 0
    timeline_count: int = 0
    entity_count: int = 0
    note_count: int = 0
    
    class Config:
        from_attributes = True


class CaseFileNode(BaseModel):
    id: str
    name: str
    relative_path: str
    kind: str
    size: int = 0
    modified_at: str
    evidence_id: Optional[str] = None
    evidence_type: Optional[str] = None
    sha256: Optional[str] = None
    children: List["CaseFileNode"] = Field(default_factory=list)


class CaseDirectoryStatus(BaseModel):
    name: str
    relative_path: str
    exists: bool
    file_count: int = 0
    size: int = 0


class CaseFilesystemResponse(BaseModel):
    case_id: str
    root_path: str
    tree: CaseFileNode
    expected_directories: List[CaseDirectoryStatus]
    totals: Dict[str, int]


class TriageFileResponse(BaseModel):
    name: str
    path: str
    size: int
    modified_at: str


class TriageDriveResponse(BaseModel):
    name: str
    path: str
    status: str
    is_case_triage: bool = False
    file_count: int = 0
    size: int = 0
    last_seen: str
    files: List[TriageFileResponse] = []


class CaseTriageResponse(BaseModel):
    case_id: str
    drives: List[TriageDriveResponse]
    configured_roots_env: str


class CaseReportItem(BaseModel):
    id: str
    name: str
    report_type: str
    relative_path: str
    size: int
    modified_at: str
    sha256: Optional[str] = None


class CaseReportInventoryResponse(BaseModel):
    case_id: str
    reports: List[CaseReportItem]
    count: int


class CaseReportGenerateRequest(BaseModel):
    report_type: str = Field(..., pattern="^(executive|technical|timeline|ioc)$")


# Evidence Schemas
class EvidenceCreate(BaseModel):
    """Schema for creating evidence."""
    evidence_type: str = Field(..., max_length=50)
    notes: Optional[str] = None


class EvidenceResponse(BaseModel):
    """Schema for evidence response."""
    id: str
    case_id: str
    evidence_type: str
    filename: str
    original_filename: str
    file_size: int
    file_path: str
    md5: Optional[str]
    sha1: Optional[str]
    sha256: str
    analysis_status: str
    analysis_result: Optional[dict]
    uploaded_by: str
    notes: Optional[str]
    created_at: datetime
    analyzed_at: Optional[datetime]
    
    class Config:
        from_attributes = True


# Timeline Schemas
class TimelineEventCreate(BaseModel):
    """Schema for creating timeline event."""
    event_type: str = Field(..., max_length=50)
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    evidence_id: Optional[str] = None
    entity_id: Optional[str] = None
    metadata: Optional[dict] = None


class TimelineEventResponse(BaseModel):
    """Schema for timeline event response."""
    id: str
    case_id: str
    event_type: str
    title: str
    description: Optional[str]
    evidence_id: Optional[str]
    entity_id: Optional[str]
    user_id: str
    metadata: Optional[dict]
    created_at: datetime
    
    class Config:
        from_attributes = True


# Entity Schemas
class EntityCreate(BaseModel):
    """Schema for creating entity."""
    entity_type: EntityType
    name: str = Field(..., min_length=1, max_length=255)
    value: str = Field(..., min_length=1, max_length=512)
    description: Optional[str] = None
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    tags: Optional[List[str]] = None
    related_evidence: Optional[List[str]] = None
    metadata: Optional[dict] = None


class EntityUpdate(BaseModel):
    """Schema for updating entity."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    value: Optional[str] = Field(None, min_length=1, max_length=512)
    description: Optional[str] = None
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    tags: Optional[List[str]] = None
    related_evidence: Optional[List[str]] = None
    metadata: Optional[dict] = None


class EntityResponse(BaseModel):
    """Schema for entity response."""
    id: str
    case_id: str
    entity_type: EntityType
    name: str
    value: str
    description: Optional[str]
    risk_score: Optional[int]
    tags: Optional[List[str]]
    related_evidence: Optional[List[str]]
    metadata: Optional[dict]
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True


# Case Note Schemas
class CaseNoteCreate(BaseModel):
    """Schema for creating case note."""
    title: str = Field(..., min_length=1, max_length=255)
    content: str = Field(..., min_length=1)
    note_type: str = Field(default="general", max_length=50)


class CaseNoteUpdate(BaseModel):
    """Schema for updating case note."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    content: Optional[str] = Field(None, min_length=1)
    note_type: Optional[str] = Field(None, max_length=50)


class CaseNoteResponse(BaseModel):
    """Schema for case note response."""
    id: str
    case_id: str
    title: str
    content: str
    note_type: str
    user_id: str
    author_name: str
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True
