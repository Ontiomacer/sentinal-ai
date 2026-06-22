from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any, List


class ScanCreate(BaseModel):
    """Schema for creating a new scan record."""
    sha256: str
    filename: str
    file_size: int
    file_path: str
    status: str = "pending"


class RiskAssessment(BaseModel):
    """Schema for risk assessment results."""
    risk_score: int = Field(..., description="Risk score from 0-100")
    severity: str = Field(..., description="Risk severity: LOW/MEDIUM/HIGH/CRITICAL")
    findings: List[str] = Field(..., description="List of security findings")
    summary: str = Field(..., description="Human-readable risk summary")
    score_breakdown: Dict[str, int] = Field(..., description="Breakdown of score by category")


class ScanResponse(BaseModel):
    """Schema for scan response."""
    scan_id: str = Field(..., description="Unique scan identifier")
    sha256: str = Field(..., description="SHA256 hash of the APK file")
    filename: str = Field(..., description="Original filename")
    file_size: int = Field(..., description="File size in bytes")
    status: str = Field(..., description="Scan status")
    created_at: datetime = Field(..., description="Timestamp of scan creation")
    analysis_result: Optional[Dict[str, Any]] = Field(None, description="Static analysis results")
    
    class Config:
        from_attributes = True
