"""
Investigation models — SQLAlchemy models for investigation sessions,
analyst notes, bookmarks, and timeline annotations.
"""

from sqlalchemy import Column, String, Text, Float, Integer, DateTime, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from app.database import Base


def generate_id() -> str:
    return str(uuid.uuid4())


class Investigation(Base):
    """An investigation session tied to a scan."""
    __tablename__ = "investigations"

    id = Column(String, primary_key=True, default=generate_id)
    scan_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False, default="Untitled Investigation")
    description = Column(Text, default="")
    status = Column(String, default="active")  # active, paused, completed, archived
    analyst_name = Column(String, default="Analyst")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Analysis metadata cached for quick access
    threat_level = Column(String, default="unknown")
    risk_score = Column(Float, default=0.0)
    malware_family = Column(String, default="")

    # Relationships
    notes = relationship("InvestigationNote", back_populates="investigation", cascade="all, delete-orphan")
    bookmarks = relationship("InvestigationBookmark", back_populates="investigation", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "analyst_name": self.analyst_name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "threat_level": self.threat_level,
            "risk_score": self.risk_score,
            "malware_family": self.malware_family,
            "notes_count": len(self.notes) if self.notes else 0,
            "bookmarks_count": len(self.bookmarks) if self.bookmarks else 0,
        }


class InvestigationNote(Base):
    """Analyst notes within an investigation."""
    __tablename__ = "investigation_notes"

    id = Column(String, primary_key=True, default=generate_id)
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False)
    content = Column(Text, nullable=False)
    note_type = Column(String, default="general")  # general, finding, question, action
    tags = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="notes")

    def to_dict(self):
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "content": self.content,
            "note_type": self.note_type,
            "tags": self.tags or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class InvestigationBookmark(Base):
    """Bookmarked items (functions, IOCs, patterns) within an investigation."""
    __tablename__ = "investigation_bookmarks"

    id = Column(String, primary_key=True, default=generate_id)
    investigation_id = Column(String, ForeignKey("investigations.id"), nullable=False)
    target_type = Column(String, nullable=False)  # function, ioc, pattern, api, string
    target_id = Column(String, nullable=False)
    label = Column(String, default="")
    notes = Column(Text, default="")
    severity = Column(String, default="medium")
    created_at = Column(DateTime, default=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="bookmarks")

    def to_dict(self):
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "label": self.label,
            "notes": self.notes,
            "severity": self.severity,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ThreatOpsInvestigation(Base):
    """Persisted, resumable Threat-Ops execution for one case evidence item."""

    __tablename__ = "threat_ops_investigations"
    __table_args__ = (
        UniqueConstraint("evidence_id", name="uq_threat_ops_investigation_evidence"),
    )

    id = Column(String, primary_key=True, default=generate_id)
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, default="pending")
    current_stage = Column(String, nullable=True)
    stages_json = Column(Text, nullable=False, default="[]")
    result_json = Column(Text, nullable=False, default="{}")
    error_json = Column(Text, nullable=True)
    resume_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
