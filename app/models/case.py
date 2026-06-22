from sqlalchemy import Column, String, Integer, DateTime, Text, Enum as SQLEnum, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import uuid
import enum


class CaseSeverity(str, enum.Enum):
    """Case severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CaseStatus(str, enum.Enum):
    """Case status types."""
    ACTIVE = "active"
    ARCHIVED = "archived"
    CLOSED = "closed"
    PENDING = "pending"


class Case(Base):
    """Database model for forensic investigation cases."""
    
    __tablename__ = "cases"
    
    id = Column(String, primary_key=True, default=lambda: f"CASE-{uuid.uuid4().hex[:8].upper()}")
    name = Column(String(255), nullable=False)
    client_name = Column(String(255), nullable=True)
    investigator = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SQLEnum(CaseSeverity), default=CaseSeverity.MEDIUM, nullable=False)
    status = Column(SQLEnum(CaseStatus), default=CaseStatus.ACTIVE, nullable=False)
    tags = Column(Text, nullable=True)  # JSON array stored as text
    
    # Clerk user ID
    user_id = Column(String(255), nullable=False, index=True)
    
    # Directory path
    case_directory = Column(String(512), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    closed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    evidence = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="case", cascade="all, delete-orphan")
    entities = relationship("Entity", back_populates="case", cascade="all, delete-orphan")
    notes = relationship("CaseNote", back_populates="case", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Case(id={self.id}, name={self.name}, status={self.status})>"


class Evidence(Base):
    """Database model for case evidence items."""
    
    __tablename__ = "evidence"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Evidence metadata
    evidence_type = Column(String(50), nullable=False)  # apk, document, image, log, etc.
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)
    file_path = Column(String(512), nullable=False)
    
    # Hashes
    md5 = Column(String(32), nullable=True)
    sha1 = Column(String(40), nullable=True)
    sha256 = Column(String(64), nullable=False, index=True)
    
    # Analysis
    analysis_status = Column(String(50), default="pending", nullable=False)
    analysis_result = Column(Text, nullable=True)  # JSON stored as text
    
    # Chain of custody
    uploaded_by = Column(String(255), nullable=False)
    notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    analyzed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    case = relationship("Case", back_populates="evidence")
    
    def __repr__(self):
        return f"<Evidence(id={self.id}, filename={self.filename}, type={self.evidence_type})>"


class TimelineEvent(Base):
    """Database model for case timeline events."""
    
    __tablename__ = "timeline_events"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Event details
    event_type = Column(String(50), nullable=False)  # upload, analysis, report, note, finding
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Associated entities
    evidence_id = Column(String, nullable=True)
    entity_id = Column(String, nullable=True)
    
    # Metadata
    user_id = Column(String(255), nullable=False)
    event_metadata = Column(Text, nullable=True)  # JSON stored as text
    
    # Timestamp
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    case = relationship("Case", back_populates="timeline_events")
    
    def __repr__(self):
        return f"<TimelineEvent(id={self.id}, type={self.event_type}, title={self.title})>"


class EntityType(str, enum.Enum):
    """Entity types for forensic tracking."""
    PERSON = "person"
    DOMAIN = "domain"
    URL = "url"
    WALLET = "wallet"
    APK = "apk"
    ORGANIZATION = "organization"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    PHONE = "phone"


class Entity(Base):
    """Database model for forensic entities."""
    
    __tablename__ = "entities"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Entity details
    entity_type = Column(SQLEnum(EntityType), nullable=False)
    name = Column(String(255), nullable=False)
    value = Column(String(512), nullable=False)  # The actual entity value (URL, wallet address, etc.)
    
    # Context
    description = Column(Text, nullable=True)
    risk_score = Column(Integer, default=0, nullable=True)
    tags = Column(Text, nullable=True)  # JSON array
    
    # Relationships
    related_evidence = Column(Text, nullable=True)  # JSON array of evidence IDs
    entity_metadata = Column(Text, nullable=True)  # JSON stored as text
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    case = relationship("Case", back_populates="entities")
    
    def __repr__(self):
        return f"<Entity(id={self.id}, type={self.entity_type}, name={self.name})>"


class CaseNote(Base):
    """Database model for investigator notes."""
    
    __tablename__ = "case_notes"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Note content
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    note_type = Column(String(50), default="general", nullable=False)  # general, finding, hypothesis, conclusion
    
    # Author
    user_id = Column(String(255), nullable=False)
    author_name = Column(String(255), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    case = relationship("Case", back_populates="notes")
    
    def __repr__(self):
        return f"<CaseNote(id={self.id}, title={self.title})>"
