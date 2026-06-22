from sqlalchemy import Column, String, Integer, DateTime, Text
from sqlalchemy.sql import func
from app.database import Base
import uuid


class Scan(Base):
    """Database model for APK scan records."""
    
    __tablename__ = "scans"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sha256 = Column(String(64), unique=True, index=True, nullable=False)
    filename = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)
    file_path = Column(String(512), nullable=False)
    status = Column(String(50), default="pending", nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Analysis results (to be populated later)
    analysis_result = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<Scan(id={self.id}, filename={self.filename}, status={self.status})>"
