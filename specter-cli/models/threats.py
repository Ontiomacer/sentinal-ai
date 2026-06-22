from __future__ import annotations

from pydantic import BaseModel, Field


class ThreatScore(BaseModel):
    score: int = 0
    level: str = "unknown"
    evidence_id: str | None = None
    mappings: list[dict] = Field(default_factory=list)
