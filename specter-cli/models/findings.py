from __future__ import annotations

from pydantic import BaseModel, Field


class Finding(BaseModel):
    title: str
    severity: str = "info"
    description: str = ""
    evidence_id: str | None = None
    metadata: dict = Field(default_factory=dict)
