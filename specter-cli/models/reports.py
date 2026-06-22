from __future__ import annotations

from pydantic import BaseModel


class ReportArtifact(BaseModel):
    id: str
    name: str
    report_type: str
    relative_path: str
    size: int
    modified_at: str
    sha256: str | None = None
