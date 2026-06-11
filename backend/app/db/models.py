from typing import Optional
from sqlmodel import SQLModel, Field
from datetime import datetime

class ScanHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    targets: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    technologies: str  # JSON encoded list of technologies
    ai_analysis: str = ""
    attack_surface_tree: str = Field(default="[]")

class Vulnerability(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scanhistory.id")
    type: str
    value: str
    severity: str
    status: str = Field(default="Investigating") # Investigating, Confirmed, Reported, Duplicate, N/A, False Positive
    is_new: bool = Field(default=True)
    fp_reason: str = Field(default="")

class ScanProfile(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True)
    config_json: str
