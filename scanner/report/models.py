from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def order(self) -> int:
        return {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}[self.value]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.order < other.order


class Finding(BaseModel):
    module: str
    title: str
    severity: Severity
    url: str
    description: str
    evidence: str = ""
    remediation: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)


class ScanReport(BaseModel):
    target_url: str
    started_at: datetime
    finished_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    @property
    def critical_count(self) -> int:
        return len(self.findings_by_severity[Severity.CRITICAL])

    @property
    def high_count(self) -> int:
        return len(self.findings_by_severity[Severity.HIGH])

    @property
    def medium_count(self) -> int:
        return len(self.findings_by_severity[Severity.MEDIUM])

    @property
    def low_count(self) -> int:
        return len(self.findings_by_severity[Severity.LOW])
