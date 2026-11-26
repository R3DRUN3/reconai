"""Pydantic models: scan request and the structured scan result."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .scope import TargetError, parse_target

Severity = Literal["info", "low", "medium", "high", "critical"]
Status = Literal["queued", "running", "completed", "failed", "cancelled"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[str] = Field(min_length=1, max_length=50,
                               description="Domains, IPs, CIDRs (max /24) or http(s) URLs. Defines the scan scope.")
    objective: str | None = Field(default=None, max_length=2000,
                                  description="Optional free text hint for the agent (e.g. 'focus on WordPress').")
    tools: list[str] | None = Field(default=None,
                                    description="Optional subset of the enabled tools to use for this scan.")
    max_steps: int | None = Field(default=None, ge=1, le=100)
    metadata: dict[str, str] = Field(default_factory=dict, description="Opaque labels echoed back in the result.")

    @field_validator("targets")
    @classmethod
    def _valid_targets(cls, v: list[str]) -> list[str]:
        out = []
        for t in v:
            try:
                parse_target(t)
            except TargetError as e:
                raise ValueError(f"{t!r}: {e}") from None
            out.append(t.strip())
        return out


class Finding(BaseModel):
    title: str
    severity: Severity = "info"
    target: str = ""
    description: str = ""
    evidence: str = ""
    recommendation: str = ""


class ToolRun(BaseModel):
    id: int
    tool: str
    arguments: dict
    argv: list[str] = Field(default_factory=list)
    status: Literal["ok", "error", "timeout", "rejected"]
    exit_code: int | None = None
    duration_s: float = 0.0
    truncated: bool = False
    output: str = ""
    started_at: datetime = Field(default_factory=utcnow)


class Usage(BaseModel):
    llm_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: Status = "queued"
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    targets: list[str]
    objective: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    model: str = ""
    tools_available: list[str] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    steps: int = 0
    summary: str = ""
    risk_rating: Severity | None = None
    findings: list[Finding] = Field(default_factory=list)
    report: str = Field(default="", description="Full human readable report (Markdown).")
    tool_runs: list[ToolRun] = Field(default_factory=list)
    usage: Usage = Field(default_factory=Usage)
    error: str | None = None

    def brief(self) -> dict:
        return {
            "scan_id": self.scan_id, "status": self.status, "targets": self.targets,
            "created_at": self.created_at, "finished_at": self.finished_at,
            "risk_rating": self.risk_rating, "findings": len(self.findings),
        }
