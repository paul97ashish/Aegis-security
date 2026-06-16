"""Structured objects that flow between pipeline stages.

Stages exchange these typed objects — never free text — so each stage is
independently testable and swappable (design §4).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(str, Enum):
    """CVSS-aligned qualitative severity bands."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Confidence(str, Enum):
    """How sure we are a candidate is a true positive."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"  # PoC reproduced it

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "confirmed": 3}[self.value]


class ActionClass(str, Enum):
    """Engagement action classes gated by the RoE (design §7)."""

    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    EXPLOITATION = "exploitation"
    DENIAL_OF_SERVICE = "denial_of_service"
    SOCIAL_ENGINEERING = "social_engineering"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DESTRUCTIVE_PAYLOADS = "destructive_payloads"


class PoCStatus(str, Enum):
    EMITTED = "emitted"  # generated, not executed (emit-for-review default)
    REPRODUCED = "reproduced"  # ran in sandbox and confirmed the issue
    FAILED = "failed"  # ran but did not reproduce
    SKIPPED = "skipped"  # execution not authorized / not attempted


# ---------------------------------------------------------------------------
# Codebase mapping (mapper stage)
# ---------------------------------------------------------------------------


class FileInfo(BaseModel):
    path: str
    language: str | None = None
    size_bytes: int = 0
    is_entry_point: bool = False


class AttackSurface(BaseModel):
    """A data-flow / attack surface discovered by the mapper."""

    kind: str  # e.g. "http_route", "cli_arg", "file_read", "deserialize", "sql"
    path: str
    line: int = 0
    detail: str = ""


class CodebaseMap(BaseModel):
    root: str
    files: list[FileInfo] = Field(default_factory=list)
    languages: dict[str, int] = Field(default_factory=dict)  # language -> file count
    frameworks: list[str] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    surfaces: list[AttackSurface] = Field(default_factory=list)

    def slices(self, max_files: int = 1) -> list[list[FileInfo]]:
        """Chunk files into small slices for narrow per-agent scanning."""
        out: list[list[FileInfo]] = []
        for i in range(0, len(self.files), max_files):
            out.append(self.files[i : i + max_files])
        return out


# ---------------------------------------------------------------------------
# Threat model (threat_model stage)
# ---------------------------------------------------------------------------


class ThreatTarget(BaseModel):
    category: str  # auth, input_handling, deserialization, sql, ssrf, file_io, secrets...
    priority: int = 0  # higher = scan first
    rationale: str = ""
    related_paths: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)


class ThreatModel(BaseModel):
    targets: list[ThreatTarget] = Field(default_factory=list)

    def ranked(self) -> list[ThreatTarget]:
        return sorted(self.targets, key=lambda t: t.priority, reverse=True)


# ---------------------------------------------------------------------------
# Findings (scanner -> triage -> verifier -> reporter)
# ---------------------------------------------------------------------------


class CodeLocation(BaseModel):
    path: str
    start_line: int = 1
    end_line: int | None = None
    snippet: str = ""


class Candidate(BaseModel):
    """A potential vulnerability proposed by a scanner. Not yet confirmed."""

    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.LOW
    cwe: str | None = None
    category: str = ""
    location: CodeLocation
    detector: str = ""  # which detector / agent produced this
    raw_evidence: str = ""
    created_at: datetime = Field(default_factory=_utcnow)

    def fingerprint(self) -> str:
        """Stable identity for dedup (path + line + cwe + title)."""
        key = f"{self.location.path}:{self.location.start_line}:{self.cwe}:{self.title}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class PoC(BaseModel):
    """A minimal reproduction artifact. Emit-for-review by default (design §6)."""

    candidate_fingerprint: str
    language: str = "text"
    description: str = ""
    payload: str = ""  # the reproduction script / request — model-generated at run time
    setup: str = ""
    expected_signal: str = ""  # what proves the bug reproduced
    status: PoCStatus = PoCStatus.EMITTED
    execution_log: str = ""

    @property
    def reproduced(self) -> bool:
        return self.status is PoCStatus.REPRODUCED


class Finding(BaseModel):
    """A triaged candidate, optionally promoted to CONFIRMED by a PoC."""

    candidate: Candidate
    poc: PoC | None = None
    cvss: float | None = None
    cvss_vector: str | None = None
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    verified: bool = False  # second-agent / PoC gate passed
    cluster_id: str | None = None

    @property
    def confirmed(self) -> bool:
        return self.verified and (self.poc is not None and self.poc.reproduced)

    @property
    def score(self) -> float:
        """Triage ordering key: severity weighted by confidence."""
        conf = (
            Confidence.CONFIRMED if self.confirmed else self.candidate.confidence
        ).rank
        return self.candidate.severity.rank * 10 + conf


class Report(BaseModel):
    target: str
    mode: str = "scan"  # "scan" | "engage"
    generated_at: datetime = Field(default_factory=_utcnow)
    findings: list[Finding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.confirmed]

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.score, reverse=True)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.candidate.severity.value] += 1
        out["confirmed"] = len(self.confirmed)
        out["total"] = len(self.findings)
        return out


# ---------------------------------------------------------------------------
# Engagement authorization (engagement layer)
# ---------------------------------------------------------------------------


class AuthDecision(BaseModel):
    """The outcome of an authorize() pre-flight check (design §7.3)."""

    allowed: bool
    action: str
    action_class: ActionClass
    target: str
    reason: str = ""
    requires_approval: bool = False
    timestamp: datetime = Field(default_factory=_utcnow)
