"""Rules-of-Engagement manifest: schema, canonicalization, and load (design §7.1).

The RoE is effectively a machine-readable authorization-to-test letter. It is
canonicalized deterministically so its hash and signatures are stable and
verifiable on every startup.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class Party(BaseModel):
    name: str
    contact: str = ""


class Window(BaseModel):
    start: datetime
    end: datetime

    def contains(self, when: datetime) -> bool:
        when = _as_utc(when)
        return _as_utc(self.start) <= when <= _as_utc(self.end)


class Engagement(BaseModel):
    id: str
    client: str
    authorized_by: Party
    tester: Party
    window: Window


class ScopeList(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    repos: list[str] = Field(default_factory=list)


class Scope(BaseModel):
    allow: ScopeList = Field(default_factory=ScopeList)
    deny: ScopeList = Field(default_factory=ScopeList)


class Rules(BaseModel):
    permitted_classes: list[str] = Field(default_factory=lambda: ["recon", "vuln_scan"])
    forbidden: list[str] = Field(
        default_factory=lambda: [
            "denial_of_service",
            "social_engineering",
            "data_exfiltration",
            "lateral_movement",
            "persistence",
            "destructive_payloads",
        ]
    )
    max_request_rate: str = "20/s"
    require_human_approval_for: list[str] = Field(default_factory=lambda: ["exploitation"])

    def rate_per_second(self) -> float:
        """Parse ``N/s`` | ``N/m`` | ``N/h`` into requests per second."""
        raw = self.max_request_rate.strip().lower()
        if "/" not in raw:
            return float(raw)
        n, _, unit = raw.partition("/")
        per = {"s": 1, "m": 60, "h": 3600}.get(unit.strip()[:1], 1)
        return float(n) / per


class Safety(BaseModel):
    abort_contact: str = ""
    kill_switch: bool = True


class RoE(BaseModel):
    engagement: Engagement
    scope: Scope = Field(default_factory=Scope)
    rules: Rules = Field(default_factory=Rules)
    safety: Safety = Field(default_factory=Safety)

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization used for hashing & signing."""
        data = self.model_dump(mode="json", exclude_none=False)
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def manifest_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def in_window(self, when: datetime | None = None) -> bool:
        return self.engagement.window.contains(when or datetime.now(UTC))


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def load_roe(path: str | Path) -> RoE:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return RoE.model_validate(raw)
