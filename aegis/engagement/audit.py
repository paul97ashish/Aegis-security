"""Tamper-evident, hash-chained, append-only audit log (design §7.6).

Every authorization decision (allow AND deny), model call, PoC attempt, and
operator confirmation is recorded. Each record embeds the previous record's
hash, so any edit or deletion breaks the chain and is detectable. In ``engage``
mode the log cannot be silently disabled (guardrail §11.5).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

GENESIS = "0" * 64


class AuditRecord(BaseModel):
    ts: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    engagement: str
    roe_hash: str
    actor: str
    action: str
    target: str = ""
    decision: str = ""  # allow | deny | n/a
    model: str = ""
    result: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)
    prev: str = GENESIS
    hash: str = ""

    def _payload_without_hash(self) -> dict[str, Any]:
        data = self.model_dump()
        data.pop("hash", None)
        return data

    def compute_hash(self) -> str:
        canonical = json.dumps(self._payload_without_hash(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only JSONL log with an in-memory tail hash."""

    def __init__(self, path: str | Path, engagement: str, roe_hash: str) -> None:
        self.path = Path(path)
        self.engagement = engagement
        self.roe_hash = roe_hash
        self._last_hash = self._load_tail_hash()

    def _load_tail_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line).get("hash", last)
                    except json.JSONDecodeError:
                        continue
        return last

    def record(
        self,
        actor: str,
        action: str,
        *,
        target: str = "",
        decision: str = "",
        model: str = "",
        result: str = "",
        detail: dict[str, Any] | None = None,
    ) -> AuditRecord:
        rec = AuditRecord(
            engagement=self.engagement,
            roe_hash=self.roe_hash,
            actor=actor,
            action=action,
            target=target,
            decision=decision,
            model=model,
            result=result,
            detail=detail or {},
            prev=self._last_hash,
        )
        rec.hash = rec.compute_hash()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(rec.model_dump_json() + "\n")
        self._last_hash = rec.hash
        return rec

    # -- integrity verification --------------------------------------------

    def verify_chain(self) -> tuple[bool, str]:
        """Re-walk the log; return (ok, message). Detects edits/deletions."""
        if not self.path.exists():
            return True, "no audit log yet"
        prev = GENESIS
        n = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                n += 1
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"line {lineno}: malformed JSON"
                stored_hash = data.get("hash", "")
                if data.get("prev") != prev:
                    return False, f"line {lineno}: broken chain (prev mismatch)"
                rec = AuditRecord.model_validate(data)
                if rec.compute_hash() != stored_hash:
                    return False, f"line {lineno}: record hash mismatch (tampered)"
                prev = stored_hash
        return True, f"audit chain intact ({n} records)"

    @property
    def head(self) -> str:
        return self._last_hash
