"""Scanner — many narrow-scope agents, each on a small slice + threat context.

Two signal sources, combined:
  1. Deterministic KB sweep (regex patterns, CWE-mapped) — always available,
     gives real candidates with no model.
  2. Optional model sweep (cheap ``sweep`` role) on the same slice for
     semantic catches the regexes miss.

The orchestrator fans these out in parallel under a bounded semaphore.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.knowledge import patterns_for_language
from aegis.models import Candidate, CodeLocation, Confidence, Severity
from aegis.prompts import PROMPTS, render
from aegis.providers import Message, ProviderRouter
from aegis.stages.threat_model import _extract_json


class Scanner:
    def __init__(self, router: ProviderRouter | None = None, *, context_lines: int = 2) -> None:
        self.router = router
        self.context_lines = context_lines

    # -- Deterministic KB sweep --------------------------------------------

    def scan_text(self, rel_path: str, text: str, language: str | None) -> list[Candidate]:
        out: list[Candidate] = []
        lines = text.splitlines()
        for pattern in patterns_for_language(language):
            rx = pattern.compiled()
            for i, line in enumerate(lines):
                if rx.search(line):
                    out.append(self._candidate_from_pattern(pattern, rel_path, lines, i))
        return out

    def scan_file(self, root: str | Path, rel_path: str, language: str | None) -> list[Candidate]:
        full = Path(root) / rel_path
        try:
            text = full.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        return self.scan_text(rel_path, text, language)

    def _candidate_from_pattern(self, pattern, rel_path, lines, idx) -> Candidate:
        start = max(0, idx - self.context_lines)
        end = min(len(lines), idx + self.context_lines + 1)
        snippet = "\n".join(lines[start:end])
        return Candidate(
            title=pattern.title,
            description=f"Pattern '{pattern.id}' matched ({pattern.category}).",
            severity=pattern.severity,
            confidence=Confidence.LOW,
            cwe=pattern.cwe,
            category=pattern.category,
            location=CodeLocation(
                path=rel_path,
                start_line=idx + 1,
                end_line=idx + 1,
                snippet=snippet,
            ),
            detector=f"kb:{pattern.id}",
            raw_evidence=lines[idx].strip()[:300],
        )

    # -- Optional model sweep ----------------------------------------------

    async def scan_with_model(
        self,
        root: str | Path,
        rel_path: str,
        language: str | None,
        category: str,
        cwe_hints: list[str],
    ) -> list[Candidate]:
        if self.router is None:
            return []
        full = Path(root) / rel_path
        try:
            code = full.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        if not code.strip():
            return []
        tmpl = PROMPTS["scanner"]
        messages = [
            Message("system", tmpl.system),
            Message("user", render(
                tmpl.user,
                category=category,
                cwe_hints=", ".join(cwe_hints) or "any",
                path=rel_path,
                language=language or "unknown",
                code=code[:8000],
            )),
        ]
        result = await self.router.complete_role("sweep", messages, max_tokens=1200)
        if not result.ok or not result.text.strip():
            return []
        return self._parse_model(result.text, rel_path, category)

    def _parse_model(self, text: str, rel_path: str, category: str) -> list[Candidate]:
        try:
            data = json.loads(_extract_json(text))
        except Exception:
            return []
        out: list[Candidate] = []
        for c in data.get("candidates", []):
            try:
                out.append(Candidate(
                    title=c.get("title", "Untitled candidate"),
                    description=c.get("description", ""),
                    severity=_coerce_severity(c.get("severity")),
                    confidence=_coerce_confidence(c.get("confidence")),
                    cwe=c.get("cwe"),
                    category=category,
                    location=CodeLocation(
                        path=rel_path,
                        start_line=int(c.get("start_line", 1) or 1),
                    ),
                    detector="model:sweep",
                    raw_evidence=c.get("evidence", ""),
                ))
            except Exception:
                continue
        return out


def _coerce_severity(value) -> Severity:
    try:
        return Severity(str(value).lower())
    except Exception:
        return Severity.MEDIUM


def _coerce_confidence(value) -> Confidence:
    try:
        return Confidence(str(value).lower())
    except Exception:
        return Confidence.LOW
