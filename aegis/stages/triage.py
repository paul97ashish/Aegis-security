"""Triage — deduplicate, cluster, and rank by severity × confidence."""

from __future__ import annotations

from aegis.models import Candidate, Confidence, Finding


class Triage:
    def run(self, candidates: list[Candidate]) -> list[Finding]:
        deduped = self._dedup(candidates)
        clustered = self._cluster(deduped)
        findings = [Finding(candidate=c, cluster_id=cid) for c, cid in clustered]
        findings.sort(key=lambda f: f.score, reverse=True)
        return findings

    def _dedup(self, candidates: list[Candidate]) -> list[Candidate]:
        """Collapse identical fingerprints, keeping the highest-confidence one."""
        best: dict[str, Candidate] = {}
        for c in candidates:
            fp = c.fingerprint()
            cur = best.get(fp)
            if cur is None or _rank(c) > _rank(cur):
                best[fp] = c
        return list(best.values())

    def _cluster(self, candidates: list[Candidate]) -> list[tuple[Candidate, str]]:
        """Group by (path, cwe) so the same bug class in one file clusters."""
        out: list[tuple[Candidate, str]] = []
        for c in candidates:
            cid = f"{c.location.path}::{c.cwe or c.category}"
            out.append((c, cid))
        return out


def _rank(c: Candidate) -> tuple[int, int]:
    return (c.severity.rank, c.confidence.rank if isinstance(c.confidence, Confidence) else 0)
