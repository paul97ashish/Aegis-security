"""Verifier — a *different* agent checks the first agent's work, PoC-gated.

This is the gate between "candidate" and "confirmed" (design §1.3). The
verifier re-reasons about the candidate, optionally generates a minimal,
non-destructive PoC, and — when execution is authorized — runs it in the
sandbox. A finding is CONFIRMED only if the PoC reproduces.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.knowledge import remediation_for_cwe
from aegis.models import Finding, PoC, PoCStatus, Severity
from aegis.prompts import PROMPTS, render
from aegis.providers import Message, ProviderRouter
from aegis.stages.threat_model import _extract_json

# Heuristic CVSS base scores by severity, used when no model score is available.
_CVSS_BY_SEVERITY = {
    Severity.INFO: 0.0,
    Severity.LOW: 3.1,
    Severity.MEDIUM: 5.3,
    Severity.HIGH: 7.5,
    Severity.CRITICAL: 9.8,
}


class Verifier:
    def __init__(self, router: ProviderRouter | None = None, sandbox=None) -> None:
        self.router = router
        self.sandbox = sandbox

    async def verify(
        self,
        finding: Finding,
        root: str | Path,
        *,
        execute_poc: bool = False,
    ) -> Finding:
        cand = finding.candidate
        # Deterministic baseline so the stage is useful with no model.
        finding.cvss = finding.cvss or _CVSS_BY_SEVERITY.get(cand.severity, 5.0)
        finding.remediation = finding.remediation or remediation_for_cwe(cand.cwe)

        verdict = "uncertain"
        if self.router is not None:
            verdict = await self._model_verify(finding, root)

        # Second-agent agreement promotes confidence but does not "confirm".
        if verdict == "true_positive":
            finding.verified = True
        elif verdict == "false_positive":
            finding.verified = False
            return finding

        # PoC gate: only execution-confirmed reproduction yields CONFIRMED.
        if finding.poc is not None and execute_poc and self.sandbox is not None:
            await self._run_poc(finding, root)
        return finding

    async def _model_verify(self, finding: Finding, root: str | Path) -> str:
        cand = finding.candidate
        code = self._context(root, cand.location.path, cand.location.start_line)
        tmpl = PROMPTS["verifier"]
        messages = [
            Message("system", tmpl.system),
            Message("user", render(
                tmpl.user,
                title=cand.title,
                cwe=cand.cwe or "unknown",
                severity=cand.severity.value,
                path=cand.location.path,
                line=cand.location.start_line,
                code=code,
            )),
        ]
        result = await self.router.complete_role("deep", messages, max_tokens=2000)
        if not result.ok or not result.text.strip():
            return "uncertain"
        return self._apply_verdict(finding, result.text)

    def _apply_verdict(self, finding: Finding, text: str) -> str:
        try:
            data = json.loads(_extract_json(text))
        except Exception:
            return "uncertain"
        verdict = str(data.get("verdict", "uncertain")).lower()
        if data.get("cvss") is not None:
            try:
                finding.cvss = float(data["cvss"])
            except (TypeError, ValueError):
                pass
        if data.get("cvss_vector"):
            finding.cvss_vector = str(data["cvss_vector"])
        if data.get("remediation"):
            finding.remediation = str(data["remediation"])
        poc_data = data.get("poc")
        if isinstance(poc_data, dict):
            finding.poc = PoC(
                candidate_fingerprint=finding.candidate.fingerprint(),
                language=poc_data.get("language", "text"),
                description=poc_data.get("description", ""),
                setup=poc_data.get("setup", ""),
                payload=poc_data.get("payload", ""),
                expected_signal=poc_data.get("expected_signal", ""),
                status=PoCStatus.EMITTED,
            )
        return verdict

    async def _run_poc(self, finding: Finding, root: str | Path) -> None:
        poc = finding.poc
        if poc is None:
            return
        try:
            outcome = await self.sandbox.run(poc, root)
        except Exception as exc:  # pragma: no cover - sandbox/runtime dependent
            poc.status = PoCStatus.SKIPPED
            poc.execution_log = f"sandbox error: {exc}"
            return
        poc.status = outcome.status
        poc.execution_log = outcome.log
        if poc.status is PoCStatus.REPRODUCED:
            finding.verified = True

    def _context(self, root: str | Path, rel: str, line: int, window: int = 25) -> str:
        try:
            text = (Path(root) / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""
        lines = text.splitlines()
        start = max(0, line - window)
        end = min(len(lines), line + window)
        return "\n".join(lines[start:end])
