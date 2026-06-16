"""Async pipeline orchestrator (design §4).

Wires the stages into a DAG: map → threat-model → parallel scan → triage →
PoC-gated verify → report. The scanner fan-out runs under a bounded semaphore
(cheap ``sweep`` model wide, strong ``deep`` model on promising candidates).

In ``engage`` mode every target proposed at every stage is routed back through
the authorization gate before any action — the harness can never expand its own
scope (guardrail §11.2).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from aegis.config import Config, Profile
from aegis.engagement.authorize import Authorizer
from aegis.models import (
    ActionClass,
    Candidate,
    CodebaseMap,
    Finding,
    Report,
    ThreatModel,
)
from aegis.providers import ProviderRouter
from aegis.sandbox import EmitForReviewSandbox
from aegis.stages import Mapper, Reporter, Scanner, ThreatModeler, Triage, Verifier

ProgressFn = Callable[[str, dict], None]


@dataclass
class PipelineResult:
    report: Report
    codebase_map: CodebaseMap
    threat_model: ThreatModel
    findings: list[Finding] = field(default_factory=list)


def _noop_progress(stage: str, data: dict) -> None:  # pragma: no cover - trivial
    pass


class Orchestrator:
    def __init__(
        self,
        config: Config,
        *,
        offline: bool = False,
        authorizer: Authorizer | None = None,
        sandbox=None,
        progress: ProgressFn = _noop_progress,
    ) -> None:
        self.config = config
        self.router = ProviderRouter(config, offline=offline)
        self.authorizer = authorizer  # None in scan mode
        self.sandbox = sandbox or EmitForReviewSandbox()
        self.progress = progress

        self.mapper = Mapper()
        self.threat_modeler = ThreatModeler(self.router)
        self.scanner = Scanner(self.router)
        self.triage = Triage()
        self.verifier = Verifier(self.router, sandbox=self.sandbox)
        self.reporter = Reporter(self.router)

    async def run(
        self,
        target: str,
        *,
        profile: Profile,
        mode: str = "scan",
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> PipelineResult:
        root = str(Path(target).resolve()) if mode == "scan" else target

        # --- map ---
        self.progress("mapper", {"target": target})
        cmap = self.mapper.map(root, include=include, exclude=exclude) if mode == "scan" \
            else self.mapper.map(target, include=include, exclude=exclude)
        self.progress("mapper.done", {"files": len(cmap.files), "surfaces": len(cmap.surfaces)})

        # --- threat model ---
        self.progress("threat_model", {})
        tmodel = await self.threat_modeler.build(cmap)
        self.progress("threat_model.done", {"targets": len(tmodel.targets)})

        # --- scan (parallel fan-out) ---
        candidates = await self._scan(root, cmap, tmodel, profile, mode)
        self.progress("scanner.done", {"candidates": len(candidates)})

        # --- triage ---
        findings = self.triage.run(candidates)
        self.progress("triage.done", {"findings": len(findings)})

        # --- verify (PoC gate) ---
        findings = await self._verify(root, findings, profile)
        self.progress("verifier.done", {
            "confirmed": sum(1 for f in findings if f.confirmed),
        })

        if profile.confirm_only:
            findings = [f for f in findings if f.confirmed]

        report = Report(
            target=target,
            mode=mode,
            findings=findings,
            metadata={
                "languages": cmap.languages,
                "frameworks": cmap.frameworks,
                "profile": profile.description,
                "scope_amendment_recommendations": (
                    self.authorizer.scope_amendment_recommendations if self.authorizer else []
                ),
            },
        )
        self.progress("report.done", report.counts())
        return PipelineResult(
            report=report, codebase_map=cmap, threat_model=tmodel, findings=findings
        )

    # -- internals ----------------------------------------------------------

    async def _scan(
        self,
        root: str,
        cmap: CodebaseMap,
        tmodel: ThreatModel,
        profile: Profile,
        mode: str,
    ) -> list[Candidate]:
        sem = asyncio.Semaphore(max(1, profile.max_parallel))
        scannable = [f for f in cmap.files if f.language]
        categories = tmodel.ranked()

        async def scan_one(file_info) -> list[Candidate]:
            async with sem:
                # Engage mode: a file/target must clear the gate before scanning.
                if mode == "engage" and self.authorizer is not None:
                    decision = self.authorizer.authorize(
                        "scan_file", ActionClass.VULN_SCAN, file_info.path, actor="scanner"
                    )
                    if not decision.allowed:
                        return []
                # 1) deterministic KB sweep (always)
                found = self.scanner.scan_file(root, file_info.path, file_info.language)
                # 2) optional model sweep on the top threat category for this file
                if categories:
                    top = categories[0]
                    found += await self.scanner.scan_with_model(
                        root, file_info.path, file_info.language,
                        top.category, top.cwe_ids,
                    )
                return found

        results = await asyncio.gather(*(scan_one(f) for f in scannable))
        return [c for batch in results for c in batch]

    async def _verify(
        self, root: str, findings: list[Finding], profile: Profile
    ) -> list[Finding]:
        sem = asyncio.Semaphore(max(1, profile.max_parallel // 2 or 1))

        async def verify_one(finding: Finding) -> Finding:
            async with sem:
                execute = profile.execute_pocs
                # Engage mode: exploitation/PoC execution must clear the gate.
                if execute and self.authorizer is not None:
                    decision = self.authorizer.authorize(
                        "run_poc", ActionClass.EXPLOITATION,
                        finding.candidate.location.path, actor="verifier",
                    )
                    execute = decision.allowed
                return await self.verifier.verify(finding, root, execute_poc=execute)

        return await asyncio.gather(*(verify_one(f) for f in findings))
