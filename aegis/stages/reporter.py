"""Reporter — remediation-first reports plus machine-readable SARIF/JSON.

Aligns with PTES / NIST SP 800-115 / OWASP WSTG (design §12): executive
summary, methodology, scope, findings with evidence + reproduction +
remediation, and an audit-trail appendix in engagement mode.
"""

from __future__ import annotations

import json
from typing import Any

from aegis.models import Finding, Report, Severity
from aegis.prompts import PROMPTS, render
from aegis.providers import Message, ProviderRouter

SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


class Reporter:
    def __init__(self, router: ProviderRouter | None = None) -> None:
        self.router = router

    # -- summary ------------------------------------------------------------

    async def executive_summary(self, report: Report) -> str:
        deterministic = self._deterministic_summary(report)
        if self.router is None:
            return deterministic
        tmpl = PROMPTS["reporter"]
        findings_txt = "\n".join(
            f"- [{f.candidate.severity.value}] {f.candidate.title} "
            f"({f.candidate.cwe or 'n/a'}) {'CONFIRMED' if f.confirmed else 'candidate'}"
            for f in report.sorted_findings()[:40]
        )
        messages = [
            Message("system", tmpl.system),
            Message("user", render(
                tmpl.user,
                target=report.target,
                mode=report.mode,
                count=len(report.findings),
                confirmed=len(report.confirmed),
                findings=findings_txt or "none",
            )),
        ]
        result = await self.router.complete_role("report", messages, max_tokens=900)
        return result.text.strip() if result.ok and result.text.strip() else deterministic

    def _deterministic_summary(self, report: Report) -> str:
        counts = report.counts()
        return (
            f"Aegis assessed {report.target} in {report.mode} mode and identified "
            f"{counts['total']} candidate findings ({counts['confirmed']} PoC-confirmed): "
            f"{counts[Severity.CRITICAL.value]} critical, {counts[Severity.HIGH.value]} high, "
            f"{counts[Severity.MEDIUM.value]} medium, {counts[Severity.LOW.value]} low. "
            "Confirmed findings reproduced under a sandboxed proof-of-concept; candidate "
            "findings warrant manual review. Prioritize remediation by severity and "
            "confirmation status."
        )

    # -- renderers ----------------------------------------------------------

    async def markdown(self, report: Report, *, scope_statement: str = "") -> str:
        summary = await self.executive_summary(report)
        counts = report.counts()
        lines: list[str] = [
            f"# Aegis Security Report — {report.target}",
            "",
            f"*Mode:* `{report.mode}`  ·  *Generated:* {report.generated_at.isoformat()}",
            "",
            "## Executive summary",
            "",
            summary,
            "",
            "## Methodology",
            "",
            "Findings were produced by the Aegis pipeline (map → threat-model → parallel "
            "scan → triage → PoC-gated verify) and align with PTES, NIST SP 800-115, and "
            "OWASP WSTG. A finding is marked **CONFIRMED** only when a sandboxed "
            "proof-of-concept reproduced it.",
            "",
        ]
        if scope_statement:
            lines += ["## Scope", "", scope_statement, ""]
        lines += [
            "## Findings overview",
            "",
            "| Severity | Count |",
            "|---|---|",
            f"| Critical | {counts[Severity.CRITICAL.value]} |",
            f"| High | {counts[Severity.HIGH.value]} |",
            f"| Medium | {counts[Severity.MEDIUM.value]} |",
            f"| Low | {counts[Severity.LOW.value]} |",
            f"| Info | {counts[Severity.INFO.value]} |",
            f"| **Confirmed (PoC)** | **{counts['confirmed']}** |",
            "",
            "## Detailed findings",
            "",
        ]
        for i, f in enumerate(report.sorted_findings(), start=1):
            lines.extend(self._finding_md(i, f))
        return "\n".join(lines)

    def _finding_md(self, idx: int, f: Finding) -> list[str]:
        c = f.candidate
        status = "✅ CONFIRMED (PoC reproduced)" if f.confirmed else (
            "🔎 Verified candidate" if f.verified else "🟡 Candidate"
        )
        out = [
            f"### {idx}. {c.title}",
            "",
            f"- **Status:** {status}",
            f"- **Severity:** {c.severity.value}"
            + (f" · **CVSS:** {f.cvss}" if f.cvss is not None else ""),
            f"- **CWE:** {c.cwe or 'n/a'}  ·  **Category:** {c.category or 'n/a'}",
            f"- **Location:** `{c.location.path}:{c.location.start_line}`",
            f"- **Detector:** {c.detector}",
            "",
        ]
        if c.description:
            out += [c.description, ""]
        if c.location.snippet:
            out += ["**Evidence:**", "", "```", c.location.snippet, "```", ""]
        if f.poc is not None:
            out += [
                f"**Proof of concept** ({f.poc.status.value}):",
                "",
                f"> {f.poc.description}" if f.poc.description else "",
                "```" + (f.poc.language or ""),
                f.poc.payload or "(emit-for-review: not executed)",
                "```",
                "",
            ]
            if f.poc.execution_log:
                out += ["<details><summary>Execution log</summary>", "",
                        "```", f.poc.execution_log[:4000], "```", "", "</details>", ""]
        if f.remediation:
            out += ["**Remediation:**", "", f.remediation, ""]
        if f.references:
            out += ["**References:** " + ", ".join(f.references), ""]
        return out

    # -- SARIF --------------------------------------------------------------

    def sarif(self, report: Report) -> dict[str, Any]:
        rules: dict[str, dict] = {}
        results: list[dict] = []
        for f in report.findings:
            c = f.candidate
            rule_id = c.cwe or c.detector or "AEGIS-GENERIC"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": c.category or "security-finding",
                    "shortDescription": {"text": c.title},
                    "helpUri": (c.cwe and f"https://cwe.mitre.org/data/definitions/{c.cwe.split('-')[-1]}.html") or "",
                    "properties": {"security-severity": str(f.cvss or _sev_score(c.severity))},
                }
            results.append({
                "ruleId": rule_id,
                "level": SARIF_LEVEL.get(c.severity, "warning"),
                "message": {"text": f"{c.title}. {f.remediation}".strip()},
                "properties": {
                    "confirmed": f.confirmed,
                    "confidence": c.confidence.value,
                    "detector": c.detector,
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": c.location.path},
                        "region": {
                            "startLine": max(1, c.location.start_line),
                            "endLine": max(1, c.location.end_line or c.location.start_line),
                            "snippet": {"text": c.location.snippet},
                        },
                    }
                }],
            })
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "Aegis",
                    "informationUri": "https://github.com/paul97ashish/aegis-security",
                    "version": "0.1.0",
                    "rules": list(rules.values()),
                }},
                "results": results,
            }],
        }

    def json_report(self, report: Report) -> str:
        return report.model_dump_json(indent=2)

    def write(
        self,
        report: Report,
        markdown: str,
        *,
        out_dir: str = ".",
        basename: str = "aegis-report",
        formats: list[str] | None = None,
    ) -> dict[str, str]:
        import os

        formats = formats or ["md", "sarif", "json"]
        os.makedirs(out_dir, exist_ok=True)
        written: dict[str, str] = {}
        if "md" in formats:
            p = os.path.join(out_dir, f"{basename}.md")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(markdown)
            written["md"] = p
        if "sarif" in formats:
            p = os.path.join(out_dir, f"{basename}.sarif")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(self.sarif(report), fh, indent=2)
            written["sarif"] = p
        if "json" in formats:
            p = os.path.join(out_dir, f"{basename}.json")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(self.json_report(report))
            written["json"] = p
        return written


def _sev_score(sev: Severity) -> float:
    return {Severity.INFO: 0.0, Severity.LOW: 3.1, Severity.MEDIUM: 5.3,
            Severity.HIGH: 7.5, Severity.CRITICAL: 9.8}[sev]
