"""Prompt templates rendered with Jinja2.

Design tactics baked in: treat the model as a discovery harness; narrow,
per-agent instructions; require a working PoC before a finding counts.
"""

from __future__ import annotations

from dataclasses import dataclass

from jinja2 import Template


@dataclass(frozen=True)
class PromptTemplate:
    name: str
    version: str
    system: str
    user: str


SCANNER = PromptTemplate(
    name="scanner",
    version="v1",
    system=(
        "You are a focused security scanner. Examine ONLY the provided code slice for the "
        "specified threat category. Report concrete, evidence-backed candidate vulnerabilities. "
        "Do not speculate beyond the code shown. Prefer recall but tag uncertain items as low "
        "confidence. Return STRICT JSON only."
    ),
    user=(
        "Threat category: {{ category }}\n"
        "CWE hints: {{ cwe_hints }}\n"
        "File: {{ path }} ({{ language }})\n\n"
        "Code:\n```\n{{ code }}\n```\n\n"
        "Return JSON: {\"candidates\": [{\"title\":str, \"severity\":\"info|low|medium|high|critical\", "
        "\"confidence\":\"low|medium|high\", \"cwe\":str, \"start_line\":int, \"description\":str, "
        "\"evidence\":str}]}. If none, return {\"candidates\": []}."
    ),
)

THREAT_MODEL = PromptTemplate(
    name="threat_model",
    version="v1",
    system=(
        "You are a threat-modeling assistant. Given a codebase summary, rank the most likely "
        "attack targets so scanning effort is prioritized. Be concrete and concise. JSON only."
    ),
    user=(
        "Languages: {{ languages }}\nFrameworks: {{ frameworks }}\n"
        "Entry points:\n{{ entry_points }}\n\nAttack surfaces:\n{{ surfaces }}\n\n"
        "Return JSON: {\"targets\": [{\"category\":str, \"priority\":int(0-100), "
        "\"rationale\":str, \"cwe_ids\":[str], \"related_paths\":[str]}]}."
    ),
)

VERIFIER = PromptTemplate(
    name="verifier",
    version="v1",
    system=(
        "You are an independent second reviewer. A different agent flagged a candidate "
        "vulnerability. Critically re-check it against the code. A finding is NOT real until a "
        "minimal proof-of-concept reproduces it. If plausibly real, produce a minimal, "
        "non-destructive PoC that proves reachability/exploitability with the least action "
        "necessary. Never include destructive payloads. JSON only."
    ),
    user=(
        "Candidate: {{ title }}\nCWE: {{ cwe }}  Severity: {{ severity }}\n"
        "File: {{ path }}:{{ line }}\n\nCode context:\n```\n{{ code }}\n```\n\n"
        "Decide if this is a true positive. Return JSON: {\"verdict\":\"true_positive|false_positive|uncertain\", "
        "\"reasoning\":str, \"cvss\":float|null, \"cvss_vector\":str|null, \"remediation\":str, "
        "\"poc\": {\"language\":str, \"description\":str, \"setup\":str, \"payload\":str, "
        "\"expected_signal\":str} | null}."
    ),
)

REPORTER = PromptTemplate(
    name="reporter",
    version="v1",
    system=(
        "You are a security report writer. Produce a remediation-first executive summary for the "
        "findings. Be precise, non-sensational, and actionable. Plain prose, no markdown headers."
    ),
    user=(
        "Target: {{ target }}\nMode: {{ mode }}\n"
        "Findings ({{ count }} total, {{ confirmed }} PoC-confirmed):\n{{ findings }}\n\n"
        "Write a 2-4 paragraph executive summary."
    ),
)

PROMPTS: dict[str, PromptTemplate] = {
    p.name: p for p in (SCANNER, THREAT_MODEL, VERIFIER, REPORTER)
}


def render(template: str, **ctx) -> str:
    return Template(template, autoescape=False).render(**ctx)
