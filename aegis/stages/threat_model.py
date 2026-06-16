"""Threat model — rank likely attack targets so effort is prioritized.

Deterministic priors derived from the mapper's attack surfaces, optionally
refined by a model call (design §3). Runs fine with no model (offline).
"""

from __future__ import annotations

import json

from aegis.models import CodebaseMap, ThreatModel, ThreatTarget
from aegis.prompts import PROMPTS, render
from aegis.providers import Message, ProviderRouter

# Surface kind -> (threat category, base priority, cwe hints).
SURFACE_TO_THREAT: dict[str, tuple[str, int, list[str]]] = {
    "sql": ("sql_injection", 90, ["CWE-89"]),
    "deserialize": ("deserialization", 85, ["CWE-502"]),
    "http_route": ("input_handling", 70, ["CWE-20", "CWE-79"]),
    "user_input": ("input_handling", 65, ["CWE-20"]),
    "outbound_http": ("ssrf", 60, ["CWE-918"]),
    "file_io": ("file_io", 55, ["CWE-22"]),
    "cli_arg": ("input_handling", 40, ["CWE-78"]),
}


class ThreatModeler:
    def __init__(self, router: ProviderRouter | None = None) -> None:
        self.router = router

    def build_deterministic(self, cmap: CodebaseMap) -> ThreatModel:
        agg: dict[str, ThreatTarget] = {}
        for surface in cmap.surfaces:
            mapping = SURFACE_TO_THREAT.get(surface.kind)
            if not mapping:
                continue
            category, base, cwes = mapping
            tgt = agg.get(category)
            if tgt is None:
                tgt = ThreatTarget(
                    category=category,
                    priority=base,
                    rationale=f"{surface.detail} observed in the codebase",
                    cwe_ids=list(cwes),
                )
                agg[category] = tgt
            else:
                # More occurrences => slightly higher priority (capped).
                tgt.priority = min(100, tgt.priority + 1)
            if surface.path not in tgt.related_paths:
                tgt.related_paths.append(surface.path)

        # Secrets and auth are always worth a look.
        agg.setdefault("secrets", ThreatTarget(
            category="secrets", priority=50, rationale="Credential/secret leakage is high impact",
            cwe_ids=["CWE-798"]))
        agg.setdefault("auth", ThreatTarget(
            category="auth", priority=45, rationale="Authentication/authorization flaws",
            cwe_ids=["CWE-287", "CWE-862"]))
        return ThreatModel(targets=list(agg.values()))

    async def build(self, cmap: CodebaseMap) -> ThreatModel:
        deterministic = self.build_deterministic(cmap)
        if self.router is None:
            return deterministic
        tmpl = PROMPTS["threat_model"]
        surfaces_txt = "\n".join(
            f"- {s.kind} @ {s.path}:{s.line} ({s.detail})" for s in cmap.surfaces[:80]
        )
        messages = [
            Message("system", tmpl.system),
            Message("user", render(
                tmpl.user,
                languages=", ".join(cmap.languages) or "unknown",
                frameworks=", ".join(cmap.frameworks) or "none detected",
                entry_points="\n".join(cmap.entry_points[:20]) or "none",
                surfaces=surfaces_txt or "none",
            )),
        ]
        result = await self.router.complete_role("sweep", messages, max_tokens=1500)
        model_targets = self._parse(result.text)
        if not model_targets:
            return deterministic
        # Merge: model priorities override, deterministic fills gaps.
        merged: dict[str, ThreatTarget] = {t.category: t for t in deterministic.targets}
        for t in model_targets:
            merged[t.category] = t
        return ThreatModel(targets=list(merged.values()))

    def _parse(self, text: str) -> list[ThreatTarget]:
        try:
            data = json.loads(_extract_json(text))
            return [ThreatTarget(**t) for t in data.get("targets", [])]
        except Exception:
            return []


def _extract_json(text: str) -> str:
    """Pull the first JSON object out of a possibly chatty model response."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]
    return text
