"""FastAPI backend reusing the same orchestrator (design §8).

Lazy-imports FastAPI so the core package installs without it.
"""

from __future__ import annotations

from pathlib import Path

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover - optional extra
    raise SystemExit(
        "FastAPI not installed. Install with: pip install 'aegis-scan[web]'"
    ) from exc

from aegis.config import load_config
from aegis.orchestrator import Orchestrator
from aegis.stages.reporter import Reporter

app = FastAPI(title="Aegis", version="0.1.0")


class ScanRequest(BaseModel):
    target: str
    profile: str = "default"
    offline: bool = True


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "aegis"}


@app.post("/scan")
async def scan(req: ScanRequest) -> dict:
    if not Path(req.target).exists():
        raise HTTPException(status_code=400, detail="target path does not exist")
    config = load_config()
    orch = Orchestrator(config, offline=req.offline)
    prof = config.profile(req.profile)
    result = await orch.run(req.target, profile=prof, mode="scan")
    reporter = Reporter(None)
    return {
        "target": req.target,
        "counts": result.report.counts(),
        "sarif": reporter.sarif(result.report),
        "findings": [f.model_dump(mode="json") for f in result.report.sorted_findings()],
    }
