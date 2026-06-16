from pathlib import Path

import pytest

from aegis.config import load_config
from aegis.orchestrator import Orchestrator
from aegis.stages.reporter import Reporter

CORPUS = str(Path(__file__).parent / "corpora")


@pytest.mark.asyncio
async def test_offline_pipeline_runs_end_to_end():
    config = load_config()
    orch = Orchestrator(config, offline=True)
    prof = config.profile("default")
    result = await orch.run(CORPUS, profile=prof, mode="scan")
    assert result.report.counts()["total"] > 0
    # Offline => no PoC execution => nothing confirmed.
    assert result.report.counts()["confirmed"] == 0
    # Verifier still attaches deterministic remediation + CVSS.
    f = result.report.sorted_findings()[0]
    assert f.cvss is not None and f.remediation


@pytest.mark.asyncio
async def test_sarif_is_well_formed():
    config = load_config()
    orch = Orchestrator(config, offline=True)
    result = await orch.run(CORPUS, profile=config.profile("default"), mode="scan")
    sarif = Reporter(None).sarif(result.report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Aegis"
    assert len(run["results"]) == result.report.counts()["total"]
    assert all("ruleId" in r and "locations" in r for r in run["results"])


@pytest.mark.asyncio
async def test_markdown_report_contains_sections():
    config = load_config()
    orch = Orchestrator(config, offline=True)
    result = await orch.run(CORPUS, profile=config.profile("default"), mode="scan")
    md = await Reporter(None).markdown(result.report)
    assert "# Aegis Security Report" in md
    assert "## Executive summary" in md
    assert "## Detailed findings" in md
