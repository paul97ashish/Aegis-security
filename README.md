# Aegis — Defensive AI Vulnerability-Research Harness

> An open-source, model-agnostic harness that finds security vulnerabilities, verifies each
> finding with a sandboxed proof-of-concept, and produces remediation-focused reports.

Aegis runs in two modes that share **one pipeline**:

- **`scan` — Self-scan:** for codebases you own.
- **`engage` — Engagement:** for **authorized** client penetration tests, gated by a signed
  Rules-of-Engagement (RoE) manifest.

See [`AEGIS_DESIGN.md`](./AEGIS_DESIGN.md) for the full design.

---

## Design principles

1. **Defensive / authorized by construction.** `scan` targets local code you own; `engage`
   targets only what a signed, in-window RoE authorizes.
2. **The harness is the product, not the model.** Orchestration, verification, and knowledge
   injection matter more than raw model quality.
3. **A finding is not real until a PoC reproduces it** — the gate between *candidate* and
   *confirmed*.
4. **Model-agnostic** — Claude, OpenRouter, Ollama, local, or OpenCode fill any role per stage.
5. **Human-in-the-loop on anything that executes.** PoCs default to *emit-for-review*.
6. **Fail closed.** Any ambiguity about authorization, scope, or signature halts the action.

---

## Install

```bash
# Core (runs the deterministic KB sweep + full pipeline, no model required):
pip install -e .

# With model providers / sandbox / UIs:
pip install -e '.[models]'    # LiteLLM + Anthropic SDK
pip install -e '.[sandbox]'   # Docker PoC sandbox
pip install -e '.[tui]'       # Textual TUI
pip install -e '.[web]'       # FastAPI web UI
pip install -e '.[dev]'       # tests, ruff, mypy
```

Python 3.11+.

---

## Quick start — `scan`

```bash
# Full pipeline, deterministic (no model calls), writes md + sarif + json:
aegis scan ./my-repo --offline

# Use models per role; only report PoC-confirmed findings:
aegis scan . --role sweep=ollama/qwen2.5-coder:7b --role deep=anthropic/claude-opus-4-8 \
             --profile deep --confirm-only

# Restrict / exclude paths:
aegis scan . --scope src/ --exclude tests/

# Execute PoCs in a sandbox (opt-in, requires ownership ack + Docker):
aegis scan . --execute-pocs --authorized

# Convert a saved JSON report to SARIF:
aegis report --in aegis-report.json --format sarif -o aegis.sarif
```

`scan` defaults to **emit-for-review**: PoCs are generated but not executed unless you pass
`--execute-pocs --authorized`.

---

## Quick start — `engage` (authorized pentest)

Engagement mode replaces the local-code lock with a contract-grade authorization layer. Nothing
runs unless it is provably in scope, inside the engagement window, and permitted by the signed
RoE.

```bash
# 1) Generate signing keypairs (client authorizer + tester):
aegis keys generate client
aegis keys generate tester

# 2) Each party signs the canonicalized manifest:
aegis keys sign configs/roe.example.yaml --key .aegis/keys/client.sec   # -> client sig
aegis keys sign configs/roe.example.yaml --key .aegis/keys/tester.sec   # -> tester sig

# 3) Provide detached signatures + pinned public keys as JSON:
#    signatures.json: {"client":"<hex>","tester":"<hex>"}
#    keys.json:       {"client":"<pubhex>","tester":"<pubhex>"}

# Verify signatures, scope, and window — do nothing else:
aegis engage --roe configs/roe.example.yaml \
             --signatures signatures.json --keys keys.json --verify-only

# Run recon + vuln_scan (no exploitation):
aegis engage --roe configs/roe.example.yaml \
             --signatures signatures.json --keys keys.json --profile recon

# Emergency stop:
aegis engage --roe configs/roe.example.yaml --kill

# Verify the tamper-evident audit chain:
aegis engage audit-verify audit.jsonl
```

The tool **fails closed** on any missing/invalid/expired/modified signature, on out-of-window
runs, and on out-of-scope targets. Every authorization decision (allow **and** deny) is written
to a hash-chained, append-only audit log.

---

## Architecture

```
target ─▶ mapper ─▶ threat_model ─▶ orchestrator (parallel scanners)
                                          │  cheap/local "sweep" model
                                          ▼
                                       triage (dedup + rank)
                                          ▼
                                   verifier (strong "deep" model)
                                   generate PoC → sandbox
                                   CONFIRMED iff it reproduces
                                          ▼
                                   reporter → Markdown + SARIF + JSON
```

Stages exchange typed objects (`Candidate`, `Finding`), never free text, so each is
independently testable and swappable. In `engage` mode every proposed target is routed back
through the authorization gate before any action — the harness can never expand its own scope.

| Stage | Module | Role |
|---|---|---|
| Surface mapping | `aegis/stages/mapper.py` | files, languages, entry points, attack surfaces |
| Threat model | `aegis/stages/threat_model.py` | rank likely attack targets |
| Scanning | `aegis/stages/scanner.py` | KB sweep + optional parallel model agents |
| Triage | `aegis/stages/triage.py` | dedup, cluster, rank by severity × confidence |
| Verify (PoC gate) | `aegis/stages/verifier.py` + `aegis/sandbox/` | second-agent check, PoC, sandbox |
| Report | `aegis/stages/reporter.py` | remediation-first MD/PDF + SARIF + JSON |
| Authorization | `aegis/engagement/` | RoE, signing, authorize gate, audit log |

---

## Model selection

`configs/default.yaml` maps logical roles → concrete models via LiteLLM, so
"local / Ollama / OpenRouter / Claude" is config, not code:

```yaml
roles:
  sweep:  ollama/qwen2.5-coder:7b        # wide, cheap, local
  deep:   anthropic/claude-opus-4-8      # high-reasoning verifier
  report: openrouter/anthropic/claude-sonnet-4-6
```

With no models configured (or `--offline`), Aegis still runs end-to-end using its deterministic,
CWE-mapped knowledge-base sweep — models *enhance* recall and drive PoC generation, they are not
required for a basic run.

---

## Guardrails (hard-coded, not flags)

1. No action outside authorization — fail closed, always.
2. No self-expanding scope — out-of-scope discoveries are reported, never touched.
3. Forbidden classes (DoS / exfiltration / persistence / destructive) stay forbidden unless the
   RoE explicitly authorizes them.
4. No detection-evasion or anti-forensics features.
5. The audit log cannot be silently disabled in `engage` mode.
6. No pre-built weaponized exploit library — PoCs are model-generated at run time against the
   specific authorized target.

---

## Development

```bash
pip install -e '.[dev]'
pytest -q          # run the suite (includes the seeded-bug eval corpus)
ruff check .       # lint
```

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
