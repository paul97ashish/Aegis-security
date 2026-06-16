# Aegis — Defensive AI Vulnerability-Research Harness

> An open-source, model-agnostic harness that finds security vulnerabilities, **verifies each
> finding with a sandboxed proof-of-concept**, and produces remediation-focused reports.

Aegis treats a language model as a *discovery harness*, not a chat box. A swarm of narrow agents
sweeps your code in parallel; a second, stronger agent independently re-checks each candidate;
and **nothing is reported as "confirmed" until a minimal proof-of-concept actually reproduces
it** in an isolated sandbox. That PoC gate is what collapses the false-positive problem that
makes most LLM-based scanners noisy.

It runs in two modes that share **one pipeline**:

| Mode | For | Authorization |
|---|---|---|
| **`scan`** (self-scan) | Codebases you own | An `--authorized` acknowledgment (only needed to *execute* PoCs) |
| **`engage`** (engagement) | **Authorized** client pentests | A cryptographically **signed Rules-of-Engagement (RoE)** manifest |

The two modes have separate, non-overlapping authorization layers. You cannot run `engage`
without a valid, in-window, signed RoE. See [`AEGIS_DESIGN.md`](./AEGIS_DESIGN.md) for the full
design rationale.

---

## Table of contents

- [Why Aegis](#why-aegis)
- [Install](#install)
- [60-second tour](#60-second-tour)
- [How it works](#how-it-works)
  - [The pipeline](#the-pipeline)
  - [Candidate → Confirmed: the PoC gate](#candidate--confirmed-the-poc-gate)
  - [Works with or without a model](#works-with-or-without-a-model)
- [`scan` — self-scan](#scan--self-scan)
- [`engage` — authorized pentest](#engage--authorized-pentest)
- [Configuration](#configuration)
- [Understanding the output](#understanding-the-output)
- [Project layout](#project-layout)
- [Extending Aegis](#extending-aegis)
- [Guardrails](#guardrails-hard-coded-not-flags)
- [Development & testing](#development--testing)
- [Troubleshooting & FAQ](#troubleshooting--faq)
- [License](#license)

---

## Why Aegis

Most "AI security scanners" prompt a model once per file and dump whatever it says — which
buries real bugs under hallucinated ones. Aegis is built on a few opinionated bets:

1. **The harness is the product, not the model.** Orchestration, verification, and knowledge
   injection matter more than raw model quality, and they are the parts *you* control.
2. **A finding is not real until a PoC reproduces it.** This is the gate between *candidate* and
   *confirmed*.
3. **Model-agnostic.** Any model — Claude, OpenRouter, Ollama, a local OpenAI-compatible server,
   or an OpenCode agent — can fill any role in the pipeline, chosen per stage via config.
4. **Human-in-the-loop on anything that executes.** PoCs default to *emit-for-review*;
   execution is opt-in and sandboxed.
5. **Fail closed.** Any ambiguity about authorization, scope, or signature halts the action.

---

## Install

Requires **Python 3.11+**.

```bash
git clone https://github.com/paul97ashish/aegis-security
cd aegis-security

# Core — runs the full pipeline with the deterministic KB sweep (no model required):
pip install -e .

# Optional extras:
pip install -e '.[models]'    # LiteLLM + Anthropic SDK (Claude / OpenRouter / Ollama / local)
pip install -e '.[sandbox]'   # Docker-backed PoC sandbox
pip install -e '.[tui]'       # Textual terminal UI
pip install -e '.[web]'       # FastAPI web UI
pip install -e '.[dev]'       # pytest, ruff, mypy
pip install -e '.[all]'       # everything above
```

The core install has **no heavy dependencies** — `litellm`, `docker`, `anthropic`, `textual`,
and `fastapi` are all lazy-imported, so the pipeline runs out of the box and you add backends
only when you want them.

---

## 60-second tour

```bash
# Scan a folder with zero configuration and zero model calls:
aegis scan ./my-repo --offline
```

```
╭──────────────────────────────────────────╮
│ aegis scan → ./my-repo  (profile: default)│
╰──────────────────────────────────────────╯
        Aegis findings
┏━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Severity        ┃ Count ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ critical        │     0 │
│ high            │     6 │
│ medium          │     1 │
│ low             │     1 │
│ info            │     0 │
│ confirmed (PoC) │     0 │
└─────────────────┴───────┘
Reports written: ./aegis-report.md, ./aegis-report.sarif, ./aegis-report.json
```

You now have a human-readable Markdown report, a SARIF file for GitHub Code Scanning / your IDE,
and a machine-readable JSON report — all from local, deterministic analysis. Add models and the
PoC sandbox to turn candidates into PoC-confirmed findings.

---

## How it works

### The pipeline

Every run flows through the same six stages. Stages exchange **typed objects** (`Candidate`,
`Finding`) — never free text — so each is independently testable and swappable.

```
   target (owned repo, or in-scope client per signed RoE)
        │
        ▼
   ┌──────────┐   index files, languages, entry points, frameworks,
   │  mapper  │   and data-flow / attack surfaces
   └────┬─────┘
        ▼
   ┌──────────────┐   rank likely attack targets (sql, deserialization,
   │ threat_model │   ssrf, input handling, secrets, auth…) so effort
   └────┬─────────┘   is prioritized
        ▼
   ┌──────────── orchestrator (async fan-out, bounded semaphore) ────────────┐
   │  scanner-1   scanner-2   scanner-3  …  scanner-N        ← cheap "sweep"  │
   │  (each agent sees one small slice + the threat context)    model, wide  │
   └────┬─────────────────────────────────────────────────────────────────────┘
        ▼
   ┌──────────┐   deduplicate, cluster, rank by severity × confidence
   │  triage  │
   └────┬─────┘
        ▼
   ┌────────────────────────┐   a *different* agent re-checks the first agent's
   │       verifier          │   work, generates a minimal PoC, and (when
   │  generate PoC → sandbox │   authorized) runs it network-off in an
   │  CONFIRMED iff reproduces│   ephemeral container    ← strong "deep" model
   └────┬───────────────────┘
        ▼
   ┌──────────┐   remediation-first Markdown/PDF + SARIF + JSON
   │ reporter │
   └──────────┘
```

| Stage | Module | What it does |
|---|---|---|
| **mapper** | `aegis/stages/mapper.py` | Walks the tree; detects languages, frameworks, entry points, and attack surfaces (HTTP routes, SQL, deserialization, file I/O, outbound HTTP…). |
| **threat_model** | `aegis/stages/threat_model.py` | Turns surfaces into a ranked list of attack categories with CWE hints, so scanning is prioritized. |
| **scanner** | `aegis/stages/scanner.py` | Two signal sources combined: a deterministic, CWE-mapped **knowledge-base sweep** (always on) and an optional **model sweep** of narrow slices, fanned out in parallel. |
| **triage** | `aegis/stages/triage.py` | Collapses duplicate fingerprints, clusters by file × CWE, ranks by severity × confidence. |
| **verifier** | `aegis/stages/verifier.py` + `aegis/sandbox/` | Independent second-agent review, minimal non-destructive PoC generation, sandbox execution. The **gate** that promotes a candidate to *confirmed*. |
| **reporter** | `aegis/stages/reporter.py` | Executive summary + per-finding evidence, PoC, and remediation; emits Markdown, SARIF, and JSON. |

The whole thing is driven by `aegis/orchestrator.py`, which runs the scanner and verifier
fan-outs concurrently under an `asyncio` semaphore (cheap model sweeps wide; strong model
deep-dives the promising candidates).

### Candidate → Confirmed: the PoC gate

This is the core idea, so it's worth being precise about the states a finding moves through:

| State | Meaning | How it's reached |
|---|---|---|
| 🟡 **Candidate** | A detector flagged something worth a look. | KB pattern match or model sweep. |
| 🔎 **Verified candidate** | A second, independent agent agrees it's plausibly a true positive. | `verifier` with a `deep` model returns `true_positive`. |
| ✅ **Confirmed** | A minimal PoC **reproduced** the issue in the sandbox. | `verifier` + sandbox, with execution authorized. |

A finding is `confirmed` only when **both** the second-agent check passed **and** the PoC
reproduced (`Finding.confirmed` in `aegis/models.py`). Pass `--confirm-only` to report
exclusively confirmed findings — the highest-signal output, ideal for gating CI.

By default, PoCs are **emit-for-review**: the verifier writes the reproduction script into the
report but does **not** run it. Execution is opt-in (`--execute-pocs`) and, in `scan` mode,
requires you to acknowledge ownership with `--authorized`.

### Works with or without a model

Aegis degrades gracefully. With `--offline` (or no providers configured) it runs the entire
pipeline using only the deterministic, CWE-mapped knowledge base in `aegis/knowledge/patterns.py`
— you still get mapped surfaces, ranked threats, deduped/ranked findings, heuristic CVSS, and
remediation guidance. Models *enhance* recall and are what generate PoCs; they are not required
for a useful run. This makes Aegis usable in air-gapped or privacy-sensitive environments and
keeps CI fast and free.

---

## `scan` — self-scan

For code you own. Emit-for-review is the default; nothing executes unless you opt in.

```bash
# Full pipeline, deterministic, writes md + sarif + json to the current dir:
aegis scan ./my-repo --offline

# Use models per role and report only PoC-confirmed findings:
aegis scan . --role sweep=ollama/qwen2.5-coder:7b \
             --role deep=anthropic/claude-opus-4-8 \
             --profile deep --confirm-only

# Limit the blast radius to specific paths:
aegis scan . --scope src/ --scope lib/ --exclude tests/

# Actually execute PoCs in a network-off Docker sandbox (opt-in + ownership ack):
aegis scan . --execute-pocs --authorized

# Re-emit a saved JSON report in another format:
aegis report --in aegis-report.json --format sarif -o aegis.sarif
```

### `aegis scan` options

| Flag | Default | Purpose |
|---|---|---|
| `TARGET` | — | Local path to scan (required). |
| `--profile, -p` | `default` | Run profile: `default`, `deep`, `recon`, `full` (see [Configuration](#configuration)). |
| `--config, -c` | `configs/default.yaml` | Path to a config YAML. |
| `--role NAME=MODEL` | — | Override a role's model (repeatable), e.g. `--role deep=anthropic/claude-opus-4-8`. |
| `--scope` | (all) | Restrict to a path prefix (repeatable). |
| `--exclude` | — | Exclude a path prefix (repeatable). |
| `--confirm-only` | off | Report only PoC-confirmed findings. |
| `--execute-pocs` | off | Run PoCs in the sandbox (otherwise emit-for-review). |
| `--authorized` | off | Acknowledge you own/are authorized for this code. **Required** to execute PoCs. |
| `--offline` | off | No model calls; deterministic KB sweep only. |
| `--out, -o` | `.` | Output directory for reports. |
| `--format, -f` | `md sarif json` | Report formats to write (repeatable). |

Aegis refuses to execute PoCs without `--authorized`, and falls back to emit-for-review if Docker
isn't available.

---

## `engage` — authorized pentest

Engagement mode replaces the local-code lock with a **contract-grade authorization layer**
aligned with PTES, NIST SP 800-115, and OWASP WSTG. Nothing runs unless it is provably in scope,
inside the engagement window, and permitted by a **signed** Rules-of-Engagement manifest. The
tool **fails closed** on anything missing, invalid, expired, modified, or out-of-scope.

### The Rules-of-Engagement manifest

The RoE (`configs/roe.example.yaml`) is effectively a machine-readable authorization-to-test
letter. It declares the parties, the hard time window, an explicit allow/deny scope, the
permitted action classes, rate limits, and forbidden behaviors:

```yaml
engagement:
  id: ACME-2026-0042
  client: "Acme Corp"
  authorized_by: { name: "Jane Director, CISO", contact: jane@acme.example }
  tester:        { name: "Paul / Your Firm",    contact: you@yourfirm.example }
  window:
    start: 2026-06-20T09:00:00Z
    end:   2026-06-27T18:00:00Z          # hard stop; the tool aborts outside this

scope:
  allow:                                 # explicit allowlist — nothing else is touchable
    hosts:   ["app.acme.example", "10.20.0.0/24"]
    domains: ["*.staging.acme.example"]
    repos:   ["github.com/acme/web-app"]
  deny:                                  # explicit exclusions always win over allow
    hosts:   ["10.20.0.5", "billing-prod.acme.example"]
    cidrs:   ["10.20.99.0/24"]

rules:
  permitted_classes: [recon, vuln_scan]  # opt-in per class; add 'exploitation' to enable
  forbidden:         [denial_of_service, social_engineering, data_exfiltration,
                      lateral_movement, persistence, destructive_payloads]
  max_request_rate:  "20/s"
  require_human_approval_for: [exploitation]

safety:
  abort_contact: "+1-555-0100"
  kill_switch:   true
```

### End-to-end engagement workflow

```bash
# 1) Each party generates an Ed25519 keypair (the .sec is private; share only the .pub):
aegis keys generate client          # -> .aegis/keys/client.sec / client.pub
aegis keys generate tester          # -> .aegis/keys/tester.sec / tester.pub

# 2) Both parties sign the CANONICALIZED manifest (order-independent, whitespace-stable):
CSIG=$(aegis keys sign configs/roe.example.yaml --key .aegis/keys/client.sec)
TSIG=$(aegis keys sign configs/roe.example.yaml --key .aegis/keys/tester.sec)

# 3) Collect detached signatures and the pinned public keys as JSON:
echo "{\"client\":\"$CSIG\",\"tester\":\"$TSIG\"}" > signatures.json
echo "{\"client\":\"$(cat .aegis/keys/client.pub)\",\"tester\":\"$(cat .aegis/keys/tester.pub)\"}" > keys.json

# 4) Dry run: verify signatures, scope, and window — and do NOTHING else:
aegis engage --roe configs/roe.example.yaml \
             --signatures signatures.json --keys keys.json --verify-only

# 5) Run recon + vuln_scan (no exploitation) against the in-scope repo:
aegis engage --roe configs/roe.example.yaml \
             --signatures signatures.json --keys keys.json --profile recon

# Emergency stop (logs a kill-switch record and halts):
aegis engage --roe configs/roe.example.yaml --kill

# Independently verify the tamper-evident audit chain at any time:
aegis engage audit-verify audit.jsonl
```

### What the authorization gate enforces (every action)

Before *any* action, the pre-flight gate in `aegis/engagement/authorize.py` checks, in order:

1. **Signatures verified** against pinned keys, and the manifest unmodified since signing.
2. **Inside the engagement window** (UTC).
3. The action class is **not forbidden** and **is explicitly permitted** (opt-in).
4. The target is **in scope**: `allow ∧ ¬deny`, with **runtime IP re-check** — hostnames are
   resolved to IPs at action time and the resolved IP is re-checked against the deny lists, so a
   domain that later resolves into an excluded range is blocked.
5. The **per-target rate budget** is within `max_request_rate`.
6. If the class is in `require_human_approval_for`, an **operator confirmation** is obtained.

Every decision — **allow and deny** — is written to an append-only, **hash-chained** audit log
(`audit.jsonl`): each record embeds the previous record's hash, so any edit or deletion breaks
the chain and is detected by `audit-verify`. Out-of-scope discoveries are **never actioned** —
they're surfaced as *recommendations to amend the RoE* and listed at the end of the run.

### `aegis engage` options

| Flag | Default | Purpose |
|---|---|---|
| `--roe` | — | Path to the RoE manifest YAML (required). |
| `--signatures` | — | JSON `{client, tester}` detached hex signatures. |
| `--keys` | — | JSON `{client, tester}` pinned public keys. |
| `--profile, -p` | `recon` | `recon` (recon + vuln_scan) or `full` (adds exploitation, approval-gated). |
| `--audit` | `audit.jsonl` | Audit log path. |
| `--verify-only` | off | Check signatures/scope/window and exit without acting. |
| `--kill` | off | Emergency stop; logs a kill-switch record. |
| `--yes` | off | Auto-approve human-approval-gated actions (use with care). |
| `audit-verify PATH` | — | Subcommand: verify a hash-chained audit log. |

> **Note on target acquisition.** Cloning the in-scope repo is an operator-side step by design,
> so scope acquisition stays a deliberate human action. Point Aegis at the already-checked-out
> in-scope path; the pipeline then routes every file through the authorization gate.

---

## Configuration

`configs/default.yaml` maps **logical roles → concrete models** via LiteLLM, so
"local / Ollama / OpenRouter / Claude" is config, not code:

```yaml
roles:
  sweep:  ollama/qwen2.5-coder:7b        # wide, cheap, local — privacy-friendly
  deep:   anthropic/claude-opus-4-8      # high-reasoning verifier (native SDK path)
  report: openrouter/anthropic/claude-sonnet-4-6

model_list:                              # LiteLLM model definitions + credentials
  - model_name: anthropic/claude-opus-4-8
    litellm_params:
      model: anthropic/claude-opus-4-8
      api_key: os.environ/ANTHROPIC_API_KEY

routing:                                 # cross-provider fallback + cooldown
  fallbacks:
    - anthropic/claude-opus-4-8: [openrouter/anthropic/claude-sonnet-4-6]
```

**Roles** — `sweep` (wide, cheap discovery), `deep` (strong verifier that reasons about
candidates and writes PoCs), `report` (summary writer). Override any of them per-run with
`--role name=model`.

**Provider selection** is automatic from the model prefix: `anthropic/…` → native Anthropic SDK
(prompt caching / extended thinking); `opencode/…` → the OpenCode agent backend; everything else
(`ollama/…`, `openrouter/…`, OpenAI-compatible) → LiteLLM. Set `ANTHROPIC_API_KEY` /
`OPENROUTER_API_KEY` in your environment as referenced by `os.environ/…` in the config.

**Profiles** bundle run settings:

| Profile | `confirm_only` | `execute_pocs` | `max_parallel` | Permitted classes |
|---|---|---|---|---|
| `default` | no | no | 8 | recon, vuln_scan |
| `deep` | no | no | 4 | recon, vuln_scan |
| `recon` | no | no | 8 | recon, vuln_scan |
| `full` | no | yes | 8 | recon, vuln_scan, **exploitation** |

**Sandbox** settings (`configs/default.yaml → sandbox`) control PoC execution: image, `network:
none`, CPU/memory caps, timeout, and read-only mounts.

---

## Understanding the output

A run writes up to three artifacts (control with `--format`):

**`aegis-report.md`** — client-ready. Executive summary, methodology, a severity overview table,
and per-finding detail. Example of a single finding:

```markdown
### 1. Possible SQL injection via string-formatted query

- **Status:** 🟡 Candidate
- **Severity:** high · **CVSS:** 7.5
- **CWE:** CWE-89  ·  **Category:** sql_injection
- **Location:** `vulnerable_app.py:35`
- **Detector:** kb:py-sql-fstring

**Evidence:**
    cur.execute("SELECT * FROM users WHERE id = '%s'" % user_id)

**Remediation:**
Use parameterized queries / prepared statements; never build SQL by string
concatenation or interpolation of untrusted input.
```

**`aegis-report.sarif`** — SARIF 2.1.0 for GitHub Advanced Security (Code Scanning) and IDEs.
Each result carries the CWE rule id, a `security-severity` score, the location/snippet, and a
`confirmed` property so confirmed findings stand out. The CI workflow uploads this automatically.

**`aegis-report.json`** — the full typed `Report` (every `Finding`, `Candidate`, and `PoC`),
suitable for dashboards or further processing. Convert it later with `aegis report --in …`.

Severities map to CVSS bands; confirmed findings always sort to the top
(`severity × confidence`).

---

## Project layout

```
aegis-security/
├── aegis/
│   ├── cli.py               # Typer entrypoint: scan, engage, keys, report
│   ├── config.py            # role→model routing, profiles, sandbox config
│   ├── models.py            # Candidate, Finding, PoC, Report, AuthDecision…
│   ├── orchestrator.py      # async pipeline DAG; routes targets through authorize()
│   ├── providers/           # ModelProvider protocol + LiteLLM / Anthropic / OpenCode
│   ├── stages/              # mapper, threat_model, scanner, triage, verifier, reporter
│   ├── engagement/          # roe, signing, authorize, scope, audit (Mode B)
│   ├── sandbox/             # docker_runner (network-off, ephemeral, capped) + emit-for-review
│   ├── knowledge/           # CWE-mapped security-pattern KB
│   └── prompts/             # versioned per-stage prompt templates
├── ui/
│   ├── tui/                 # Textual app  (python -m ui.tui <target>)
│   └── web/                 # FastAPI app  (uvicorn ui.web.app:app)
├── configs/
│   ├── default.yaml         # role→model routing + profiles + sandbox
│   └── roe.example.yaml     # example signed-RoE manifest
├── tests/
│   ├── corpora/             # seeded-bug fixtures for evals
│   └── test_*.py            # 28 tests across models, scope, signing, authorize, pipeline
└── .github/workflows/ci.yml # lint + test + offline self-scan + SARIF upload
```

---

## Extending Aegis

- **Add a detector.** Append a `SecurityPattern` (regex, CWE, severity, languages, remediation)
  to `aegis/knowledge/patterns.py`. It immediately participates in the sweep, triage, SARIF
  rules, and the eval corpus.
- **Add a model provider.** Implement the small `ModelProvider` protocol in
  `aegis/providers/base.py` and register selection in `aegis/providers/__init__.py`.
- **Tune prompts.** Per-stage templates live in `aegis/prompts/templates.py` and are versioned.
- **Harden the sandbox.** `aegis/sandbox/docker_runner.py` already runs network-off, read-only,
  CPU/mem/time-capped; the design notes gVisor/Firejail as further hardening.
- **Eval a model config.** Seed known bugs into `tests/corpora/` and measure precision/recall and
  PoC-confirmation rate per config — how you prove "local sweep + Claude verifier" is good enough
  versus a Claude-only run.

---

## Guardrails (hard-coded, not flags)

1. **No action outside authorization.** `scan` = local code you own; `engage` = signed,
   in-window, in-scope only. Fail closed, always.
2. **No self-expanding scope** — out-of-scope discoveries are reported, never touched.
3. **Forbidden classes stay forbidden** (DoS / exfiltration / persistence / destructive) unless
   the RoE explicitly authorizes them.
4. **No detection-evasion or anti-forensics features.**
5. **The audit log cannot be silently disabled** in `engage` mode.
6. **No pre-built weaponized exploit library** — PoC content is model-generated at run time
   against the specific authorized target; the project ships the orchestration and the controls.

---

## Development & testing

```bash
pip install -e '.[dev]'
pytest -q          # 28 tests, incl. the seeded-bug eval corpus
ruff check .       # lint
```

The CI workflow (`.github/workflows/ci.yml`) runs lint + tests on Python 3.11 and 3.12, then
performs an **offline self-scan of Aegis itself** and uploads the SARIF to GitHub Code Scanning.

### Interfaces beyond the CLI

```bash
# Terminal UI (live pipeline view + findings table):
pip install -e '.[tui]'
python -m ui.tui ./my-repo

# Web API (scan dashboard / findings board backend):
pip install -e '.[web]'
uvicorn ui.web.app:app --reload    # POST /scan {"target": "./my-repo"}
```

Both are thin shells over the same `Orchestrator`.

---

## Troubleshooting & FAQ

**`aegis: command not found`** — install the package (`pip install -e .`); the `aegis` script is
registered as a console entry point.

**My scan found 0 findings.** The deterministic KB covers common high-signal patterns (SQLi,
command injection, deserialization, secrets, weak crypto, SSRF, path traversal, XSS, TLS-off,
debug-mode, JWT-none). Clean code, or languages/patterns outside the KB, legitimately yield zero.
Add models (drop `--offline`) for semantic catches the regexes miss, or add detectors.

**Nothing is ever "confirmed".** Confirmation requires PoC execution. Use
`--execute-pocs --authorized` with Docker installed (`pip install -e '.[sandbox]'`), and a `deep`
model configured to generate PoCs. Without these, findings stay at candidate / verified-candidate.

**Engagement won't start.** It fails closed by design. Check that: both signatures are present and
valid, the public keys match the signing keys, the manifest hasn't changed since signing, and the
current UTC time is inside the window. `--verify-only` tells you exactly which check failed.

**Which models should I use?** A cheap/local model for `sweep` (e.g. `ollama/qwen2.5-coder:7b`)
and a strong model for `deep` (e.g. `anthropic/claude-opus-4-8`) is the intended sweet spot:
breadth from the cheap sweep, precision and PoCs from the strong verifier.

---

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
