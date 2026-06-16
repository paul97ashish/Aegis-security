# Aegis — Defensive AI Vulnerability-Research Harness

> An open-source, model-agnostic harness that finds security vulnerabilities, verifies each
> finding with a sandboxed proof-of-concept, and produces remediation-focused reports.
> Inspired by the architecture of Anthropic's restricted "Mythos" security harness, but built
> on publicly available and local models.
>
> It runs in two modes that share one pipeline:
> - **`scan` — Self-scan:** for codebases you own.
> - **`engage` — Engagement:** for **authorized** client penetration tests, gated by a signed
>   Rules-of-Engagement manifest.

**Name placeholder:** `aegis` (a shield — pick your own). Suggested repo: `aegis-scan`.

---

## 1. Design principles

1. **Defensive / authorized by construction.** `scan` targets local code you own; `engage`
   targets only what a signed, in-window Rules-of-Engagement (RoE) manifest authorizes.
   There is no mode that points exploits at systems you have no right to test.
2. **The harness is the product, not the model.** A strong harness around public/local
   models is the lever you control. Orchestration, verification, and knowledge injection
   matter more than raw model quality.
3. **A finding is not real until a PoC reproduces it.** PoC generation is the *gate* between
   "candidate" and "confirmed," which is what collapses the false-positive problem.
4. **Model-agnostic.** Any model from Claude, OpenRouter, Ollama, a local server, or OpenCode
   can fill any role in the pipeline, selected per-stage.
5. **Human-in-the-loop on anything that executes.** Generated PoCs default to *emit-for-review*;
   execution is opt-in, sandboxed (self-scan) or operator-confirmed and in-scope (engagement).
6. **Fail closed.** Any ambiguity about authorization, scope, or signature halts the action.

---

## 2. The two modes at a glance

| | `aegis scan` (self-scan) | `aegis engage` (authorized pentest) |
|---|---|---|
| Target | Local path you own | Client systems named in a signed RoE |
| Authorization | `--authorized` acknowledgment | Cryptographically signed RoE manifest (client + tester) |
| Scope lock | Local filesystem path | Allow/deny lists + engagement window, enforced per action |
| PoC execution | Sandboxed, network-off, emit-for-review default | RoE-bounded, operator-approved, in-scope only |
| Audit log | Optional | Mandatory, tamper-evident, cannot be silently disabled |
| Shared | Same pipeline, same model layer, same reporting | |

The two modes have **separate, non-overlapping authorization layers**. You cannot run
`engage` without a valid RoE.

---

## 3. Feature parity with the Mythos-style harness

The reference harness (Anthropic's tooling for vetted security teams) decomposes the work
into discrete agents instead of one-shot prompting. Aegis mirrors each capability:

| Mythos-style capability | Aegis stage | What it does |
|---|---|---|
| Codebase / surface mapping | `mapper` | Indexes files, languages, entry points, frameworks, data-flow surfaces |
| Threat-model builder | `threat_model` | Ranks likely attack targets (auth, input handling, deserialization, SQL, SSRF, file I/O, secrets) so effort is prioritized |
| Scanning subagents | `scanner` | Many narrow-scope agents run **in parallel**, each on a small slice + threat context |
| Triage | `triage` | Deduplicates, clusters, ranks by severity × confidence |
| Second-agent verification | `verifier` | A *different* agent checks the first agent's work — PoC-gated |
| PoC / exploit-chain proof | `verifier` → `sandbox` | Generates a minimal reproduction, runs it in isolation, confirms or rejects |
| Report writing | `reporter` | Remediation-first reports + machine-readable SARIF |
| Multi-model fan-out | `orchestrator` | Cheap model sweeps wide; strong model deep-dives on promising candidates |

**Tactical patterns baked in (from public Glasswing-participant write-ups):**
treat the model as a discovery harness rather than a chat interface; work in bite-sized
pieces with narrow per-agent instructions; use a second agent to check the first; ask many
agents separate questions in parallel about different parts of the attack chain; require a
working PoC before a finding counts as confirmed.

---

## 4. Architecture (shared pipeline)

```
   target (owned repo  ──▶ ┌──────────┐
   OR in-scope client      │  mapper  │  (index + data-flow / attack surface)
   per signed RoE)         └────┬─────┘
                                ▼
                          ┌─────────────┐
                          │ threat_model│  (prioritized attack surface)
                          └────┬────────┘
                                ▼
        ┌───────────── orchestrator (async fan-out) ──────────────┐
        │  scanner-1  scanner-2  scanner-3 ...  scanner-N          │  ← cheap/local model
        └────────────────────────┬─────────────────────────────────┘
                                ▼
                          ┌──────────┐
                          │  triage  │  (dedup + rank)
                          └────┬─────┘
                                ▼
                          ┌──────────────────────┐
                          │      verifier         │  ← strong model (deep reasoning)
                          │ generate PoC → sandbox│
                          │ CONFIRMED iff reproduces│
                          └────┬──────────────────┘
                                ▼
                          ┌──────────┐
                          │ reporter │  → Markdown/PDF + SARIF + JSON
                          └──────────┘
```

In `engage` mode, **every target proposed at every stage** is routed back through the
authorization gate (§7) before any action — the harness can never expand its own scope.

Each arrow carries structured objects (`Candidate`, `Finding`) — never free text — so stages
are independently testable and swappable.

---

## 5. Model-selection layer

LiteLLM is the unifying abstraction: one YAML maps logical roles → concrete models, so
"local / Ollama / OpenRouter / Claude" is config, not code. It also gives you retries,
cross-provider fallback, and per-key spend tracking for free.

```yaml
# configs/default.yaml
roles:
  sweep:   ollama/qwen2.5-coder:7b      # wide, cheap, local — privacy-friendly
  deep:    claude-opus-4-8              # high-reasoning verifier
  report:  openrouter/anthropic/claude-sonnet-4-6

model_list:
  - model_name: ollama/qwen2.5-coder:7b
    litellm_params: { model: ollama/qwen2.5-coder:7b, api_base: http://localhost:11434 }
  - model_name: claude-opus-4-8
    litellm_params: { model: anthropic/claude-opus-4-8, api_key: os.environ/ANTHROPIC_API_KEY }
  - model_name: openrouter/anthropic/claude-sonnet-4-6
    litellm_params: { model: openrouter/anthropic/claude-sonnet-4-6, api_key: os.environ/OPENROUTER_API_KEY }

routing:
  fallbacks: [{ claude-opus-4-8: [openrouter/anthropic/claude-sonnet-4-6] }]
  allowed_fails: 3
  cooldown_time: 60
```

**Provider matrix**

| Source | How | Notes |
|---|---|---|
| Claude | LiteLLM `anthropic/...` **or** native Anthropic SDK | Use native SDK for the verifier role to get prompt caching + extended thinking |
| OpenRouter | LiteLLM `openrouter/...` | Easiest access to many hosted models; adds some latency/cost |
| Ollama / local | LiteLLM `ollama/...` (or any OpenAI-compatible `api_base`) | Keeps sensitive code on-machine; ideal for the wide `sweep` role |
| OpenCode | Adapter shelling out to `opencode run` / its server | Optional **agent backend**, not a raw model — brings its own agentic loop, LSP, tool use |

Provider layer = a thin `ModelProvider` protocol with `LiteLLMProvider` (covers
Claude/OpenRouter/Ollama/local), an optional native `AnthropicProvider` (caching-sensitive
roles), and `OpenCodeProvider` (subprocess/server).

---

## 6. Mode A — `scan` (self-scan, local code you own)

- Target is a local path; an `--authorized` acknowledgment is required before any PoC runs.
- PoCs run in an ephemeral, **network-disabled** container against your own code;
  **emit-for-review is the default**, execution is opt-in.
- Output: candidate + confirmed findings, remediation guidance, SARIF for IDE/GitHub.

```bash
aegis scan ./my-repo                          # full pipeline, default profile
aegis scan . --profile deep --confirm-only    # only PoC-confirmed findings
aegis scan . --role sweep=ollama/qwen2.5-coder:7b --role deep=claude-opus-4-8
aegis scan . --scope src/ --exclude tests/
aegis report --format sarif -o aegis.sarif
```

---

## 7. Mode B — `engage` (authorized client penetration testing)

Engagement Mode does **not** remove safety controls — it replaces the local-code lock with a
stricter, contract-grade authorization layer aligned with PTES, NIST SP 800-115, and
OWASP WSTG. Nothing runs unless it is provably in scope, inside the engagement window, and
permitted by the signed RoE.

### 7.1 The signed Rules-of-Engagement manifest

Signed by **both** the client authorizer and the tester. The tool recomputes its hash and
verifies signatures on startup and **fails closed** on anything missing, invalid, expired, or
modified. This file is effectively your machine-readable authorization-to-test letter.

```yaml
engagement:
  id: ACME-2026-0042
  client: "Acme Corp"
  authorized_by: { name: "Jane Director, CISO", contact: jane@acme.example }
  tester:        { name: "Paul / <your firm>",   contact: you@yourfirm.example }
  window:
    start: 2026-06-20T09:00:00Z
    end:   2026-06-27T18:00:00Z            # hard stop; tool aborts outside this

scope:
  allow:                                   # explicit allowlist — nothing else is touchable
    hosts:   ["app.acme.example", "10.20.0.0/24"]
    domains: ["*.staging.acme.example"]
    repos:   ["github.com/acme/web-app"]
  deny:                                    # explicit exclusions win over allow
    hosts:   ["10.20.0.5", "billing-prod.acme.example"]
    cidrs:   ["10.20.99.0/24"]

rules:
  permitted_classes: [recon, vuln_scan, exploitation]   # opt-in per class
  forbidden:         [denial_of_service, social_engineering, data_exfiltration,
                      lateral_movement, persistence, destructive_payloads]
  max_request_rate:  20/s                  # protect client availability
  require_human_approval_for: [exploitation]  # PoC fires only after operator confirms

safety:
  abort_contact: "+1-555-0100"             # client SOC / emergency stop
  kill_switch:   true
```

Store the human-signed PDF authorization alongside it; the tool records the hash of both.

### 7.2 Signing & verification

Sign the canonicalized manifest with a detached signature (minisign/age or GPG). On startup
the tool recomputes the manifest hash, verifies both signatures against pinned public keys,
checks the window against current UTC, and fails closed on any error. The manifest hash is
stamped into every audit record.

### 7.3 Pre-flight authorization gate (runs before *every* action)

```python
def authorize(action, target, roe):
    assert roe.signature_valid and not roe.modified_since_signing   # else ABORT
    assert now_utc() in roe.window                                  # else ABORT
    assert action.class_ in roe.rules.permitted_classes             # else SKIP+LOG
    assert action.class_ not in roe.rules.forbidden                 # else SKIP+LOG
    assert in_scope(target, roe.scope)                              # allow ∧ ¬deny
    assert rate_budget_ok(target, roe.rules.max_request_rate)
    if action.class_ in roe.rules.require_human_approval_for:
        assert operator_confirmed(action, target)                  # interactive gate
    return True   # only now may the action proceed; the decision is logged either way
```

`in_scope()` resolves hostnames to IPs **at action time** and re-checks the resolved IP
against allow/deny — so a domain that later resolves into an excluded range is blocked.

### 7.4 Continuous scope enforcement

Scope is enforced at every stage. Any target a model proposes — a discovered subdomain, a
pivot host, a linked service — passes back through `authorize()`.

**Out-of-scope discoveries are flagged, never actioned.** An interesting out-of-scope host is
recorded as a *recommendation to amend scope* and stays untouched until a re-signed RoE
includes it. This rule is hard-coded, not configurable.

### 7.5 RoE-bounded execution

- **Class opt-in:** recon/vuln_scan/exploitation are each available only if listed. Default
  profile is recon + vuln_scan only.
- **Human approval gate** on exploitation/PoC actions by default.
- **Availability protection:** global and per-host rate limits; DoS-style actions are a
  forbidden class.
- **Non-destructive by default:** PoCs prove reachability/exploitability with the minimum
  necessary action; destructive payloads, persistence, and exfiltration are forbidden classes.
- **Kill switch:** one command (plus a watchdog on the abort contact) halts all activity.

### 7.6 Tamper-evident audit log (chain of custody)

Append-only, hash-chained JSONL — each record includes the prior record's hash:

```json
{"ts":"2026-06-20T09:14:02Z","engagement":"ACME-2026-0042","roe_hash":"…",
 "actor":"scanner-3","action":"http_probe","target":"app.acme.example",
 "decision":"allow","model":"ollama/qwen2.5-coder:7b","result":"200","prev":"…"}
```

Every authorization decision (allow **and** deny), model call, PoC attempt, and operator
confirmation is recorded — your legal protection, report evidence, and proof you stayed in scope.

```bash
aegis engage --roe roe.yaml --verify-only      # check signatures, scope, window; do nothing
aegis engage --roe roe.yaml --profile recon    # recon + vuln_scan, no exploitation
aegis engage --roe roe.yaml --profile full     # exploitation classes (with approval gate)
aegis engage --roe roe.yaml --kill             # emergency stop
```

---

## 8. Interfaces (CLI + TUI + optional Web UI)

- **CLI (primary):** Typer + Rich. `aegis scan …` and `aegis engage …` as above.
- **TUI:** Textual — live pipeline view (agents in flight, candidates streaming, confirm/reject
  queue, finding detail). Good for interactive triage.
- **Web UI (later):** FastAPI backend + small React/HTMX frontend — scan dashboard, findings
  board, diff-style PoC viewer, exports. Reuses the same orchestrator.

All three are thin shells over the same `orchestrator` API.

---

## 9. Repository layout

```
aegis-scan/
├── README.md
├── pyproject.toml                # uv / hatch; Python 3.12+
├── configs/
│   └── default.yaml              # role→model routing, profiles
├── aegis/
│   ├── cli.py                    # Typer entrypoint (scan + engage)
│   ├── config.py                 # pydantic-settings loader
│   ├── orchestrator.py           # async pipeline DAG; routes targets through authorize()
│   ├── models.py                 # Candidate, Finding, PoC, Report dataclasses
│   ├── providers/
│   │   ├── base.py               # ModelProvider protocol
│   │   ├── litellm_provider.py
│   │   ├── anthropic_provider.py # caching / extended-thinking path
│   │   └── opencode_provider.py
│   ├── stages/
│   │   ├── mapper.py
│   │   ├── threat_model.py
│   │   ├── scanner.py
│   │   ├── triage.py
│   │   ├── verifier.py
│   │   └── reporter.py
│   ├── engagement/               # Mode B authorization layer
│   │   ├── roe.py                # manifest schema (pydantic) + load
│   │   ├── signing.py            # sign / verify (minisign or GPG), fail-closed
│   │   ├── authorize.py          # the pre-flight gate (§7.3)
│   │   ├── scope.py              # allow/deny resolution, runtime IP re-check
│   │   └── audit.py              # hash-chained append-only log
│   ├── sandbox/
│   │   └── docker_runner.py      # network-off, ephemeral, resource-capped
│   ├── knowledge/                # injectable security-pattern KB (CWE-mapped)
│   └── prompts/                  # versioned per-stage prompt templates
├── ui/
│   ├── tui/                      # Textual app
│   └── web/                      # FastAPI + frontend
├── tests/
│   └── corpora/                  # seeded-bug fixtures for evals
└── .github/workflows/ci.yml
```

---

## 10. Tech stack

- **Language:** Python 3.12+ (harness language is independent of target-codebase language).
- **CLI/TUI:** Typer, Rich, Textual.
- **Model layer:** LiteLLM (+ optional native Anthropic SDK).
- **Concurrency:** `asyncio` with a bounded semaphore for agent fan-out.
- **Data models / config:** Pydantic v2, pydantic-settings.
- **Signing:** minisign/age or GPG (detached signatures, pinned public keys).
- **Code mapping:** ripgrep + heuristics for v1; Tree-sitter (+ Roslyn for .NET) for
  language-aware data-flow later.
- **Sandbox:** Docker SDK (no-network, read-only mounts, CPU/mem/time caps); document
  gVisor/Firejail as hardening.
- **Output:** Markdown/PDF report + **SARIF** (GitHub Advanced Security / IDE) + JSON.
- **Web UI:** FastAPI + HTMX or a small React app.

---

## 11. Guardrails & boundaries (hard-coded, not flags)

These hold across both modes and are not configurable:

1. **No action outside authorization.** `scan` = local code you own; `engage` = signed,
   in-window, in-scope only. Fail closed, always.
2. **No self-expanding scope** — out-of-scope discoveries are reported, never touched.
3. **Forbidden classes stay forbidden** unless explicitly authorized in the RoE;
   destructive/DoS/exfiltration/persistence are off by default.
4. **No detection-evasion or anti-forensics features.** A legitimate assessment documents what
   it did. (Contracted stealth testing is achieved via rate/timing controls and explicit RoE
   terms — not tooling that erases evidence.)
5. **The audit log cannot be silently disabled** in `engage` mode.
6. **No pre-built weaponized exploit library.** PoC content is model-generated at run time
   against the specific authorized target; the project ships the orchestration and the controls.

---

## 12. Reporting & standards alignment

- Findings scored with **CVSS**; mapped to **CWE** and, where applicable, **CVE**.
- Report structure: executive summary, methodology (PTES / NIST SP 800-115 / OWASP WSTG),
  scope statement (from the RoE in engagement mode), findings with evidence + reproduction +
  remediation, and an appendix of the audit trail.
- Formats: client-ready Markdown/PDF, plus SARIF/JSON for downstream tooling.

---

## 13. Phased roadmap

| Phase | Deliverable | Outcome |
|---|---|---|
| 0 | Provider layer + config + CLI skeleton | `aegis scan` runs end-to-end with a stub pipeline |
| 1 | `mapper` + single-pass `scanner` + `reporter` | MVP: candidate findings on a real repo |
| 2 | `threat_model` + parallel scanners + `triage` | Prioritized, deduped findings at scale |
| 3 | `verifier` + Docker `sandbox` (PoC gate) | Confirmed vs. unconfirmed; false positives collapse |
| 4 | `engagement/` module (RoE, signing, authorize, audit) | Authorized `engage` mode, fail-closed |
| 5 | TUI + SARIF export + GitHub Action | Interactive triage; CI integration |
| 6 | Knowledge base + prompt caching + eval harness | Benchmarked, tunable, reproducible |

**Eval harness:** seed known bugs (OWASP Benchmark, Juliet, or hand-planted CWEs) into
`tests/corpora/`, then measure precision/recall and PoC-confirmation rate per model config —
how you prove a local-model sweep + Claude verifier is "good enough" versus a Claude-only run.

---

## 14. Open questions to decide before coding

1. Primary target language(s) first? (A .NET monolith argues for Roslyn-aware mapping early —
   tree-sitter-c-sharp + Roslyn analyzers as a hybrid signal source.)
2. Self-hosted LiteLLM proxy (shared spend limits, virtual keys) vs. in-process LiteLLM SDK?
3. License — Apache-2.0 (permissive, common for security tooling) vs. AGPL (copyleft)?
4. Native GitHub `code-scanning` upload, or SARIF artifact only?
5. Signing scheme — minisign (simple) vs. GPG (ubiquitous in client orgs)?
