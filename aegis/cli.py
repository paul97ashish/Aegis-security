"""Aegis CLI — ``scan`` (self-scan) and ``engage`` (authorized pentest).

Thin shell over the orchestrator (design §8). The two modes share one pipeline
but have separate, non-overlapping authorization layers.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegis import __version__
from aegis.config import load_config
from aegis.orchestrator import Orchestrator
from aegis.stages.reporter import Reporter

app = typer.Typer(
    name="aegis",
    help="Aegis — defensive, PoC-gated AI vulnerability-research harness.",
    no_args_is_help=True,
    add_completion=False,
)
engage_app = typer.Typer(help="Authorized client penetration testing (RoE-gated).")
app.add_typer(engage_app, name="engage")
keys_app = typer.Typer(help="Manage RoE signing keys.")
app.add_typer(keys_app, name="keys")

console = Console()


def _parse_roles(role: list[str]) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for item in role:
        if "=" not in item:
            raise typer.BadParameter(f"--role expects role=model, got {item!r}")
        k, v = item.split("=", 1)
        overrides[k.strip()] = v.strip()
    return overrides


def _progress_printer(stage: str, data: dict) -> None:
    console.log(f"[cyan]{stage}[/cyan] {data}")


def _render_report_table(result) -> None:
    counts = result.report.counts()
    table = Table(title="Aegis findings", show_lines=False)
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ("critical", "high", "medium", "low", "info"):
        table.add_row(sev, str(counts[sev]))
    table.add_row("[bold]confirmed (PoC)[/bold]", f"[bold]{counts['confirmed']}[/bold]")
    console.print(table)


@app.command()
def version() -> None:
    """Print the Aegis version."""
    console.print(f"aegis {__version__}")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Local path you own to scan."),
    profile: str = typer.Option("default", "--profile", "-p", help="Run profile."),
    config_path: Path | None = typer.Option(None, "--config", "-c", help="Config YAML."),
    role: list[str] = typer.Option([], "--role", help="Override role=model (repeatable)."),
    scope: list[str] = typer.Option([], "--scope", help="Restrict to path prefix(es)."),
    exclude: list[str] = typer.Option([], "--exclude", help="Exclude path prefix(es)."),
    confirm_only: bool = typer.Option(False, "--confirm-only", help="Only PoC-confirmed findings."),
    execute_pocs: bool = typer.Option(
        False, "--execute-pocs", help="Run PoCs in the sandbox (opt-in; emit-for-review otherwise)."
    ),
    authorized: bool = typer.Option(
        False, "--authorized", help="Acknowledge you own/are authorized for this code (required to execute PoCs)."
    ),
    offline: bool = typer.Option(False, "--offline", help="No model calls; deterministic KB sweep only."),
    out_dir: str = typer.Option(".", "--out", "-o", help="Output directory for reports."),
    fmt: list[str] = typer.Option(["md", "sarif", "json"], "--format", "-f", help="Report formats."),
) -> None:
    """Self-scan local code you own. Emit-for-review is the default."""
    if not Path(target).exists():
        raise typer.BadParameter(f"target path does not exist: {target}")
    if execute_pocs and not authorized:
        console.print("[red]Refusing to execute PoCs without --authorized.[/red]")
        raise typer.Exit(2)

    config = load_config(config_path)
    if role:
        config = config.with_role_overrides(_parse_roles(role))

    prof = config.profile(profile)
    prof = prof.model_copy(update={
        "confirm_only": confirm_only or prof.confirm_only,
        "execute_pocs": execute_pocs or prof.execute_pocs,
    })

    sandbox = None
    if execute_pocs:
        try:
            from aegis.sandbox import DockerSandbox

            sandbox = DockerSandbox(config.sandbox)
        except Exception:
            console.print("[yellow]Docker sandbox unavailable; falling back to emit-for-review.[/yellow]")

    console.print(Panel.fit(f"[bold]aegis scan[/bold] → {target}  (profile: {profile})"))
    orch = Orchestrator(config, offline=offline, sandbox=sandbox, progress=_progress_printer)
    result = asyncio.run(orch.run(
        target, profile=prof, mode="scan",
        include=list(scope) or None, exclude=list(exclude) or None,
    ))

    _render_report_table(result)
    reporter = Reporter(None if offline else orch.router)
    markdown = asyncio.run(reporter.markdown(result.report))
    written = reporter.write(result.report, markdown, out_dir=out_dir, formats=list(fmt))
    console.print(f"[green]Reports written:[/green] {', '.join(written.values())}")


@app.command()
def report(
    json_in: Path = typer.Option(..., "--in", help="Existing aegis JSON report."),
    fmt: str = typer.Option("sarif", "--format", "-f", help="md|sarif|json"),
    out: Path | None = typer.Option(None, "--out", "-o", help="Output file."),
) -> None:
    """Convert a saved JSON report into another format."""
    from aegis.models import Report

    rep = Report.model_validate_json(json_in.read_text(encoding="utf-8"))
    reporter = Reporter(None)
    if fmt == "sarif":
        text = json.dumps(reporter.sarif(rep), indent=2)
    elif fmt == "json":
        text = reporter.json_report(rep)
    else:
        text = asyncio.run(reporter.markdown(rep))
    if out:
        out.write_text(text, encoding="utf-8")
        console.print(f"[green]Wrote[/green] {out}")
    else:
        console.print(text)


# --------------------------------------------------------------------------
# Engagement (Mode B)
# --------------------------------------------------------------------------


def _load_and_verify_roe(roe_path: Path, sig_path: Path | None, keys_path: Path | None):
    """Load RoE and verify signatures against pinned keys. Fails closed."""
    from aegis.engagement import load_roe, verify_manifest
    from aegis.engagement.signing import SignatureBundle, SigningError

    roe = load_roe(roe_path)
    verified = False
    detail = "signatures not provided"
    if sig_path and keys_path:
        sigs = json.loads(Path(sig_path).read_text(encoding="utf-8"))
        keys = json.loads(Path(keys_path).read_text(encoding="utf-8"))
        try:
            verify_manifest(roe, SignatureBundle(client=sigs["client"], tester=sigs["tester"]), keys)
            verified = True
            detail = "client + tester signatures valid"
        except SigningError as exc:
            console.print(f"[red]Signature verification FAILED: {exc}[/red]")
            raise typer.Exit(3) from exc
    return roe, verified, detail


@engage_app.callback(invoke_without_command=True)
def engage_main(
    ctx: typer.Context,
    roe: Path = typer.Option(..., "--roe", help="Signed Rules-of-Engagement manifest (YAML)."),
    signatures: Path | None = typer.Option(None, "--signatures", help="JSON {client, tester} detached sigs."),
    keys: Path | None = typer.Option(None, "--keys", help="JSON {client, tester} pinned public keys."),
    profile: str = typer.Option("recon", "--profile", "-p", help="recon|full"),
    config_path: Path | None = typer.Option(None, "--config", "-c"),
    audit_log: Path = typer.Option(Path("audit.jsonl"), "--audit", help="Audit log path."),
    verify_only: bool = typer.Option(False, "--verify-only", help="Check sigs/scope/window; do nothing."),
    kill: bool = typer.Option(False, "--kill", help="Emergency stop: halt all activity."),
    yes: bool = typer.Option(False, "--yes", help="Auto-approve human-approval-gated actions (use with care)."),
) -> None:
    """Authorized client pentest, gated by a signed RoE."""
    if ctx.invoked_subcommand is not None:
        return

    from datetime import datetime

    from aegis.engagement import AuditLog, Authorizer, ScopeChecker

    roe_obj, verified, detail = _load_and_verify_roe(roe, signatures, keys)
    roe_hash = roe_obj.manifest_hash()
    in_window = roe_obj.in_window(datetime.now(UTC))

    console.print(Panel.fit(
        f"[bold]Engagement[/bold] {roe_obj.engagement.id} — {roe_obj.engagement.client}\n"
        f"Signatures: {'[green]verified[/green]' if verified else '[red]NOT verified[/red]'} ({detail})\n"
        f"Window: {'[green]open[/green]' if in_window else '[red]closed[/red]'}  "
        f"({roe_obj.engagement.window.start} → {roe_obj.engagement.window.end})\n"
        f"RoE hash: {roe_hash[:16]}…"
    ))

    if kill:
        console.print("[red bold]KILL SWITCH ENGAGED — all activity halted.[/red bold]")
        log = AuditLog(audit_log, roe_obj.engagement.id, roe_hash)
        log.record(actor="operator", action="kill_switch", decision="n/a", result="halted")
        raise typer.Exit(0)

    if verify_only:
        ok_color = "green" if (verified and in_window) else "red"
        console.print(f"[{ok_color}]verify-only complete[/{ok_color}] "
                      f"(signatures={verified}, window_open={in_window})")
        raise typer.Exit(0 if (verified and in_window) else 4)

    if not verified:
        console.print("[red]Refusing to engage without verified signatures (fail closed).[/red]")
        raise typer.Exit(3)
    if not in_window:
        console.print("[red]Refusing to engage outside the engagement window (fail closed).[/red]")
        raise typer.Exit(4)

    config = load_config(config_path)
    prof = config.profile(profile)
    # RoE permitted_classes constrain the profile.
    prof = prof.model_copy(update={"permitted_classes": roe_obj.rules.permitted_classes})

    log = AuditLog(audit_log, roe_obj.engagement.id, roe_hash)
    approval_fn = (lambda action, target: True) if yes else (
        lambda action, target: typer.confirm(f"Approve {action} on {target}?")
    )
    authorizer = Authorizer(
        roe_obj, audit=log, scope_checker=ScopeChecker(roe_obj.scope),
        signatures_verified=True, approval_fn=approval_fn,
    )

    # In engage mode the "target" is the in-scope repo named in the RoE.
    repos = roe_obj.scope.allow.repos
    if not repos:
        console.print("[yellow]No repos in RoE scope; engage code-scan needs an allowed repo.[/yellow]")
        raise typer.Exit(0)
    target = repos[0]
    console.print(f"[cyan]Engaging in-scope repo:[/cyan] {target}")

    orch = Orchestrator(config, authorizer=authorizer, progress=_progress_printer)
    # NOTE: code-target acquisition (clone) is operator-side and out of scope for
    # this scaffold; the pipeline runs against an already-checked-out path if local.
    local = Path(target)
    if not local.exists():
        console.print("[yellow]RoE repo is not a local path; clone it in-scope, then point --config target.[/yellow]")
        ok, msg = log.verify_chain()
        console.print(f"Audit: {msg}")
        raise typer.Exit(0)

    result = asyncio.run(orch.run(str(local), profile=prof, mode="engage"))
    _render_report_table(result)
    ok, msg = log.verify_chain()
    console.print(f"[green]Audit chain:[/green] {msg}")
    if authorizer.scope_amendment_recommendations:
        console.print("[yellow]Out-of-scope discoveries (recommend amending RoE):[/yellow]")
        for rec in authorizer.scope_amendment_recommendations:
            console.print(f"  • {rec}")


@engage_app.command("audit-verify")
def audit_verify(audit_log: Path = typer.Argument(..., help="Audit JSONL to verify.")) -> None:
    """Verify the tamper-evident audit chain."""
    from aegis.engagement import AuditLog

    log = AuditLog(audit_log, engagement="", roe_hash="")
    ok, msg = log.verify_chain()
    color = "green" if ok else "red"
    console.print(f"[{color}]{msg}[/{color}]")
    raise typer.Exit(0 if ok else 1)


# --------------------------------------------------------------------------
# Key management
# --------------------------------------------------------------------------


@keys_app.command("generate")
def keys_generate(
    name: str = typer.Argument(..., help="Key name (e.g. client, tester)."),
    out_dir: Path = typer.Option(Path(".aegis/keys"), "--out", "-o"),
) -> None:
    """Generate an Ed25519 keypair for RoE signing."""
    from aegis.engagement.signing import write_keypair

    priv, pub = write_keypair(out_dir, name)
    console.print(f"[green]Wrote[/green] private={priv} public={pub}")
    console.print("[yellow]Keep the .sec private key safe; distribute only the .pub.[/yellow]")


@keys_app.command("sign")
def keys_sign(
    roe: Path = typer.Argument(..., help="RoE manifest YAML to sign."),
    private_key: Path = typer.Option(..., "--key", help="Ed25519 private key (.sec)."),
) -> None:
    """Print a detached hex signature for the canonicalized manifest."""
    from aegis.engagement import load_roe, sign_manifest

    roe_obj = load_roe(roe)
    sig = sign_manifest(roe_obj, private_key.read_text(encoding="utf-8").strip())
    # Raw stdout (no Rich wrapping) so the signature is machine-capturable.
    print(sig)


if __name__ == "__main__":  # pragma: no cover
    app()
