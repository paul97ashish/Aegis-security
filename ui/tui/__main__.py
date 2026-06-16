"""Textual TUI app: live pipeline view + finding detail (design §8).

Lazy-imports Textual so the core package installs without it.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.widgets import DataTable, Footer, Header, Log, Static
except ImportError:  # pragma: no cover - optional extra
    print("Textual not installed. Install with: pip install 'aegis-scan[tui]'")
    sys.exit(1)

from aegis.config import load_config
from aegis.orchestrator import Orchestrator


class AegisTUI(App):
    """Live pipeline view: stages stream on the left, findings table on the right."""

    CSS = """
    #log { width: 40%; border: round $accent; }
    #findings { width: 60%; border: round $accent; }
    """
    BINDINGS = [("q", "quit", "Quit")]

    def __init__(self, target: str, profile: str = "default") -> None:
        super().__init__()
        self.target = target
        self.profile_name = profile
        self._log: Log | None = None
        self._table: DataTable | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="log"):
                yield Static("[b]Pipeline[/b]")
                self._log = Log()
                yield self._log
            with Vertical(id="findings"):
                yield Static("[b]Findings[/b]")
                self._table = DataTable()
                yield self._table
        yield Footer()

    async def on_mount(self) -> None:
        assert self._table is not None
        self._table.add_columns("Sev", "CWE", "Title", "Status")
        self.run_worker(self._run_pipeline(), exclusive=True)

    def _progress(self, stage: str, data: dict) -> None:
        if self._log is not None:
            self._log.write_line(f"{stage}: {data}")

    async def _run_pipeline(self) -> None:
        config = load_config()
        orch = Orchestrator(config, offline=True, progress=self._progress)
        prof = config.profile(self.profile_name)
        result = await orch.run(self.target, profile=prof, mode="scan")
        assert self._table is not None
        for f in result.report.sorted_findings():
            status = "CONFIRMED" if f.confirmed else ("verified" if f.verified else "candidate")
            self._table.add_row(
                f.candidate.severity.value,
                f.candidate.cwe or "-",
                f.candidate.title[:50],
                status,
            )
        self._progress("done", result.report.counts())


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python -m ui.tui <target> [profile]")
        sys.exit(2)
    target = sys.argv[1]
    profile = sys.argv[2] if len(sys.argv) > 2 else "default"
    if not Path(target).exists():
        print(f"target does not exist: {target}")
        sys.exit(2)
    AegisTUI(target, profile).run()


if __name__ == "__main__":  # pragma: no cover
    main()
