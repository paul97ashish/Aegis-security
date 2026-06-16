"""Docker-backed PoC sandbox: network-off, read-only mounts, CPU/mem/time caps.

Emit-for-review is the default (design §6); execution is opt-in. The Docker SDK
is imported lazily so the package works without it — falling back to the
``EmitForReviewSandbox`` which never executes anything.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

from aegis.config import SandboxConfig
from aegis.models import PoC, PoCStatus


@dataclass
class SandboxOutcome:
    status: PoCStatus
    log: str = ""
    exit_code: int | None = None
    signals: list[str] = field(default_factory=list)


class EmitForReviewSandbox:
    """Default sandbox: emits the PoC for human review, executes nothing."""

    name = "emit-for-review"

    async def run(self, poc: PoC, root: str | Path) -> SandboxOutcome:  # noqa: ARG002
        return SandboxOutcome(
            status=PoCStatus.SKIPPED,
            log="emit-for-review: PoC generated but not executed (execution not enabled).",
        )


class DockerSandbox:
    """Run a PoC inside an ephemeral, network-disabled container.

    The PoC's payload is written into a temp dir mounted read-only; the
    container has no network, capped CPU/memory, and a hard timeout. Success
    is decided by the PoC's ``expected_signal`` appearing in output.
    """

    name = "docker"

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self.config = config or SandboxConfig()
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            import docker
        except ImportError as exc:  # pragma: no cover - optional extra
            raise RuntimeError(
                "docker SDK not installed. Install with: pip install 'aegis-scan[sandbox]'"
            ) from exc
        self._client = docker.from_env()
        return self._client

    async def run(self, poc: PoC, root: str | Path) -> SandboxOutcome:
        # Offload the blocking Docker calls to a thread.
        return await asyncio.to_thread(self._run_blocking, poc, str(root))

    def _run_blocking(self, poc: PoC, root: str) -> SandboxOutcome:  # pragma: no cover - needs docker
        import tempfile

        client = self._ensure_client()
        cfg = self.config
        with tempfile.TemporaryDirectory(prefix="aegis-poc-") as workdir:
            script_name = "poc.py" if poc.language.startswith("py") else "poc.sh"
            script_path = Path(workdir) / script_name
            script_path.write_text(poc.payload, encoding="utf-8")
            cmd = ["python", f"/poc/{script_name}"] if script_name.endswith(".py") else [
                "sh", f"/poc/{script_name}"
            ]
            try:
                container = client.containers.run(
                    image=cfg.image,
                    command=cmd,
                    network_disabled=(cfg.network == "none"),
                    mem_limit=cfg.mem_limit,
                    nano_cpus=int(cfg.cpu_limit * 1_000_000_000),
                    volumes={workdir: {"bind": "/poc", "mode": "ro"}},
                    read_only=cfg.read_only,
                    detach=True,
                )
            except Exception as exc:
                return SandboxOutcome(status=PoCStatus.SKIPPED, log=f"container start failed: {exc}")

            try:
                result = container.wait(timeout=cfg.timeout_seconds)
                logs = container.logs().decode("utf-8", "replace")
                exit_code = result.get("StatusCode", 1)
            except Exception as exc:
                logs = f"execution error/timeout: {exc}"
                exit_code = None
            finally:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

        reproduced = bool(poc.expected_signal) and poc.expected_signal in logs
        return SandboxOutcome(
            status=PoCStatus.REPRODUCED if reproduced else PoCStatus.FAILED,
            log=logs,
            exit_code=exit_code,
            signals=[poc.expected_signal] if reproduced else [],
        )
