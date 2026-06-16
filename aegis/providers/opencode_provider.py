"""OpenCode provider — an optional *agent backend*, not a raw model.

OpenCode brings its own agentic loop, LSP, and tool use; Aegis drives it via
subprocess (``opencode run``). It is selected per-role like any other provider
(design §5).
"""

from __future__ import annotations

import asyncio
import shutil

from aegis.providers.base import CompletionResult, Message, ProviderError


class OpenCodeProvider:
    name = "opencode"

    def __init__(self, binary: str = "opencode", timeout: int = 180) -> None:
        self._binary = binary
        self._timeout = timeout

    def _resolve(self) -> str:
        path = shutil.which(self._binary)
        if not path:
            raise ProviderError(
                f"opencode binary {self._binary!r} not found on PATH; install OpenCode to use this provider"
            )
        return path

    async def complete(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        **kwargs,
    ) -> CompletionResult:
        prompt = "\n\n".join(f"[{m.role}]\n{m.content}" for m in messages)
        try:
            binary = self._resolve()
        except ProviderError as exc:
            return CompletionResult(text="", model=model, error=str(exc))

        cmd = [binary, "run", "--model", model, prompt]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)
        except TimeoutError:  # pragma: no cover - runtime dependent
            return CompletionResult(text="", model=model, error="opencode timed out")
        except Exception as exc:  # pragma: no cover
            return CompletionResult(text="", model=model, error=str(exc))

        if proc.returncode != 0:
            return CompletionResult(
                text="", model=model, error=(err or b"").decode("utf-8", "replace")
            )
        return CompletionResult(text=(out or b"").decode("utf-8", "replace"), model=model)


def _unused(_: str | None) -> None:  # keep import surface minimal
    return None
