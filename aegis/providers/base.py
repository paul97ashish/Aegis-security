"""The ``ModelProvider`` protocol — a thin seam over any model backend.

Roles (sweep/deep/report) are bound to concrete providers via config, so the
pipeline code never names a vendor (design §5).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class CompletionResult:
    text: str
    model: str
    raw: dict | None = None
    usage: dict = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@runtime_checkable
class ModelProvider(Protocol):
    """Anything that can turn messages into text can fill a pipeline role."""

    name: str

    async def complete(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        **kwargs,
    ) -> CompletionResult: ...


class ProviderError(RuntimeError):
    """Raised when a provider is unavailable or misconfigured."""
