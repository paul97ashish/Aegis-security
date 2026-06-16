"""Provider layer: a thin ``ModelProvider`` seam plus a role-aware router.

``ProviderRouter`` resolves a logical role (sweep/deep/report) to a concrete
model id and the right backend, with a graceful offline fallback so the
pipeline always runs (degrading to the deterministic KB sweep).
"""

from __future__ import annotations

from aegis.config import Config
from aegis.providers.anthropic_provider import AnthropicProvider
from aegis.providers.base import (
    CompletionResult,
    Message,
    ModelProvider,
    ProviderError,
)
from aegis.providers.litellm_provider import EchoProvider, LiteLLMProvider
from aegis.providers.opencode_provider import OpenCodeProvider

__all__ = [
    "AnthropicProvider",
    "CompletionResult",
    "EchoProvider",
    "LiteLLMProvider",
    "Message",
    "ModelProvider",
    "OpenCodeProvider",
    "ProviderError",
    "ProviderRouter",
    "select_provider",
]


def select_provider(model: str, config: Config) -> ModelProvider:
    """Pick a backend for a model id based on its prefix."""
    if model.startswith("opencode/") or model.startswith("opencode:"):
        return OpenCodeProvider()
    if model.startswith("anthropic/"):
        return AnthropicProvider(extended_thinking=False)
    # Everything else (ollama/, openrouter/, claude-*, openai-compatible) -> LiteLLM.
    return LiteLLMProvider(
        model_list=config.litellm_model_list(),
        routing=config.routing.model_dump(),
    )


class ProviderRouter:
    """Resolves roles to (model, provider) and runs completions.

    Offline-friendly: if a provider is unavailable it returns an empty result
    rather than raising, letting deterministic stages carry the run.
    """

    def __init__(self, config: Config, *, offline: bool = False) -> None:
        self.config = config
        self.offline = offline
        self._echo = EchoProvider()
        self._cache: dict[str, ModelProvider] = {}

    def provider_for_role(self, role: str) -> tuple[str, ModelProvider]:
        model = self.config.model_for_role(role)
        if self.offline:
            return model, self._echo
        if model not in self._cache:
            self._cache[model] = select_provider(model, self.config)
        return model, self._cache[model]

    async def complete_role(
        self,
        role: str,
        messages: list[Message],
        *,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        **kwargs,
    ) -> CompletionResult:
        model, provider = self.provider_for_role(role)
        try:
            return await provider.complete(
                messages,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs,
            )
        except ProviderError as exc:
            return CompletionResult(text="", model=model, error=str(exc))
