"""Native Anthropic provider for caching-sensitive / extended-thinking roles.

Used for the ``deep`` verifier role to get prompt caching and extended
thinking that the generic LiteLLM path does not expose (design §5). Imported
lazily; falls back cleanly when the SDK or key is absent.
"""

from __future__ import annotations

import os

from aegis.providers.base import CompletionResult, Message, ProviderError


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        extended_thinking: bool = False,
        thinking_budget_tokens: int = 4000,
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._extended_thinking = extended_thinking
        self._thinking_budget = thinking_budget_tokens
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:  # pragma: no cover - optional extra
            raise ProviderError(
                "anthropic SDK not installed. Install with: pip install 'aegis-scan[models]'"
            ) from exc
        if not self._api_key:
            raise ProviderError("ANTHROPIC_API_KEY is not set")
        self._client = AsyncAnthropic(api_key=self._api_key)
        return self._client

    @staticmethod
    def _normalize_model(model: str) -> str:
        # Accept both "anthropic/claude-..." and bare ids.
        return model.split("/", 1)[1] if model.startswith("anthropic/") else model

    async def complete(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        **kwargs,
    ) -> CompletionResult:
        model = self._normalize_model(model)
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        convo = [
            {"role": m.role, "content": m.content}
            for m in messages
            if m.role in ("user", "assistant")
        ]
        try:
            client = self._ensure_client()
            extra: dict = {}
            if self._extended_thinking:
                extra["thinking"] = {
                    "type": "enabled",
                    "budget_tokens": self._thinking_budget,
                }
            resp = await client.messages.create(
                model=model,
                system=system or None,
                messages=convo,
                temperature=temperature,
                max_tokens=max_tokens,
                **extra,
            )
        except ProviderError:
            raise
        except Exception as exc:  # pragma: no cover - network dependent
            return CompletionResult(text="", model=model, error=str(exc))

        text = "".join(
            block.text for block in resp.content if getattr(block, "type", "") == "text"
        )
        usage = {}
        if getattr(resp, "usage", None) is not None:
            usage = {
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens,
            }
        return CompletionResult(text=text, model=model, usage=usage)
