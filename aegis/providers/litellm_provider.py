"""LiteLLM-backed provider — covers Claude, OpenRouter, Ollama, and any
OpenAI-compatible local server through one interface (design §5).

``litellm`` is imported lazily so the core package and tests run without it.
"""

from __future__ import annotations

import asyncio
from typing import Any

from aegis.providers.base import CompletionResult, Message, ProviderError


class LiteLLMProvider:
    name = "litellm"

    def __init__(
        self,
        model_list: list[dict[str, Any]] | None = None,
        routing: dict[str, Any] | None = None,
    ) -> None:
        self._model_list = model_list or []
        self._routing = routing or {}
        self._router = None  # built lazily

    def _ensure_router(self):
        if self._router is not None:
            return self._router
        try:
            import litellm  # noqa: F401
            from litellm import Router
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise ProviderError(
                "litellm is not installed. Install with: pip install 'aegis-scan[models]'"
            ) from exc
        if self._model_list:
            self._router = Router(
                model_list=self._model_list,
                fallbacks=self._routing.get("fallbacks", []),
                allowed_fails=self._routing.get("allowed_fails", 3),
                cooldown_time=self._routing.get("cooldown_time", 60),
            )
        return self._router

    async def complete(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        **kwargs,
    ) -> CompletionResult:
        payload = [{"role": m.role, "content": m.content} for m in messages]
        try:
            router = self._ensure_router()
            if router is not None:
                resp = await router.acompletion(
                    model=model,
                    messages=payload,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    **kwargs,
                )
            else:
                import litellm

                resp = await litellm.acompletion(
                    model=model,
                    messages=payload,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    **kwargs,
                )
        except ProviderError:
            raise
        except Exception as exc:  # pragma: no cover - network/runtime dependent
            return CompletionResult(text="", model=model, error=str(exc))

        text = ""
        usage: dict[str, Any] = {}
        try:
            text = resp.choices[0].message.content or ""
            if getattr(resp, "usage", None) is not None:
                usage = dict(resp.usage)
        except Exception:  # pragma: no cover - defensive
            text = str(resp)
        return CompletionResult(text=text, model=model, usage=usage)


class EchoProvider:
    """Deterministic offline provider used as a fallback and in tests.

    It never calls the network; it returns an empty JSON-ish answer so the
    pipeline degrades gracefully to the deterministic KB sweep when no model
    is configured.
    """

    name = "echo"

    async def complete(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        **kwargs,
    ) -> CompletionResult:
        await asyncio.sleep(0)
        return CompletionResult(text="", model=f"echo:{model}")
