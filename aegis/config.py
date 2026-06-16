"""Configuration loader: role->model routing and run profiles (design §5).

LiteLLM is the unifying abstraction; this module turns ``configs/default.yaml``
into typed settings. Logical roles (``sweep``/``deep``/``report``) are mapped to
concrete models so "local / Ollama / OpenRouter / Claude" is config, not code.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "configs" / "default.yaml"


class ModelEntry(BaseModel):
    model_name: str
    litellm_params: dict[str, Any] = Field(default_factory=dict)


class RoutingConfig(BaseModel):
    fallbacks: list[dict[str, list[str]]] = Field(default_factory=list)
    allowed_fails: int = 3
    cooldown_time: int = 60


class Profile(BaseModel):
    """A named run configuration."""

    description: str = ""
    confirm_only: bool = False  # only report PoC-confirmed findings
    execute_pocs: bool = False  # opt-in PoC execution (emit-for-review otherwise)
    max_parallel: int = 8
    permitted_classes: list[str] = Field(default_factory=lambda: ["recon", "vuln_scan"])


class SandboxConfig(BaseModel):
    image: str = "python:3.12-slim"
    network: str = "none"  # network-off by default (design §6)
    cpu_limit: float = 1.0
    mem_limit: str = "512m"
    timeout_seconds: int = 30
    read_only: bool = True


class Config(BaseModel):
    roles: dict[str, str] = Field(
        default_factory=lambda: {
            "sweep": "ollama/qwen2.5-coder:7b",
            "deep": "claude-opus-4-8",
            "report": "openrouter/anthropic/claude-sonnet-4-6",
        }
    )
    model_list: list[ModelEntry] = Field(default_factory=list)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    profiles: dict[str, Profile] = Field(default_factory=dict)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)

    # Convenience -----------------------------------------------------------

    def model_for_role(self, role: str) -> str:
        if role not in self.roles:
            raise KeyError(f"unknown role {role!r}; known roles: {sorted(self.roles)}")
        return self.roles[role]

    def litellm_model_list(self) -> list[dict[str, Any]]:
        """Shape expected by ``litellm.Router``."""
        return [e.model_dump() for e in self.model_list]

    def profile(self, name: str) -> Profile:
        if name in self.profiles:
            return self.profiles[name]
        # Sensible built-in defaults so the tool runs without a config file.
        builtins = {
            "default": Profile(description="balanced sweep + verify"),
            "deep": Profile(description="deep verify", confirm_only=False, max_parallel=4),
            "recon": Profile(
                description="recon + vuln_scan, no exploitation",
                permitted_classes=["recon", "vuln_scan"],
            ),
            "full": Profile(
                description="exploitation classes (approval-gated)",
                execute_pocs=True,
                permitted_classes=["recon", "vuln_scan", "exploitation"],
            ),
        }
        if name in builtins:
            return builtins[name]
        raise KeyError(f"unknown profile {name!r}")

    def with_role_overrides(self, overrides: dict[str, str]) -> Config:
        """Apply ``--role sweep=...`` CLI overrides without mutating self."""
        merged = dict(self.roles)
        merged.update(overrides)
        return self.model_copy(update={"roles": merged})


def _expand_env(value: Any) -> Any:
    """Resolve ``os.environ/VAR`` references (LiteLLM convention)."""
    if isinstance(value, str) and value.startswith("os.environ/"):
        return os.environ.get(value.split("/", 1)[1], "")
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def load_config(path: Path | None = None) -> Config:
    """Load config from YAML, falling back to built-in defaults."""
    path = path or DEFAULT_CONFIG_PATH
    if not Path(path).exists():
        return Config()
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    raw = _expand_env(raw)
    return Config.model_validate(raw)
