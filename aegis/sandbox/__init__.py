"""Sandboxed PoC execution (network-off, ephemeral, resource-capped)."""

from aegis.sandbox.docker_runner import (
    DockerSandbox,
    EmitForReviewSandbox,
    SandboxOutcome,
)

__all__ = ["DockerSandbox", "EmitForReviewSandbox", "SandboxOutcome"]
