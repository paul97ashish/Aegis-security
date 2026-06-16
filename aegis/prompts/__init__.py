"""Versioned per-stage prompt templates.

Prompts are treated as code: versioned, narrow, and bite-sized. Each stage
gets a small, focused instruction (the "discovery harness" pattern, design §3)
rather than one big chat prompt.
"""

from aegis.prompts.templates import PROMPTS, PromptTemplate, render

__all__ = ["PROMPTS", "PromptTemplate", "render"]
