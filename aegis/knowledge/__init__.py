"""Injectable, CWE-mapped security-pattern knowledge base.

The KB powers a real, deterministic first-pass sweep so the pipeline produces
candidate findings even with no model available, and provides threat-modeling
priors and remediation guidance that get injected into model prompts.
"""

from aegis.knowledge.patterns import (
    PATTERNS,
    SecurityPattern,
    patterns_for_language,
    remediation_for_cwe,
)

__all__ = [
    "PATTERNS",
    "SecurityPattern",
    "patterns_for_language",
    "remediation_for_cwe",
]
