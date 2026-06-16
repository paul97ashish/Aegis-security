"""Engagement (Mode B) authorization layer.

Replaces the local-code lock of ``scan`` with a contract-grade authorization
layer: a signed Rules-of-Engagement manifest, a fail-closed pre-flight gate,
continuous scope enforcement, and a tamper-evident audit log (design §7).
"""

from aegis.engagement.audit import AuditLog, AuditRecord
from aegis.engagement.authorize import AuthorizationError, Authorizer
from aegis.engagement.roe import RoE, load_roe
from aegis.engagement.scope import ScopeChecker
from aegis.engagement.signing import (
    SigningError,
    generate_keypair,
    sign_manifest,
    verify_manifest,
)

__all__ = [
    "AuditLog",
    "AuditRecord",
    "AuthorizationError",
    "Authorizer",
    "RoE",
    "ScopeChecker",
    "SigningError",
    "generate_keypair",
    "load_roe",
    "sign_manifest",
    "verify_manifest",
]
