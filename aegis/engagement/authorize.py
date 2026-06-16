"""The pre-flight authorization gate — runs before *every* action (design §7.3).

Fail closed on anything missing, invalid, expired, modified, or out-of-scope.
Every decision (allow AND deny) is recorded to the audit log. Out-of-scope
discoveries are never actioned — they are flagged as scope-amendment
recommendations (guardrail §11.2).
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime

from aegis.engagement.audit import AuditLog
from aegis.engagement.roe import RoE
from aegis.engagement.scope import ScopeChecker
from aegis.models import ActionClass, AuthDecision


class AuthorizationError(RuntimeError):
    """Raised when a hard authorization precondition fails (fail closed)."""


# Operator confirmation callback: (action, target) -> bool.
ApprovalFn = Callable[[str, str], bool]


class Authorizer:
    def __init__(
        self,
        roe: RoE,
        *,
        audit: AuditLog | None = None,
        scope_checker: ScopeChecker | None = None,
        signatures_verified: bool = False,
        approval_fn: ApprovalFn | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.roe = roe
        self.audit = audit
        self.scope = scope_checker or ScopeChecker(roe.scope)
        self.signatures_verified = signatures_verified
        self.approval_fn = approval_fn
        self._clock = clock
        # Per-target sliding-window rate budget.
        self._rate_window: dict[str, deque[float]] = {}
        # Discoveries that fell out of scope (reported, never actioned).
        self.scope_amendment_recommendations: list[str] = []

    def authorize(
        self,
        action: str,
        action_class: ActionClass,
        target: str,
        *,
        actor: str = "orchestrator",
    ) -> AuthDecision:
        decision = self._decide(action, action_class, target)
        if self.audit is not None:
            self.audit.record(
                actor=actor,
                action=action,
                target=target,
                decision="allow" if decision.allowed else "deny",
                result=decision.reason,
                detail={
                    "class": action_class.value,
                    "requires_approval": decision.requires_approval,
                },
            )
        return decision

    def require(self, action: str, action_class: ActionClass, target: str, **kw) -> AuthDecision:
        """Like ``authorize`` but raises on denial (for hard preconditions)."""
        decision = self.authorize(action, action_class, target, **kw)
        if not decision.allowed:
            raise AuthorizationError(f"{action} on {target} denied: {decision.reason}")
        return decision

    # -- internal decision logic -------------------------------------------

    def _decide(self, action: str, action_class: ActionClass, target: str) -> AuthDecision:
        def deny(reason: str, approval: bool = False) -> AuthDecision:
            return AuthDecision(
                allowed=False, action=action, action_class=action_class,
                target=target, reason=reason, requires_approval=approval,
            )

        # Signature & integrity (fail closed).
        if not self.signatures_verified:
            return deny("RoE signatures not verified")

        # Engagement window.
        if not self.roe.in_window(self._clock()):
            return deny("outside engagement window")

        # Forbidden classes always win.
        if action_class.value in self.roe.rules.forbidden:
            return deny(f"action class {action_class.value} is forbidden by RoE")

        # Class must be explicitly permitted (opt-in).
        if action_class.value not in self.roe.rules.permitted_classes:
            return deny(f"action class {action_class.value} not in permitted_classes")

        # Scope: allow ∧ ¬deny, with runtime IP re-check.
        scope_result = self.scope.check(target)
        if not scope_result.in_scope:
            self._note_out_of_scope(target, scope_result.reason)
            return deny(f"out of scope: {scope_result.reason}")

        # Availability protection: per-target rate budget.
        if not self._rate_ok(target):
            return deny("per-target rate budget exceeded")

        # Human approval gate (interactive).
        requires_approval = action_class.value in self.roe.rules.require_human_approval_for
        if requires_approval:
            if self.approval_fn is None or not self.approval_fn(action, target):
                return deny("operator approval required and not granted", approval=True)

        return AuthDecision(
            allowed=True, action=action, action_class=action_class,
            target=target, reason=scope_result.reason, requires_approval=requires_approval,
        )

    def _note_out_of_scope(self, target: str, reason: str) -> None:
        rec = f"{target} ({reason})"
        if "not in allowlist" in reason and rec not in self.scope_amendment_recommendations:
            self.scope_amendment_recommendations.append(rec)

    def _rate_ok(self, target: str) -> bool:
        rate = self.roe.rules.rate_per_second()
        if rate <= 0:
            return True
        now = time.monotonic()
        window = self._rate_window.setdefault(target, deque())
        while window and now - window[0] > 1.0:
            window.popleft()
        if len(window) >= rate:
            return False
        window.append(now)
        return True
