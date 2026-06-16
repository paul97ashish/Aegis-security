"""Scope resolution: allow ∧ ¬deny, with runtime IP re-check (design §7.3-7.4).

Deny always wins over allow. Hostnames are resolved to IPs *at action time* and
the resolved IP is re-checked against the deny lists — so a domain that later
resolves into an excluded range is blocked. Out-of-scope targets are never
actioned; they are reported as scope-amendment recommendations.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatch

from aegis.engagement.roe import Scope

Resolver = Callable[[str], list[str]]


def _default_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({info[4][0] for info in infos})
    except (socket.gaierror, OSError):
        return []


@dataclass
class ScopeResult:
    in_scope: bool
    reason: str
    resolved_ips: list[str]


class ScopeChecker:
    def __init__(self, scope: Scope, resolver: Resolver | None = None) -> None:
        self.scope = scope
        self._resolver = resolver or _default_resolver

    # -- public API ---------------------------------------------------------

    def check(self, target: str) -> ScopeResult:
        target = target.strip()
        if not target:
            return ScopeResult(False, "empty target", [])

        # Repo URLs are matched literally against allow/deny repos.
        if _looks_like_repo(target):
            return self._check_repo(target)

        ip = _as_ip(target)
        # 1) Deny wins on the literal target first.
        denied = self._match_deny(target, ip)
        if denied:
            return ScopeResult(False, f"explicitly denied: {denied}", [])

        # 2) Must be allowed.
        allowed = self._match_allow(target, ip)
        if not allowed:
            return ScopeResult(False, "not in allowlist", [])

        # 3) Runtime IP re-check for hostnames (resolve now, re-check deny).
        resolved: list[str] = []
        if ip is None:
            resolved = self._resolver(target)
            for r in resolved:
                rip = _as_ip(r)
                blocked = self._match_deny(r, rip)
                if blocked:
                    return ScopeResult(
                        False,
                        f"resolved IP {r} is denied ({blocked})",
                        resolved,
                    )

        return ScopeResult(True, f"in scope via {allowed}", resolved)

    def is_in_scope(self, target: str) -> bool:
        return self.check(target).in_scope

    # -- matching helpers ---------------------------------------------------

    def _check_repo(self, target: str) -> ScopeResult:
        norm = _norm_repo(target)
        for d in self.scope.deny.repos:
            if _norm_repo(d) == norm:
                return ScopeResult(False, "repo explicitly denied", [])
        for a in self.scope.allow.repos:
            if _norm_repo(a) == norm:
                return ScopeResult(True, "repo in allowlist", [])
        return ScopeResult(False, "repo not in allowlist", [])

    def _match_deny(self, target: str, ip) -> str | None:
        sl = self.scope.deny
        if target in sl.hosts:
            return f"host {target}"
        if _match_domains(target, sl.domains):
            return f"domain {target}"
        cidr = _match_cidrs(ip, sl.cidrs + sl.hosts)
        if cidr:
            return f"cidr {cidr}"
        return None

    def _match_allow(self, target: str, ip) -> str | None:
        sl = self.scope.allow
        if target in sl.hosts:
            return f"host {target}"
        if _match_domains(target, sl.domains):
            return f"domain {target}"
        cidr = _match_cidrs(ip, sl.cidrs + sl.hosts)
        if cidr:
            return f"cidr/host {cidr}"
        return None


# -- module helpers ---------------------------------------------------------


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _match_domains(target: str, domains: list[str]) -> bool:
    return any(fnmatch(target, pat) for pat in domains)


def _match_cidrs(ip, entries: list[str]) -> str | None:
    if ip is None:
        return None
    for entry in entries:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            # A bare host IP in the hosts list also matters for IP re-check.
            single = _as_ip(entry)
            if single is not None and single == ip:
                return entry
            continue
        if ip in net:
            return entry
    return None


def _looks_like_repo(target: str) -> bool:
    return target.startswith(("http://", "https://", "git@", "ssh://")) or (
        "/" in target and ("github.com" in target or "gitlab" in target or target.endswith(".git"))
    )


def _norm_repo(url: str) -> str:
    url = url.strip().lower()
    for prefix in ("https://", "http://", "ssh://", "git@"):
        if url.startswith(prefix):
            url = url[len(prefix):]
    url = url.replace(":", "/").rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    return url
