from aegis.engagement.roe import Scope, ScopeList
from aegis.engagement.scope import ScopeChecker


def _scope() -> Scope:
    return Scope(
        allow=ScopeList(
            hosts=["app.acme.example", "10.20.0.0/24"],
            domains=["*.staging.acme.example"],
            repos=["github.com/acme/web-app"],
        ),
        deny=ScopeList(
            hosts=["10.20.0.5", "billing-prod.acme.example"],
            cidrs=["10.20.99.0/24"],
        ),
    )


def test_allow_host_in_scope():
    chk = ScopeChecker(_scope(), resolver=lambda h: [])
    assert chk.is_in_scope("app.acme.example")


def test_deny_wins_over_allow():
    chk = ScopeChecker(_scope(), resolver=lambda h: [])
    # 10.20.0.5 is inside the allowed /24 but explicitly denied.
    res = chk.check("10.20.0.5")
    assert not res.in_scope and "denied" in res.reason


def test_not_in_allowlist_blocked():
    chk = ScopeChecker(_scope(), resolver=lambda h: [])
    assert not chk.is_in_scope("evil.example")


def test_wildcard_domain_allowed():
    chk = ScopeChecker(_scope(), resolver=lambda h: [])
    assert chk.is_in_scope("web.staging.acme.example")


def test_runtime_ip_recheck_blocks_resolved_into_deny():
    # Host is allowed by domain but resolves into a denied CIDR at action time.
    scope = Scope(
        allow=ScopeList(domains=["*.staging.acme.example"]),
        deny=ScopeList(cidrs=["10.20.99.0/24"]),
    )
    chk = ScopeChecker(scope, resolver=lambda h: ["10.20.99.7"])
    res = chk.check("evil.staging.acme.example")
    assert not res.in_scope and "resolved IP" in res.reason


def test_repo_scope():
    chk = ScopeChecker(_scope(), resolver=lambda h: [])
    assert chk.is_in_scope("https://github.com/acme/web-app.git")
    assert not chk.is_in_scope("https://github.com/acme/secret-repo")
