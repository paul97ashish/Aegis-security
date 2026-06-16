from datetime import UTC, datetime

from aegis.engagement import AuditLog, Authorizer
from aegis.engagement.roe import load_roe
from aegis.engagement.scope import ScopeChecker
from aegis.models import ActionClass

ROE_PATH = "configs/roe.example.yaml"


def _in_window_clock():
    # The example RoE window is 2026-06-20..27; pick a time inside it.
    return lambda: datetime(2026, 6, 22, 12, 0, tzinfo=UTC)


def _authorizer(tmp_path, **kw):
    roe = load_roe(ROE_PATH)
    audit = AuditLog(tmp_path / "audit.jsonl", roe.engagement.id, roe.manifest_hash())
    return Authorizer(
        roe,
        audit=audit,
        scope_checker=ScopeChecker(roe.scope, resolver=lambda h: []),
        signatures_verified=True,
        clock=_in_window_clock(),
        **kw,
    ), audit


def test_unsigned_fails_closed(tmp_path):
    roe = load_roe(ROE_PATH)
    auth = Authorizer(roe, signatures_verified=False, clock=_in_window_clock())
    d = auth.authorize("scan", ActionClass.VULN_SCAN, "app.acme.example")
    assert not d.allowed and "signatures" in d.reason


def test_permitted_class_in_scope_allowed(tmp_path):
    auth, _ = _authorizer(tmp_path)
    d = auth.authorize("scan", ActionClass.VULN_SCAN, "app.acme.example")
    assert d.allowed


def test_forbidden_class_denied(tmp_path):
    auth, _ = _authorizer(tmp_path)
    d = auth.authorize("dos", ActionClass.DENIAL_OF_SERVICE, "app.acme.example")
    assert not d.allowed and "forbidden" in d.reason


def test_out_of_scope_denied_and_recommended(tmp_path):
    auth, _ = _authorizer(tmp_path)
    d = auth.authorize("scan", ActionClass.VULN_SCAN, "evil.example")
    assert not d.allowed
    assert any("evil.example" in r for r in auth.scope_amendment_recommendations)


def test_exploitation_requires_approval(tmp_path):
    auth, _ = _authorizer(tmp_path, approval_fn=lambda a, t: False)
    # exploitation not in example permitted_classes -> denied for that reason first
    d = auth.authorize("poc", ActionClass.EXPLOITATION, "app.acme.example")
    assert not d.allowed


def test_audit_chain_records_and_verifies(tmp_path):
    auth, audit = _authorizer(tmp_path)
    auth.authorize("scan", ActionClass.VULN_SCAN, "app.acme.example")
    auth.authorize("scan", ActionClass.VULN_SCAN, "evil.example")
    ok, msg = audit.verify_chain()
    assert ok, msg


def test_audit_tamper_detected(tmp_path):
    auth, audit = _authorizer(tmp_path)
    auth.authorize("scan", ActionClass.VULN_SCAN, "app.acme.example")
    path = tmp_path / "audit.jsonl"
    lines = path.read_text().splitlines()
    tampered = lines[0].replace("app.acme.example", "attacker.example")
    path.write_text(tampered + "\n")
    ok, msg = audit.verify_chain()
    assert not ok and "tampered" in msg
