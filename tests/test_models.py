from aegis.models import (
    Candidate,
    CodeLocation,
    Confidence,
    Finding,
    PoC,
    PoCStatus,
    Report,
    Severity,
)


def _candidate(**kw) -> Candidate:
    base = dict(
        title="SQLi",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        cwe="CWE-89",
        location=CodeLocation(path="app.py", start_line=10),
    )
    base.update(kw)
    return Candidate(**base)


def test_fingerprint_is_stable_and_short():
    c1 = _candidate()
    c2 = _candidate()
    assert c1.fingerprint() == c2.fingerprint()
    assert len(c1.fingerprint()) == 16


def test_severity_and_confidence_rank_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.LOW.rank
    assert Confidence.CONFIRMED.rank > Confidence.HIGH.rank


def test_finding_confirmed_requires_verified_and_reproduced():
    c = _candidate()
    f = Finding(candidate=c)
    assert not f.confirmed
    f.verified = True
    assert not f.confirmed  # no PoC yet
    f.poc = PoC(candidate_fingerprint=c.fingerprint(), status=PoCStatus.EMITTED)
    assert not f.confirmed  # emitted, not reproduced
    f.poc.status = PoCStatus.REPRODUCED
    assert f.confirmed


def test_report_counts_and_sorting():
    high = Finding(candidate=_candidate(severity=Severity.HIGH))
    low = Finding(candidate=_candidate(severity=Severity.LOW, location=CodeLocation(path="b.py", start_line=1)))
    report = Report(target=".", findings=[low, high])
    counts = report.counts()
    assert counts["high"] == 1 and counts["low"] == 1 and counts["total"] == 2
    assert report.sorted_findings()[0] is high
