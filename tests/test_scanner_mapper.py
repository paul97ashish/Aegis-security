from pathlib import Path

from aegis.stages import Mapper, Scanner, Triage

CORPUS = Path(__file__).parent / "corpora"


def test_mapper_indexes_python_and_surfaces():
    cmap = Mapper().map(CORPUS)
    assert cmap.languages.get("python", 0) >= 1
    kinds = {s.kind for s in cmap.surfaces}
    # vulnerable_app.py reads files / sql / outbound http etc.
    assert "sql" in kinds or "outbound_http" in kinds


def test_scanner_finds_seeded_cwes():
    scanner = Scanner()
    text = (CORPUS / "vulnerable_app.py").read_text()
    candidates = scanner.scan_text("vulnerable_app.py", text, "python")
    found_cwes = {c.cwe for c in candidates}
    # The KB sweep should catch the obvious planted bugs.
    for cwe in ("CWE-89", "CWE-78", "CWE-502", "CWE-798", "CWE-327", "CWE-94"):
        assert cwe in found_cwes, f"missing {cwe} in {found_cwes}"


def test_triage_dedups_and_ranks():
    scanner = Scanner()
    text = (CORPUS / "vulnerable_app.py").read_text()
    candidates = scanner.scan_text("vulnerable_app.py", text, "python")
    # Duplicate the candidate list; triage must collapse identical fingerprints.
    findings = Triage().run(candidates + candidates)
    fps = [f.candidate.fingerprint() for f in findings]
    assert len(fps) == len(set(fps))
    # Sorted by score descending.
    scores = [f.score for f in findings]
    assert scores == sorted(scores, reverse=True)
