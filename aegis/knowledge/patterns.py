"""CWE-mapped security patterns.

Each pattern is a *candidate generator*, not a verdict: a regex hit means
"worth a closer look", which the verifier (and ultimately a PoC) confirms or
rejects. Keeping these conservative-but-broad is intentional — recall first,
precision via the PoC gate (design §1.3).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aegis.models import Severity


@dataclass(frozen=True)
class SecurityPattern:
    id: str
    title: str
    category: str
    cwe: str
    severity: Severity
    regex: str
    languages: tuple[str, ...]  # empty == all languages
    remediation: str
    references: tuple[str, ...] = field(default_factory=tuple)

    _compiled: re.Pattern = field(default=None, repr=False, compare=False, hash=False)  # type: ignore[assignment]

    def compiled(self) -> re.Pattern:
        object_setattr = object.__setattr__
        if self._compiled is None:
            object_setattr(self, "_compiled", re.compile(self.regex))
        return self._compiled


# Remediation guidance, keyed by CWE, reused by reporter + prompt injection.
REMEDIATIONS: dict[str, str] = {
    "CWE-89": "Use parameterized queries / prepared statements; never build SQL by string concatenation or interpolation of untrusted input.",
    "CWE-78": "Avoid invoking a shell. Use argument-vector APIs (e.g. subprocess with a list and shell=False) and validate/allowlist inputs.",
    "CWE-94": "Never eval/exec untrusted input. Use safe parsers (ast.literal_eval, JSON) or a sandboxed expression evaluator.",
    "CWE-502": "Do not deserialize untrusted data with unsafe loaders (pickle, yaml.load, Java native serialization). Use safe formats (JSON) and yaml.safe_load.",
    "CWE-918": "Validate and allowlist outbound request targets; resolve and re-check IPs; block internal/link-local ranges; disable redirects to untrusted hosts.",
    "CWE-22": "Canonicalize paths and confirm they remain within an allowed base directory; reject '..' and absolute paths from user input.",
    "CWE-798": "Remove hardcoded credentials. Load secrets from a secret manager or environment; rotate any exposed keys.",
    "CWE-327": "Replace weak/broken algorithms (MD5, SHA1, DES, ECB) with vetted modern primitives (SHA-256+, AES-GCM, Argon2/bcrypt for passwords).",
    "CWE-330": "Use a cryptographically secure RNG (secrets, os.urandom) for tokens, IDs, and keys — not the stdlib PRNG.",
    "CWE-295": "Do not disable TLS certificate verification. Pin or validate certificates; fix the trust store instead.",
    "CWE-79": "Encode/escape output by context; prefer framework auto-escaping; avoid sinks like innerHTML/dangerouslySetInnerHTML with untrusted data.",
    "CWE-489": "Disable debug mode in production; it can leak stack traces, enable code execution consoles, and weaken security.",
    "CWE-259": "Do not hardcode passwords. Externalize and rotate credentials.",
    "CWE-347": "Verify cryptographic signatures with a fixed, strong algorithm; reject 'none' and attacker-controlled algorithm selection.",
}


def remediation_for_cwe(cwe: str | None) -> str:
    if not cwe:
        return "Validate and sanitize untrusted input at trust boundaries; apply least privilege."
    return REMEDIATIONS.get(cwe, "Apply the standard remediation for this CWE; see the linked references.")


PATTERNS: list[SecurityPattern] = [
    SecurityPattern(
        id="py-sql-fstring",
        title="Possible SQL injection via string-formatted query",
        category="sql_injection",
        cwe="CWE-89",
        severity=Severity.HIGH,
        regex=r"""(?i)(execute|executemany|cursor\.execute|\.raw)\s*\(\s*[furb]*["'].*?(%s|%\(|\{|\+|%\s|format\()""",
        languages=("python",),
        remediation=REMEDIATIONS["CWE-89"],
        references=("https://cwe.mitre.org/data/definitions/89.html",),
    ),
    SecurityPattern(
        id="generic-sql-concat",
        title="Possible SQL injection via concatenated query string",
        category="sql_injection",
        cwe="CWE-89",
        severity=Severity.HIGH,
        regex=r"""(?i)(select|insert|update|delete)\b[^;'"]{0,120}["']\s*\+\s*\w""",
        languages=(),
        remediation=REMEDIATIONS["CWE-89"],
        references=("https://cwe.mitre.org/data/definitions/89.html",),
    ),
    SecurityPattern(
        id="py-os-system",
        title="Command execution via os.system / popen",
        category="command_injection",
        cwe="CWE-78",
        severity=Severity.HIGH,
        regex=r"\bos\.(system|popen)\s*\(",
        languages=("python",),
        remediation=REMEDIATIONS["CWE-78"],
        references=("https://cwe.mitre.org/data/definitions/78.html",),
    ),
    SecurityPattern(
        id="py-subprocess-shell",
        title="subprocess called with shell=True",
        category="command_injection",
        cwe="CWE-78",
        severity=Severity.HIGH,
        regex=r"subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
        languages=("python",),
        remediation=REMEDIATIONS["CWE-78"],
        references=("https://cwe.mitre.org/data/definitions/78.html",),
    ),
    SecurityPattern(
        id="py-eval-exec",
        title="Dynamic code execution via eval/exec",
        category="code_injection",
        cwe="CWE-94",
        severity=Severity.HIGH,
        regex=r"\b(eval|exec)\s*\(",
        languages=("python",),
        remediation=REMEDIATIONS["CWE-94"],
        references=("https://cwe.mitre.org/data/definitions/94.html",),
    ),
    SecurityPattern(
        id="js-eval",
        title="Dynamic code execution via eval/Function",
        category="code_injection",
        cwe="CWE-94",
        severity=Severity.HIGH,
        regex=r"\b(eval\s*\(|new\s+Function\s*\()",
        languages=("javascript", "typescript"),
        remediation=REMEDIATIONS["CWE-94"],
        references=("https://cwe.mitre.org/data/definitions/94.html",),
    ),
    SecurityPattern(
        id="py-pickle-load",
        title="Unsafe deserialization via pickle",
        category="deserialization",
        cwe="CWE-502",
        severity=Severity.HIGH,
        regex=r"\bpickle\.(load|loads)\s*\(",
        languages=("python",),
        remediation=REMEDIATIONS["CWE-502"],
        references=("https://cwe.mitre.org/data/definitions/502.html",),
    ),
    SecurityPattern(
        id="py-yaml-load",
        title="Unsafe YAML load (arbitrary object construction)",
        category="deserialization",
        cwe="CWE-502",
        severity=Severity.HIGH,
        regex=r"yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)",
        languages=("python",),
        remediation=REMEDIATIONS["CWE-502"],
        references=("https://cwe.mitre.org/data/definitions/502.html",),
    ),
    SecurityPattern(
        id="py-ssrf-requests",
        title="Possible SSRF: outbound request to dynamic URL",
        category="ssrf",
        cwe="CWE-918",
        severity=Severity.MEDIUM,
        regex=r"""(requests\.(get|post|put|delete|head)|urllib\.request\.urlopen|httpx\.(get|post))\s*\(\s*[furb]*["']?\s*(\{|%s|\+|f["'])""",
        languages=("python",),
        remediation=REMEDIATIONS["CWE-918"],
        references=("https://cwe.mitre.org/data/definitions/918.html",),
    ),
    SecurityPattern(
        id="py-path-traversal",
        title="Possible path traversal via concatenated file path",
        category="path_traversal",
        cwe="CWE-22",
        severity=Severity.MEDIUM,
        regex=r"""open\s*\(\s*[^)]*(\+\s*\w+|os\.path\.join\s*\([^)]*request|\{)""",
        languages=("python",),
        remediation=REMEDIATIONS["CWE-22"],
        references=("https://cwe.mitre.org/data/definitions/22.html",),
    ),
    SecurityPattern(
        id="generic-aws-key",
        title="Hardcoded AWS access key id",
        category="secrets",
        cwe="CWE-798",
        severity=Severity.CRITICAL,
        regex=r"\bAKIA[0-9A-Z]{16}\b",
        languages=(),
        remediation=REMEDIATIONS["CWE-798"],
        references=("https://cwe.mitre.org/data/definitions/798.html",),
    ),
    SecurityPattern(
        id="generic-secret-assign",
        title="Hardcoded secret / credential",
        category="secrets",
        cwe="CWE-798",
        severity=Severity.HIGH,
        regex=r"""(?i)(api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*["'][^"'\s]{8,}["']""",
        languages=(),
        remediation=REMEDIATIONS["CWE-798"],
        references=("https://cwe.mitre.org/data/definitions/798.html",),
    ),
    SecurityPattern(
        id="generic-weak-hash",
        title="Weak cryptographic hash (MD5/SHA1)",
        category="weak_crypto",
        cwe="CWE-327",
        severity=Severity.MEDIUM,
        regex=r"(?i)(hashlib\.(md5|sha1)\s*\(|MessageDigest\.getInstance\(\s*[\"'](MD5|SHA-?1)|createHash\(\s*[\"'](md5|sha1))",
        languages=(),
        remediation=REMEDIATIONS["CWE-327"],
        references=("https://cwe.mitre.org/data/definitions/327.html",),
    ),
    SecurityPattern(
        id="py-insecure-random",
        title="Insecure RNG used where security-sensitive randomness is likely",
        category="weak_crypto",
        cwe="CWE-330",
        severity=Severity.LOW,
        regex=r"\brandom\.(random|randint|choice|randrange)\s*\(",
        languages=("python",),
        remediation=REMEDIATIONS["CWE-330"],
        references=("https://cwe.mitre.org/data/definitions/330.html",),
    ),
    SecurityPattern(
        id="py-tls-verify-off",
        title="TLS certificate verification disabled",
        category="tls",
        cwe="CWE-295",
        severity=Severity.HIGH,
        regex=r"verify\s*=\s*False",
        languages=("python",),
        remediation=REMEDIATIONS["CWE-295"],
        references=("https://cwe.mitre.org/data/definitions/295.html",),
    ),
    SecurityPattern(
        id="js-tls-verify-off",
        title="TLS certificate verification disabled",
        category="tls",
        cwe="CWE-295",
        severity=Severity.HIGH,
        regex=r"rejectUnauthorized\s*:\s*false",
        languages=("javascript", "typescript"),
        remediation=REMEDIATIONS["CWE-295"],
        references=("https://cwe.mitre.org/data/definitions/295.html",),
    ),
    SecurityPattern(
        id="js-dom-xss",
        title="Possible DOM XSS sink",
        category="xss",
        cwe="CWE-79",
        severity=Severity.MEDIUM,
        regex=r"(\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\()",
        languages=("javascript", "typescript"),
        remediation=REMEDIATIONS["CWE-79"],
        references=("https://cwe.mitre.org/data/definitions/79.html",),
    ),
    SecurityPattern(
        id="py-flask-debug",
        title="Debug mode enabled (information disclosure / RCE console)",
        category="misconfig",
        cwe="CWE-489",
        severity=Severity.MEDIUM,
        regex=r"(app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)",
        languages=("python",),
        remediation=REMEDIATIONS["CWE-489"],
        references=("https://cwe.mitre.org/data/definitions/489.html",),
    ),
    SecurityPattern(
        id="jwt-none-alg",
        title="JWT 'none' algorithm or unverified decode",
        category="auth",
        cwe="CWE-347",
        severity=Severity.HIGH,
        regex=r"""(algorithm[s]?\s*[:=]\s*\[?\s*["']none["']|verify\s*[:=]\s*False|verify_signature\s*[:=]\s*False)""",
        languages=(),
        remediation=REMEDIATIONS["CWE-347"],
        references=("https://cwe.mitre.org/data/definitions/347.html",),
    ),
]


def patterns_for_language(language: str | None) -> list[SecurityPattern]:
    """Patterns that apply to a language (plus language-agnostic ones)."""
    lang = (language or "").lower()
    return [p for p in PATTERNS if not p.languages or lang in p.languages]
