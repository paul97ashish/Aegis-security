"""Mapper — index files, languages, entry points, frameworks, attack surfaces.

v1 uses extension heuristics + lightweight content probes (ripgrep-style). The
design notes Tree-sitter / Roslyn for language-aware data-flow later (§10).
"""

from __future__ import annotations

import re
from pathlib import Path

from aegis.models import AttackSurface, CodebaseMap, FileInfo

# Extension -> language.
LANG_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".rs": "rust",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sh": "shell",
    ".sql": "sql",
}

# Directories never worth scanning.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache", "vendor",
    "target", ".idea", ".vscode", "site-packages",
}

# Framework signatures: filename or import marker -> framework label.
FRAMEWORK_MARKERS: list[tuple[str, str]] = [
    ("flask", "Flask"),
    ("django", "Django"),
    ("fastapi", "FastAPI"),
    ("express", "Express"),
    ("react", "React"),
    ("spring", "Spring"),
    ("rails", "Rails"),
    ("laravel", "Laravel"),
]

ENTRY_POINT_NAMES = {
    "main.py", "app.py", "wsgi.py", "asgi.py", "manage.py", "__main__.py",
    "index.js", "server.js", "app.js", "main.go", "main.rs", "program.cs",
}

# Attack-surface probes: (regex, kind, detail).
SURFACE_PROBES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"@(app|router|blueprint)\.(route|get|post|put|delete|patch)", re.I), "http_route", "HTTP route handler"),
    (re.compile(r"app\.(get|post|put|delete|use)\s*\(", re.I), "http_route", "Express route"),
    (re.compile(r"\b(request|req)\.(args|form|json|body|params|query|GET|POST)\b"), "user_input", "Reads request input"),
    (re.compile(r"\b(input|sys\.argv|argparse|os\.environ)\b"), "cli_arg", "CLI / env input"),
    (re.compile(r"\b(open|read|readFile|fopen)\s*\("), "file_io", "File I/O"),
    (re.compile(r"\b(pickle|yaml\.load|Marshal|unserialize|ObjectInputStream)\b"), "deserialize", "Deserialization"),
    (re.compile(r"\b(execute|query|cursor)\b.*\b(select|insert|update|delete)\b", re.I), "sql", "SQL query"),
    (re.compile(r"\b(requests\.|urlopen|httpx\.|fetch\(|axios\.)"), "outbound_http", "Outbound HTTP"),
]


class Mapper:
    def __init__(self, max_file_bytes: int = 1_500_000) -> None:
        self.max_file_bytes = max_file_bytes

    def map(self, root: str | Path, *, include: list[str] | None = None,
            exclude: list[str] | None = None) -> CodebaseMap:
        root_path = Path(root).resolve()
        include = include or []
        exclude = exclude or []

        files: list[FileInfo] = []
        languages: dict[str, int] = {}
        frameworks: set[str] = set()
        entry_points: list[str] = []
        surfaces: list[AttackSurface] = []

        for path in self._walk(root_path):
            rel = str(path.relative_to(root_path))
            if include and not any(rel.startswith(p.rstrip("/")) for p in include):
                continue
            if exclude and any(rel.startswith(p.rstrip("/")) for p in exclude):
                continue

            lang = LANG_BY_EXT.get(path.suffix.lower())
            try:
                size = path.stat().st_size
            except OSError:
                continue
            is_entry = path.name in ENTRY_POINT_NAMES
            info = FileInfo(path=rel, language=lang, size_bytes=size, is_entry_point=is_entry)
            files.append(info)
            if lang:
                languages[lang] = languages.get(lang, 0) + 1
            if is_entry:
                entry_points.append(rel)

            if lang and size <= self.max_file_bytes:
                text = self._read(path)
                if text:
                    frameworks |= self._detect_frameworks(text)
                    surfaces.extend(self._detect_surfaces(rel, text))

        return CodebaseMap(
            root=str(root_path),
            files=files,
            languages=languages,
            frameworks=sorted(frameworks),
            entry_points=entry_points,
            surfaces=surfaces,
        )

    # Internal helpers ------------------------------------------------------

    def _walk(self, root: Path):
        if root.is_file():
            yield root
            return
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            yield path

    def _read(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    def _detect_frameworks(self, text: str) -> set[str]:
        low = text.lower()
        return {label for marker, label in FRAMEWORK_MARKERS if marker in low}

    def _detect_surfaces(self, rel: str, text: str) -> list[AttackSurface]:
        out: list[AttackSurface] = []
        lines = text.splitlines()
        for i, line in enumerate(lines, start=1):
            for rx, kind, detail in SURFACE_PROBES:
                if rx.search(line):
                    out.append(AttackSurface(kind=kind, path=rel, line=i, detail=detail))
                    break  # one surface tag per line is enough
        return out
