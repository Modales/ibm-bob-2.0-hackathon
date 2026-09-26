"""
cross_language_parser.py — Polyglot Static Analysis
===================================================

IBM Bob 2.0 Hackathon · /services/orchestrator/

The AST mutation engine gives us deep, structural analysis for Python. Real
enterprise estates are polyglot, though — so this module extends coverage to
JavaScript/TypeScript and Java via curated, regex-based security scanners.

Architecture
------------
* ``detect_language`` — extension + content heuristics decide which scanner
  (or the Python AST pipeline) handles a file.
* Language scanners emit ``PolyglotFinding`` records in exactly the shape the
  auditor service returns, so findings flow into the IBM Bob multi-agent
  pipeline unchanged — the downstream stages never know (or care) which
  parser produced them.
* Regex parsing is a deliberate trade-off: it is not a full grammar, but it
  is dependency-free, fast, safe on hostile input, and demonstrably effective
  for the high-signal patterns (``eval()``, ``dangerouslySetInnerHTML``,
  hardcoded secrets, ``Runtime.exec``, weak crypto) that hackathon scenarios
  and most real audits hinge on.
"""

from __future__ import annotations

import asyncio
import re
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    UNKNOWN = "unknown"


class PolyglotFinding(BaseModel):
    """
    Auditor-compatible finding. Mirrors ``VulnerabilityItem`` in main.py so
    results drop straight into the existing pipeline without translation.
    """

    file_path: str
    line_number: int
    description: str
    severity: str = Field(..., description="low | medium | high | critical")
    language: Language
    rule_id: str = Field(..., description="Stable rule identifier, e.g. JS001.")


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_EXTENSION_MAP: Dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT, ".jsx": Language.JAVASCRIPT, ".mjs": Language.JAVASCRIPT, ".cjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT, ".tsx": Language.TYPESCRIPT, ".mts": Language.TYPESCRIPT,
    ".java": Language.JAVA,
}

_CONTENT_HINTS: List[Tuple[re.Pattern[str], Language]] = [
    (re.compile(r"\binterface\s+\w+\s*\{|\btype\s+\w+\s*=\s*"), Language.TYPESCRIPT),
    (re.compile(r"\bpublic\s+(static\s+)?class\s+\w+|\bSystem\.out\.println"), Language.JAVA),
    (re.compile(r"\bconsole\.log\(|=>|require\(|import .* from "), Language.JAVASCRIPT),
    (re.compile(r"^\s*(def|class|import|from)\s", re.MULTILINE), Language.PYTHON),
]


def detect_language(file_path: str, content: Optional[str] = None) -> Language:
    """
    Detect a file's language: extension first, content heuristics as fallback.
    """
    suffix = Path(file_path).suffix.lower()
    if suffix in _EXTENSION_MAP:
        return _EXTENSION_MAP[suffix]
    if content:
        for pattern, language in _CONTENT_HINTS:
            if pattern.search(content):
                return language
    return Language.UNKNOWN


# ---------------------------------------------------------------------------
# Rule tables — (rule_id, severity, regex, human description)
# ---------------------------------------------------------------------------

_JS_TS_RULES: List[Tuple[str, str, re.Pattern[str], str]] = [
    ("JS001", "critical", re.compile(r"\beval\s*\("), "Use of eval() — arbitrary code execution risk."),
    ("JS002", "high", re.compile(r"dangerouslySetInnerHTML"), "React dangerouslySetInnerHTML — potential XSS sink."),
    ("JS003", "high", re.compile(r"""(?:api[_-]?key|api[_-]?secret|access[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]""", re.IGNORECASE), "Hardcoded API key/secret in source."),
    ("JS004", "medium", re.compile(r"\binnerHTML\s*="), "Direct innerHTML assignment — potential DOM XSS."),
    ("JS005", "high", re.compile(r"crypto\.createHash\(['\"](?:md5|sha1)['\"]\)"), "Weak hash algorithm (md5/sha1) in Node crypto."),
    ("JS006", "medium", re.compile(r"\bchild_process\.exec\s*\("), "child_process.exec with possible shell injection."),
    ("JS007", "low", re.compile(r"\bconsole\.log\s*\("), "console.log left in code — may leak data in production."),
]

_JAVA_RULES: List[Tuple[str, str, re.Pattern[str], str]] = [
    ("JV001", "critical", re.compile(r"\bRuntime\.getRuntime\(\)\.exec\s*\("), "Runtime.exec() — command injection risk."),
    ("JV002", "high", re.compile(r"MessageDigest\.getInstance\(['\"](?:MD5|SHA-1)['\"]\)"), "Weak hash algorithm (MD5/SHA-1)."),
    ("JV003", "high", re.compile(r"""(?:password|secret|apiKey)\s*=\s*"[A-Za-z0-9_\-]{8,}"""", re.IGNORECASE), "Hardcoded credential in source."),
    ("JV004", "high", re.compile(r"Statement\s+\w+\s*=.*createStatement\(\).*(?:\+|\bexecuteQuery\s*\(\s*\"[^\"]*\"\s*\+)"), "Possible SQL injection via string-built Statement."),
    ("JV005", "medium", re.compile(r"new\s+ObjectInputStream\s*\("), "Java deserialization — untrusted object stream risk."),
    ("JV006", "low", re.compile(r"\bSystem\.out\.println\s*\("), "System.out.println left in code — use a logger."),
]

#: Python fallback rules — used only when the AST engine is unavailable
#: (syntax-broken legacy files that still need triage).
_PYTHON_RULES: List[Tuple[str, str, re.Pattern[str], str]] = [
    ("PY001", "critical", re.compile(r"\beval\s*\("), "Use of eval()."),
    ("PY002", "critical", re.compile(r"\bexec\s*\("), "Use of exec()."),
    ("PY003", "high", re.compile(r"hashlib\.(?:md5|sha1)\s*\("), "Weak hash algorithm (md5/sha1)."),
    ("PY004", "high", re.compile(r"""(?:api_key|secret|password)\s*=\s*['"][A-Za-z0-9_\-]{8,}['"]""", re.IGNORECASE), "Hardcoded credential in source."),
    ("PY005", "medium", re.compile(r"\bos\.system\s*\(|\bsubprocess\.call\s*\([^)]*shell\s*=\s*True"), "Shell execution risk."),
]

_RULES_BY_LANGUAGE: Dict[Language, List[Tuple[str, str, re.Pattern[str], str]]] = {
    Language.JAVASCRIPT: _JS_TS_RULES,
    Language.TYPESCRIPT: _JS_TS_RULES,
    Language.JAVA: _JAVA_RULES,
    Language.PYTHON: _PYTHON_RULES,
}


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _scan_with_rules(content: str, file_path: str, language: Language) -> List[PolyglotFinding]:
    """Apply a language's rule table line-by-line (accurate line numbers)."""
    findings: List[PolyglotFinding] = []
    rules = _RULES_BY_LANGUAGE.get(language, [])
    lines = content.splitlines()
    for rule_id, severity, pattern, description in rules:
        for lineno, line in enumerate(lines, start=1):
            if pattern.search(line):
                findings.append(PolyglotFinding(
                    file_path=file_path, line_number=lineno,
                    description=description, severity=severity,
                    language=language, rule_id=rule_id,
                ))
    return findings


async def scan_file(file_path: str, content: Optional[str] = None) -> List[PolyglotFinding]:
    """
    Scan one file. If ``content`` is omitted the file is read from disk
    (offloaded to a worker thread). Unknown languages yield no findings.
    """
    if content is None:
        try:
            content = await asyncio.to_thread(Path(file_path).read_text, "utf-8")
        except OSError:
            return []
    language = detect_language(file_path, content)
    if language is Language.UNKNOWN:
        return []
    return await asyncio.to_thread(_scan_with_rules, content, file_path, language)


async def scan_repository(repo_path: str, max_files: int = 500) -> List[PolyglotFinding]:
    """
    Walk a repository and scan every supported source file concurrently
    (bounded gather — at most ``max_files`` files to keep demos snappy).
    """
    root = Path(repo_path)
    if not root.is_dir():
        return []
    candidates = [
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in _EXTENSION_MAP
    ][:max_files]
    batches = await asyncio.gather(*(scan_file(str(p)) for p in candidates))
    return [finding for batch in batches for finding in batch]


# ---------------------------------------------------------------------------
# Self-test: `python cross_language_parser.py`
# ---------------------------------------------------------------------------

if __name__ == "__main__":  # pragma: no cover
    async def _demo() -> None:
        samples = {
            "app/Login.tsx": 'const apiKey = "sk-live-abcdef1234567890";\nthis.setState({});\n<div dangerouslySetInnerHTML={{__html: data}} />',
            "Legacy.java": 'class Legacy {\n  String password = "hunter2hunter2";\n  void run() { Runtime.getRuntime().exec(cmd); }\n}',
            "broken.py": "def check(p):\n    return eval(p)  # unparseable legacy? still scanned",
        }
        for path, code in samples.items():
            lang = detect_language(path, code)
            findings = await scan_file(path, code)
            print(f"{path} -> {lang.value}, {len(findings)} finding(s)")
            for f in findings:
                print(f"  [{f.rule_id}] line {f.line_number} ({f.severity}): {f.description}")

    asyncio.run(_demo())
