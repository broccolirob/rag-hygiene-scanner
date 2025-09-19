# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Robert Schneider

"""
Core scanning functions
"""

from __future__ import annotations

import pathlib
from typing import Any, Dict, Iterable, List, Tuple, TypedDict

import yaml

from .patterns import load_rules_from_config, severity_rank


# ---------------- Types ----------------
class Finding(TypedDict):
    doc_id: str
    code: str
    severity: str
    desc: str
    evidence: str


class ScanResult(TypedDict):
    files_scanned: int
    findings: List[Finding]


# ---------------- Config ----------------
ALLOWED_EXTS = {".md", ".markdown", ".txt", ".html", ".htm"}
SKIP_DIRS = {".git", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache"}
MAX_SNIPPET_LEN = 200


def should_scan_file(p: pathlib.Path) -> bool:
    """Return True if the file looks like a text doc we should scan."""
    return p.is_file() and p.suffix.lower() in ALLOWED_EXTS


# ---------------- File walking ----------------
def iter_files(path: pathlib.Path) -> Iterable[pathlib.Path]:
    """
    Yield files to scan:
      - If 'path' is a file, yield it when extension is allowed
      - If 'path' is a directory, recurse and yield allowed files
    Hidden/tooling dirs are ignored in practice by checking names, but
    rglob() cannot be pruned; we simply skip matches.
    """
    if path.is_file():
        if should_scan_file(path):
            yield path
        return

    for f in path.rglob("*"):
        try:
            if f.is_dir():
                # Can't prune rglob, but we can skip by name
                if f.name in SKIP_DIRS:
                    continue
                continue
            if should_scan_file(f):
                yield f
        except PermissionError:
            # Ignore unreadable entries quietly
            continue


# ---------------- Config loader ----------------
def load_config(cfg_path: str | None) -> Dict[str, Any] | None:
    """Load YAML into a dict, or return None if no path provided."""
    if not cfg_path:
        return None
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------- Text scanning ----------------
def _make_snippet(text: str, span: Tuple[int, int], ctx: int = 40) -> str:
    """Return a short, single-line context snippet around a match."""
    s, e = span
    start = max(s - ctx, 0)
    end = min(e + ctx, len(text))
    snippet = text[start:end].replace("\n", " ")
    return snippet[:MAX_SNIPPET_LEN]


def scan_text(text: str, doc_id: str, rules) -> List[Finding]:
    """
    Apply compiled rules to a single text and return finding dicts.
    Finding schema: { doc_id, code, severity, desc, evidence }
    """
    findings: List[Finding] = []
    for r in rules:
        for m in r.pattern.finditer(text):
            findings.append(
                Finding(
                    doc_id=doc_id,
                    code=r.code,
                    severity=r.severity,
                    desc=r.desc,
                    evidence=_make_snippet(text, m.span()),
                )
            )
    return findings


# ---------------- Path scanning ----------------
def scan_path(path: str, cfg: Dict[str, Any] | None) -> ScanResult:
    """
    Read eligible files from 'path' and scan them with active rules.
    Returns:
      { "files_scanned": int, "findings": [Finding, ...] }
    """
    p = pathlib.Path(path)
    rules = load_rules_from_config(cfg)
    findings: List[Finding] = []
    files_scanned = 0

    for f in iter_files(p):
        files_scanned += 1
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            findings.append(
                Finding(
                    doc_id=f.as_posix(),
                    code="READERR",
                    severity="low",
                    desc=f"read_error: {e}",
                    evidence="",
                )
            )
            continue
        findings.extend(scan_text(text, f.as_posix(), rules))

    return ScanResult(files_scanned=files_scanned, findings=findings)


# ---------------- Exit code logic ----------------
def exit_code_for_findings(findings: List[Finding], min_sev: str) -> int:
    """
    Return 1 if any finding severity >= min_sev (by rank); else 0.
    - min_sev: "low"|"med"|"high"
    """
    try:
        threshold = severity_rank(min_sev)
    except Exception:
        threshold = severity_rank("med")

    def sev_of(f: Finding) -> int:
        try:
            return severity_rank(f.get("severity", "med"))
        except Exception:
            return severity_rank("med")

    should_fail = any(sev_of(f) >= threshold for f in findings)
    return 1 if should_fail else 0
