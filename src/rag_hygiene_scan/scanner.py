"""
Core scanning functions
"""
from __future__ import annotations
from typing import Dict, Any, Iterable, List, Tuple
import pathlib
import yaml

from .patterns import load_rules_from_config, severity_rank

# Configuration
ALLOWED_EXTS = {".md", ".markdown", ".txt", ".html", ".htm"}

# File walking
def iter_files(path: pathlib.Path) -> Iterable[pathlib.Path]:
    """
    Yield files to scan (by extension) for a given file or directory.
    - If 'path' is a file, yield it if the extension is allowed.
    - If 'path' is a directory, recurse and yield matching files.
    """
    if path.is_file():
        if path.suffix.lower() in ALLOWED_EXTS:
            yield path
        return

    # Directory: recurse
    # Skip common hidden dirs quickly
    skip_dirs = {".git", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache"}
    for f in path.rglob("*"):
        try:
            # Skip directories and common hidden dirs
            if f.is_dir():  # rglob returns both files/dirs
                if f.name in skip_dirs:
                    continue
                else:
                    continue
            if f.suffix.lower() in ALLOWED_EXTS:
                yield f
        except PermissionError:
            # Ignore unreadable entries
            continue

# Config loader
def load_config(cfg_path: str | None) -> Dict[str, Any] | None:
    if not cfg_path:
        return None
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)

# Text scanning
def _make_snippet(text: str, span: Tuple[int, int], ctx: int = 40) -> str:
    s, e = span
    start = max(s - ctx, 0)
    end   = min(e + ctx, len(text))
    snippet = text[start:end].replace("\n", " ")
    return snippet[:200]  # cap snippet length

def scan_text(text: str, doc_id: str, rules) -> List[Dict[str, Any]]:
    """
    Apply compiled rules to a single text and return finding dicts.
    Finding schema:
      { doc_id, code, severity, desc, evidence }
    """
    findings: List[Dict[str, Any]] = []
    for r in rules:
        for m in r.pattern.finditer(text):
            findings.append({
                "doc_id": doc_id,
                "code": r.code,
                "severity": r.severity,
                "desc": r.desc,
                "evidence": _make_snippet(text, m.span())
            })
    return findings

# Path scanning (files/dirs)
def scan_path(path: str, cfg: Dict[str, Any] | None) -> Dict[str, Any]:
    """
    Read eligible files from 'path' and scan them with active rules.
    Returns:
      {
        "files_scanned": int,
        "findings": [ { doc_id, code, severity, desc, evidence }, ... ]
      }
    """
    p = pathlib.Path(path)
    rules = load_rules_from_config(cfg)
    findings: List[Dict[str, Any]] = []
    files_scanned = 0

    # If the user passed a file with a disallowed extension, still report 0 files_scanned
    # but don't error.
    for f in iter_files(p):
        files_scanned += 1
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            findings.append({
                "doc_id": f.as_posix(),
                "code": "READERR",
                "severity": "low",
                "desc": f"read_error: {e}",
                "evidence": ""
            })
            continue
        findings.extend(scan_text(text, f.as_posix(), rules))

    return {"files_scanned": files_scanned, "findings": findings}

# Exit code logic
def exit_code_for_findings(findings: List[Dict[str, Any]], min_sev: str) -> int:
    """
    Return 1 if any finding severity >= min_sev (by rank); else 0.
    - min_sev: "low"|"med"|"high"
    """
    try:
        threshold = severity_rank(min_sev)
    except Exception:
        # Be conservative if an invalid string is passed; treat as "med"
        threshold = severity_rank("med")

    def sev_of(f):
        try:
            return severity_rank(f.get("severity", "med"))
        except Exception:
            return severity_rank("med")

    should_fail = any(sev_of(f) >= threshold for f in findings)
    return 1 if should_fail else 0
