"""
Core scanning functions. This stub returns an empty findings list so the CLI works now.
"""
from __future__ import annotations
from typing import Dict, Any
import pathlib
import yaml  # dependency already in pyproject
from .patterns import load_rules_from_config

def iter_files(path: pathlib.Path):
    if path.is_file():
        yield path
        return
    for f in path.rglob("*"):
        if f.suffix.lower() in {".md", ".markdown", ".txt", ".html"}:
            yield f

def load_config(cfg_path: str | None) -> Dict[str, Any] | None:
    if not cfg_path:
        return None
    with open(cfg_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)

def scan_path(path: str, cfg: Dict[str, Any] | None) -> Dict[str, Any]:
    """Stub scan: walks files and returns an empty findings list for now."""
    p = pathlib.Path(path)
    _rules = load_rules_from_config(cfg)
    files_scanned = sum(1 for _ in iter_files(p))
    return {"files_scanned": files_scanned, "findings": []}

def exit_code_for_findings(findings, min_sev: str) -> int:
    """For now, never fail the build (return 0). Real threshold logic later."""
    _ = (findings, min_sev)
    return 0
