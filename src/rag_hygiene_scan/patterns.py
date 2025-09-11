"""
Pattern / rule definitions for the RAG hygiene scanner.
(Real rules come in later chunks; this is a minimal scaffold.)
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Pattern, List, Dict, Any
import re

@dataclass(frozen=True)
class Rule:
    code: str
    desc: str
    pattern: Pattern
    severity: str  # "low" | "med" | "high"

# Placeholder: empty default set (we'll add real ones in later chunks)
DEFAULT_RULES: List[Rule] = []

SEVERITY_ORDER = {"low": 1, "med": 2, "high": 3}

def load_rules_from_config(cfg: Dict[str, Any] | None) -> List[Rule]:
    """For now, just return DEFAULT_RULES; config support comes later."""
    _ = cfg
    return DEFAULT_RULES
