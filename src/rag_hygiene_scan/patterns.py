"""
Pattern / rule definitions for the RAG hygiene scanner.
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

# Core indirect-injection indicators
INJECTION_RULES: List[Rule] = [
    Rule("INJ001", "Indirect instruction: ignore previous rules/instructions",
         re.compile(r"(?i)\bignore (all|previous|above) (instructions?|rules?)\b"), "med"),
    Rule("INJ002", "Policy override language",
         re.compile(r"(?i)\boverride (policy|guardrails?)\b"), "med"),
    Rule("INJ003", "Benign marker pattern (e.g., append [TESTMARK])",
         re.compile(r"(?i)\bappend\s*\[TESTMARK\]"), "low"),
]

# Risky HTML/Markdown indicators
HTML_RULES: List[Rule] = [
    Rule("HTML001", "Raw <script> tag present",
         re.compile(r"<\s*script\b", re.I), "high"),
    Rule("HTML002", "<iframe> or similar embedded content present",
         re.compile(r"<\s*iframe\b", re.I), "high"),
    Rule("HTML003", "javascript: URI scheme present",
         re.compile(r"(?i)javascript\s*:"), "high"),
]

# PII/secret heuristics
PII_SECRET_RULES: List[Rule] = [
    Rule("PII001", "Email-like string",
         re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "low"),
    Rule("PII002", "US-like phone pattern",
         re.compile(r"(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}"), "low"),
    Rule("SEC001", "Likely secret prefix (sk_live|sk_test)",
         re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}\b"), "high"),
]

# Compose defaults
DEFAULT_RULES: List[Rule] = [*INJECTION_RULES, *HTML_RULES, *PII_SECRET_RULES]

SEVERITY_ORDER = {"low": 1, "med": 2, "high": 3}

def load_rules_from_config(cfg: Dict[str, Any] | None) -> List[Rule]:
    """
    Returns default rules; in a later chunk we'll allow YAML to add/override.
    """
    _ = cfg
    return DEFAULT_RULES
