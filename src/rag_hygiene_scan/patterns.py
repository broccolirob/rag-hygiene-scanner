"""
Pattern / rule definitions for the RAG hygiene scanner.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Pattern, List, Dict, Any
import re

# Severity helpers
ALLOWED_SEVERITIES = {"low", "med", "high"}
SEVERITY_ORDER = {"low": 1, "med": 2, "high": 3}

def severity_rank(sev: str) -> int:
    s = (sev or "").lower()
    if s not in SEVERITY_ORDER:
        raise ValueError(f"Invalid severity: {sev!r}. Allowed: {sorted(ALLOWED_SEVERITIES)}")
    return SEVERITY_ORDER[s]

def compile_re(pat: str, ignore_case: bool = True) -> Pattern:
    return re.compile(pat, re.I if ignore_case else 0)

# Rule model
@dataclass(frozen=True)
class Rule:
    code: str
    desc: str
    pattern: Pattern
    severity: str  # "low" | "med" | "high"

# Core indirect-injection indicators
INJECTION_RULES: List[Rule] = [
    Rule("INJ001", "Indirect instruction: ignore previous rules/instructions",
         compile_re(r"\bignore (all|previous|above) (instructions?|rules?)\b"), "med"),
    Rule("INJ002", "Policy override language",
         compile_re(r"\boverride (policy|guardrails?)\b"), "med"),
    Rule("INJ003", "Benign marker pattern (e.g., append [TESTMARK])",
         compile_re(r"\bappend\s*\[TESTMARK\]"), "low"),
]

# Risky HTML/Markdown indicators
HTML_RULES: List[Rule] = [
    Rule("HTML001", "Raw <script> tag present", compile_re(r"<\s*script\b", True), "high"),
    Rule("HTML002", "<iframe> or similar embedded content present", compile_re(r"<\s*iframe\b"), "high"),
    Rule("HTML003", "javascript: URI scheme present", compile_re(r"javascript\s*:", True), "high"),
]

# PII/secret heuristics
PII_SECRET_RULES: List[Rule] = [
    Rule("PII001", "Email-like string", compile_re(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "low"),
    Rule("PII002", "US-like phone pattern", compile_re(r"(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}"), "low"),
    Rule("SEC001", "Likely secret prefix (sk_live|sk_test)",
         compile_re(r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}\b"), "high"),
]

def _compose_default_rules() -> List[Rule]:
    return [*INJECTION_RULES, *HTML_RULES, *PII_SECRET_RULES]

# For now, return defaults unchanged
def load_rules_from_config(cfg: Dict[str, Any] | None) -> List[Rule]:
    _ = cfg
    return _compose_default_rules()
