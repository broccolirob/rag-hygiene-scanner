# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Robert Schneider

"""
Pattern / rule definitions for the RAG hygiene scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Pattern

# Severity helpers
ALLOWED_SEVERITIES = {"low", "med", "high"}
SEVERITY_ORDER = {"low": 1, "med": 2, "high": 3}


def severity_rank(sev: str) -> int:
    s = (sev or "").lower()
    if s not in SEVERITY_ORDER:
        raise ValueError(
            f"Invalid severity: {sev!r}. Allowed: {sorted(ALLOWED_SEVERITIES)}"
        )
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
    Rule(
        "INJ001",
        "Indirect instruction: ignore previous rules/instructions",
        compile_re(r"\bignore (all|previous|above) (instructions?|rules?)\b"),
        "med",
    ),
    Rule(
        "INJ002",
        "Policy override language",
        compile_re(r"\boverride (policy|guardrails?)\b"),
        "med",
    ),
    Rule(
        "INJ003",
        "Benign marker pattern (e.g., append [TESTMARK])",
        compile_re(r"\bappend\s*\[TESTMARK\]"),
        "low",
    ),
]

# Risky HTML/Markdown indicators
HTML_RULES: List[Rule] = [
    Rule(
        "HTML001", "Raw <script> tag present", compile_re(r"<\s*script\b", True), "high"
    ),
    Rule(
        "HTML002",
        "<iframe> or similar embedded content present",
        compile_re(r"<\s*iframe\b"),
        "high",
    ),
    Rule(
        "HTML003",
        "javascript: URI scheme present",
        compile_re(r"javascript\s*:", True),
        "high",
    ),
]

# PII/secret heuristics
PII_SECRET_RULES: List[Rule] = [
    Rule(
        "PII001",
        "Email-like string",
        compile_re(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        "low",
    ),
    Rule(
        "PII002",
        "US-like phone pattern",
        compile_re(r"(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}"),
        "low",
    ),
    Rule(
        "SEC001",
        "Likely secret prefix (sk_live|sk_test)",
        compile_re(r"\bsk_(?:live|test)_[A-Za-z0-9]{8,}\b"),
        "high",
    ),
]


def _compose_default_rules() -> List[Rule]:
    return [*INJECTION_RULES, *HTML_RULES, *PII_SECRET_RULES]


def load_rules_from_config(cfg: Dict[str, Any] | None) -> List[Rule]:
    """
    Build the active ruleset from defaults and an optional config dict.
    Supported config keys:
      - disable: [ "CODE1", "CODE2" ]
      - severity_overrides: { "CODE": "low|med|high" }
      - rules:               # add or replace rules by code
          - code: "USR001"
            desc: "Custom instruction phrase"
            pattern: "\\bcomply with the note below\\b"
            severity: "med"
            ignore_case: true
    """
    rules = _compose_default_rules()  # start with defaults
    if not cfg:
        return rules

    # 1) disable by code
    disabled = set(cfg.get("disable", []))
    if disabled:
        rules = [r for r in rules if r.code not in disabled]

    # 2) severity overrides
    sev_over = cfg.get("severity_overrides", {}) or {}
    if sev_over:
        new_rules: List[Rule] = []
        for r in rules:
            if r.code in sev_over:
                new_sev = sev_over[r.code].lower()
                severity_rank(new_sev)  # validate (raises if invalid)
                new_rules.append(Rule(r.code, r.desc, r.pattern, new_sev))
            else:
                new_rules.append(r)
        rules = new_rules

    # 3) add/replace rules
    add_rules = cfg.get("rules", []) or []
    by_code = {r.code: r for r in rules}
    for item in add_rules:
        code = item.get("code")
        pat = item.get("pattern")
        if not code or not pat:
            continue  # skip invalid entries
        desc = item.get("desc", "custom")
        sev = item.get("severity", "med").lower()
        severity_rank(sev)  # validate
        ignore_case = bool(item.get("ignore_case", True))
        compiled = compile_re(pat, ignore_case)
        by_code[code] = Rule(code, desc, compiled, sev)

    return list(by_code.values())
