import re
from rag_hygiene_scan.patterns import load_rules_from_config, compile_re

def _by_code(rules):
    return {r.code: r for r in rules}

def test_disable_rule_by_code():
    cfg = {"disable": ["INJ003"]}  # drop benign marker rule
    rules = _by_code(load_rules_from_config(cfg))
    assert "INJ003" not in rules     # disabled
    assert "INJ001" in rules         # others still present

def test_severity_override_applies_and_validates():
    cfg = {"severity_overrides": {"HTML003": "med"}}
    rules = _by_code(load_rules_from_config(cfg))
    assert rules["HTML003"].severity == "med"

def test_add_custom_rule_and_replace_existing():
    cfg = {
        "rules": [
            {
                "code": "USR001",
                "desc": "Custom indirect phrase",
                "pattern": r"\bcomply with the note below\b",
                "severity": "med",
                "ignore_case": True,
            },
            {
                # Replace existing INJ002 with a stricter version
                "code": "INJ002",
                "desc": "Override-policy (stricter)",
                "pattern": r"\boverride policy\b",  # no 'guardrails' alias
                "severity": "med",
                "ignore_case": True,
            },
        ]
    }
    rules = _by_code(load_rules_from_config(cfg))
    assert "USR001" in rules
    assert rules["INJ002"].desc.startswith("Override-policy")
    # The USR001 pattern should match (and be case-insensitive)
    assert rules["USR001"].pattern.search("Please COMPLY WITH THE NOTE BELOW.")

def test_ignore_case_flag_controls_matching():
    cfg = {
        "rules": [
            {
                "code": "USR002",
                "desc": "Case-sensitive test",
                "pattern": r"abc",
                "severity": "low",
                "ignore_case": False,
            }
        ]
    }
    rules = _by_code(load_rules_from_config(cfg))
    # Ensure pattern does NOT match 'ABC' when ignore_case is False
    assert rules["USR002"].pattern.search("ABC") is None
    # But matches lowercase
    assert rules["USR002"].pattern.search("xyz abc 123")
