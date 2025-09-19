from rag_hygiene_scan.patterns import load_rules_from_config


def _rule(patterns, code):
    return next(r for r in patterns if r.code == code)


def test_email_phone_and_secret_prefix_detected():
    rules = load_rules_from_config(None)

    text = "Contact us at alice.smith@example.com or (415) 555-1212."
    assert _rule(rules, "PII001").pattern.search(text)
    assert _rule(rules, "PII002").pattern.search(text)

    sec = "This should never appear: sk_live_abcdEFGH1234"
    assert _rule(rules, "SEC001").pattern.search(sec)
