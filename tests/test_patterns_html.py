from rag_hygiene_scan.patterns import load_rules_from_config

def _rule(patterns, code):
    return next(r for r in patterns if r.code == code)

def test_html_script_iframe_and_js_scheme_detected():
    rules = load_rules_from_config(None)

    html = "<div>ok</div><script>alert(1)</script>"
    assert _rule(rules, "HTML001").pattern.search(html)

    html2 = "<iframe src='https://example.com/embed'></iframe>"
    assert _rule(rules, "HTML002").pattern.search(html2)

    html3 = '<a href="javascript:alert(1)">click</a>'
    assert _rule(rules, "HTML003").pattern.search(html3)
