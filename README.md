# RAG Corpus Hygiene Scanner
![CI](https://github.com/broccolirob/rag-hygiene-scanner/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

**Catch risky content *before* it reaches your RAG index.**  
Find:
- **Indirect instruction indicators** — e.g., “ignore previous instructions”, “override policy”, benign canaries like `[TESTMARK]`
- **Risky HTML/Markdown** — `<script>`, `<iframe>`, `javascript:` URIs (common XSS vectors if rendered)
- **PII/secret‑like strings** — email/phone formats, prefixes like `sk_live_`/`sk_test_`

Outputs **JSON/CSV** and returns **non‑zero** if findings meet your threshold — perfect for **CI gates** on docs/KB changes.

---

## Table of Contents
- [Install](#install)
- [Quick Start](#quick-start)
- [Configuration (`rules.yaml`)](#configuration-rulesyaml)
- [Exit Codes & Thresholds](#exit-codes--thresholds)
- [Output Schema](#output-schema)
- [Examples Included](#examples-included)
- [Use in CI/CD (GitHub Actions)](#use-in-cicd-github-actions)
- [Security Mapping (OWASP / NIST / CISA / SSDF)](#security-mapping-owasp--nist--cisa--ssdf)
- [Notes & Safety](#notes--safety)
- [License](#license)

---

## Install

```bash
# From repo root (editable install for local development)
pip install -e .

# (Optional) With pipx
# pipx install .
```

> Requires Python **3.10+**.

---

## Quick Start

```bash
# Pretty JSON to stdout; fail on >= "med"
rag-scan examples --format json --fail-on med

# CSV to file (for spreadsheets)
rag-scan examples --format csv -o findings.csv --fail-on med

# Always print a one-line severity summary to stderr
rag-scan examples --summary
```

---

## Configuration (`rules.yaml`)

Tune the ruleset without code changes: **disable**, **override severities**, or **add/replace** patterns.

```yaml
# rules.yaml
disable:
  - INJ003         # Ignore benign [TESTMARK] canary in this repo

severity_overrides:
  HTML003: med     # Treat 'javascript:' as medium

rules:
  - code: USR001
    desc: Custom indirect phrase
    pattern: "\\bcomply with the note below\\b"
    severity: med
    ignore_case: true

  - code: USR002
    desc: ZWSP-obfuscated IGNORE (I\u200bG\u200bN\u200bO\u200bR\u200bE)
    pattern: "I\\u200bG\\u200bN\\u200bO\\u200bR\\u200bE"
    severity: med
```

Use it:

```bash
rag-scan docs/ -c rules.yaml --fail-on med --summary
```

---

## Exit Codes & Thresholds

* `0` → **No** findings at/above threshold (`--fail-on low|med|high`)
* `1` → At least **one** finding meets threshold
* `2` → Usage error (e.g., bad path)

```bash
# Fail only on high-severity issues
rag-scan examples --fail-on high

# Print summary regardless of pass/fail
rag-scan examples --summary
```

---

## Output Schema

**JSON/CSV columns:** `doc_id, code, severity, desc, evidence`

* `doc_id` — file path scanned
* `code` — rule ID (e.g., `INJ001`, `HTML003`, `SEC001`)
* `severity` — `low | med | high`
* `evidence` — short, single‑line snippet around the match

**Example JSON (truncated):**

```json
[
  {
    "doc_id": "examples/unsafe.html",
    "code": "HTML003",
    "severity": "high",
    "desc": "javascript: URI scheme present",
    "evidence": "<a href=\"javascript:alert(1)\">bad link</a>"
  }
]
```

---

## Examples Included

* `examples/poison.md` → **INJ001/INJ003** (indirect instruction, benign marker)
* `examples/unsafe.html` → **HTML001/002/003** (script/iframe/javascript:)
* `examples/pii.txt` → **PII001/PII002/SEC001** (email, US phone, secret prefix)

Run quick check:

```bash
rag-scan examples --format json --fail-on med --summary > /tmp/findings.json
```

---

## Use in CI/CD (GitHub Actions)

Add a step to your workflow to **gate PRs** that change docs/KB:

```yaml
- name: RAG hygiene scan (docs)
  run: |
    rag-scan docs/ --format json --fail-on med --summary > rag_findings.json
```

* The job **fails** when exit code is non‑zero (findings ≥ threshold).
* Upload `rag_findings.json` as an artifact for review.

---

## Security Mapping (OWASP / NIST / CISA / SSDF)

This tool helps enforce controls that reduce real LLM‑app risks:

| Category                          | What this tool detects or enables                                                                                     | Standard(s) it supports                                                                            |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| **Prompt / Indirect Injection**   | Flags instruction‑shaped text in content (e.g., “ignore previous…”), supports allowlisting/transform design via rules | **OWASP LLM Top‑10** A01 (Prompt Injection); **NIST AI 600‑1**: Content filtering before model use |
| **Insecure Output Handling**      | Identifies risky HTML/MD (`<script>`, `<iframe>`, `javascript:`) likely to cause XSS if rendered                      | **OWASP LLM Top‑10** A02; **SSDF 800‑218**: Taint/sanitize untrusted outputs                       |
| **Training‑Data / RAG Poisoning** | Scans KB for malicious patterns and provenance hints; pairs with allowlists/metadata filters in your RAG              | **OWASP LLM Top‑10** A03; **NIST AI 600‑1**: Data provenance & pre‑processing                      |
| **Sensitive Info Disclosure**     | Heuristics for PII and secret‑like tokens to prevent accidental indexing/exposure                                     | **OWASP LLM Top‑10** A07; **NIST AI 600‑1**: Privacy controls                                      |
| **SDLC / CI Gate**                | Thresholded exit codes + summary → easy **TEVV** integration as part of normal releases                               | **CISA TEVV** (AI red‑team/testing in SDLC); **SSDF 800‑218** (release gates)                      |

> This scanner is **one layer** in a defense‑in‑depth approach. Pair it with retrieval allowlists, index‑time sanitization, tuned guardrails, least‑privilege tool schemas, and front‑end output sanitizers.

---

## Notes & Safety

* Use on **non‑production** content.
* Patterns are **indicators**, not perfect classification—tune with `rules.yaml`.
* Keep benign canaries (e.g., `[TESTMARK]`) for regression tests; you can disable them per‑repo.

---

## License

MIT — see `LICENSE`.
