# RAG Corpus Hygiene Scanner

**Purpose:** Catch risky content **before** it reaches your RAG index:
- **Indirect instruction indicators** (e.g., “ignore previous instructions”, “override policy”)
- **Risky HTML/Markdown** (e.g., `<script>`, `<iframe>`, `javascript:` URIs)
- **PII/secret‑like** strings (emails, phone formats, `sk_live/_test_` prefixes)

Outputs **JSON/CSV** and returns a **non‑zero exit** if findings meet your threshold (great for **CI gates**).

---

## Install

```bash
# from repo root
pip install -e .
# or with pipx
pipx install .
```