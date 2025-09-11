"""
CLI entrypoint. Accepts args and calls the (stub) scanner.
"""
from __future__ import annotations
import argparse, sys, json
from .scanner import scan_path, load_config, exit_code_for_findings
from .report import to_json, to_csv

def main():
    ap = argparse.ArgumentParser(
        prog="rag-scan",
        description="Scan Markdown/HTML/txt destined for RAG indexes for hygiene risks."
    )
    ap.add_argument("path", help="File or directory to scan")
    ap.add_argument("-c","--config", help="YAML with custom rules", default=None)
    ap.add_argument("-o","--out", help="Output file (default: stdout)", default="-")
    ap.add_argument("--format", choices=["json","csv"], default="json")
    ap.add_argument("--fail-on", choices=["low","med","high"], default="med")
    args = ap.parse_args()

    cfg = load_config(args.config)
    result = scan_path(args.path, cfg)
    findings = result["findings"]

    if args.out == "-":
        if args.format == "json":
            print(json.dumps(findings, indent=2))
        else:
            to_csv(findings, sys.stdout)
    else:
        with open(args.out, "w", encoding="utf-8", newline="") as fh:
            if args.format == "json":
                to_json(findings, fh)
            else:
                to_csv(findings, fh)

    sys.exit(exit_code_for_findings(findings, args.fail_on))
