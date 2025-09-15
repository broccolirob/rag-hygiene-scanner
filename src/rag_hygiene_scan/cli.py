"""
CLI entrypoint. Accepts args and calls the (stub) scanner.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Optional

from .scanner import scan_path, load_config, exit_code_for_findings
from .report import to_json, to_csv

EPILOG = """examples:
  rag-scan examples/ --format json --fail-on med
  rag-scan docs/ -c rules.yaml -o findings.csv --format csv
"""

def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="rag-scan",
        description="Scan Markdown/HTML/txt destined for RAG indexes for hygiene risks.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("path", help="File or directory to scan")
    ap.add_argument("-c", "--config", help="YAML with custom rules", default=None)
    ap.add_argument("-o", "--out", help="Output file (default: stdout)", default="-")
    ap.add_argument("--format", choices=["json", "csv"], default="json",
                    help="Output format (default: json)")
    ap.add_argument("--fail-on", choices=["low", "med", "high"], default="med",
                    help="Exit nonzero if any finding >= this severity (default: med)")
    return ap.parse_args(argv)

def main(argv: Optional[list[str]] = None) -> None:
    args = _parse_args(argv)

    p = pathlib.Path(args.path)
    if not p.exists():
        print(f"error: path not found: {p}", file=sys.stderr)
        sys.exit(2)

    cfg = load_config(args.config)
    result = scan_path(str(p), cfg)
    findings = result["findings"]

    # Write output
    if args.out == "-":
        if args.format == "json":
            # JSON to stdout (pretty)
            print(json.dumps(findings, indent=2, ensure_ascii=False))
        else:
            to_csv(findings, sys.stdout)
    else:
        mode = "w"
        with open(args.out, mode, encoding="utf-8", newline="") as fh:
            if args.format == "json":
                to_json(findings, fh)
            else:
                to_csv(findings, fh)

    # Exit code per threshold
    sys.exit(exit_code_for_findings(findings, args.fail_on))

if __name__ == "__main__":
    main()
