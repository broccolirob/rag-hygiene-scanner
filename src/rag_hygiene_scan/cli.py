# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Robert Schneider

"""
CLI entrypoint. Accepts args and calls the (stub) scanner.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Dict, Optional

from .scanner import exit_code_for_findings, load_config, scan_path

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
    ap.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)",
    )
    ap.add_argument(
        "--fail-on",
        choices=["low", "med", "high"],
        default="med",
        help="Exit nonzero if any finding >= this severity (default: med)",
    )
    ap.add_argument(
        "--summary",
        action="store_true",
        help="Print counts by severity to stderr (always). "
        "Without this flag, a summary only prints when failing.",
    )
    return ap.parse_args(argv)


def _count_by_severity(findings) -> Dict[str, int]:
    counts = {"low": 0, "med": 0, "high": 0}
    for f in findings:
        sev = (f.get("severity") or "med").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


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
            print(json.dumps(findings, indent=2, ensure_ascii=False))
        else:
            # lazy import to avoid circular
            from .report import to_csv

            to_csv(findings, sys.stdout)
    else:
        from .report import to_csv, to_json

        with open(args.out, "w", encoding="utf-8", newline="") as fh:
            (to_json if args.format == "json" else to_csv)(findings, fh)

    exit_code = exit_code_for_findings(findings, args.fail_on)

    # Human-friendly summary to stderr
    counts = _count_by_severity(findings)
    if args.summary or exit_code != 0:
        print(
            f"summary: low={counts['low']} med={counts['med']} high={counts['high']} "
            f"(threshold: >= {args.fail_on})",
            file=sys.stderr,
        )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
