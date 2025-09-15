"""
Report writers (JSON/CSV). Writing logic is already useful even with empty results.
"""
from __future__ import annotations
import json, csv
from typing import List, Dict, Any, TextIO

def to_json(findings: List[Dict[str, Any]], fp: TextIO) -> None:
    # Pretty, deterministic key order isn’t required, but nice for diffs
    json.dump(findings, fp, indent=2, ensure_ascii=False)

def to_csv(findings: List[Dict[str, Any]], fp: TextIO) -> None:
    w = csv.DictWriter(
        fp,
        fieldnames=["doc_id", "code", "severity", "desc", "evidence"],
        lineterminator="\n",
    )
    w.writeheader()
    for f in findings:
        w.writerow(f)
