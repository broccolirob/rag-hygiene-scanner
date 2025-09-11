"""
Report writers (JSON/CSV). Writing logic is already useful even with empty results.
"""
from __future__ import annotations
from typing import List, Dict, Any, TextIO
import json, csv

def to_json(findings: List[Dict[str, Any]], fp: TextIO) -> None:
    json.dump(findings, fp, indent=2)

def to_csv(findings: List[Dict[str, Any]], fp: TextIO) -> None:
    w = csv.DictWriter(fp, fieldnames=["doc_id","code","severity","desc","evidence"])
    w.writeheader()
    for f in findings:
        w.writerow(f)
