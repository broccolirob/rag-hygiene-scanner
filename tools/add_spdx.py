import pathlib
import sys

HEADER = """# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Robert Schneider
"""


def has_header(text: str) -> bool:
    return any("SPDX-License-Identifier:" in line for line in text.splitlines()[:5])


def main(root="src"):
    changed = 0
    for p in pathlib.Path(root).rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        if not has_header(text):
            p.write_text(HEADER + "\n" + text, encoding="utf-8")
            changed += 1
    print(f"Annotated {changed} files")


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "src"
    main(root)
