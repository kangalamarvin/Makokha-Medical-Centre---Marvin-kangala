"""Quick security guardrails: grep for risky SQL construction patterns.

This script is intentionally lightweight and dependency-free so it can run in
CI or locally.

Goal: prevent reintroducing patterns where `text()` is used for ordering.

Usage:
  python scripts/security_sql_patterns_check.py

Exit code:
  0 = OK
  1 = risky pattern found
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]

# Patterns we want to prevent creeping back in.
# Keep these conservative to avoid false positives.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "SQLAlchemy order_by(text(...))",
        re.compile(r"\border_by\(\s*text\(", re.IGNORECASE),
    ),
    (
        "SQLAlchemy order_by(sa_text(...))",
        re.compile(r"\border_by\(\s*sa_text\(", re.IGNORECASE),
    ),
]

# Files to scan.
INCLUDE_SUFFIXES = {".py"}
EXCLUDE_DIRS = {
    ".git",
    "venv",
    "__pycache__",
    "node_modules",
    "instance",
    "migrations",
    "uploads",
    "backups",
}

# Exclude this script itself to avoid self-matching on explanatory text.
EXCLUDE_FILES = {
    Path(__file__).resolve(),
}


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune excluded dirs
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]

        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in INCLUDE_SUFFIXES:
                yield p


def main() -> int:
    findings: list[str] = []

    for path in iter_files(WORKSPACE_ROOT):
        if path.resolve() in EXCLUDE_FILES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for label, pat in PATTERNS:
            for m in pat.finditer(text):
                # Rough line number without loading heavy tooling
                line_no = text.count("\n", 0, m.start()) + 1
                rel = path.relative_to(WORKSPACE_ROOT).as_posix()
                findings.append(f"{rel}:{line_no}: {label}")

    if findings:
        print("Risky SQL construction patterns found:\n")
        for f in findings[:200]:
            print(f"- {f}")
        if len(findings) > 200:
            print(f"\n(truncated; total findings: {len(findings)})")
        return 1

    print("OK: no blocked SQL patterns detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
