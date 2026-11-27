#!/usr/bin/env python3
"""Reject implementation items in crate-root lib.rs files."""

from pathlib import Path
import re
import sys


IMPLEMENTATION_ITEM = re.compile(
    r"^\s*(?:(?:pub(?:\([^)]*\))?)\s+)?"
    r"(?:async\s+)?(?:const|static|type|struct|enum|union|trait|impl|fn|macro_rules!)\b"
)
DOC_FENCE = re.compile(r"^\s*///\s*```")


def check(path: Path) -> list[str]:
    errors = []
    in_doc_example = False

    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if DOC_FENCE.match(line):
            in_doc_example = not in_doc_example
            continue
        if in_doc_example or line.lstrip().startswith(("///", "//!")):
            continue
        if IMPLEMENTATION_ITEM.match(line):
            errors.append(f"{path}:{line_number}: move implementation items into a module")

    return errors


def main() -> int:
    roots = sorted(Path("crates").glob("*/src/lib.rs"))
    errors = [error for path in roots for error in check(path)]
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Checked {len(roots)} crate lib.rs files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
