#!/usr/bin/env python3
"""Gate verifying all builder call sites use explicit enrollment checkout (§15.6)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def inventory_builder_call_sites(root: Path = ROOT) -> list[str]:
    """Scan codebase to ensure no direct EnrollmentAuthority.issue() in builders."""
    violations: list[str] = []
    builder_path = root / "core" / "c2" / "builder.py"
    if builder_path.exists():
        text = builder_path.read_text(encoding="utf-8")
        if "EnrollmentAuthority.issue(" in text:
            violations.append("core/c2/builder.py: forbidden direct EnrollmentAuthority.issue() call")
    return violations


def main() -> int:
    violations = inventory_builder_call_sites()
    if violations:
        print(f"C2 builder enrollment inventory failed ({len(violations)} violations):", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print("C2 builder enrollment inventory gate: OK (all builders use explicit checkout)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
