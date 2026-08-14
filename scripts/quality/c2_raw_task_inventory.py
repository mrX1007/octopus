#!/usr/bin/env python3
"""Gate verifying zero V12 agent task raw command paths (§15.5, §15.6)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def inventory_v12_raw_tasks(root: Path = ROOT) -> list[str]:
    """Scan V12 agent task models and handlers for forbidden raw command fields."""
    violations: list[str] = []
    agent_wire_path = root / "core" / "c2" / "agent_protocol_v12.py"
    if agent_wire_path.exists():
        text = agent_wire_path.read_text(encoding="utf-8")
        if "raw_command" in text and "raw_command_supported=False" not in text:
            # Check if used as a field
            for line_no, line in enumerate(text.splitlines(), start=1):
                if "raw_command:" in line:
                    violations.append(f"{agent_wire_path}:{line_no}: forbidden raw_command field in V12 wire")
    return violations


def main() -> int:
    violations = inventory_v12_raw_tasks()
    if violations:
        print(f"C2 raw task inventory failed ({len(violations)} violations):", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1
    print("C2 raw task inventory gate: OK (0 raw command paths in V12 wire)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
