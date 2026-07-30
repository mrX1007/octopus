"""Dependency-safe console entry point for the optional C2 service."""

from __future__ import annotations

import importlib.util
import sys

_C2_DEPENDENCIES = ("fastapi", "uvicorn")
_C2_EXTRA = "octopus-security[c2]"


def _missing_dependencies() -> list[str]:
    return [name for name in _C2_DEPENDENCIES if importlib.util.find_spec(name) is None]


def main() -> int:
    """Run the C2 daemon, or explain how to install its optional dependencies."""

    missing = _missing_dependencies()
    if missing:
        print(
            "octopus-c2 requires the optional C2 dependencies "
            f"(missing: {', '.join(missing)}). Install them with: "
            f"python -m pip install '{_C2_EXTRA}'",
            file=sys.stderr,
        )
        return 2

    from core.c2.daemon import main as daemon_main

    result = daemon_main()
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
