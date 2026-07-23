#!/usr/bin/env python3
"""Import first-party entrypoints without optional dependency profiles."""

from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODULES = (
    "config",
    "db",
    "core.ai.pipeline",
    "core.ai.runtime",
    "core.plugins.loader",
    "core.tools",
    "octopus",
)

PROFILE_MODULES = {
    "runtime": DEFAULT_MODULES,
    "c2": ("core.c2", "core.c2.builder", "core.c2.daemon"),
    "reporting": ("export",),
    "osint-browser": ("search", "shodan_module", "core.osint.shardbrowser"),
    "mysql": ("db",),
}


@dataclass(frozen=True)
class ImportFailure:
    module: str
    error_type: str
    message: str


def run_import_smoke(modules: Sequence[str]) -> list[ImportFailure]:
    """Import every requested module and return all failures."""
    root_text = str(PROJECT_ROOT)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    importlib.invalidate_caches()

    failures = []
    for module in modules:
        try:
            importlib.import_module(module)
        except Exception as exc:  # Import-time failures may use any exception type.
            failures.append(
                ImportFailure(
                    module=module,
                    error_type=type(exc).__name__,
                    message=str(exc),
                )
            )
    return failures


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--module",
        action="append",
        dest="modules",
        help="module to import; repeat to override the default entrypoint set",
    )
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILE_MODULES),
        default="runtime",
        help="declared optional dependency profile to import",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    modules = tuple(args.modules or PROFILE_MODULES[args.profile])
    failures = run_import_smoke(modules)
    if failures:
        for failure in failures:
            print(
                f"import smoke failed: {failure.module}: "
                f"{failure.error_type}: {failure.message}",
                file=sys.stderr,
            )
        return 1
    print(f"import smoke passed: {len(modules)} modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
