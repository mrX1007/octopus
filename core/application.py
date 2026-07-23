"""Installed CLI entry point for the canonical application lifecycle.

``octopus.py`` remains an import-compatible facade for external callers, but
the installed console script dispatches directly to the decomposed CLI instead
of re-executing that legacy module through :mod:`runpy`.
"""

from __future__ import annotations

from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch the canonical CLI and return its process exit code."""

    from core.cli.main import main as cli_main

    return cli_main(argv)


__all__ = ["main"]
