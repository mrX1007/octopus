#!/usr/bin/env python3
"""Thin entry point for the generated, blinded discovery lab v3."""

import sys
from pathlib import Path

try:
    from core.benchmarks.v3.server import main
except ModuleNotFoundError as exc:
    if exc.name != "core":
        raise
    # Source-tree execution places only this script directory on sys.path.
    # The container puts /opt/octobench there already and never takes this path.
    repository_root = Path(__file__).resolve().parents[4]
    sys.path.insert(0, str(repository_root))
    from core.benchmarks.v3.server import main

if __name__ == "__main__":
    main()
