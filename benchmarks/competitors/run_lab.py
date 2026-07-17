#!/usr/bin/env python3
"""Repository-local entry point for the isolated benchmark lab controller."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    runpy.run_module("core.benchmarks.competitors.labctl", run_name="__main__")


if __name__ == "__main__":
    main()
