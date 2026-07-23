#!/usr/bin/env python3
"""Publish a reproducible fixture reveal only after campaign closure."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from core.benchmarks.v3.fixture import load_private_fixture  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private_manifest", type=Path)
    parser.add_argument("reveal_manifest", type=Path)
    parser.add_argument(
        "--campaign-closed",
        action="store_true",
        help="Required acknowledgement that no product run remains scheduled.",
    )
    args = parser.parse_args()
    if not args.campaign_closed:
        raise SystemExit("--campaign-closed is required")
    variant = load_private_fixture(args.private_manifest)
    variant.write_reveal_manifest(
        args.reveal_manifest,
        campaign_closed=True,
    )


if __name__ == "__main__":
    main()
