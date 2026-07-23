#!/usr/bin/env python3
"""Generate a controller-private Lab v3 manifest and a blinded product view."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from core.benchmarks.v3.fixture import (  # noqa: E402
    SCENARIO_FAMILIES,
    generate_fixture_variant,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("family", choices=SCENARIO_FAMILIES)
    parser.add_argument("matched_fixture_seed", type=int)
    parser.add_argument("private_manifest", type=Path)
    parser.add_argument("--product-view", type=Path)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    variant = generate_fixture_variant(
        args.family,
        matched_fixture_seed=args.matched_fixture_seed,
    )
    variant.write_private_manifest(args.private_manifest)
    if args.product_view is not None:
        args.product_view.parent.mkdir(parents=True, exist_ok=True)
        args.product_view.write_text(
            json.dumps(
                variant.product_view(base_url=args.base_url),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
