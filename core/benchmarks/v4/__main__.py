"""CLI for preparing, publishing, and verifying Benchmark v4 companions."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from ..v3.analysis import load_analysis_plan
from .publication import publish_v4_results, verify_v4_results
from .schema import build_efficiency_plan, freeze_efficiency_plan, load_efficiency_plan


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare and verify additive Benchmark v4 efficiency evidence.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="freeze an efficiency plan before execution")
    prepare.add_argument("--source-analysis-plan", required=True, type=Path)
    prepare.add_argument("--output", required=True, type=Path)
    prepare.add_argument("--efficiency-track-id")
    prepare.add_argument("--schedule-seed", type=_nonnegative_integer, default=1)
    prepare.add_argument(
        "--diagnostic",
        action="store_true",
        help="allow a retrospective, non-attested diagnostic plan",
    )

    publish = subparsers.add_parser("publish", help="publish a companion for a verified v3 bundle")
    publish.add_argument("--plan", required=True, type=Path)
    publish.add_argument("--source-v3", required=True, type=Path)
    publish.add_argument("--output", required=True, type=Path)

    verify = subparsers.add_parser("verify", help="recompute and verify a v4 companion")
    verify.add_argument("directory", type=Path)
    verify.add_argument("--source-v3", required=True, type=Path)

    args = parser.parse_args(argv)
    if args.command == "prepare":
        source_plan = load_analysis_plan(args.source_analysis_plan)
        plan = build_efficiency_plan(
            source_plan,
            efficiency_track_id=args.efficiency_track_id,
            schedule_seed=args.schedule_seed,
            publication_tier="diagnostic" if args.diagnostic else source_plan.publication_tier,
            require_run_attestation=not args.diagnostic,
        )
        print(freeze_efficiency_plan(plan, args.output))
        return 0
    if args.command == "publish":
        plan = load_efficiency_plan(args.plan)
        print(publish_v4_results(plan, args.source_v3, args.output))
        return 0
    result = verify_v4_results(args.directory, source_v3_directory=args.source_v3)
    print(json.dumps(result, sort_keys=True))
    return 0


def _nonnegative_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be nonnegative")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
