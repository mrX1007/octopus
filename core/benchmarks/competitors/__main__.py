"""CLI for running and publishing external-system benchmark matrices."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from ..schema import MIN_BENCHMARK_REPETITIONS, BenchmarkSchemaError, load_scenarios
from .matrix import publish_competitor_matrix, run_competitor_matrix
from .schema import (
    CompetitorSchemaError,
    SystemManifest,
    load_system_manifest,
    load_system_manifests,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _argument_parser()
    args = parser.parse_args(argv)
    if not args.system_manifest and not args.system_directory:
        parser.error("at least one --system-manifest or --system-directory is required")

    try:
        manifests = _load_manifests(
            args.system_manifest,
            args.system_directory,
        )
        scenarios = load_scenarios(args.scenario_directory)
        result = run_competitor_matrix(
            manifests,
            scenarios,
            repetitions=args.repetitions,
        )
        destination = publish_competitor_matrix(result, args.output_directory)
    except (BenchmarkSchemaError, CompetitorSchemaError, FileExistsError, OSError) as exc:
        print(f"competitor benchmark failed: {exc}", file=sys.stderr)
        return 2

    print(destination)
    print(
        "matrix={} aggregates={}/{} failed={} timeout={} partial={} invalid={} violations={}".format(
            result.matrix_id,
            result.completeness["written_aggregates"],
            result.completeness["expected_aggregates"],
            result.completeness["failed_runs"],
            result.completeness["timeout_runs"],
            result.completeness["partial_runs"],
            result.completeness["invalid_runs"],
            result.completeness["policy_violations"],
        )
    )
    if args.strict and result.has_strict_failures:
        return 1
    return 0


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the same versioned benchmark scenarios through two or more "
            "external systems and publish a checksummed comparison."
        )
    )
    parser.add_argument(
        "--system-manifest",
        action="append",
        default=[],
        type=Path,
        help="System manifest JSON; repeat for multiple systems.",
    )
    parser.add_argument(
        "--system-directory",
        action="append",
        default=[],
        type=Path,
        help="Directory of system manifest JSON files; repeatable.",
    )
    parser.add_argument(
        "--scenario-directory",
        required=True,
        type=Path,
        help="Directory containing the common benchmark scenario JSON files.",
    )
    parser.add_argument(
        "--output-directory",
        required=True,
        type=Path,
        help="New publish-ready directory; an existing destination is rejected.",
    )
    parser.add_argument(
        "--repetitions",
        type=_repetitions,
        default=MIN_BENCHMARK_REPETITIONS,
        help=f"Runs per system/scenario (minimum: {MIN_BENCHMARK_REPETITIONS}).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Publish results, then return non-zero if any run failed, timed out, "
            "was partial or invalid, or recorded a policy violation."
        ),
    )
    return parser


def _repetitions(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("repetitions must be an integer") from exc
    if parsed < MIN_BENCHMARK_REPETITIONS:
        raise argparse.ArgumentTypeError(
            f"repetitions must be at least {MIN_BENCHMARK_REPETITIONS}"
        )
    return parsed


def _load_manifests(
    manifest_paths: Sequence[Path],
    directories: Sequence[Path],
) -> tuple[SystemManifest, ...]:
    manifests = [load_system_manifest(path) for path in manifest_paths]
    for directory in directories:
        manifests.extend(load_system_manifests(directory))
    return tuple(manifests)


if __name__ == "__main__":
    raise SystemExit(main())
