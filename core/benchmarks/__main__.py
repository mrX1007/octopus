"""Command-line writer for hermetic benchmark aggregates and comparison data."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run hermetic OCTOPUS benchmark replays and write JSON results.",
    )
    parser.add_argument(
        "--scenario-directory",
        type=Path,
        default=_REPOSITORY_ROOT / "benchmarks" / "scenarios",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path.cwd() / "octobench-results" / "builtin-catalog",
    )
    parser.add_argument(
        "--comparison-output",
        type=Path,
        default=Path.cwd()
        / "octobench-results"
        / "noop-repeat-comparison-v1.json",
    )
    parser.add_argument(
        "--comparison-only",
        action="store_true",
        help="Write only the deterministic task-efficiency comparison.",
    )
    args = parser.parse_args(argv)

    # Keep --help import-pure for an installed wheel; runtime modules may load
    # optional application profiles only after argument parsing succeeds.
    from .harness import BenchmarkHarness
    from .schema import load_scenarios
    from .task_efficiency import write_task_efficiency_comparison

    written: list[Path] = []
    if not args.comparison_only:
        harness = BenchmarkHarness()
        for scenario in load_scenarios(args.scenario_directory):
            destination = args.output_directory / f"{scenario.scenario_id}-v1.json"
            written.append(harness.write(harness.run(scenario), destination))
    written.append(write_task_efficiency_comparison(args.comparison_output))
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
