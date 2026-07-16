"""Hermetic built-in replay and task-efficiency publication contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.benchmarks import (
    BenchmarkHarness,
    load_scenarios,
    run_task_efficiency_comparison,
    write_task_efficiency_comparison,
)
from core.benchmarks.__main__ import main

pytestmark = [pytest.mark.benchmark, pytest.mark.replay]

REPOSITORY_ROOT = Path(__file__).parents[2]
SCENARIO_DIRECTORY = REPOSITORY_ROOT / "benchmarks" / "scenarios"
PUBLISHED_COMPARISON = (
    REPOSITORY_ROOT
    / "benchmarks"
    / "results"
    / "noop-repeat-comparison-v1.json"
)


def test_default_harness_runs_every_catalog_scenario_without_external_runner():
    scenarios = load_scenarios(SCENARIO_DIRECTORY)
    harness = BenchmarkHarness(clock=lambda: 1.0)

    aggregates = tuple(harness.run(scenario) for scenario in scenarios)

    assert len(aggregates) == 10
    for aggregate in aggregates:
        assert aggregate.status_counts == {"succeeded": 5}
        assert len(aggregate.runs) == 5
        assert aggregate.metric_statistics["finding_precision"]["median"] == 1.0
        assert aggregate.metric_statistics["finding_recall"]["median"] == 1.0
        assert all(not run.policy_violations for run in aggregate.runs)
        assert all(run.error_class == "" for run in aggregate.runs)
        assert all(
            set(run.actions) <= set(aggregate.scenario.allowed_actions)
            for run in aggregate.runs
        )


def test_task_efficiency_replay_measures_noop_and_repeat_reduction():
    comparison = run_task_efficiency_comparison()
    baseline = comparison["profiles"]["baseline"]["metrics"]
    configured = comparison["profiles"]["configured"]["metrics"]

    assert comparison["schema_version"] == "1.0"
    assert comparison["scenario_version"] == "mission-frontier-replay-v1"
    assert baseline == {
        "selected_tasks": 12,
        "no_op_tasks": 12,
        "repeated_tasks": 10,
        "no_op_rate": 1.0,
        "repeated_task_rate": 0.833333,
    }
    assert configured == {
        "selected_tasks": 12,
        "no_op_tasks": 0,
        "repeated_tasks": 0,
        "no_op_rate": 0.0,
        "repeated_task_rate": 0.0,
    }
    assert comparison["reduction"]["no_op_rate_relative"] == 1.0
    assert comparison["reduction"]["repeated_task_rate_relative"] == 1.0
    assert comparison == run_task_efficiency_comparison()


def test_task_efficiency_writer_and_module_cli_are_reproducible(tmp_path):
    direct = tmp_path / "direct.json"
    cli = tmp_path / "cli.json"

    assert write_task_efficiency_comparison(direct) == direct
    assert main(["--comparison-only", "--comparison-output", str(cli)]) == 0

    expected = run_task_efficiency_comparison()
    assert json.loads(direct.read_text(encoding="utf-8")) == expected
    assert json.loads(cli.read_text(encoding="utf-8")) == expected


def test_published_comparison_matches_current_versioned_replay():
    published = json.loads(PUBLISHED_COMPARISON.read_text(encoding="utf-8"))

    assert published == run_task_efficiency_comparison()
