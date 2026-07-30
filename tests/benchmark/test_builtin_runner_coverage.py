"""Hermetic branch coverage for the built-in benchmark replay runner."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.benchmarks import builtin_runner
from core.benchmarks.schema import load_scenarios

pytestmark = [pytest.mark.unit, pytest.mark.benchmark, pytest.mark.replay]

SCENARIO_DIRECTORY = Path(__file__).parents[2] / "benchmarks" / "scenarios"


def _scenario(
    *,
    category: str = "fixture",
    max_tools: int = 1,
    max_seconds: float = 10.0,
    max_output_bytes: int = 10_000,
):
    return SimpleNamespace(
        category=category,
        scenario_id="fixture-scenario",
        budgets={
            "max_tools": max_tools,
            "max_seconds": max_seconds,
            "max_output_bytes": max_output_bytes,
        },
    )


def _runner_with_handler(handler):
    runner = builtin_runner.BuiltinReplayRunner()
    runner._handlers["fixture"] = handler
    return runner


def test_every_catalog_replay_runs_once_entirely_in_process() -> None:
    scenarios = load_scenarios(SCENARIO_DIRECTORY)
    runner = builtin_runner.BuiltinReplayRunner()

    results = {
        scenario.category: runner(scenario, 1, scenario.seed)
        for scenario in scenarios
    }

    assert set(results) == {
        "authorized_internal_discovery",
        "clean_negative",
        "contradictions",
        "crash_resume",
        "credential_discovery_safe_validation",
        "invalid_empty_llm",
        "service_discovery_verification",
        "timeout_partial_result",
        "verified_ssh_inventory",
        "web_api_mapping",
    }
    for scenario in scenarios:
        result = results[scenario.category]
        assert result["status"] == "succeeded"
        assert result["duration_seconds"] >= 0
        assert result["metrics"]["component_checks"] >= 1
        assert result["metrics"]["no_op_task_rate"] == 0.0
        assert result["metrics"]["repeated_task_rate"] == 0.0
        assert result["artifact_refs"] == (
            f"benchmark-replay://{scenario.scenario_id}/1/{scenario.seed}",
        )
        assert len(result["actions"]) <= scenario.budgets["max_tools"]
        assert len(json.dumps(result, sort_keys=True, default=str).encode()) <= (
            scenario.budgets["max_output_bytes"]
        )


def test_unknown_category_is_rejected_before_creating_a_replay() -> None:
    runner = builtin_runner.BuiltinReplayRunner()

    with pytest.raises(ValueError, match="no built-in replay for category:unknown"):
        runner(_scenario(category="unknown"), 1, 1)


def test_action_budget_is_enforced_with_an_in_process_handler(monkeypatch) -> None:
    monkeypatch.setattr(
        builtin_runner,
        "time",
        SimpleNamespace(monotonic=lambda: 10.0),
    )
    runner = _runner_with_handler(
        lambda _scenario, _root: {"actions": ("first", "second")}
    )

    with pytest.raises(ValueError, match="exceeds scenario max_tools budget"):
        runner(_scenario(max_tools=1), 1, 1)


def test_duration_budget_is_enforced_with_a_deterministic_clock(monkeypatch) -> None:
    ticks = iter((10.0, 12.0))
    monkeypatch.setattr(
        builtin_runner,
        "time",
        SimpleNamespace(monotonic=lambda: next(ticks)),
    )
    runner = _runner_with_handler(lambda _scenario, _root: {"actions": ()})

    with pytest.raises(ValueError, match="exceeds scenario max_seconds budget"):
        runner(_scenario(max_seconds=1.0), 1, 1)


def test_serialized_output_budget_is_enforced_in_memory(monkeypatch) -> None:
    monkeypatch.setattr(
        builtin_runner,
        "time",
        SimpleNamespace(monotonic=lambda: 10.0),
    )
    runner = _runner_with_handler(
        lambda _scenario, _root: {"actions": (), "payload": "x" * 1_000}
    )

    with pytest.raises(ValueError, match="exceeds scenario max_output_bytes budget"):
        runner(_scenario(max_output_bytes=32), 1, 1)
