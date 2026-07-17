"""Versioned benchmark schema and five-repetition aggregation contracts."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from core.benchmarks import (
    REQUIRED_SCENARIO_CATEGORIES,
    BenchmarkHarness,
    BenchmarkScenario,
    BenchmarkSchemaError,
    load_scenario,
    load_scenarios,
)

pytestmark = pytest.mark.benchmark

SCENARIO_DIRECTORY = Path(__file__).parents[2] / "benchmarks" / "scenarios"
JSON_SCHEMA_PATH = (
    Path(__file__).parents[2]
    / "docs"
    / "schemas"
    / "benchmark-scenario-v1.schema.json"
)


def test_portable_json_schema_matches_runtime_contract():
    schema = json.loads(JSON_SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_version"] == {"const": "1.0"}
    assert schema["properties"]["repetitions"]["minimum"] == 5
    assert set(schema["properties"]["category"]["enum"]) == set(
        REQUIRED_SCENARIO_CATEGORIES
    )


def test_required_scenario_catalog_is_versioned_and_complete():
    scenarios = load_scenarios(SCENARIO_DIRECTORY)

    assert len(scenarios) == 10
    assert {item.category for item in scenarios} == set(REQUIRED_SCENARIO_CATEGORIES)
    assert all(item.schema_version == "1.0" for item in scenarios)
    assert all(item.repetitions >= 5 for item in scenarios)
    assert all(item.lab["version"] and item.target["version"] for item in scenarios)
    assert all(item.model["provider"] and item.model["parameters"] is not None for item in scenarios)
    assert all(item.tool_versions and item.allowed_actions for item in scenarios)


def test_harness_runs_five_repetitions_and_publishes_median_variance(tmp_path):
    scenario = load_scenario(SCENARIO_DIRECTORY / "01-service-discovery-verification.json")

    def runner(_scenario, repetition, seed):
        assert seed == scenario.seed + repetition - 1
        return {
            "status": "succeeded",
            "actions": ["replay_service_discovery", "verify_service"],
            "reported_findings": ["ssh_service", "https_service"],
            "verified_findings": ["ssh_service", "https_service"],
            "metrics": {"quality_score": float(repetition)},
            "duration_seconds": repetition / 10,
            "artifact_refs": [f"artifact://run/{repetition}"],
        }

    harness = BenchmarkHarness(runner, clock=lambda: 100.0)
    aggregate = harness.run(scenario)
    statistics = aggregate.metric_statistics["quality_score"]

    assert len(aggregate.runs) == 5
    assert aggregate.status_counts == {"succeeded": 5}
    assert statistics == {
        "count": 5.0,
        "median": 3.0,
        "variance": 2.0,
        "minimum": 1.0,
        "maximum": 5.0,
    }
    assert aggregate.metric_statistics["finding_precision"]["median"] == 1.0
    assert aggregate.metric_statistics["finding_recall"]["median"] == 1.0
    assert aggregate.runs[0].environment["model"] == scenario.model

    destination = harness.write(aggregate, tmp_path / "aggregate.json")
    persisted = json.loads(destination.read_text())
    assert persisted["aggregate_id"] == aggregate.aggregate_id
    assert len(persisted["runs"]) == 5


def test_runner_namespace_separates_system_identity_without_changing_scenario():
    scenario = load_scenario(
        SCENARIO_DIRECTORY / "06-clean-negative.json"
    )

    def runner(_scenario, _repetition, _seed):
        return {
            "status": "succeeded",
            "actions": ["replay_negative_checks"],
            "reported_findings": [],
        }

    first = BenchmarkHarness(
        runner,
        clock=lambda: 1.0,
        run_namespace="system:first:1.0",
        runner_metadata={"system_under_test": {"id": "first", "version": "1.0"}},
    ).run(scenario)
    second = BenchmarkHarness(
        runner,
        clock=lambda: 1.0,
        run_namespace="system:second:1.0",
        runner_metadata={"system_under_test": {"id": "second", "version": "1.0"}},
    ).run(scenario)

    assert first.scenario.scenario_id == second.scenario.scenario_id
    assert first.aggregate_id != second.aggregate_id
    assert first.runs[0].run_id != second.runs[0].run_id
    assert first.runs[0].environment["runner"]["system_under_test"] == {
        "id": "first",
        "version": "1.0",
    }

    changed_lab = replace(
        scenario,
        lab={**scenario.lab, "version": "changed-lab-version"},
    )
    changed = BenchmarkHarness(
        runner,
        clock=lambda: 1.0,
        run_namespace="system:first:1.0",
    ).run(changed_lab)
    assert changed.runs[0].run_id != first.runs[0].run_id


def test_allowed_action_violation_invalidates_run_without_executing_fallback():
    scenario = load_scenario(SCENARIO_DIRECTORY / "06-clean-negative.json")
    calls = []

    def runner(_scenario, repetition, _seed):
        calls.append(repetition)
        return {
            "actions": ["unapproved_action"],
            "reported_findings": [],
            "metrics": {"quality_score": 1.0},
        }

    aggregate = BenchmarkHarness(runner, clock=lambda: 1.0).run(scenario)

    assert calls == [1, 2, 3, 4, 5]
    assert aggregate.status_counts == {"invalid": 5}
    assert all(item.policy_violations == ("unapproved_action",) for item in aggregate.runs)
    assert "quality_score" not in aggregate.metric_statistics


def test_runner_failure_records_only_error_class():
    scenario = load_scenario(SCENARIO_DIRECTORY / "06-clean-negative.json")

    def runner(_scenario, _repetition, _seed):
        raise RuntimeError("sensitive runner detail")

    aggregate = BenchmarkHarness(runner, clock=lambda: 1.0).run(scenario)

    assert aggregate.status_counts == {"failed": 5}
    assert {item.error_class for item in aggregate.runs} == {"RuntimeError"}
    assert "sensitive runner detail" not in json.dumps(aggregate.to_dict())


def test_ablations_require_explicitly_stable_toggle():
    payload = load_scenario(
        SCENARIO_DIRECTORY / "01-service-discovery-verification.json"
    ).to_dict()
    payload["ablations"] = [{"toggle": "stable_parser_mode", "values": [False, True]}]
    scenario = BenchmarkScenario.from_dict(payload)

    def runner(*_args):
        return {
            "actions": ["replay_service_discovery"],
            "reported_findings": [],
        }

    with pytest.raises(BenchmarkSchemaError, match="unstable_ablation_toggle"):
        BenchmarkHarness(runner).run(scenario)

    aggregate = BenchmarkHarness(
        runner,
        stable_toggles=("stable_parser_mode",),
        clock=lambda: 1.0,
    ).run(scenario)
    assert len(aggregate.runs) == 5


def test_schema_and_runtime_reject_less_than_five_repetitions():
    payload = load_scenario(SCENARIO_DIRECTORY / "06-clean-negative.json").to_dict()
    payload["repetitions"] = 4

    with pytest.raises(BenchmarkSchemaError, match="repetitions_below_minimum:5"):
        BenchmarkScenario.from_dict(payload)

    scenario = load_scenario(SCENARIO_DIRECTORY / "06-clean-negative.json")
    with pytest.raises(BenchmarkSchemaError, match="repetitions_below_minimum:5"):
        BenchmarkHarness(lambda *_args: {}).run(scenario, repetitions=4)


def test_schema_validates_observational_budgets_and_explicit_policy():
    payload = load_scenario(
        SCENARIO_DIRECTORY / "01-service-discovery-verification.json"
    ).to_dict()
    payload["budgets"].update(
        {
            "max_model_tokens": 1000,
            "max_cost_usd": 2.5,
            "policy": {
                "max_tools": "observational",
                "max_seconds": "hard",
                "max_output_bytes": "hard",
                "max_model_tokens": "observational",
                "max_cost_usd": "observational",
            },
        }
    )

    scenario = BenchmarkScenario.from_dict(payload)

    assert scenario.budgets["max_model_tokens"] == 1000
    assert scenario.budgets["max_cost_usd"] == 2.5
    assert scenario.budgets["policy"]["max_cost_usd"] == "observational"


@pytest.mark.parametrize(
    ("name", "value", "error"),
    [
        ("max_model_tokens", 0, "invalid_positive_integer:budgets.max_model_tokens"),
        ("max_model_tokens", 1.5, "invalid_positive_integer:budgets.max_model_tokens"),
        ("max_cost_usd", 0, "invalid_positive_number:budgets.max_cost_usd"),
        ("max_cost_usd", float("inf"), "invalid_positive_number:budgets.max_cost_usd"),
    ],
)
def test_schema_rejects_invalid_observational_budget_values(name, value, error):
    payload = load_scenario(
        SCENARIO_DIRECTORY / "01-service-discovery-verification.json"
    ).to_dict()
    payload["budgets"][name] = value

    with pytest.raises(BenchmarkSchemaError, match=error):
        BenchmarkScenario.from_dict(payload)


def test_observational_budgets_require_explicit_enforcement_policy():
    payload = load_scenario(
        SCENARIO_DIRECTORY / "01-service-discovery-verification.json"
    ).to_dict()
    payload["budgets"]["max_model_tokens"] = 1000

    with pytest.raises(BenchmarkSchemaError, match=r"missing:budgets\.policy"):
        BenchmarkScenario.from_dict(payload)
