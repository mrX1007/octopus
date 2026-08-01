"""Frozen design and missing-data contracts for Benchmark v4."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest

from core.benchmarks.v3 import build_analysis_plan, freeze_analysis_plan
from core.benchmarks.v4.__main__ import main as v4_main
from core.benchmarks.v4.analysis import _comparison_key, hierarchical_paired_bootstrap
from core.benchmarks.v4.schema import (
    ALL_RESOURCES,
    PRIMARY_RESOURCES,
    RESOURCE_UNITS,
    BenchmarkV4SchemaError,
    EfficiencyRunProjection,
    ResourceObservation,
    build_efficiency_plan,
    freeze_efficiency_plan,
    load_efficiency_plan,
)

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]

SCHEMA_ROOT = Path(__file__).parents[2] / "docs" / "schemas"


def _source_plan(*, repetitions: int = 2):
    return build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=("alpha", "beta"),
        scenario_ids=("deep-navigation-v3", "redirect-safety-v3"),
        repetitions=repetitions,
        base_fixture_seed=73,
        publication_tier="canary",
        bootstrap_samples=100,
    )


def test_efficiency_plan_is_isolated_frozen_and_position_balanced(tmp_path: Path) -> None:
    source = _source_plan()
    plan = build_efficiency_plan(
        source,
        efficiency_track_id="small-model-efficiency-v4",
        schedule_seed=19,
        publication_tier="canary",
    )

    assert plan.source_track_id == source.track_id
    assert plan.efficiency_track_id != source.track_id
    assert plan.primary_resources == PRIMARY_RESOURCES
    assert plan.methodology["automatic_winner"] is False
    assert plan.methodology["resource_direction"] == "lower_is_better"
    assert plan.methodology["resource_pair_population"] == "both_task_status_completed"
    assert (
        plan.methodology["multiple_testing"]
        == "bonferroni_comparison_pairs_x_primary_resources"
    )
    assert len(plan.schedule) == len(source.scenario_ids) * source.repetitions
    assert {
        (block.scenario_id, block.repetition, block.matched_fixture_seed)
        for block in plan.schedule
    } == {
        (scenario_id, repetition, source.fixture_seeds[scenario_id][repetition - 1])
        for scenario_id in source.scenario_ids
        for repetition in range(1, source.repetitions + 1)
    }
    for scenario_id in source.scenario_ids:
        first_positions = [
            block.system_order[0]
            for block in plan.schedule
            if block.scenario_id == scenario_id
        ]
        assert first_positions.count("alpha") == first_positions.count("beta")

    destination = freeze_efficiency_plan(plan, tmp_path / "efficiency-plan.json")
    assert load_efficiency_plan(destination) == plan
    assert freeze_efficiency_plan(plan, destination) == destination
    with pytest.raises(FileExistsError, match="differs"):
        freeze_efficiency_plan(replace(plan, bootstrap_seed=999), destination)


def test_efficiency_plan_digest_and_schedule_reject_tampering() -> None:
    plan = build_efficiency_plan(
        _source_plan(),
        efficiency_track_id="small-model-efficiency-v4",
        schedule_seed=31,
        publication_tier="canary",
    )
    payload = plan.to_dict()
    payload["schedule"][0]["system_order"].reverse()

    with pytest.raises(BenchmarkV4SchemaError):
        type(plan).from_dict(payload)

    extra = plan.to_dict()
    extra["winner"] = "alpha"
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_efficiency_plan"):
        type(plan).from_dict(extra)

    malformed_pair = plan.to_dict()
    malformed_pair["comparison_pairs"].append(["alpha"])
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_efficiency_plan"):
        type(plan).from_dict(malformed_pair)

    oversized = plan.to_dict()
    oversized["repetitions"] = 10_001
    with pytest.raises(BenchmarkV4SchemaError, match="repetitions"):
        type(plan).from_dict(oversized)

    with pytest.raises(BenchmarkV4SchemaError, match="bootstrap_samples"):
        replace(plan, bootstrap_samples=100_001)


def test_hierarchical_bootstrap_is_bounded_deterministic_and_zero_safe() -> None:
    pairs = {"scenario-a": ((2.0, 1.0), (4.0, 2.0))}

    first = hierarchical_paired_bootstrap(
        pairs,
        estimand="geometric_ratio",
        samples=100,
        seed=73,
    )
    second = hierarchical_paired_bootstrap(
        pairs,
        estimand="geometric_ratio",
        samples=100,
        seed=73,
    )

    assert first == second
    assert first["estimate"] == first["lower"] == first["upper"] == 0.5
    assert hierarchical_paired_bootstrap({}, samples=100)["available"] is False
    with pytest.raises(BenchmarkV4SchemaError, match="nonpositive"):
        hierarchical_paired_bootstrap(
            {"scenario-a": ((0.0, 1.0),)},
            estimand="geometric_ratio",
            samples=100,
        )
    with pytest.raises(BenchmarkV4SchemaError, match="design"):
        hierarchical_paired_bootstrap(pairs, samples=100_001)


def test_comparison_gate_keys_are_collision_resistant() -> None:
    assert _comparison_key("a:b", "c") != _comparison_key("a", "b:c")


def test_v4_cli_prepares_a_frozen_diagnostic_plan(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_path = freeze_analysis_plan(_source_plan(), tmp_path / "analysis-plan.json")
    output = tmp_path / "efficiency-plan.json"

    assert v4_main(
        [
            "prepare",
            "--source-analysis-plan",
            str(source_path),
            "--output",
            str(output),
            "--efficiency-track-id",
            "small-model-efficiency-v4-diagnostic",
            "--diagnostic",
        ]
    ) == 0

    plan = load_efficiency_plan(output)
    assert plan.publication_tier == "diagnostic"
    assert plan.require_run_attestation is False
    assert str(output) in capsys.readouterr().out


def test_unavailable_resource_round_trip_never_imputes_zero() -> None:
    missing = ResourceObservation.unavailable(
        "model_tokens",
        source="budget_enforcement",
        unit="tokens",
        reason="source_metric_missing",
    )

    assert missing.to_dict()["value"] is None
    assert ResourceObservation.from_dict(missing.to_dict()) == missing
    invalid_payload = missing.to_dict()
    invalid_payload["value"] = 0.0
    with pytest.raises(BenchmarkV4SchemaError, match="unavailable_resource_has_value"):
        ResourceObservation.from_dict(invalid_payload)
    with pytest.raises(BenchmarkV4SchemaError, match="unavailable_resource_has_value"):
        ResourceObservation(
            name="model_tokens",
            available=False,
            reliability="unavailable",
            source="budget_enforcement",
            unit="tokens",
            value=0.0,
            reason="source_metric_missing",
        )


def test_v4_plan_and_run_payloads_validate_against_published_json_schemas() -> None:
    source = _source_plan()
    plan = build_efficiency_plan(
        source,
        efficiency_track_id="small-model-efficiency-v4",
        publication_tier="canary",
    )
    resources = {
        name: ResourceObservation.unavailable(
            name,
            source="test_controller",
            unit=RESOURCE_UNITS[name],
            reason="test_missing",
        )
        for name in ALL_RESOURCES
    }
    projection = EfficiencyRunProjection(
        run_id="run-alpha",
        efficiency_track_id=plan.efficiency_track_id,
        source_track_id=source.track_id,
        system_id="alpha",
        scenario_id=source.scenario_ids[0],
        repetition=1,
        matched_fixture_seed=source.fixture_seeds[source.scenario_ids[0]][0],
        execution_status="failed",
        task_status="not_completed",
        started_at=1.0,
        finished_at=2.0,
        batch_id="batch-one",
        host_id="host-one",
        efficiency_plan_attested=True,
        quality=ResourceObservation.unavailable(
            "verified_f1",
            source="sealed_evaluator_v3",
            unit="ratio",
            reason="test_missing",
        ),
        resources=resources,
    )

    plan_schema = json.loads(
        (SCHEMA_ROOT / "benchmark-efficiency-plan-v4.schema.json").read_text(encoding="utf-8")
    )
    run_schema = json.loads(
        (SCHEMA_ROOT / "benchmark-efficiency-run-v4.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(plan_schema)
    jsonschema.Draft202012Validator.check_schema(run_schema)
    jsonschema.validate(plan.to_dict(), plan_schema)
    jsonschema.validate(projection.to_dict(), run_schema)

    wrong_version = projection.to_dict()
    wrong_version["schema_version"] = "999.0"
    with pytest.raises(BenchmarkV4SchemaError, match="unsupported_efficiency_run_schema"):
        EfficiencyRunProjection.from_dict(wrong_version)

    with pytest.raises(BenchmarkV4SchemaError, match="quality_out_of_range"):
        replace(
            projection,
            quality=ResourceObservation(
                name="verified_f1",
                available=True,
                reliability="derived",
                source="sealed_evaluator_v3",
                unit="ratio",
                value=1.1,
            ),
        )
    overrange_quality = projection.to_dict()
    overrange_quality["quality"]["value"] = 1.1
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(overrange_quality, run_schema)
