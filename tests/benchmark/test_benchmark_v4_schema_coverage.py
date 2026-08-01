"""Hermetic branch coverage for the Benchmark v4 schema and CLI contracts."""

from __future__ import annotations

import copy
import runpy
import sys
import warnings
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import core.benchmarks.v4.__main__ as cli
from core.benchmarks.v3 import build_analysis_plan
from core.benchmarks.v4 import schema

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


@pytest.fixture
def source_plan():
    return build_analysis_plan(
        track_id="small-model-stress-v3",
        system_ids=("alpha", "beta"),
        scenario_ids=("scenario-a",),
        repetitions=2,
        base_fixture_seed=19,
        publication_tier="canary",
        bootstrap_samples=100,
    )


@pytest.fixture
def plan(source_plan):
    return schema.build_efficiency_plan(
        source_plan,
        efficiency_track_id="coverage-efficiency-v4",
        schedule_seed=7,
        publication_tier="canary",
    )


def _observation(name: str, *, unit: str | None = None) -> schema.ResourceObservation:
    return schema.ResourceObservation(
        name=name,
        available=True,
        reliability="measured",
        source="coverage-controller",
        unit=unit or schema.RESOURCE_UNITS[name],
        value=1.0,
    )


@pytest.fixture
def projection(plan):
    block = next(item for item in plan.schedule if item.repetition == 1)
    return schema.EfficiencyRunProjection(
        run_id="coverage-run",
        efficiency_track_id=plan.efficiency_track_id,
        source_track_id=plan.source_track_id,
        system_id="alpha",
        scenario_id=block.scenario_id,
        repetition=block.repetition,
        matched_fixture_seed=block.matched_fixture_seed,
        execution_status="succeeded",
        task_status="completed",
        started_at=1.0,
        finished_at=2.0,
        batch_id="coverage-batch",
        host_id="coverage-host",
        efficiency_plan_attested=True,
        quality=schema.ResourceObservation(
            name="verified_f1",
            available=True,
            reliability="derived",
            source="sealed-evaluator-v3",
            unit="ratio",
            value=0.8,
        ),
        resources={name: _observation(name) for name in schema.ALL_RESOURCES},
    )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"repetition": 0}, "schedule.repetition"),
        ({"matched_fixture_seed": -1}, "matched_fixture_seed"),
        ({"system_order": ("alpha", "alpha")}, "system_order"),
    ],
)
def test_schedule_block_rejects_invalid_fields(kwargs: dict[str, Any], match: str) -> None:
    values: dict[str, Any] = {
        "scenario_id": "scenario-a",
        "repetition": 1,
        "matched_fixture_seed": 1,
        "system_order": ("alpha", "beta"),
    }
    values.update(kwargs)

    with pytest.raises(schema.BenchmarkV4SchemaError, match=match):
        schema.ScheduleBlock(**values)


def test_schedule_block_loader_wraps_and_rethrows(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "matched_fixture_seed": 1,
        "repetition": 1,
        "scenario_id": "scenario-a",
        "system_order": ["alpha", "beta"],
    }
    invalid_order = {**payload, "system_order": "alpha,beta"}
    with pytest.raises(schema.BenchmarkV4SchemaError, match="schedule_block"):
        schema.ScheduleBlock.from_dict(invalid_order)

    too_large = {**payload, "repetition": schema.MAX_REPETITIONS + 1}
    with pytest.raises(schema.BenchmarkV4SchemaError, match=r"schedule\.repetition"):
        schema.ScheduleBlock.from_dict(too_large)

    def type_error(*_args: Any, **_kwargs: Any) -> int:
        raise TypeError("synthetic conversion failure")

    monkeypatch.setattr(schema, "_integer", type_error)
    with pytest.raises(schema.BenchmarkV4SchemaError, match="schedule_block"):
        schema.ScheduleBlock.from_dict(payload)


@pytest.mark.parametrize(
    ("updates", "match"),
    [
        ({"comparison_pairs": (1,)}, "comparison_pair"),
        ({"comparison_pairs": (("alpha",),)}, "comparison_pair"),
        ({"coverage_gates": []}, "coverage_gates"),
        (
            {
                "coverage_gates": {
                    "wall_time_seconds": True,
                    "fixture_http_requests": 1.0,
                }
            },
            "coverage_gates",
        ),
        (
            {
                "coverage_gates": {
                    "wall_time_seconds": object(),
                    "fixture_http_requests": 1.0,
                }
            },
            "coverage_gates",
        ),
        ({"schema_version": "999.0"}, "unsupported_efficiency_plan_schema"),
        ({"efficiency_track_id": "small-model-stress-v3"}, "not_isolated"),
        ({"system_ids": ("alpha",)}, "unique_systems"),
        ({"scenario_ids": ()}, "unique_scenarios"),
        ({"repetitions": 0}, "repetitions"),
        ({"schedule_seed": -1}, "schedule_seed"),
        ({"primary_resources": ("wall_time_seconds",)}, "primary_resources"),
        ({"secondary_resources": ()}, "secondary_resources"),
        ({"quality_metric": "quality"}, "quality_metric"),
        (
            {"methodology": {**dict(schema.EFFICIENCY_METHODOLOGY), "automatic_winner": True}},
            "methodology",
        ),
        (
            {"coverage_gates": {"wall_time_seconds": 1.1, "fixture_http_requests": 1.0}},
            "coverage_gates",
        ),
        ({"noninferiority_margin": -0.1}, "noninferiority_margin"),
        ({"alpha": 1.0}, "alpha"),
        ({"bootstrap_samples": 99}, "bootstrap_samples"),
        ({"bootstrap_seed": -1}, "bootstrap_seed"),
        ({"publication_tier": "private"}, "publication_tier"),
        ({"require_run_attestation": False}, "requires_attestation"),
        ({"require_run_attestation": 1}, "require_run_attestation"),
        ({"comparison_pairs": ()}, "requires_comparison_pair"),
        ({"comparison_pairs": (("alpha", "alpha"),)}, "comparison_pair"),
        (
            {"comparison_pairs": (("alpha", "beta"), ("beta", "alpha"))},
            "duplicate_efficiency_comparison_pair",
        ),
        ({"methodology": {}}, "methodology"),
        (
            {"methodology": {**dict(schema.EFFICIENCY_METHODOLOGY), "claim_resources": "wall"}},
            "methodology",
        ),
        (
            {"methodology": {**dict(schema.EFFICIENCY_METHODOLOGY), "bootstrap_unit": None}},
            "methodology",
        ),
    ],
)
def test_efficiency_plan_rejects_invalid_contracts(plan, updates: dict[str, Any], match: str) -> None:
    with pytest.raises(schema.BenchmarkV4SchemaError, match=match):
        replace(plan, **updates)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("schema_version", "999.0", "unsupported_efficiency_plan_schema"),
        ("frozen", False, "not_frozen"),
        ("plan_digest", "0" * 64, "digest_mismatch"),
        ("plan_id", "efficiency-plan-" + "0" * 20, "id_mismatch"),
        ("schedule", "invalid", "invalid_efficiency_plan"),
        ("comparison_pairs", [["alpha"]], "invalid_efficiency_plan"),
        ("coverage_gates", [], "invalid_efficiency_plan"),
        ("methodology", [], "invalid_efficiency_plan"),
        ("repetitions", 0, "repetitions"),
    ],
)
def test_efficiency_plan_loader_rejects_tampering(plan, field: str, value: Any, match: str) -> None:
    payload = copy.deepcopy(plan.to_dict())
    payload[field] = value

    with pytest.raises(schema.BenchmarkV4SchemaError, match=match):
        schema.EfficiencyPlan.from_dict(payload)


def test_efficiency_plan_loader_wraps_conversion_failure(
    plan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = copy.deepcopy(plan.to_dict())

    def type_error(*_args: Any, **_kwargs: Any) -> float:
        raise TypeError("synthetic conversion failure")

    monkeypatch.setattr(schema, "_number", type_error)
    with pytest.raises(schema.BenchmarkV4SchemaError, match="invalid_efficiency_plan"):
        schema.EfficiencyPlan.from_dict(payload)


def test_efficiency_plan_loader_requires_exact_keys(plan) -> None:
    payload = copy.deepcopy(plan.to_dict())
    payload["unexpected"] = True

    with pytest.raises(schema.BenchmarkV4SchemaError, match="invalid_efficiency_plan"):
        schema.EfficiencyPlan.from_dict(payload)


def test_schedule_contract_rejects_coverage_and_order_tampering(plan) -> None:
    first, second = plan.schedule

    with pytest.raises(schema.BenchmarkV4SchemaError, match=r"invalid:efficiency_plan\.schedule"):
        replace(plan, schedule=())
    with pytest.raises(schema.BenchmarkV4SchemaError, match="duplicate_efficiency_schedule_block"):
        replace(plan, schedule=(first, first))
    with pytest.raises(schema.BenchmarkV4SchemaError, match="block_coverage_mismatch"):
        replace(plan, schedule=(replace(first, scenario_id="other"), second))
    with pytest.raises(schema.BenchmarkV4SchemaError, match="system_coverage_mismatch"):
        replace(plan, schedule=(replace(first, system_order=("alpha", "gamma")), second))
    with pytest.raises(schema.BenchmarkV4SchemaError, match="schedule_not_deterministic"):
        replace(plan, schedule=(replace(first, system_order=tuple(reversed(first.system_order))), second))


def test_schedule_contract_defensively_rejects_position_imbalance(
    plan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imbalanced = tuple(replace(block, system_order=("alpha", "beta")) for block in plan.schedule)
    monkeypatch.setattr(schema, "_build_schedule", lambda **_kwargs: imbalanced)

    with pytest.raises(schema.BenchmarkV4SchemaError, match="position_imbalance"):
        replace(plan, schedule=imbalanced)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"reliability": "unknown"}, "resource.reliability"),
        ({"available": 1}, "resource.available"),
        ({"value": None}, "resource.value"),
        ({"reliability": "unavailable"}, "available_resource_unavailable"),
        (
            {"available": False, "reliability": "unavailable", "value": 1.0, "reason": "missing"},
            "unavailable_resource_has_value",
        ),
        (
            {"available": False, "reliability": "measured", "value": None, "reason": "missing"},
            "unavailable_resource_reliability",
        ),
        (
            {"available": False, "reliability": "unavailable", "value": None, "reason": ""},
            "requires_reason",
        ),
    ],
)
def test_resource_observation_rejects_invalid_states(kwargs: dict[str, Any], match: str) -> None:
    values: dict[str, Any] = {
        "name": "wall_time_seconds",
        "available": True,
        "reliability": "measured",
        "source": "coverage-controller",
        "unit": "seconds",
        "value": 1.0,
        "reason": "",
    }
    values.update(kwargs)

    with pytest.raises(schema.BenchmarkV4SchemaError, match=match):
        schema.ResourceObservation(**values)


def test_resource_observation_loader_and_optional_reason_branches() -> None:
    available = _observation("wall_time_seconds")
    assert "reason" not in available.to_dict()
    missing = schema.ResourceObservation.unavailable(
        "model_tokens",
        source="coverage-controller",
        unit="tokens",
        reason="not-recorded",
    )
    assert missing.to_dict()["reason"] == "not-recorded"
    assert schema.ResourceObservation.from_dict(available.to_dict()) == available

    malformed = available.to_dict()
    malformed["unexpected"] = True
    with pytest.raises(schema.BenchmarkV4SchemaError, match="invalid_resource_observation"):
        schema.ResourceObservation.from_dict(malformed)

    nonnull_missing = missing.to_dict()
    nonnull_missing["value"] = 0.0
    with pytest.raises(schema.BenchmarkV4SchemaError, match="unavailable_resource_has_value"):
        schema.ResourceObservation.from_dict(nonnull_missing)


def test_efficiency_run_projection_rejects_invalid_contracts(projection) -> None:
    with pytest.raises(schema.BenchmarkV4SchemaError, match="unsupported_efficiency_run_schema"):
        replace(projection, schema_version="999.0")
    with pytest.raises(schema.BenchmarkV4SchemaError, match="efficiency_plan_attested"):
        replace(projection, efficiency_plan_attested=1)
    with pytest.raises(schema.BenchmarkV4SchemaError, match="schedule_key"):
        replace(projection, repetition=0)
    with pytest.raises(schema.BenchmarkV4SchemaError, match="timestamp"):
        replace(projection, started_at=float("nan"))
    with pytest.raises(schema.BenchmarkV4SchemaError, match="timestamp_order"):
        replace(projection, finished_at=0.0)
    with pytest.raises(schema.BenchmarkV4SchemaError, match="batch_id"):
        replace(projection, batch_id="bad\x00batch")
    with pytest.raises(schema.BenchmarkV4SchemaError, match="host_id"):
        replace(projection, host_id="bad\x00host")
    with pytest.raises(schema.BenchmarkV4SchemaError, match="execution_status"):
        replace(projection, execution_status="unknown")
    with pytest.raises(schema.BenchmarkV4SchemaError, match="task_status"):
        replace(projection, task_status="unknown")

    wrong_quality = replace(projection.quality, name="other_quality")
    with pytest.raises(schema.BenchmarkV4SchemaError, match="quality_metric_mismatch"):
        replace(projection, quality=wrong_quality)
    excessive_quality = replace(projection.quality, value=1.1)
    with pytest.raises(schema.BenchmarkV4SchemaError, match="quality_out_of_range"):
        replace(projection, quality=excessive_quality)

    with pytest.raises(schema.BenchmarkV4SchemaError, match=r"efficiency_run\.resources"):
        replace(projection, resources=[])
    incomplete_resources = dict(projection.resources)
    incomplete_resources.pop("wall_time_seconds")
    with pytest.raises(schema.BenchmarkV4SchemaError, match="resource_set_mismatch"):
        replace(projection, resources=incomplete_resources)
    wrong_name = dict(projection.resources)
    wrong_name["wall_time_seconds"] = _observation("tool_calls")
    with pytest.raises(schema.BenchmarkV4SchemaError, match="resource_name_mismatch"):
        replace(projection, resources=wrong_name)
    wrong_unit = dict(projection.resources)
    wrong_unit["wall_time_seconds"] = _observation("wall_time_seconds", unit="calls")
    with pytest.raises(schema.BenchmarkV4SchemaError, match="resource_unit_mismatch"):
        replace(projection, resources=wrong_unit)
    with pytest.raises(schema.BenchmarkV4SchemaError, match="quality_unit_mismatch"):
        replace(projection, quality=replace(projection.quality, unit="count"))

    empty_location = replace(projection, batch_id="", host_id="")
    assert empty_location.block_key == (
        projection.scenario_id,
        projection.repetition,
        projection.matched_fixture_seed,
    )


def test_efficiency_run_projection_loader_boundaries(projection) -> None:
    payload = projection.to_dict()
    assert schema.EfficiencyRunProjection.from_dict(payload) == projection

    extra = copy.deepcopy(payload)
    extra["unexpected"] = True
    with pytest.raises(schema.BenchmarkV4SchemaError, match="invalid_efficiency_run"):
        schema.EfficiencyRunProjection.from_dict(extra)

    invalid_quality = copy.deepcopy(payload)
    invalid_quality["quality"] = []
    with pytest.raises(schema.BenchmarkV4SchemaError, match=r"efficiency_run\.quality"):
        schema.EfficiencyRunProjection.from_dict(invalid_quality)

    invalid_resources = copy.deepcopy(payload)
    invalid_resources["resources"] = []
    with pytest.raises(schema.BenchmarkV4SchemaError, match=r"efficiency_run\.resources"):
        schema.EfficiencyRunProjection.from_dict(invalid_resources)

    invalid_resource = copy.deepcopy(payload)
    invalid_resource["resources"]["wall_time_seconds"] = []
    with pytest.raises(schema.BenchmarkV4SchemaError, match=r"efficiency_run\.resource"):
        schema.EfficiencyRunProjection.from_dict(invalid_resource)


def test_build_efficiency_plan_rejects_invalid_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(schema.BenchmarkV4SchemaError, match="requires_analysis_plan"):
        schema.build_efficiency_plan(object())

    class OversizedSource:
        repetitions = schema.MAX_REPETITIONS + 1

    monkeypatch.setattr(schema, "AnalysisPlan", OversizedSource)
    with pytest.raises(schema.BenchmarkV4SchemaError, match="repetitions"):
        schema.build_efficiency_plan(OversizedSource())


def test_freeze_and_load_failure_boundaries(
    plan,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(schema.BenchmarkV4SchemaError, match="invalid_efficiency_plan"):
        schema.freeze_efficiency_plan(object(), tmp_path / "invalid.json")

    missing = tmp_path / "missing.json"
    with pytest.raises(schema.BenchmarkV4SchemaError, match="load_failed"):
        schema.load_efficiency_plan(missing)

    nonmapping = tmp_path / "nonmapping.json"
    nonmapping.write_text("[]\n", encoding="utf-8")
    with pytest.raises(schema.BenchmarkV4SchemaError, match="invalid_efficiency_plan"):
        schema.load_efficiency_plan(nonmapping)

    destination = tmp_path / "atomic-failure.json"

    def replace_failure(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(schema.os, "replace", replace_failure)
    with pytest.raises(OSError, match="synthetic replace failure"):
        schema.freeze_efficiency_plan(plan, destination)
    assert not destination.exists()
    assert not tuple(tmp_path.glob(".atomic-failure.json.*.tmp"))


def test_private_scalar_and_container_validators() -> None:
    assert schema._identifier("alpha-1", "identifier") == "alpha-1"
    assert schema._digest("a" * 64, "digest") == "a" * 64
    assert schema._text("value", "text") == "value"
    assert schema._number("1.5", "number") == 1.5
    assert schema._integer(2, "integer", minimum=1, maximum=3) == 2
    assert schema._boolean(True, "boolean") is True
    assert schema._mapping({"key": "value"}, "mapping") == {"key": "value"}
    schema._exact_keys({"key": 1}, {"key"}, "keys")
    assert schema._sequence([]) is True
    assert schema._sequence("not-a-sequence") is False

    invalid_calls = (
        (schema._identifier, (" Bad", "identifier"), {}),
        (schema._digest, ("bad", "digest"), {}),
        (schema._text, ("", "text"), {}),
        (schema._number, (True, "number"), {}),
        (schema._number, (object(), "number"), {}),
        (schema._number, (float("inf"), "number"), {}),
        (schema._integer, (True, "integer"), {"minimum": 0}),
        (schema._integer, (-1, "integer"), {"minimum": 0}),
        (schema._boolean, (1, "boolean"), {}),
        (schema._mapping, ([], "mapping"), {}),
        (schema._exact_keys, ({"extra": 1}, {"expected"}, "keys"), {}),
    )
    for function, args, kwargs in invalid_calls:
        with pytest.raises(schema.BenchmarkV4SchemaError):
            function(*args, **kwargs)


def test_cli_publish_verify_and_integer_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    sentinel_plan = object()
    published = tmp_path / "published"
    monkeypatch.setattr(cli, "load_efficiency_plan", lambda _path: sentinel_plan)
    monkeypatch.setattr(
        cli,
        "publish_v4_results",
        lambda plan, source, output: (
            published
            if plan is sentinel_plan and source == tmp_path / "source" and output == tmp_path / "output"
            else None
        ),
    )
    assert (
        cli.main(
            [
                "publish",
                "--plan",
                str(tmp_path / "plan.json"),
                "--source-v3",
                str(tmp_path / "source"),
                "--output",
                str(tmp_path / "output"),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.strip() == str(published)

    verification = {"status": "verified", "runs": 2}
    monkeypatch.setattr(cli, "verify_v4_results", lambda directory, *, source_v3_directory: verification)
    assert (
        cli.main(
            [
                "verify",
                str(tmp_path / "bundle"),
                "--source-v3",
                str(tmp_path / "source"),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.strip() == '{"runs": 2, "status": "verified"}'

    assert cli._nonnegative_integer("0") == 0
    with pytest.raises(Exception, match="integer"):
        cli._nonnegative_integer("not-an-integer")
    with pytest.raises(Exception, match="nonnegative"):
        cli._nonnegative_integer("-1")


def test_cli_module_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["benchmark-v4", "--help"])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        with pytest.raises(SystemExit) as raised:
            runpy.run_module("core.benchmarks.v4.__main__", run_name="__main__")
    assert raised.value.code == 0
