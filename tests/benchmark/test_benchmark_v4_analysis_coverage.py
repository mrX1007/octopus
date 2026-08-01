"""Hermetic branch coverage for Benchmark v4 efficiency analysis."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from core.benchmarks.v4 import analysis
from core.benchmarks.v4.schema import BenchmarkV4SchemaError, ResourceObservation
from tests.benchmark.test_benchmark_v4_publication import _canary_inputs

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


@pytest.fixture(scope="module")
def canary() -> SimpleNamespace:
    source_plan, plan, runs, context, ledgers = _canary_inputs()
    projections = analysis.extract_efficiency_runs(plan, source_plan, runs, ledgers)
    return SimpleNamespace(
        context=context,
        ledgers=ledgers,
        plan=plan,
        projections=projections,
        runs=runs,
        source_plan=source_plan,
    )


def _unchecked_copy(value: Any, **changes: Any) -> Any:
    copied = replace(value)
    for name, replacement in changes.items():
        object.__setattr__(copied, name, replacement)
    return copied


def _noninferiority_stubs() -> dict[str, dict[str, Any]]:
    gate = {
        "effect": {"available": False, "sample_size": 0},
        "left_noninferior": False,
        "right_noninferior": False,
    }
    return {
        "task_completion_rate": gate,
        "verified_f1": gate,
        "verified_f1_both_completed": gate,
    }


def test_extract_rejects_duplicate_missing_and_unattested_runs(
    canary: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(analysis, "_validate_v3_schedule_once", lambda *_args: None)

    with pytest.raises(BenchmarkV4SchemaError, match="duplicate_efficiency_source_run"):
        analysis.extract_efficiency_runs(
            canary.plan,
            canary.source_plan,
            (canary.runs[0], canary.runs[0]),
            (),
        )

    with pytest.raises(
        BenchmarkV4SchemaError,
        match="efficiency_runs_do_not_match_frozen_schedule",
    ):
        analysis.extract_efficiency_runs(
            canary.plan,
            canary.source_plan,
            canary.runs[:-1],
            (),
        )

    first = canary.runs[0]
    unattested = replace(
        first,
        environment={
            **dict(first.environment),
            "efficiency_plan_digest": "0" * 64,
        },
    )
    runs = (unattested, *canary.runs[1:])
    with pytest.raises(BenchmarkV4SchemaError, match="run_missing_efficiency_plan_attestation"):
        analysis.extract_efficiency_runs(
            canary.plan,
            canary.source_plan,
            runs,
            canary.ledgers,
        )


def test_bootstrap_rejects_estimand_empty_nonfinite_and_nonpositive_inputs() -> None:
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_hierarchical_bootstrap_estimand"):
        analysis.hierarchical_paired_bootstrap(
            {"scenario": [(1.0, 2.0)]},
            estimand="unknown",  # type: ignore[arg-type]
            samples=100,
        )

    assert analysis.hierarchical_paired_bootstrap(
        {"empty": []},
        samples=100,
    ) == {
        "available": False,
        "reason": "no_eligible_pairs",
        "sample_size": 0,
        "scenario_count": 0,
    }

    with pytest.raises(BenchmarkV4SchemaError, match="nonfinite_hierarchical_bootstrap_value"):
        analysis.hierarchical_paired_bootstrap(
            {"scenario": [(1.0, float("nan"))]},
            samples=100,
        )
    with pytest.raises(BenchmarkV4SchemaError, match="nonpositive_geometric_ratio_value"):
        analysis.hierarchical_paired_bootstrap(
            {"scenario": [(0.0, 1.0)]},
            estimand="geometric_ratio",
            samples=100,
        )


def test_source_plan_binding_rejects_every_mismatch(canary: SimpleNamespace) -> None:
    with pytest.raises(BenchmarkV4SchemaError, match="efficiency_analysis_requires_frozen_plans"):
        analysis._validate_source_plan(object(), canary.source_plan)  # type: ignore[arg-type]

    bad_digest = _unchecked_copy(canary.plan, source_analysis_plan_digest="0" * 64)
    with pytest.raises(BenchmarkV4SchemaError, match="source_analysis_plan_digest_mismatch"):
        analysis._validate_source_plan(bad_digest, canary.source_plan)

    bad_track = _unchecked_copy(canary.plan, source_track_id="other-track")
    with pytest.raises(BenchmarkV4SchemaError, match="source_analysis_track_mismatch"):
        analysis._validate_source_plan(bad_track, canary.source_plan)

    bad_design = _unchecked_copy(canary.plan, system_ids=tuple(reversed(canary.plan.system_ids)))
    with pytest.raises(BenchmarkV4SchemaError, match="efficiency_plan_source_design_mismatch"):
        analysis._validate_source_plan(bad_design, canary.source_plan)

    bad_tier = _unchecked_copy(canary.plan, publication_tier="full")
    with pytest.raises(BenchmarkV4SchemaError, match="efficiency_source_publication_tier_mismatch"):
        analysis._validate_source_plan(bad_tier, canary.source_plan)

    first = canary.plan.schedule[0]
    changed_seed = replace(first, matched_fixture_seed=first.matched_fixture_seed + 1)
    bad_schedule = _unchecked_copy(
        canary.plan,
        schedule=(changed_seed, *canary.plan.schedule[1:]),
    )
    with pytest.raises(BenchmarkV4SchemaError, match="efficiency_schedule_source_seed_mismatch"):
        analysis._validate_source_plan(bad_schedule, canary.source_plan)


def test_schedule_validation_cache_evicts_deterministically(
    canary: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cached = {f"{index:064x}" for index in range(analysis._MAX_VALIDATED_SCHEDULES)}
    monkeypatch.setattr(analysis, "_VALIDATED_SCHEDULE_CACHE", cached)
    monkeypatch.setattr(analysis, "analyze_runs", lambda *_args: {})

    analysis._validate_v3_schedule_once(canary.source_plan, canary.runs)

    assert len(cached) == analysis._MAX_VALIDATED_SCHEDULES
    assert f"{0:064x}" not in cached


def test_ledger_index_rejects_invalid_records_and_coverage(canary: SimpleNamespace) -> None:
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_efficiency_controller_ledgers"):
        analysis._index_ledgers(canary.runs, "invalid")  # type: ignore[arg-type]
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_efficiency_controller_ledgers"):
        analysis._index_ledgers(canary.runs, [object()])  # type: ignore[list-item]
    with pytest.raises(BenchmarkV4SchemaError, match="duplicate_efficiency_controller_ledger"):
        analysis._index_ledgers(canary.runs, [{"run_id": ""}])

    duplicate = {"run_id": canary.runs[0].run_id}
    with pytest.raises(BenchmarkV4SchemaError, match="duplicate_efficiency_controller_ledger"):
        analysis._index_ledgers(canary.runs, [duplicate, duplicate])
    with pytest.raises(BenchmarkV4SchemaError, match="efficiency_ledger_run_coverage_mismatch"):
        analysis._index_ledgers(canary.runs, [])


def test_validated_ledger_summary_rejects_all_corruption_classes(
    canary: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = canary.runs[0]
    record = deepcopy(canary.ledgers[0])

    mismatched = deepcopy(record)
    mismatched["system_id"] = "other-system"
    with pytest.raises(BenchmarkV4SchemaError, match="efficiency_ledger_run_mismatch"):
        analysis._validated_ledger_summary(run, mismatched)

    missing = deepcopy(record)
    missing.pop("entries")
    with pytest.raises(BenchmarkV4SchemaError, match="efficiency_ledger_measurements_missing"):
        analysis._validated_ledger_summary(run, missing)

    invalid_entries = deepcopy(record)
    invalid_entries["entries"] = "invalid"
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_efficiency_ledger_entries"):
        analysis._validated_ledger_summary(run, invalid_entries)

    bad_root = deepcopy(record)
    bad_root["ledger_root_digest"] = "f" * 64
    with pytest.raises(BenchmarkV4SchemaError, match="efficiency_ledger_root_mismatch"):
        analysis._validated_ledger_summary(run, bad_root)

    zero_summary = {
        "entry_count": 0,
        "evidence_bearing_request_count": 0,
        "repeated_request_count": 0,
        "unique_target_count": 0,
        "unsuccessful_request_count": 0,
    }
    summary_mismatch = deepcopy(record)
    summary_mismatch["efficiency_summary"] = zero_summary
    with pytest.raises(BenchmarkV4SchemaError, match="efficiency_ledger_summary_mismatch"):
        analysis._validated_ledger_summary(run, summary_mismatch)

    summary_only = deepcopy(record)
    summary_only.pop("entries")
    summary_only["efficiency_summary"] = zero_summary
    with monkeypatch.context() as context:
        context.setattr(analysis, "_compact_summary", lambda _value: None)
        with pytest.raises(BenchmarkV4SchemaError, match="efficiency_ledger_measurements_missing"):
            analysis._validated_ledger_summary(run, summary_only)

    unattested = replace(run, artifact_refs=())
    with pytest.raises(BenchmarkV4SchemaError, match="efficiency_ledger_root_not_attested"):
        analysis._validated_ledger_summary(unattested, record)

    invalid_count = replace(
        run,
        environment={**dict(run.environment), "controller_ledger_entries": True},
    )
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_controller_ledger_entry_count"):
        analysis._validated_ledger_summary(invalid_count, record)

    wrong_count = replace(
        run,
        environment={
            **dict(run.environment),
            "controller_ledger_entries": int(run.environment["controller_ledger_entries"]) + 1,
        },
    )
    with pytest.raises(BenchmarkV4SchemaError, match="efficiency_ledger_entry_count_mismatch"):
        analysis._validated_ledger_summary(wrong_count, record)


def test_compact_summary_and_budget_observation_boundaries(canary: SimpleNamespace) -> None:
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_efficiency_ledger_summary"):
        analysis._compact_summary([])
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_efficiency_ledger_summary"):
        analysis._compact_summary(
            {
                "entry_count": 1,
                "evidence_bearing_request_count": 0,
                "repeated_request_count": 0,
                "unique_target_count": 1,
                "unsuccessful_request_count": True,
            }
        )
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_efficiency_ledger_summary"):
        analysis._compact_summary(
            {
                "entry_count": 1,
                "evidence_bearing_request_count": 0,
                "repeated_request_count": 1,
                "unique_target_count": 1,
                "unsuccessful_request_count": 0,
            }
        )

    missing = analysis._budget_observation(SimpleNamespace(budget_enforcement=()), "tool_calls")
    assert missing.available is False
    assert missing.reason == "budget_observation_not_recorded"

    source_record = next(item for item in canary.runs[0].budget_enforcement if item.budget_name == "max_tools")
    self_reported = analysis._budget_observation(
        SimpleNamespace(budget_enforcement=(replace(source_record, reliable=False),)),
        "tool_calls",
    )
    assert self_reported.reliability == "self_reported"
    assert self_reported.reason == "not_independently_verified"


def test_resource_effect_rejects_corrupt_available_values(canary: SimpleNamespace) -> None:
    block = canary.plan.schedule[0]
    by_system = {
        item.system_id: item
        for item in canary.projections
        if item.block_key == (block.scenario_id, block.repetition, block.matched_fixture_seed)
    }
    left = by_system[canary.plan.comparison_pairs[0][0]]
    right = by_system[canary.plan.comparison_pairs[0][1]]

    corrupt_resource = replace(left.resources["wall_time_seconds"])
    object.__setattr__(corrupt_resource, "value", None)
    resources = dict(left.resources)
    resources["wall_time_seconds"] = corrupt_resource
    corrupt_left = replace(left, resources=resources)
    with pytest.raises(BenchmarkV4SchemaError, match="available_resource_missing_value"):
        analysis._resource_effect(
            canary.plan,
            [(corrupt_left, right)],
            left.system_id,
            right.system_id,
            "wall_time_seconds",
            0,
            0,
            canary.plan.alpha / 2,
            {"base_eligible": True},
            {},
        )

    corrupt_quality = replace(left.quality)
    object.__setattr__(corrupt_quality, "value", None)
    corrupt_left = replace(left, quality=corrupt_quality)
    with pytest.raises(BenchmarkV4SchemaError, match="available_quality_missing_value"):
        analysis._resource_effect(
            canary.plan,
            [(corrupt_left, right)],
            left.system_id,
            right.system_id,
            "wall_time_seconds",
            0,
            0,
            canary.plan.alpha / 2,
            {"base_eligible": True},
            {},
        )


def test_resource_effect_counts_both_and_left_incomplete_tasks(canary: SimpleNamespace) -> None:
    block = canary.plan.schedule[0]
    by_system = {
        item.system_id: item
        for item in canary.projections
        if item.block_key == (block.scenario_id, block.repetition, block.matched_fixture_seed)
    }
    left = by_system[canary.plan.comparison_pairs[0][0]]
    right = by_system[canary.plan.comparison_pairs[0][1]]
    incomplete_left = replace(left, task_status="not_completed")
    incomplete_right = replace(right, task_status="not_completed")

    result = analysis._resource_effect(
        canary.plan,
        [(incomplete_left, incomplete_right), (incomplete_left, right)],
        left.system_id,
        right.system_id,
        "wall_time_seconds",
        0,
        0,
        canary.plan.alpha / 2,
        {"base_eligible": False},
        _noninferiority_stubs(),
    )

    assert result["exclusions"]["reason_counts"] == {
        "both_tasks_not_completed": 1,
        "left_task_not_completed": 1,
    }


def test_group_pairs_and_pareto_boundaries(canary: SimpleNamespace) -> None:
    pair = (canary.projections[0], canary.projections[1])
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_quality_pair_projection"):
        analysis._group_pairs([pair], lambda _item: 1.0, require_available=True)

    unavailable = ResourceObservation.unavailable(
        "verified_f1",
        source="test",
        unit="ratio",
        reason="missing",
    )
    left = SimpleNamespace(quality=unavailable, scenario_id="scenario")
    right = SimpleNamespace(quality=unavailable, scenario_id="scenario")
    assert (
        analysis._group_pairs(
            [(left, right)],
            lambda item: item.quality,
            require_available=True,
        )
        == {}
    )

    available = canary.projections[0].quality
    corrupt_available = replace(available)
    object.__setattr__(corrupt_available, "value", None)
    left = SimpleNamespace(quality=available, scenario_id="scenario")
    right = SimpleNamespace(quality=corrupt_available, scenario_id="scenario")
    assert (
        analysis._group_pairs(
            [(left, right)],
            lambda item: item.quality,
            require_available=True,
        )
        == {}
    )

    assert analysis._pareto_class(1.0, 1.0, 1.0, 1.0) == "tie"
    assert analysis._pareto_class(1.0, 0.5, 1.0, 2.0) == "left_dominates"
    assert analysis._pareto_class(0.5, 1.0, 2.0, 1.0) == "right_dominates"
    assert analysis._pareto_class(1.0, 0.5, 2.0, 1.0) == "tradeoff"


def test_empty_summaries_preserve_missingness() -> None:
    observation = analysis._observation_summary([])
    assert observation["coverage"] is None
    assert observation["mean"] is None

    quality = analysis._quality_summary([], [])
    assert quality["verified_f1_mean"] is None
    assert quality["verified_recall"]["coverage"] is None


def test_context_declaration_and_numeric_helper_boundaries(
    canary: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system_ids = canary.plan.system_ids
    assert analysis._system_declarations({"systems": "invalid"}, system_ids) == {}
    assert analysis._system_declarations({"systems": [object()]}, system_ids) == {}
    assert (
        analysis._system_declarations(
            {
                "systems": [
                    {"system_id": system_ids[0]},
                    {"system_id": system_ids[0]},
                ]
            },
            system_ids,
        )
        == {}
    )

    attestation = {
        "efficiency_track_id": canary.plan.efficiency_track_id,
        "plan_digest": canary.plan.digest,
        "plan_id": canary.plan.plan_id,
        "source_analysis_plan_digest": canary.plan.source_analysis_plan_digest,
        "source_track_id": canary.plan.source_track_id,
    }
    assert (
        analysis._campaign_attestation_matches(
            canary.plan,
            {
                "campaign": "invalid",
                "efficiency_plan_attestation": attestation,
            },
        )
        is False
    )

    with pytest.raises(BenchmarkV4SchemaError, match="invalid_efficiency_campaign_context"):
        analysis._campaign_context([])  # type: ignore[arg-type]
    with pytest.raises(BenchmarkV4SchemaError, match="invalid_efficiency_campaign_context"):
        analysis._campaign_context({"unsupported": object()})
    with monkeypatch.context() as context:
        context.setattr(analysis, "canonical_json", lambda _value: "x" * 8_000_001)
        with pytest.raises(BenchmarkV4SchemaError, match="efficiency_campaign_context_too_large"):
            analysis._campaign_context({})

    with pytest.raises(BenchmarkV4SchemaError, match="percentile_requires_values"):
        analysis._percentile([], 0.5)
    assert analysis._percentile([3.0], 0.5) == 3.0
    with pytest.raises(BenchmarkV4SchemaError, match="invalid:test_digest"):
        analysis._require_digest("not-a-digest", "test_digest")
