"""Deterministic efficiency projections and statistics for Benchmark v4."""

from __future__ import annotations

import math
import random
import statistics
import threading
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from typing import Any, Literal, cast

from ..v3.analysis import AnalysisPlan, analyze_runs, wilson_interval
from ..v3.ledger import LedgerEntry, verify_ledger_entries
from ..v3.schema import BenchmarkRunV3, canonical_json, stable_digest
from .schema import (
    ALL_RESOURCES,
    EFFICIENCY_STATISTICS_SCHEMA_VERSION,
    MAX_BOOTSTRAP_SAMPLES,
    PRIMARY_RESOURCES,
    QUALITY_METRIC,
    RESOURCE_UNITS,
    SECONDARY_RESOURCES,
    BenchmarkV4SchemaError,
    EfficiencyPlan,
    EfficiencyRunProjection,
    ResourceObservation,
)

_BUDGET_BY_RESOURCE = {
    "api_cost_usd": "max_cost_usd",
    "model_tokens": "max_model_tokens",
    "output_bytes": "max_output_bytes",
    "tool_calls": "max_tools",
}
_SUMMARY_KEYS = frozenset(
    {
        "entry_count",
        "evidence_bearing_request_count",
        "repeated_request_count",
        "unique_target_count",
        "unsuccessful_request_count",
    }
)
_VALIDATED_SCHEDULE_CACHE: set[str] = set()
_VALIDATED_SCHEDULE_CACHE_LOCK = threading.Lock()
_MAX_VALIDATED_SCHEDULES = 8


def extract_efficiency_runs(
    plan: EfficiencyPlan,
    source_analysis_plan: AnalysisPlan,
    runs: Sequence[BenchmarkRunV3],
    controller_ledgers: Sequence[Mapping[str, Any]],
) -> tuple[EfficiencyRunProjection, ...]:
    """Validate v3 evidence and project controller-owned resource observations."""

    items = tuple(runs)
    _validate_source_plan(plan, source_analysis_plan)
    # This is deliberately a validation call.  Its aggregate is not published
    # because a verified publisher may supply compact runs without action rows.
    _validate_v3_schedule_once(source_analysis_plan, items)
    by_key = {(run.scenario_id, run.repetition, run.matched_fixture_seed, run.system_id): run for run in items}
    if len(by_key) != len(items):
        raise BenchmarkV4SchemaError("duplicate_efficiency_source_run")
    expected_keys = _scheduled_run_keys(plan)
    if set(by_key) != set(expected_keys):
        raise BenchmarkV4SchemaError("efficiency_runs_do_not_match_frozen_schedule")
    if plan.require_run_attestation and any(
        str(run.environment.get("efficiency_plan_digest") or "") != plan.digest for run in items
    ):
        raise BenchmarkV4SchemaError("run_missing_efficiency_plan_attestation")

    ledger_by_run = _index_ledgers(items, controller_ledgers)
    projections: list[EfficiencyRunProjection] = []
    for key in expected_keys:
        run = by_key[key]
        ledger_summary = _validated_ledger_summary(run, ledger_by_run[run.run_id])
        quality = _verified_f1(run)
        resources: dict[str, ResourceObservation] = {
            "wall_time_seconds": ResourceObservation(
                name="wall_time_seconds",
                available=True,
                reliability="measured",
                source="controller_runner",
                unit=RESOURCE_UNITS["wall_time_seconds"],
                value=float(run.duration_seconds),
            ),
            "fixture_http_requests": _ledger_observation("fixture_http_requests", ledger_summary["entry_count"]),
            "unique_fixture_targets": _ledger_observation(
                "unique_fixture_targets", ledger_summary["unique_target_count"]
            ),
            "repeated_fixture_requests": _ledger_observation(
                "repeated_fixture_requests", ledger_summary["repeated_request_count"]
            ),
            "unsuccessful_fixture_requests": _ledger_observation(
                "unsuccessful_fixture_requests", ledger_summary["unsuccessful_request_count"]
            ),
            "evidence_bearing_requests": _ledger_observation(
                "evidence_bearing_requests", ledger_summary["evidence_bearing_request_count"]
            ),
        }
        for resource_name in ("tool_calls", "output_bytes", "model_tokens", "api_cost_usd"):
            resources[resource_name] = _budget_observation(run, resource_name)
        projections.append(
            EfficiencyRunProjection(
                run_id=run.run_id,
                efficiency_track_id=plan.efficiency_track_id,
                source_track_id=run.track_id,
                system_id=run.system_id,
                scenario_id=run.scenario_id,
                repetition=run.repetition,
                matched_fixture_seed=run.matched_fixture_seed,
                execution_status=run.execution_status,
                task_status=run.task_status,
                started_at=float(run.started_at),
                finished_at=float(run.finished_at),
                batch_id=str(run.environment.get("batch_id") or ""),
                host_id=str(run.environment.get("host_id") or ""),
                efficiency_plan_attested=(str(run.environment.get("efficiency_plan_digest") or "") == plan.digest),
                quality=quality,
                resources=resources,
            )
        )
    return tuple(projections)


def hierarchical_paired_bootstrap(
    paired_by_scenario: Mapping[str, Sequence[tuple[float, float]]],
    *,
    estimand: Literal["difference", "geometric_ratio"] = "difference",
    samples: int = 10_000,
    alpha: float = 0.05,
    seed: int = 1,
) -> dict[str, Any]:
    """Resample scenarios, then matched blocks, with equal scenario weight."""

    if (
        isinstance(samples, bool)
        or not isinstance(samples, int)
        or not 100 <= samples <= MAX_BOOTSTRAP_SAMPLES
        or isinstance(alpha, bool)
        or not isinstance(alpha, (int, float))
        or not math.isfinite(alpha)
        or not 0.0 < alpha < 1.0
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or seed < 0
    ):
        raise BenchmarkV4SchemaError("invalid_hierarchical_bootstrap_design")
    if estimand not in {"difference", "geometric_ratio"}:
        raise BenchmarkV4SchemaError("invalid_hierarchical_bootstrap_estimand")
    groups: dict[str, tuple[tuple[float, float], ...]] = {}
    for scenario_id, raw_pairs in sorted(paired_by_scenario.items()):
        pairs = tuple((float(left), float(right)) for left, right in raw_pairs)
        if not pairs:
            continue
        if any(not math.isfinite(value) for pair in pairs for value in pair):
            raise BenchmarkV4SchemaError("nonfinite_hierarchical_bootstrap_value")
        if estimand == "geometric_ratio" and any(value <= 0 for pair in pairs for value in pair):
            raise BenchmarkV4SchemaError("nonpositive_geometric_ratio_value")
        groups[str(scenario_id)] = pairs
    if not groups:
        return {"available": False, "reason": "no_eligible_pairs", "sample_size": 0, "scenario_count": 0}

    scenario_ids = tuple(sorted(groups))

    def pair_effect(pair: tuple[float, float]) -> float:
        left, right = pair
        return math.log(right / left) if estimand == "geometric_ratio" else right - left

    scenario_points = {
        scenario_id: statistics.fmean(pair_effect(pair) for pair in groups[scenario_id]) for scenario_id in scenario_ids
    }
    point = statistics.fmean(scenario_points.values())
    rng = random.Random(seed)
    sampled_effects: list[float] = []
    for _ in range(samples):
        selected_scenarios = [scenario_ids[rng.randrange(len(scenario_ids))] for _ in scenario_ids]
        scenario_effects: list[float] = []
        for scenario_id in selected_scenarios:
            pairs = groups[scenario_id]
            scenario_effects.append(statistics.fmean(pair_effect(pairs[rng.randrange(len(pairs))]) for _ in pairs))
        sampled_effects.append(statistics.fmean(scenario_effects))
    sampled_effects.sort()
    lower = _percentile(sampled_effects, alpha / 2.0)
    upper = _percentile(sampled_effects, 1.0 - alpha / 2.0)
    if estimand == "geometric_ratio":
        estimate, lower, upper = math.exp(point), math.exp(lower), math.exp(upper)
        named = {"geometric_mean_ratio_right_over_left": _round(estimate)}
    else:
        estimate = point
        named = {"effect_right_minus_left": _round(estimate)}
    return {
        "alpha": alpha,
        "available": True,
        "bootstrap_samples": samples,
        "estimate": _round(estimate),
        "estimand": estimand,
        "lower": _round(lower),
        "sample_size": sum(len(pairs) for pairs in groups.values()),
        "scenario_count": len(groups),
        "scenario_estimates": {
            scenario_id: _round(math.exp(value) if estimand == "geometric_ratio" else value)
            for scenario_id, value in sorted(scenario_points.items())
        },
        "upper": _round(upper),
        **named,
    }


def analyze_efficiency(
    plan: EfficiencyPlan,
    source_analysis_plan: AnalysisPlan,
    runs: Sequence[BenchmarkRunV3],
    controller_ledgers: Sequence[Mapping[str, Any]],
    campaign_context: Mapping[str, Any],
) -> dict[str, Any]:
    """Produce honest, quality-gated efficiency statistics without a winner."""

    items = tuple(runs)
    projections = extract_efficiency_runs(plan, source_analysis_plan, items, controller_ledgers)
    context = _campaign_context(campaign_context)
    fairness = _fairness_assessment(plan, items, projections, context)
    by_run_id = {run.run_id: run for run in items}
    by_system: dict[str, list[EfficiencyRunProjection]] = defaultdict(list)
    for projection in projections:
        by_system[projection.system_id].append(projection)
    systems = {
        system_id: _system_statistics(
            by_system[system_id],
            [by_run_id[item.run_id] for item in by_system[system_id]],
            plan,
        )
        for system_id in plan.system_ids
    }
    comparisons = [
        _comparison_statistics(plan, projections, left_id, right_id, fairness, comparison_index)
        for comparison_index, (left_id, right_id) in enumerate(plan.comparison_pairs)
    ]
    paired_effects = [
        effect for comparison in comparisons for effect in cast(Sequence[dict[str, Any]], comparison["paired_effects"])
    ]
    fairness["primary_metric_gates"] = {
        _comparison_key(str(item["left_system_id"]), str(item["right_system_id"])): item["primary_metric_gates"]
        for item in comparisons
    }
    fairness["eligible"] = bool(
        fairness["base_eligible"]
        and all(
            gate["passed"]
            for comparison in comparisons
            for gate in cast(Mapping[str, Mapping[str, Any]], comparison["primary_metric_gates"]).values()
        )
    )
    return {
        "automatic_winner": False,
        "comparisons": comparisons,
        "efficiency_plan_digest": plan.digest,
        "efficiency_plan_id": plan.plan_id,
        "efficiency_track_id": plan.efficiency_track_id,
        "fairness": fairness,
        "paired_effects": paired_effects,
        "run_count": len(projections),
        "schema_version": EFFICIENCY_STATISTICS_SCHEMA_VERSION,
        "source_analysis_plan_digest": source_analysis_plan.digest,
        "source_v3_validation": {
            "analysis_plan_digest": source_analysis_plan.digest,
            "analysis_plan_id": source_analysis_plan.plan_id,
            "run_count": len(items),
            "schedule_validated": True,
        },
        "systems": systems,
    }


def _validate_source_plan(plan: EfficiencyPlan, source: AnalysisPlan) -> None:
    if not isinstance(plan, EfficiencyPlan) or not isinstance(source, AnalysisPlan):
        raise BenchmarkV4SchemaError("efficiency_analysis_requires_frozen_plans")
    if plan.source_analysis_plan_digest != source.digest:
        raise BenchmarkV4SchemaError("source_analysis_plan_digest_mismatch")
    if plan.source_track_id != source.track_id:
        raise BenchmarkV4SchemaError("source_analysis_track_mismatch")
    if (
        plan.system_ids != source.system_ids
        or plan.scenario_ids != source.scenario_ids
        or plan.repetitions != source.repetitions
        or plan.comparison_pairs != source.comparison_pairs
    ):
        raise BenchmarkV4SchemaError("efficiency_plan_source_design_mismatch")
    if plan.publication_tier != "diagnostic" and plan.publication_tier != source.publication_tier:
        raise BenchmarkV4SchemaError("efficiency_source_publication_tier_mismatch")
    observed = {(block.scenario_id, block.repetition): block.matched_fixture_seed for block in plan.schedule}
    expected = {
        (scenario_id, repetition): source.fixture_seeds[scenario_id][repetition - 1]
        for scenario_id in source.scenario_ids
        for repetition in range(1, source.repetitions + 1)
    }
    if observed != expected:
        raise BenchmarkV4SchemaError("efficiency_schedule_source_seed_mismatch")


def _validate_v3_schedule_once(source: AnalysisPlan, runs: Sequence[BenchmarkRunV3]) -> None:
    """Memoize exact immutable schedule validation, never v3 aggregate output."""

    # A cache hit stands for a complete ``analyze_runs`` validation, so bind
    # it to the complete canonical run payload rather than only schedule keys.
    fingerprint = stable_digest(
        {
            "analysis_plan_digest": source.digest,
            "runs": [run.to_dict() for run in runs],
            "validator": "benchmark-v3-analyze-runs",
        }
    )
    with _VALIDATED_SCHEDULE_CACHE_LOCK:
        if fingerprint in _VALIDATED_SCHEDULE_CACHE:
            return
    analyze_runs(source, runs)
    with _VALIDATED_SCHEDULE_CACHE_LOCK:
        if len(_VALIDATED_SCHEDULE_CACHE) >= _MAX_VALIDATED_SCHEDULES:
            _VALIDATED_SCHEDULE_CACHE.remove(min(_VALIDATED_SCHEDULE_CACHE))
        _VALIDATED_SCHEDULE_CACHE.add(fingerprint)


def _scheduled_run_keys(plan: EfficiencyPlan) -> tuple[tuple[str, int, int, str], ...]:
    return tuple(
        (block.scenario_id, block.repetition, block.matched_fixture_seed, system_id)
        for block in plan.schedule
        for system_id in block.system_order
    )


def _index_ledgers(
    runs: Sequence[BenchmarkRunV3],
    records: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        raise BenchmarkV4SchemaError("invalid_efficiency_controller_ledgers")
    indexed: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise BenchmarkV4SchemaError("invalid_efficiency_controller_ledgers")
        run_id = str(record.get("run_id") or "")
        if not run_id or run_id in indexed:
            raise BenchmarkV4SchemaError("duplicate_efficiency_controller_ledger")
        indexed[run_id] = record
    expected = {run.run_id for run in runs}
    if set(indexed) != expected:
        raise BenchmarkV4SchemaError("efficiency_ledger_run_coverage_mismatch")
    return indexed


def _validated_ledger_summary(
    run: BenchmarkRunV3,
    record: Mapping[str, Any],
) -> dict[str, int]:
    if (
        record.get("schema_version") != "1.0"
        or record.get("run_id") != run.run_id
        or record.get("system_id") != run.system_id
        or record.get("scenario_id") != run.scenario_id
        or record.get("repetition") != run.repetition
        or record.get("matched_fixture_seed") != run.matched_fixture_seed
        or record.get("fixture_variant_digest") != run.fixture_variant_digest
    ):
        raise BenchmarkV4SchemaError("efficiency_ledger_run_mismatch")
    raw_entries = record.get("entries")
    raw_summary = record.get("efficiency_summary")
    has_entries = raw_entries is not None
    has_summary = raw_summary is not None
    if not has_entries and not has_summary:
        raise BenchmarkV4SchemaError("efficiency_ledger_measurements_missing")
    computed: dict[str, int] | None = None
    root_digest = str(record.get("ledger_root_digest") or "")
    if has_entries:
        if not isinstance(raw_entries, Sequence) or isinstance(raw_entries, (str, bytes, bytearray)):
            raise BenchmarkV4SchemaError("invalid_efficiency_ledger_entries")
        entries = verify_ledger_entries(
            cast(Sequence[Mapping[str, Any]], raw_entries),
            variant_digest=run.fixture_variant_digest,
        )
        computed = _summary_from_entries(entries)
        expected_root = entries[-1].entry_digest if entries else "0" * 64
        if root_digest != expected_root:
            raise BenchmarkV4SchemaError("efficiency_ledger_root_mismatch")
    if has_summary:
        summary = _compact_summary(raw_summary)
        if computed is not None and summary != computed:
            raise BenchmarkV4SchemaError("efficiency_ledger_summary_mismatch")
        computed = summary
    if computed is None:
        raise BenchmarkV4SchemaError("efficiency_ledger_measurements_missing")
    _require_digest(root_digest, "efficiency_ledger_root_digest")
    if f"sha256:{root_digest}" not in run.artifact_refs:
        raise BenchmarkV4SchemaError("efficiency_ledger_root_not_attested")
    declared_count = run.environment.get("controller_ledger_entries")
    if isinstance(declared_count, bool) or not isinstance(declared_count, int):
        raise BenchmarkV4SchemaError("invalid_controller_ledger_entry_count")
    if declared_count != computed["entry_count"]:
        raise BenchmarkV4SchemaError("efficiency_ledger_entry_count_mismatch")
    return computed


def _summary_from_entries(entries: Sequence[LedgerEntry]) -> dict[str, int]:
    unique_targets = {(entry.method, entry.target_digest) for entry in entries}
    return {
        "entry_count": len(entries),
        "evidence_bearing_request_count": sum(bool(entry.evidence_ids) for entry in entries),
        "repeated_request_count": len(entries) - len(unique_targets),
        "unique_target_count": len(unique_targets),
        "unsuccessful_request_count": sum(entry.status >= 400 for entry in entries),
    }


def _compact_summary(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != _SUMMARY_KEYS:
        raise BenchmarkV4SchemaError("invalid_efficiency_ledger_summary")
    summary: dict[str, int] = {}
    for name in sorted(_SUMMARY_KEYS):
        raw = value.get(name)
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise BenchmarkV4SchemaError("invalid_efficiency_ledger_summary")
        summary[name] = raw
    count = summary["entry_count"]
    if (
        summary["unique_target_count"] > count
        or summary["repeated_request_count"] != count - summary["unique_target_count"]
        or summary["unsuccessful_request_count"] > count
        or summary["evidence_bearing_request_count"] > count
    ):
        raise BenchmarkV4SchemaError("invalid_efficiency_ledger_summary")
    return summary


def _ledger_observation(name: str, value: int) -> ResourceObservation:
    return ResourceObservation(
        name=name,
        available=True,
        reliability="verified",
        source="controller_ledger",
        unit=RESOURCE_UNITS[name],
        value=float(value),
    )


def _budget_observation(run: BenchmarkRunV3, resource_name: str) -> ResourceObservation:
    budget_name = _BUDGET_BY_RESOURCE[resource_name]
    record = next((item for item in run.budget_enforcement if item.budget_name == budget_name), None)
    if record is None:
        return ResourceObservation.unavailable(
            resource_name,
            source="budget_enforcement",
            unit=RESOURCE_UNITS[resource_name],
            reason="budget_observation_not_recorded",
        )
    if record.measured is None:
        return ResourceObservation.unavailable(
            resource_name,
            source="budget_enforcement",
            unit=RESOURCE_UNITS[resource_name],
            reason="budget_measurement_unavailable",
        )
    return ResourceObservation(
        name=resource_name,
        available=True,
        reliability="measured" if record.reliable else "self_reported",
        source="budget_enforcement",
        unit=RESOURCE_UNITS[resource_name],
        value=float(record.measured),
        reason="" if record.reliable else "not_independently_verified",
    )


def _verified_f1(run: BenchmarkRunV3) -> ResourceObservation:
    recall = run.evaluation.metric("verified_recall", "all_scheduled")
    precision = run.evaluation.metric("verified_claim_precision", "all_scheduled")
    if not recall.available or not precision.available or recall.value is None or precision.value is None:
        return ResourceObservation.unavailable(
            QUALITY_METRIC,
            source="sealed_evaluator_v3",
            unit=RESOURCE_UNITS[QUALITY_METRIC],
            reason="verified_quality_components_unavailable",
        )
    denominator = float(recall.value) + float(precision.value)
    value = 0.0 if denominator == 0.0 else 2.0 * float(recall.value) * float(precision.value) / denominator
    return ResourceObservation(
        name=QUALITY_METRIC,
        available=True,
        reliability="derived",
        source="sealed_evaluator_v3",
        unit=RESOURCE_UNITS[QUALITY_METRIC],
        value=value,
    )


def _system_statistics(
    projections: Sequence[EfficiencyRunProjection],
    runs: Sequence[BenchmarkRunV3],
    plan: EfficiencyPlan,
) -> dict[str, Any]:
    execution_successes = sum(item.execution_status == "succeeded" for item in projections)
    completions = sum(item.task_status == "completed" for item in projections)
    resources = {name: _observation_summary([item.resources[name] for item in projections]) for name in ALL_RESOURCES}
    quality = _quality_summary(projections, runs)
    return {
        "completed_yield_per_resource": {name: _yield_summary(projections, name) for name in ALL_RESOURCES},
        "quality": quality,
        "resources": resources,
        "run_count": len(projections),
        "scenarios": {
            scenario_id: {
                "quality": _quality_summary(
                    [item for item in projections if item.scenario_id == scenario_id],
                    [run for run in runs if run.scenario_id == scenario_id],
                ),
                "resources": {
                    name: _observation_summary(
                        [item.resources[name] for item in projections if item.scenario_id == scenario_id]
                    )
                    for name in ALL_RESOURCES
                },
                "run_count": sum(item.scenario_id == scenario_id for item in projections),
            }
            for scenario_id in plan.scenario_ids
        },
        "stability": {
            "execution_outcome_counts": dict(sorted(Counter(item.execution_status for item in projections).items())),
            "execution_success_rate": _round(execution_successes / len(projections)),
            "execution_success_wilson": wilson_interval(execution_successes, len(projections), alpha=plan.alpha),
            "task_completion_rate": _round(completions / len(projections)),
            "task_completion_wilson": wilson_interval(completions, len(projections), alpha=plan.alpha),
            "task_outcome_counts": dict(sorted(Counter(item.task_status for item in projections).items())),
        },
    }


def _quality_summary(
    projections: Sequence[EfficiencyRunProjection],
    runs: Sequence[BenchmarkRunV3],
) -> dict[str, Any]:
    f1 = _observation_summary([item.quality for item in projections])
    components: dict[str, Any] = {}
    for metric_name in ("verified_recall", "verified_claim_precision"):
        observations = [run.evaluation.metric(metric_name, "all_scheduled") for run in runs]
        values = [float(item.value) for item in observations if item.available and item.value is not None]
        components[metric_name] = {
            "available": len(values),
            "coverage": _round(len(values) / len(observations)) if observations else None,
            "mean": _round(statistics.fmean(values)) if values else None,
            "median": _round(statistics.median(values)) if values else None,
            "scheduled": len(observations),
        }
    return {
        "verified_claim_precision": components["verified_claim_precision"],
        "verified_f1": f1,
        "verified_f1_availability": f1["available"],
        "verified_f1_mean": f1["mean"],
        "verified_f1_median": f1["median"],
        "verified_recall": components["verified_recall"],
    }


def _observation_summary(observations: Sequence[ResourceObservation]) -> dict[str, Any]:
    available = [item for item in observations if item.available and item.value is not None]
    values = [float(item.value) for item in available if item.value is not None]
    return {
        "available": len(available),
        "coverage": _round(len(available) / len(observations)) if observations else None,
        "maximum": _round(max(values)) if values else None,
        "mean": _round(statistics.fmean(values)) if values else None,
        "median": _round(statistics.median(values)) if values else None,
        "minimum": _round(min(values)) if values else None,
        "reliability_counts": dict(sorted(Counter(item.reliability for item in observations).items())),
        "scheduled": len(observations),
        "total": _round(sum(values)) if values else None,
    }


def _yield_summary(projections: Sequence[EfficiencyRunProjection], resource_name: str) -> dict[str, Any]:
    usable = [
        item
        for item in projections
        if item.resources[resource_name].available and item.resources[resource_name].value is not None
    ]
    denominator = sum(float(item.resources[resource_name].value or 0.0) for item in usable)
    quality_items = [item for item in usable if item.quality.available and item.quality.value is not None]
    return {
        "available": denominator > 0,
        "completed_tasks_per_unit": (
            _round(sum(item.task_status == "completed" for item in usable) / denominator) if denominator > 0 else None
        ),
        "reason": "" if denominator > 0 else "no_positive_resource_observations",
        "resource_total": _round(denominator) if denominator > 0 else None,
        "run_count": len(usable),
        "verified_f1_per_unit": (
            _round(sum(float(item.quality.value or 0.0) for item in quality_items) / denominator)
            if denominator > 0 and len(quality_items) == len(usable)
            else None
        ),
    }


def _comparison_statistics(
    plan: EfficiencyPlan,
    projections: Sequence[EfficiencyRunProjection],
    left_id: str,
    right_id: str,
    fairness: Mapping[str, Any],
    comparison_index: int,
) -> dict[str, Any]:
    indexed = {
        (item.system_id, item.scenario_id, item.repetition, item.matched_fixture_seed): item for item in projections
    }
    paired = [
        (
            indexed[(left_id, block.scenario_id, block.repetition, block.matched_fixture_seed)],
            indexed[(right_id, block.scenario_id, block.repetition, block.matched_fixture_seed)],
        )
        for block in plan.schedule
    ]
    family_size = len(plan.comparison_pairs) * len(PRIMARY_RESOURCES)
    claim_alpha = plan.alpha / family_size
    completion_pairs = _group_pairs(
        paired,
        lambda item: 1.0 if item.task_status == "completed" else 0.0,
        require_available=False,
    )
    quality_pairs = _group_pairs(paired, lambda item: item.quality, require_available=True)
    jointly_completed = [(left, right) for left, right in paired if _both_completed(left, right)]
    paired_quality_pairs = _group_pairs(jointly_completed, lambda item: item.quality, require_available=True)
    completion_effect = hierarchical_paired_bootstrap(
        completion_pairs,
        samples=plan.bootstrap_samples,
        alpha=claim_alpha,
        seed=_stream_seed(plan, comparison_index, "completion"),
    )
    quality_effect = hierarchical_paired_bootstrap(
        quality_pairs,
        samples=plan.bootstrap_samples,
        alpha=claim_alpha,
        seed=_stream_seed(plan, comparison_index, "quality"),
    )
    paired_quality_effect = hierarchical_paired_bootstrap(
        paired_quality_pairs,
        samples=plan.bootstrap_samples,
        alpha=claim_alpha,
        seed=_stream_seed(plan, comparison_index, "paired-quality"),
    )
    noninferiority = {
        "task_completion_rate": _noninferiority_gate(completion_effect, plan.completion_noninferiority_margin),
        "verified_f1": _noninferiority_gate(quality_effect, plan.noninferiority_margin),
        "verified_f1_both_completed": _noninferiority_gate(paired_quality_effect, plan.noninferiority_margin),
    }
    primary_metric_gates: dict[str, Any] = {}
    paired_effects: list[dict[str, Any]] = []
    resource_details: dict[str, Any] = {}
    for resource_index, resource_name in enumerate(ALL_RESOURCES):
        detail = _resource_effect(
            plan,
            paired,
            left_id,
            right_id,
            resource_name,
            comparison_index,
            resource_index,
            claim_alpha,
            fairness,
            noninferiority,
        )
        resource_details[resource_name] = detail
        paired_effects.append(detail["effect_projection"])
        if resource_name in PRIMARY_RESOURCES:
            coverage_gate = cast(Mapping[str, Any], detail["coverage_gate"])
            population_gate = cast(Mapping[str, Any], detail["claim_population_gate"])
            primary_metric_gates[resource_name] = {
                "claim_population": dict(population_gate),
                "measurement_coverage": dict(coverage_gate),
                "passed": bool(coverage_gate["passed"] and population_gate["passed"]),
            }
    return {
        "all_scheduled_noninferiority": noninferiority,
        "left_system_id": left_id,
        "multiple_testing": {
            "claim_alpha": claim_alpha,
            "family_size": family_size,
            "method": "bonferroni_comparison_pairs_x_primary_resources",
            "nominal_alpha": plan.alpha,
        },
        "paired_effects": paired_effects,
        "primary_metric_gates": primary_metric_gates,
        "resources": resource_details,
        "right_system_id": right_id,
        "scheduled_pair_count": len(paired),
    }


def _resource_effect(
    plan: EfficiencyPlan,
    paired: Sequence[tuple[EfficiencyRunProjection, EfficiencyRunProjection]],
    left_id: str,
    right_id: str,
    resource_name: str,
    comparison_index: int,
    resource_index: int,
    claim_alpha: float,
    fairness: Mapping[str, Any],
    noninferiority: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    ratio_by_scenario: dict[str, list[tuple[float, float]]] = defaultdict(list)
    qpr_by_scenario: dict[str, list[tuple[float, float]]] = defaultdict(list)
    pareto = Counter({"left_dominates": 0, "right_dominates": 0, "tie": 0, "tradeoff": 0})
    exclusions: Counter[str] = Counter()
    jointly_completed_count = 0
    resource_available_count = 0
    measurement_pair_count = 0
    for left, right in paired:
        left_measurement = left.resources[resource_name]
        right_measurement = right.resources[resource_name]
        if left_measurement.available and right_measurement.available:
            measurement_pair_count += 1
        if not _both_completed(left, right):
            if left.task_status != "completed" and right.task_status != "completed":
                exclusions["both_tasks_not_completed"] += 1
            elif left.task_status != "completed":
                exclusions["left_task_not_completed"] += 1
            else:
                exclusions["right_task_not_completed"] += 1
            continue
        jointly_completed_count += 1
        left_resource = left.resources[resource_name]
        right_resource = right.resources[resource_name]
        if not left_resource.available or not right_resource.available:
            exclusions["resource_unavailable"] += 1
            continue
        if left_resource.value is None or right_resource.value is None:
            raise BenchmarkV4SchemaError("available_resource_missing_value")
        resource_available_count += 1
        if left.quality.available and right.quality.available:
            if left.quality.value is None or right.quality.value is None:
                raise BenchmarkV4SchemaError("available_quality_missing_value")
            pareto[
                _pareto_class(
                    float(left.quality.value),
                    float(right.quality.value),
                    float(left_resource.value),
                    float(right_resource.value),
                )
            ] += 1
        else:
            exclusions["quality_unavailable"] += 1
            continue
        if float(left_resource.value) <= 0 or float(right_resource.value) <= 0:
            exclusions["nonpositive_resource"] += 1
            continue
        scenario_id = left.scenario_id
        ratio_by_scenario[scenario_id].append((float(left_resource.value), float(right_resource.value)))
        qpr_by_scenario[scenario_id].append(
            (
                float(left.quality.value) / float(left_resource.value),
                float(right.quality.value) / float(right_resource.value),
            )
        )
    ratio = hierarchical_paired_bootstrap(
        ratio_by_scenario,
        estimand="geometric_ratio",
        samples=plan.bootstrap_samples,
        alpha=claim_alpha,
        seed=_stream_seed(plan, comparison_index, f"ratio:{resource_index}:{resource_name}"),
    )
    quality_per_resource = hierarchical_paired_bootstrap(
        qpr_by_scenario,
        estimand="difference",
        samples=plan.bootstrap_samples,
        alpha=claim_alpha,
        seed=_stream_seed(plan, comparison_index, f"qpr:{resource_index}:{resource_name}"),
    )
    eligible_pairs = sum(len(values) for values in qpr_by_scenario.values())
    coverage = measurement_pair_count / len(paired) if paired else 0.0
    required_coverage = plan.coverage_gates.get(resource_name) if resource_name in PRIMARY_RESOURCES else None
    coverage_gate = {
        "eligible_pair_count": eligible_pairs,
        "measurement_pair_count": measurement_pair_count,
        "observed": _round(coverage),
        "passed": bool(required_coverage is not None and coverage >= required_coverage),
        "required": required_coverage,
        "scheduled_pair_count": len(paired),
    }
    ratio_scenario_ids = tuple(sorted(ratio_by_scenario))
    qpr_scenario_ids = tuple(sorted(qpr_by_scenario))
    required_scenario_ids = tuple(plan.scenario_ids)
    all_scheduled_pairs_eligible = eligible_pairs == jointly_completed_count == len(paired)
    exact_scenario_coverage = set(ratio_scenario_ids) == set(required_scenario_ids) and set(qpr_scenario_ids) == set(
        required_scenario_ids
    )
    claim_population_gate = {
        "all_scheduled_pairs_eligible": all_scheduled_pairs_eligible,
        "eligible_pair_count": eligible_pairs,
        "eligible_pair_coverage": _round(eligible_pairs / len(paired)) if paired else 0.0,
        "exact_scenario_coverage": exact_scenario_coverage,
        "jointly_completed_pair_count": jointly_completed_count,
        "passed": all_scheduled_pairs_eligible and exact_scenario_coverage,
        "quality_per_resource_scenario_ids": list(qpr_scenario_ids),
        "required_scenario_ids": list(required_scenario_ids),
        "resource_ratio_scenario_ids": list(ratio_scenario_ids),
        "scheduled_pair_count": len(paired),
    }
    base = bool(fairness.get("base_eligible")) and coverage_gate["passed"]
    completion_gate = noninferiority["task_completion_rate"]
    quality_gate = noninferiority["verified_f1"]
    paired_quality_gate = noninferiority["verified_f1_both_completed"]
    ratio_available = bool(ratio.get("available"))
    qpr_available = bool(quality_per_resource.get("available"))
    all_scheduled_quality_complete = quality_gate["effect"].get("sample_size") == len(paired)
    completed_quality_complete = paired_quality_gate["effect"].get("sample_size") == jointly_completed_count
    right_supported = bool(
        resource_name in PRIMARY_RESOURCES
        and base
        and all_scheduled_quality_complete
        and completed_quality_complete
        and claim_population_gate["passed"]
        and completion_gate["right_noninferior"]
        and quality_gate["right_noninferior"]
        and paired_quality_gate["right_noninferior"]
        and ratio_available
        and qpr_available
        and cast(float, ratio.get("upper")) < 1.0
        and cast(float, quality_per_resource.get("lower")) > 0.0
    )
    left_supported = bool(
        resource_name in PRIMARY_RESOURCES
        and base
        and all_scheduled_quality_complete
        and completed_quality_complete
        and claim_population_gate["passed"]
        and completion_gate["left_noninferior"]
        and quality_gate["left_noninferior"]
        and paired_quality_gate["left_noninferior"]
        and ratio_available
        and qpr_available
        and cast(float, ratio.get("lower")) > 1.0
        and cast(float, quality_per_resource.get("upper")) < 0.0
    )
    directional_claim = (
        "right_more_efficient"
        if right_supported
        else "left_more_efficient"
        if left_supported
        else "secondary_descriptive_only"
        if resource_name in SECONDARY_RESOURCES
        else "inconclusive"
    )
    effect_projection = {
        "directional_claim": directional_claim,
        "left_system_id": left_id,
        "quality_qualified_pairs": eligible_pairs,
        "resource": resource_name,
        "right_system_id": right_id,
    }
    return {
        "claim_population_gate": claim_population_gate,
        "coverage_gate": coverage_gate,
        "directional_claims": {
            "automatic_winner": False,
            "claim_eligible_resource": resource_name in PRIMARY_RESOURCES,
            "left_more_efficient": left_supported,
            "result": directional_claim,
            "right_more_efficient": right_supported,
        },
        "effect_projection": effect_projection,
        "exclusions": {
            "excluded_pair_count": len(paired) - eligible_pairs,
            "reason_counts": dict(sorted(exclusions.items())),
        },
        "jointly_completed_pair_count": jointly_completed_count,
        "pareto_counts": dict(sorted(pareto.items())),
        "population": "both_task_status_completed",
        "quality_per_resource_delta": quality_per_resource,
        "resource_available_pair_count": resource_available_count,
        "resource_ratio": ratio,
        "scheduled_pair_count": len(paired),
    }


def _noninferiority_gate(effect: Mapping[str, Any], margin: float) -> dict[str, Any]:
    available = bool(effect.get("available"))
    lower = effect.get("lower")
    upper = effect.get("upper")
    return {
        "effect": dict(effect),
        "left_noninferior": bool(available and isinstance(upper, (int, float)) and upper <= margin),
        "margin": margin,
        "right_noninferior": bool(available and isinstance(lower, (int, float)) and lower >= -margin),
    }


def _group_pairs(
    paired: Sequence[tuple[EfficiencyRunProjection, EfficiencyRunProjection]],
    extractor: Any,
    *,
    require_available: bool,
) -> dict[str, list[tuple[float, float]]]:
    grouped: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for left, right in paired:
        left_value = extractor(left)
        right_value = extractor(right)
        if require_available:
            if not isinstance(left_value, ResourceObservation) or not isinstance(right_value, ResourceObservation):
                raise BenchmarkV4SchemaError("invalid_quality_pair_projection")
            if (
                not left_value.available
                or not right_value.available
                or left_value.value is None
                or right_value.value is None
            ):
                continue
            values = (float(left_value.value), float(right_value.value))
        else:
            values = (float(left_value), float(right_value))
        grouped[left.scenario_id].append(values)
    return grouped


def _pareto_class(
    left_quality: float,
    right_quality: float,
    left_resource: float,
    right_resource: float,
) -> str:
    if left_quality == right_quality and left_resource == right_resource:
        return "tie"
    if left_quality >= right_quality and left_resource <= right_resource:
        return "left_dominates"
    if right_quality >= left_quality and right_resource <= left_resource:
        return "right_dominates"
    return "tradeoff"


def _both_completed(left: EfficiencyRunProjection, right: EfficiencyRunProjection) -> bool:
    return left.task_status == "completed" and right.task_status == "completed"


def _fairness_assessment(
    plan: EfficiencyPlan,
    runs: Sequence[BenchmarkRunV3],
    projections: Sequence[EfficiencyRunProjection],
    context: Mapping[str, Any],
) -> dict[str, Any]:
    expected_order = _scheduled_run_keys(plan)
    unique_starts = len({item.started_at for item in projections}) == len(projections)
    actual_order = tuple(
        (item.scenario_id, item.repetition, item.matched_fixture_seed, item.system_id)
        for item in sorted(projections, key=lambda item: (item.started_at, item.run_id))
    )
    chronological = sorted(projections, key=lambda item: (item.started_at, item.run_id))
    non_overlapping = all(left.finished_at <= right.started_at for left, right in zip(chronological, chronological[1:]))
    schedule_order = unique_starts and non_overlapping and actual_order == expected_order
    by_block: dict[tuple[str, int, int], list[EfficiencyRunProjection]] = defaultdict(list)
    for item in projections:
        by_block[item.block_key].append(item)
    paired_host_batch = all(
        len({item.host_id for item in block}) == 1
        and len({item.batch_id for item in block}) == 1
        and all(item.host_id and item.batch_id for item in block)
        for block in by_block.values()
    )
    manifests = _system_declarations(context, plan.system_ids)
    profiles = [item.get("fairness_profile") for item in manifests.values()]
    profile_maps = [item for item in profiles if isinstance(item, Mapping)]
    profile_ids = {str(item.get("profile_id") or "") for item in profile_maps} - {""}
    common_profile = len(profile_maps) == len(plan.system_ids) and len(profile_ids) == 1
    same_hardware = common_profile and all(item.get("same_hardware") is True for item in profile_maps)
    same_model_declared = common_profile and all(item.get("same_model") is True for item in profile_maps)
    models = [item.get("model") for item in manifests.values()]
    same_model_payload = (
        len(models) == len(plan.system_ids)
        and all(isinstance(item, Mapping) for item in models)
        and len({canonical_json(item) for item in models}) == 1
    )
    runtime_model_digests: list[str] = []
    for manifest in manifests.values():
        metadata = manifest.get("metadata")
        runtime = metadata.get("runtime_provenance") if isinstance(metadata, Mapping) else None
        runtime_model_digests.append(
            str(runtime.get("ollama_model_digest") or "") if isinstance(runtime, Mapping) else ""
        )
    shared_runtime_model_digest = (
        len(runtime_model_digests) == len(plan.system_ids)
        and all(runtime_model_digests)
        and len(set(runtime_model_digests)) == 1
    )
    run_attestation = all(item.efficiency_plan_attested for item in projections)
    campaign_attestation = _campaign_attestation_matches(plan, context)
    no_policy_violations = not any(run.policy_violations for run in runs)
    prospective_design = plan.publication_tier != "diagnostic" and plan.require_run_attestation
    checks = {
        "campaign_attestation": campaign_attestation,
        "common_profile": common_profile,
        "counterbalanced_first_position": True,
        "exact_ledger_run_coverage": True,
        "no_policy_violations": no_policy_violations,
        "paired_host_batch": paired_host_batch,
        "prospective_design": prospective_design,
        "run_attestation": run_attestation,
        "same_hardware_declaration": same_hardware,
        "same_model_declaration": same_model_declared and same_model_payload,
        "shared_runtime_model_digest": shared_runtime_model_digest,
        "schedule_order": schedule_order,
    }
    return {
        **checks,
        "base_eligible": all(checks.values()),
        "diagnostic_attestation_waiver": not plan.require_run_attestation,
        "eligible": False,
        "primary_metric_gates": {},
    }


def _system_declarations(context: Mapping[str, Any], system_ids: Sequence[str]) -> dict[str, Mapping[str, Any]]:
    raw = context.get("systems")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for item in raw:
        if not isinstance(item, Mapping):
            return {}
        system_id = str(item.get("system_id") or "")
        if system_id in result:
            return {}
        result[system_id] = item
    return result if set(result) == set(system_ids) else {}


def _campaign_attestation_matches(plan: EfficiencyPlan, context: Mapping[str, Any]) -> bool:
    attestation = context.get("efficiency_plan_attestation")
    expected = {
        "efficiency_track_id": plan.efficiency_track_id,
        "plan_digest": plan.digest,
        "plan_id": plan.plan_id,
        "source_analysis_plan_digest": plan.source_analysis_plan_digest,
        "source_track_id": plan.source_track_id,
    }
    if not isinstance(attestation, Mapping) or dict(attestation) != expected:
        return False
    campaign = context.get("campaign")
    benchmark = campaign.get("benchmark_v3") if isinstance(campaign, Mapping) else None
    if not isinstance(benchmark, Mapping):
        return False
    return (
        benchmark.get("analysis_plan_digest") == plan.source_analysis_plan_digest
        and benchmark.get("track_id") == plan.source_track_id
        and benchmark.get("efficiency_plan_digest") == plan.digest
        and benchmark.get("efficiency_track_id") == plan.efficiency_track_id
    )


def _campaign_context(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkV4SchemaError("invalid_efficiency_campaign_context")
    try:
        encoded = canonical_json(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise BenchmarkV4SchemaError("invalid_efficiency_campaign_context") from exc
    if len(encoded.encode("utf-8")) > 8_000_000:
        raise BenchmarkV4SchemaError("efficiency_campaign_context_too_large")
    return value


def _stream_seed(plan: EfficiencyPlan, comparison_index: int, stream: str) -> int:
    return (
        plan.bootstrap_seed
        + comparison_index * 100_000
        + int(stable_digest({"efficiency_bootstrap_stream": stream})[:8], 16)
    )


def _comparison_key(left_system_id: str, right_system_id: str) -> str:
    return "pair-" + stable_digest({"left_system_id": left_system_id, "right_system_id": right_system_id})[:32]


def _percentile(sorted_values: Sequence[float], fraction: float) -> float:
    if not sorted_values:
        raise BenchmarkV4SchemaError("percentile_requires_values")
    position = (len(sorted_values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(sorted_values[lower])
    weight = position - lower
    return float(sorted_values[lower]) * (1.0 - weight) + float(sorted_values[upper]) * weight


def _require_digest(value: str, name: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise BenchmarkV4SchemaError(f"invalid:{name}")


def _round(value: float | None) -> float | None:
    return round(float(value), 9) if value is not None else None


__all__ = [
    "analyze_efficiency",
    "extract_efficiency_runs",
    "hierarchical_paired_bootstrap",
]
