"""Frozen design and deterministic statistics for Benchmark v3."""

from __future__ import annotations

import json
import math
import os
import random
import statistics
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from .schema import POPULATIONS, BenchmarkRunV3, BenchmarkV3SchemaError, stable_digest
from .tracks import get_track, validate_single_track, validate_track_design

ANALYSIS_PLAN_SCHEMA_VERSION = "1.0"
STATISTICS_SCHEMA_VERSION = "1.0"
DEFAULT_ANALYSIS_METRICS = (
    "full_claim_precision",
    "reported_recall",
    "verified_recall",
)


@dataclass(frozen=True)
class AnalysisPlan:
    """A pre-run, hash-frozen statistical design."""

    track_id: str
    system_ids: tuple[str, ...]
    scenario_ids: tuple[str, ...]
    repetitions: int
    fixture_seeds: Mapping[str, tuple[int, ...]]
    comparison_pairs: tuple[tuple[str, str], ...]
    metrics: tuple[str, ...] = DEFAULT_ANALYSIS_METRICS
    populations: tuple[str, ...] = ("all_scheduled", "completion_conditional")
    deadlines_seconds: tuple[float, ...] = (30.0, 60.0, 120.0)
    alpha: float = 0.05
    bootstrap_samples: int = 10_000
    bootstrap_seed: int = 1
    publication_tier: str = "full"
    batches: int = 1
    hosts: int = 1
    paired_blocks: int = 0
    require_run_plan_attestation: bool = True
    exclusion_rules: tuple[str, ...] = ()
    schema_version: str = ANALYSIS_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        get_track(self.track_id)
        object.__setattr__(self, "system_ids", tuple(self.system_ids))
        object.__setattr__(self, "scenario_ids", tuple(self.scenario_ids))
        try:
            normalized_pairs = tuple((str(item[0]), str(item[1])) for item in self.comparison_pairs if len(item) == 2)
        except (IndexError, TypeError):
            raise BenchmarkV3SchemaError("invalid:analysis_plan.comparison_pair") from None
        if len(normalized_pairs) != len(self.comparison_pairs):
            raise BenchmarkV3SchemaError("invalid:analysis_plan.comparison_pair")
        object.__setattr__(self, "comparison_pairs", normalized_pairs)
        object.__setattr__(self, "metrics", tuple(self.metrics))
        object.__setattr__(self, "populations", tuple(self.populations))
        object.__setattr__(self, "deadlines_seconds", tuple(self.deadlines_seconds))
        object.__setattr__(self, "exclusion_rules", tuple(self.exclusion_rules))
        object.__setattr__(
            self,
            "fixture_seeds",
            MappingProxyType({str(key): tuple(value) for key, value in sorted(self.fixture_seeds.items())}),
        )
        if len(self.system_ids) < 2 or len(set(self.system_ids)) != len(self.system_ids):
            raise BenchmarkV3SchemaError("analysis_plan_requires_unique_systems")
        if not self.scenario_ids or len(set(self.scenario_ids)) != len(self.scenario_ids):
            raise BenchmarkV3SchemaError("analysis_plan_requires_unique_scenarios")
        for value in (*self.system_ids, *self.scenario_ids, *self.metrics):
            _identifier(value, "analysis_plan.identifier")
        if self.repetitions < 1:
            raise BenchmarkV3SchemaError("invalid:analysis_plan.repetitions")
        if self.batches < 1 or self.hosts < 1 or self.paired_blocks < 0:
            raise BenchmarkV3SchemaError("invalid:analysis_plan.design_count")
        if set(self.fixture_seeds) != set(self.scenario_ids):
            raise BenchmarkV3SchemaError("analysis_plan_fixture_seed_scenarios")
        for scenario_id, seeds in self.fixture_seeds.items():
            if len(seeds) != self.repetitions or len(set(seeds)) != len(seeds):
                raise BenchmarkV3SchemaError("analysis_plan_fixture_seed_count")
            if any(seed < 0 or seed >= 2**63 for seed in seeds):
                raise BenchmarkV3SchemaError("invalid:analysis_plan.fixture_seed")
            if not scenario_id:
                raise BenchmarkV3SchemaError("invalid:analysis_plan.scenario_id")
        allowed_pairs = set(self.system_ids)
        canonical_pair_set: set[tuple[str, str]] = set()
        for left, right in self.comparison_pairs:
            if left == right or left not in allowed_pairs or right not in allowed_pairs:
                raise BenchmarkV3SchemaError("invalid:analysis_plan.comparison_pair")
            pair = (min(left, right), max(left, right))
            if pair in canonical_pair_set:
                raise BenchmarkV3SchemaError("duplicate_analysis_comparison_pair")
            canonical_pair_set.add(pair)
        if not self.comparison_pairs:
            raise BenchmarkV3SchemaError("analysis_plan_requires_comparison_pair")
        if not self.metrics or len(set(self.metrics)) != len(self.metrics):
            raise BenchmarkV3SchemaError("invalid:analysis_plan.metrics")
        if not self.populations or set(self.populations) - POPULATIONS:
            raise BenchmarkV3SchemaError("invalid:analysis_plan.populations")
        if (
            not self.deadlines_seconds
            or any(value <= 0 or not math.isfinite(value) for value in self.deadlines_seconds)
            or tuple(sorted(self.deadlines_seconds)) != self.deadlines_seconds
        ):
            raise BenchmarkV3SchemaError("invalid:analysis_plan.deadlines")
        if not 0.0 < self.alpha < 1.0:
            raise BenchmarkV3SchemaError("invalid:analysis_plan.alpha")
        if self.bootstrap_samples < 100:
            raise BenchmarkV3SchemaError("analysis_plan_bootstrap_too_small")
        if self.bootstrap_seed < 0:
            raise BenchmarkV3SchemaError("invalid:analysis_plan.bootstrap_seed")
        validate_track_design(
            self.track_id,
            repetitions=self.repetitions,
            paired_blocks=self.paired_blocks,
            batches=self.batches,
            hosts=self.hosts,
            publication_tier=self.publication_tier,
        )

    @property
    def digest(self) -> str:
        return stable_digest(self._digest_payload())

    @property
    def plan_id(self) -> str:
        return "analysis-plan-" + self.digest[:20]

    def _digest_payload(self) -> dict[str, Any]:
        return {
            "alpha": self.alpha,
            "batches": self.batches,
            "bootstrap_samples": self.bootstrap_samples,
            "bootstrap_seed": self.bootstrap_seed,
            "comparison_pairs": [list(item) for item in self.comparison_pairs],
            "deadlines_seconds": list(self.deadlines_seconds),
            "exclusion_rules": list(self.exclusion_rules),
            "fixture_seeds": {key: list(value) for key, value in sorted(self.fixture_seeds.items())},
            "hosts": self.hosts,
            "metrics": list(self.metrics),
            "paired_blocks": self.paired_blocks,
            "populations": list(self.populations),
            "publication_tier": self.publication_tier,
            "repetitions": self.repetitions,
            "require_run_plan_attestation": self.require_run_plan_attestation,
            "scenario_ids": list(self.scenario_ids),
            "schema_version": self.schema_version,
            "system_ids": list(self.system_ids),
            "track_id": self.track_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._digest_payload(),
            "frozen": True,
            "plan_digest": self.digest,
            "plan_id": self.plan_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> AnalysisPlan:
        if str(payload.get("schema_version") or "") != ANALYSIS_PLAN_SCHEMA_VERSION:
            raise BenchmarkV3SchemaError("unsupported_analysis_plan_schema")
        raw_seeds = payload.get("fixture_seeds")
        raw_pairs_value = payload.get("comparison_pairs")
        if not isinstance(raw_seeds, Mapping) or not _sequence(raw_pairs_value):
            raise BenchmarkV3SchemaError("invalid_analysis_plan")
        raw_pairs = list(cast(Sequence[Any], raw_pairs_value))
        plan = cls(
            track_id=str(payload.get("track_id") or ""),
            system_ids=tuple(str(item) for item in payload.get("system_ids") or []),
            scenario_ids=tuple(str(item) for item in payload.get("scenario_ids") or []),
            repetitions=int(payload.get("repetitions") or 0),
            fixture_seeds={
                str(key): tuple(int(item) for item in value) for key, value in raw_seeds.items() if _sequence(value)
            },
            comparison_pairs=tuple(
                (str(item[0]), str(item[1])) for item in raw_pairs if _sequence(item) and len(item) == 2
            ),
            metrics=tuple(str(item) for item in payload.get("metrics") or []),
            populations=tuple(str(item) for item in payload.get("populations") or []),
            deadlines_seconds=tuple(float(item) for item in payload.get("deadlines_seconds") or []),
            alpha=float(payload.get("alpha") or 0.0),
            bootstrap_samples=int(payload.get("bootstrap_samples") or 0),
            bootstrap_seed=int(payload.get("bootstrap_seed") or 0),
            publication_tier=str(payload.get("publication_tier") or ""),
            batches=int(payload.get("batches") or 0),
            hosts=int(payload.get("hosts") or 0),
            paired_blocks=int(payload.get("paired_blocks") or 0),
            require_run_plan_attestation=bool(payload.get("require_run_plan_attestation", True)),
            exclusion_rules=tuple(str(item) for item in payload.get("exclusion_rules") or []),
        )
        if payload.get("frozen") is not True:
            raise BenchmarkV3SchemaError("analysis_plan_not_frozen")
        if str(payload.get("plan_digest") or "") != plan.digest:
            raise BenchmarkV3SchemaError("analysis_plan_digest_mismatch")
        if str(payload.get("plan_id") or "") != plan.plan_id:
            raise BenchmarkV3SchemaError("analysis_plan_id_mismatch")
        return plan


def build_analysis_plan(
    *,
    track_id: str,
    system_ids: Sequence[str],
    scenario_ids: Sequence[str],
    repetitions: int,
    base_fixture_seed: int,
    publication_tier: str = "full",
    batches: int = 1,
    hosts: int = 1,
    paired_blocks: int | None = None,
    metrics: Sequence[str] = DEFAULT_ANALYSIS_METRICS,
    populations: Sequence[str] = ("all_scheduled", "completion_conditional"),
    deadlines_seconds: Sequence[float] = (30.0, 60.0, 120.0),
    alpha: float = 0.05,
    bootstrap_samples: int = 10_000,
    bootstrap_seed: int = 1,
    comparison_pairs: Sequence[tuple[str, str]] | None = None,
    require_run_plan_attestation: bool = True,
    exclusion_rules: Sequence[str] = (),
) -> AnalysisPlan:
    """Create a deterministic schedule without exposing it to product processes."""

    if isinstance(base_fixture_seed, bool) or not 0 <= int(base_fixture_seed) < 2**256:
        raise BenchmarkV3SchemaError("invalid:base_fixture_seed")
    systems = tuple(str(item) for item in system_ids)
    scenarios = tuple(str(item) for item in scenario_ids)
    if comparison_pairs is None:
        comparisons = tuple(
            (systems[left], systems[right]) for left in range(len(systems)) for right in range(left + 1, len(systems))
        )
    else:
        comparisons = tuple((str(left), str(right)) for left, right in comparison_pairs)
    fixture_seeds = {
        scenario_id: tuple(
            int(
                stable_digest(
                    {
                        "base_fixture_seed": int(base_fixture_seed),
                        "repetition": repetition,
                        "scenario_id": scenario_id,
                    }
                )[:15],
                16,
            )
            for repetition in range(1, int(repetitions) + 1)
        )
        for scenario_id in scenarios
    }
    return AnalysisPlan(
        track_id=track_id,
        system_ids=systems,
        scenario_ids=scenarios,
        repetitions=int(repetitions),
        fixture_seeds=fixture_seeds,
        comparison_pairs=comparisons,
        metrics=tuple(metrics),
        populations=tuple(populations),
        deadlines_seconds=tuple(float(item) for item in deadlines_seconds),
        alpha=float(alpha),
        bootstrap_samples=int(bootstrap_samples),
        bootstrap_seed=int(bootstrap_seed),
        publication_tier=publication_tier,
        batches=int(batches),
        hosts=int(hosts),
        paired_blocks=int(paired_blocks if paired_blocks is not None else repetitions),
        require_run_plan_attestation=require_run_plan_attestation,
        exclusion_rules=tuple(exclusion_rules),
    )


def freeze_analysis_plan(plan: AnalysisPlan, path: str | Path) -> Path:
    """Write once; an existing byte-different plan is never replaced."""

    destination = Path(path).resolve()
    payload = (
        json.dumps(
            plan.to_dict(),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_text(encoding="utf-8") != payload:
            raise FileExistsError("frozen_analysis_plan_differs")
        return destination
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary_name)
        raise
    return destination


def load_analysis_plan(path: str | Path) -> AnalysisPlan:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkV3SchemaError("analysis_plan_load_failed") from exc
    if not isinstance(payload, Mapping):
        raise BenchmarkV3SchemaError("invalid_analysis_plan")
    return AnalysisPlan.from_dict(payload)


def wilson_interval(
    successes: int,
    trials: int,
    *,
    alpha: float = 0.05,
) -> dict[str, float | int | None]:
    """Wilson score interval for a binomial proportion."""

    if trials < 0 or successes < 0 or successes > trials:
        raise BenchmarkV3SchemaError("invalid_wilson_counts")
    if not 0.0 < alpha < 1.0:
        raise BenchmarkV3SchemaError("invalid_wilson_alpha")
    if trials == 0:
        return {
            "estimate": None,
            "lower": None,
            "successes": successes,
            "trials": trials,
            "upper": None,
        }
    z = statistics.NormalDist().inv_cdf(1.0 - alpha / 2.0)
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (proportion + z * z / (2.0 * trials)) / denominator
    margin = z * math.sqrt(proportion * (1.0 - proportion) / trials + z * z / (4.0 * trials * trials)) / denominator
    return {
        "estimate": _round(proportion),
        "lower": _round(max(0.0, centre - margin)),
        "successes": successes,
        "trials": trials,
        "upper": _round(min(1.0, centre + margin)),
    }


def paired_bootstrap(
    paired_values: Sequence[tuple[float, float]],
    *,
    samples: int = 10_000,
    alpha: float = 0.05,
    seed: int = 1,
) -> dict[str, Any]:
    """Bootstrap the mean paired effect (right minus left) deterministically."""

    pairs = tuple((float(left), float(right)) for left, right in paired_values)
    if not pairs:
        return {
            "available": False,
            "reason": "no_complete_pairs",
            "sample_size": 0,
        }
    if samples < 100 or not 0.0 < alpha < 1.0:
        raise BenchmarkV3SchemaError("invalid_paired_bootstrap_design")
    if any(not math.isfinite(value) for pair in pairs for value in pair):
        raise BenchmarkV3SchemaError("nonfinite_paired_bootstrap_value")
    differences = [right - left for left, right in pairs]
    point = statistics.fmean(differences)
    rng = random.Random(int(seed))
    effects = sorted(
        statistics.fmean(differences[rng.randrange(len(differences))] for _ in differences) for _ in range(samples)
    )
    lower = _percentile(effects, alpha / 2.0)
    upper = _percentile(effects, 1.0 - alpha / 2.0)
    if len(differences) > 1:
        spread = statistics.stdev(differences)
        standardized = point / spread if spread > 0 else None
    else:
        standardized = None
    return {
        "alpha": alpha,
        "available": True,
        "bootstrap_samples": samples,
        "effect_right_minus_left": _round(point),
        "lower": _round(lower),
        "sample_size": len(pairs),
        "standardized_paired_effect": (_round(standardized) if standardized is not None else None),
        "upper": _round(upper),
    }


def kaplan_meier(
    observations: Sequence[tuple[float, bool]],
    *,
    horizon_seconds: float | None = None,
) -> dict[str, Any]:
    """Censor-aware completion-time survival estimate and restricted mean."""

    values = tuple((float(duration), bool(censored)) for duration, censored in observations)
    if not values:
        return {
            "available": False,
            "reason": "no_duration_observations",
            "sample_size": 0,
        }
    if any(duration < 0 or not math.isfinite(duration) for duration, _ in values):
        raise BenchmarkV3SchemaError("invalid_duration_observation")
    observed_max = max(duration for duration, _ in values)
    horizon = observed_max if horizon_seconds is None else float(horizon_seconds)
    if horizon < 0 or not math.isfinite(horizon):
        raise BenchmarkV3SchemaError("invalid_survival_horizon")
    grouped: dict[float, list[bool]] = defaultdict(list)
    for duration, censored in values:
        grouped[min(duration, horizon)].append(censored or duration > horizon)
    at_risk = len(values)
    survival = 1.0
    median: float | None = None
    points: list[dict[str, Any]] = []
    rmst = 0.0
    previous_time = 0.0
    for duration in sorted(grouped):
        rmst += survival * max(0.0, duration - previous_time)
        flags = grouped[duration]
        events = sum(not item for item in flags)
        censors = sum(item for item in flags)
        if at_risk > 0 and events:
            survival *= 1.0 - events / at_risk
        points.append(
            {
                "at_risk": at_risk,
                "censored": censors,
                "completion_events": events,
                "survival": _round(survival),
                "time_seconds": _round(duration),
            }
        )
        if median is None and survival <= 0.5:
            median = duration
        at_risk -= events + censors
        previous_time = duration
    if previous_time < horizon:
        rmst += survival * (horizon - previous_time)
    return {
        "available": True,
        "completion_events": sum(not censored for _, censored in values),
        "horizon_seconds": _round(horizon),
        "median_completion_seconds": _round(median) if median is not None else None,
        "restricted_mean_completion_seconds": _round(rmst),
        "sample_size": len(values),
        "survival_curve": points,
    }


def analyze_runs(
    plan: AnalysisPlan,
    runs: Sequence[BenchmarkRunV3],
) -> dict[str, Any]:
    """Validate the frozen schedule and produce deterministic statistics."""

    items = tuple(runs)
    _validate_schedule(plan, items)
    track = validate_single_track(items)
    grouped: dict[tuple[str, str], list[BenchmarkRunV3]] = defaultdict(list)
    by_system: dict[str, list[BenchmarkRunV3]] = defaultdict(list)
    for run in items:
        grouped[(run.system_id, run.scenario_id)].append(run)
        by_system[run.system_id].append(run)

    systems: dict[str, Any] = {}
    for system_id in plan.system_ids:
        scenario_stats = {
            scenario_id: _group_statistics(
                grouped[(system_id, scenario_id)],
                plan,
            )
            for scenario_id in plan.scenario_ids
        }
        systems[system_id] = {
            "overall": _group_statistics(by_system[system_id], plan),
            "scenarios": scenario_stats,
        }

    paired_effects: list[dict[str, Any]] = []
    indexed = {(run.system_id, run.scenario_id, run.matched_fixture_seed): run for run in items}
    for comparison_index, (left_id, right_id) in enumerate(plan.comparison_pairs):
        for population in plan.populations:
            for metric_name in plan.metrics:
                values: list[tuple[float, float]] = []
                for scenario_id in plan.scenario_ids:
                    for seed in plan.fixture_seeds[scenario_id]:
                        left = indexed[(left_id, scenario_id, seed)].evaluation.metric(
                            metric_name,
                            population,
                        )
                        right = indexed[(right_id, scenario_id, seed)].evaluation.metric(
                            metric_name,
                            population,
                        )
                        if left.available and right.available:
                            if left.value is None or right.value is None:
                                raise BenchmarkV3SchemaError("available_metric_missing_value")
                            values.append((float(left.value), float(right.value)))
                result = paired_bootstrap(
                    values,
                    samples=plan.bootstrap_samples,
                    alpha=plan.alpha,
                    seed=plan.bootstrap_seed
                    + comparison_index * 10_000
                    + _stable_small_int(f"{population}:{metric_name}"),
                )
                paired_effects.append(
                    {
                        "left_system_id": left_id,
                        "metric": metric_name,
                        "population": population,
                        "right_system_id": right_id,
                        "statistics": result,
                    }
                )

    return {
        "analysis_plan_digest": plan.digest,
        "analysis_plan_id": plan.plan_id,
        "automatic_winner": False,
        "leaderboard_contract": {
            "merge_group": track.merge_group,
            "mixed_tracks": "forbidden",
            "track_id": track.track_id,
        },
        "paired_effects": paired_effects,
        "run_count": len(items),
        "schema_version": STATISTICS_SCHEMA_VERSION,
        "systems": systems,
    }


def _group_statistics(
    runs: Sequence[BenchmarkRunV3],
    plan: AnalysisPlan,
) -> dict[str, Any]:
    execution_counts = Counter(run.execution_status for run in runs)
    task_counts = Counter(run.task_status for run in runs)
    metrics: dict[str, Any] = {}
    for population in plan.populations:
        population_metrics: dict[str, Any] = {}
        for name in plan.metrics:
            observations = [run.evaluation.metric(name, population) for run in runs]
            available = [item for item in observations if item.available]
            numerator = sum(item.numerator or 0 for item in available if item.numerator is not None)
            denominator = sum(item.denominator or 0 for item in available if item.denominator is not None)
            values = [float(item.value) for item in available if item.value is not None]
            population_metrics[name] = {
                "availability": {
                    "available": len(available),
                    "scheduled": len(observations),
                },
                "mean": _round(statistics.fmean(values)) if values else None,
                "median": _round(statistics.median(values)) if values else None,
                "reliability_counts": dict(sorted(Counter(item.reliability for item in observations).items())),
                "wilson": (
                    wilson_interval(numerator, denominator, alpha=plan.alpha)
                    if denominator
                    else wilson_interval(0, 0, alpha=plan.alpha)
                ),
            }
        metrics[population] = population_metrics
    deadline_statistics = {
        _deadline_key(deadline): wilson_interval(
            sum(
                run.task_status == "completed" and not run.duration_censored and run.duration_seconds <= deadline
                for run in runs
            ),
            len(runs),
            alpha=plan.alpha,
        )
        for deadline in plan.deadlines_seconds
    }
    horizon = max(plan.deadlines_seconds)
    duration = kaplan_meier(
        [(run.duration_seconds, run.duration_censored) for run in runs],
        horizon_seconds=horizon,
    )
    applied_model_seeds = sum(run.model_seed_status == "applied" and run.applied_model_seed is not None for run in runs)
    budget_records = [item for run in runs for item in run.budget_enforcement]
    return {
        "action_telemetry": {
            "available_runs": sum(run.action_telemetry_available for run in runs),
            "events": sum(len(run.action_telemetry) for run in runs),
            "scheduled_runs": len(runs),
        },
        "budget_enforcement": {
            "exceeded_records": sum(item.exceeded is True for item in budget_records),
            "records": len(budget_records),
            "reliable_records": sum(item.reliable for item in budget_records),
        },
        "completion_by_deadline": deadline_statistics,
        "duration": duration,
        "execution_outcomes": {
            "counts": dict(sorted(execution_counts.items())),
            "succeeded_wilson": wilson_interval(
                execution_counts.get("succeeded", 0),
                len(runs),
                alpha=plan.alpha,
            ),
        },
        "metrics": metrics,
        "model_seed": {
            "applied": applied_model_seeds,
            "scheduled": len(runs),
            "status_counts": dict(sorted(Counter(run.model_seed_status for run in runs).items())),
        },
        "run_count": len(runs),
        "task_outcomes": {
            "completed_wilson": wilson_interval(
                task_counts.get("completed", 0),
                len(runs),
                alpha=plan.alpha,
            ),
            "counts": dict(sorted(task_counts.items())),
        },
    }


def _validate_schedule(plan: AnalysisPlan, runs: Sequence[BenchmarkRunV3]) -> None:
    expected = {
        (system_id, scenario_id, repetition, seed)
        for system_id in plan.system_ids
        for scenario_id in plan.scenario_ids
        for repetition, seed in enumerate(plan.fixture_seeds[scenario_id], start=1)
    }
    actual = {
        (
            run.system_id,
            run.scenario_id,
            run.repetition,
            run.matched_fixture_seed,
        )
        for run in runs
    }
    if len(actual) != len(runs):
        raise BenchmarkV3SchemaError("duplicate_scheduled_run")
    if actual != expected:
        raise BenchmarkV3SchemaError("runs_do_not_match_frozen_schedule")
    if any(run.track_id != plan.track_id for run in runs):
        raise BenchmarkV3SchemaError("run_track_differs_from_analysis_plan")
    if plan.require_run_plan_attestation:
        for run in runs:
            if str(run.environment.get("analysis_plan_digest") or "") != plan.digest:
                raise BenchmarkV3SchemaError("run_missing_analysis_plan_attestation")
    paired_variants: dict[tuple[str, int], set[str]] = defaultdict(set)
    for run in runs:
        paired_variants[(run.scenario_id, run.matched_fixture_seed)].add(run.fixture_variant_digest)
    if any(len(digests) != 1 or "" in digests for digests in paired_variants.values()):
        raise BenchmarkV3SchemaError("matched_seed_fixture_variant_mismatch")
    if plan.publication_tier == "full":
        observed_batches = {str(run.environment.get("batch_id") or "") for run in runs} - {""}
        observed_hosts = {str(run.environment.get("host_id") or "") for run in runs} - {""}
        if len(observed_batches) < plan.batches:
            raise BenchmarkV3SchemaError("insufficient_attested_batches")
        if len(observed_hosts) < plan.hosts:
            raise BenchmarkV3SchemaError("insufficient_attested_hosts")


def _percentile(sorted_values: Sequence[float], fraction: float) -> float:
    if not sorted_values:
        raise BenchmarkV3SchemaError("percentile_requires_values")
    position = (len(sorted_values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(sorted_values[lower])
    weight = position - lower
    return float(sorted_values[lower]) * (1.0 - weight) + float(sorted_values[upper]) * weight


def _deadline_key(value: float) -> str:
    return f"{value:g}s"


def _round(value: float | None) -> float | None:
    return round(float(value), 9) if value is not None else None


def _stable_small_int(value: str) -> int:
    return int(stable_digest({"bootstrap_stream": value})[:8], 16)


def _sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _identifier(value: str, name: str) -> str:
    raw = str(value).strip()
    text = raw.lower()
    if (
        not text
        or len(text) > 160
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_.:-" for character in text)
    ):
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    if text[0] not in "abcdefghijklmnopqrstuvwxyz0123456789":
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    if raw != text:
        raise BenchmarkV3SchemaError(f"invalid:{name}")
    return text
