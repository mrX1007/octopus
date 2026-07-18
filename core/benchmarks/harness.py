"""Replay-first benchmark execution with five-run statistical aggregation."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import statistics
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from .schema import (
    MIN_BENCHMARK_REPETITIONS,
    BenchmarkAggregate,
    BenchmarkRun,
    BenchmarkScenario,
    BenchmarkSchemaError,
)

_ERROR_CLASS = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")


class BenchmarkRunner(Protocol):
    def __call__(
        self,
        scenario: BenchmarkScenario,
        repetition: int,
        seed: int,
    ) -> Mapping[str, Any]: ...


class BenchmarkHarness:
    """Run injected or built-in replay logic without launching external tools."""

    def __init__(
        self,
        runner: BenchmarkRunner | None = None,
        *,
        stable_toggles: Sequence[str] = (),
        clock: Callable[[], float] = time.time,
        run_namespace: str = "",
        runner_metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if runner is None:
            # Import lazily so custom-runner users do not pay for project
            # component imports and so the built-in runner can use the harness
            # without creating an import cycle.
            from .builtin_runner import BuiltinReplayRunner

            runner = BuiltinReplayRunner()
        self.runner: BenchmarkRunner = runner
        self.stable_toggles = frozenset(str(item) for item in stable_toggles)
        self.clock = clock
        self.run_namespace = str(run_namespace or "")[:256]
        self.runner_metadata = {
            str(key)[:128]: _bounded_metadata(value)
            for key, value in (runner_metadata or {}).items()
        }

    def run(
        self,
        scenario: BenchmarkScenario,
        *,
        repetitions: int | None = None,
    ) -> BenchmarkAggregate:
        count = scenario.repetitions if repetitions is None else int(repetitions)
        if count < MIN_BENCHMARK_REPETITIONS:
            raise BenchmarkSchemaError(
                f"repetitions_below_minimum:{MIN_BENCHMARK_REPETITIONS}"
            )
        self._validate_ablations(scenario)
        runs = tuple(
            self._run_once(scenario, repetition=index + 1, seed=scenario.seed + index)
            for index in range(count)
        )
        metric_statistics = self._aggregate_metrics(runs)
        status_counts = dict(sorted(Counter(item.status for item in runs).items()))
        generated_at = self.clock()
        aggregate_id = _stable_id(
            "benchmark-aggregate",
            {
                "scenario_id": scenario.scenario_id,
                "run_ids": [item.run_id for item in runs],
            },
        )
        return BenchmarkAggregate(
            aggregate_id=aggregate_id,
            scenario=scenario,
            runs=runs,
            metric_statistics=metric_statistics,
            status_counts=status_counts,
            generated_at=generated_at,
        )

    def write(self, aggregate: BenchmarkAggregate, path: str | Path) -> Path:
        """Atomically persist one complete aggregate, never a partial JSON file."""

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
        payload = json.dumps(
            aggregate.to_dict(),
            indent=2,
            sort_keys=True,
            default=str,
        )
        temporary.write_text(payload + "\n", encoding="utf-8")
        os.replace(temporary, destination)
        return destination

    def _run_once(
        self,
        scenario: BenchmarkScenario,
        *,
        repetition: int,
        seed: int,
    ) -> BenchmarkRun:
        started_at = self.clock()
        error_class = ""
        try:
            raw = self.runner(scenario, repetition, seed)
            if not isinstance(raw, Mapping):
                raise TypeError("benchmark runner must return a mapping")
            result = dict(raw)
            status = str(result.get("status") or "succeeded").lower()
            reported_error_class = _optional_error_class(
                result.get("error_class")
            )
            if status != "succeeded" and reported_error_class:
                error_class = reported_error_class
        except Exception as exc:
            result = {}
            status = "failed"
            error_class = type(exc).__name__
        finished_at = self.clock()
        recorded_started_at = _optional_timestamp(result.get("started_at"))
        recorded_finished_at = _optional_timestamp(result.get("finished_at"))
        if (
            recorded_started_at is not None
            and recorded_finished_at is not None
            and recorded_finished_at >= recorded_started_at
        ):
            started_at = recorded_started_at
            finished_at = recorded_finished_at
        duration = _nonnegative_number(
            result.get("duration_seconds"),
            default=max(0.0, finished_at - started_at),
        )
        actions = _string_tuple(result.get("actions") or [])
        allowed = set(scenario.allowed_actions)
        violations = tuple(
            sorted({action for action in actions if action not in allowed})
        )
        if violations:
            status = "invalid"
        metrics = {
            str(key): _nonnegative_number(value)
            for key, value in (result.get("metrics") or {}).items()
            if _is_number(value)
        } if isinstance(result.get("metrics") or {}, Mapping) else {}
        metrics.update(self._ground_truth_metrics(scenario, result))
        reported_findings = _string_tuple(result.get("reported_findings") or [])
        expected_findings = _string_tuple(
            scenario.ground_truth.get("expected_findings") or []
        )
        reported_finding_set = set(reported_findings)
        derived_coverage_gaps = tuple(
            finding
            for finding in expected_findings
            if finding not in reported_finding_set
        )
        runner_coverage_gaps = _string_tuple(result.get("coverage_gaps") or [])
        coverage_gaps = tuple(
            dict.fromkeys((*derived_coverage_gaps, *runner_coverage_gaps))
        )
        result_summary = {
            "status": status,
            "reported_findings": list(reported_findings),
            "verified_findings": list(_string_tuple(result.get("verified_findings") or [])),
            "coverage_gaps": list(coverage_gaps),
        }
        artifact_refs = _string_tuple(result.get("artifact_refs") or [])
        environment = {
            "lab": dict(scenario.lab),
            "target": dict(scenario.target),
            "model": dict(scenario.model),
            "tool_versions": dict(scenario.tool_versions),
            "strategy_config": dict(scenario.strategy_config),
            "budgets": dict(scenario.budgets),
        }
        if self.runner_metadata:
            environment["runner"] = dict(self.runner_metadata)
        run_id = _stable_id(
            "benchmark-run",
            {
                "run_namespace": self.run_namespace,
                "scenario_id": scenario.scenario_id,
                "scenario_contract": scenario.to_dict(),
                "repetition": repetition,
                "seed": seed,
                "status": status,
                "metrics": metrics,
                "actions": actions,
            },
        )
        return BenchmarkRun(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            repetition=repetition,
            seed=seed,
            status=status,
            actions=actions,
            policy_violations=violations,
            metrics=metrics,
            result_summary=result_summary,
            artifact_refs=artifact_refs,
            duration_seconds=duration,
            started_at=started_at,
            finished_at=finished_at,
            environment=environment,
            error_class=error_class,
        )

    def _validate_ablations(self, scenario: BenchmarkScenario) -> None:
        unstable = sorted(
            {
                str(item.get("toggle") or "")
                for item in scenario.ablations
                if str(item.get("toggle") or "") not in self.stable_toggles
            }
        )
        if unstable:
            raise BenchmarkSchemaError(
                "unstable_ablation_toggle:" + ",".join(unstable)
            )

    @staticmethod
    def _ground_truth_metrics(
        scenario: BenchmarkScenario,
        result: Mapping[str, Any],
    ) -> dict[str, float]:
        expected = set(_string_tuple(scenario.ground_truth.get("expected_findings") or []))
        forbidden = set(_string_tuple(scenario.ground_truth.get("forbidden_findings") or []))
        reported = set(_string_tuple(result.get("reported_findings") or []))
        true_positive = len(expected & reported)
        false_positive = len(reported - expected)
        forbidden_hits = len(forbidden & reported)
        return {
            "finding_precision": _rate(true_positive, true_positive + false_positive, empty=1.0),
            "finding_recall": _rate(true_positive, len(expected), empty=1.0),
            "forbidden_finding_rate": _rate(forbidden_hits, len(forbidden), empty=0.0),
        }

    @staticmethod
    def _aggregate_metrics(
        runs: Sequence[BenchmarkRun],
    ) -> dict[str, dict[str, float]]:
        names = sorted({name for run in runs for name in run.metrics})
        statistics_by_name: dict[str, dict[str, float]] = {}
        for name in names:
            values = [
                float(run.metrics[name])
                for run in runs
                if run.status == "succeeded" and name in run.metrics
            ]
            if not values:
                continue
            statistics_by_name[name] = {
                "count": float(len(values)),
                "median": round(float(statistics.median(values)), 6),
                "variance": round(float(statistics.pvariance(values)), 6),
                "minimum": round(min(values), 6),
                "maximum": round(max(values), 6),
            }
        return statistics_by_name


def _stable_id(namespace: str, payload: Any) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8", "replace")
    return f"{namespace}://sha256/{hashlib.sha256(encoded).hexdigest()}"


def _string_tuple(values: Any) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        values = [values]
    if not isinstance(values, Sequence):
        return ()
    return tuple(dict.fromkeys(str(item)[:4_096] for item in values[:256] if str(item)))


def _bounded_metadata(value: Any, *, depth: int = 0) -> Any:
    if depth >= 4:
        return "[depth-bounded]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        return {
            str(key)[:128]: _bounded_metadata(item, depth=depth + 1)
            for key, item in list(value.items())[:64]
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [
            _bounded_metadata(item, depth=depth + 1)
            for item in value[:64]
        ]
    return str(value)[:4_096]


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _optional_timestamp(value: Any) -> float | None:
    if not _is_number(value):
        return None
    parsed = float(value)
    return parsed if parsed >= 0 else None


def _optional_error_class(value: Any) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    return candidate if _ERROR_CLASS.fullmatch(candidate) else "InvalidRunnerErrorClass"


def _nonnegative_number(value: Any, *, default: float = 0.0) -> float:
    if not _is_number(value):
        return round(float(default), 6)
    parsed = float(value)
    return round(parsed if parsed >= 0 else 0.0, 6)


def _rate(numerator: int, denominator: int, *, empty: float) -> float:
    if denominator <= 0:
        return empty
    return round(float(numerator) / float(denominator), 6)


__all__ = ["BenchmarkHarness", "BenchmarkRunner"]
