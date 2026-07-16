"""Deterministic, configuration-owned scoring for mission task candidates.

The scorer is intentionally pure: callers derive bounded signals from current
mission state, while this module applies configured weights and produces a
stable explanation suitable for a decision trace.  It never executes a task or
grants execution permission.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields
from typing import Any, ClassVar

TASK_SCORING_SCHEMA_VERSION = "1.0"

_REWARD_FACTORS = (
    "information_gain",
    "coverage_value",
    "verification_value",
    "path_value",
)
_PENALTY_FACTORS = (
    "cost",
    "repeat",
    "risk",
    "uncertainty",
)
_FACTOR_ORDER = _REWARD_FACTORS + _PENALTY_FACTORS


class TaskScoringConfigError(ValueError):
    """Raised when task-scoring configuration is missing or invalid."""


class TaskScoringSignalError(ValueError):
    """Raised when a candidate supplies an invalid normalized signal."""


def _finite_number(value: Any, *, label: str, error: type[ValueError]) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise error(f"{label} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        raise error(f"{label} must be a finite number")
    return number


@dataclass(frozen=True)
class TaskScoringWeights:
    """Configured reward and penalty weights; no implicit defaults live here."""

    information_gain: float
    coverage_value: float
    verification_value: float
    path_value: float
    cost: float
    repeat: float
    risk: float
    uncertainty: float

    CONFIG_PATH: ClassVar[tuple[str, ...]] = ("strategy", "task_scoring")

    def __post_init__(self) -> None:
        for item in fields(self):
            value = _finite_number(
                getattr(self, item.name),
                label=f"task scoring weight {item.name}",
                error=TaskScoringConfigError,
            )
            if not 0.0 <= value <= 1_000.0:
                raise TaskScoringConfigError(
                    f"task scoring weight {item.name} must be between 0 and 1000"
                )
            object.__setattr__(self, item.name, value)

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> TaskScoringWeights:
        """Load every weight from ``strategy.task_scoring.weights``.

        Missing or misspelled weights are rejected instead of being silently
        replaced with code defaults.  Application defaults belong to
        ``config.DEFAULTS`` and the shipped ``config.yaml``.
        """

        current: Any = config
        traversed: list[str] = []
        for key in cls.CONFIG_PATH:
            traversed.append(key)
            if not isinstance(current, Mapping) or key not in current:
                raise TaskScoringConfigError(
                    f"missing task scoring config: {'.'.join(traversed)}"
                )
            current = current[key]
        if not isinstance(current, Mapping):
            raise TaskScoringConfigError(
                f"{'.'.join(cls.CONFIG_PATH)} must be a mapping"
            )

        schema_version = current.get("schema_version")
        if schema_version != TASK_SCORING_SCHEMA_VERSION:
            raise TaskScoringConfigError(
                "unsupported task scoring schema version: "
                f"{schema_version!r}; expected {TASK_SCORING_SCHEMA_VERSION!r}"
            )
        if "weights" not in current:
            raise TaskScoringConfigError(
                f"missing task scoring config: {'.'.join(cls.CONFIG_PATH)}.weights"
            )
        current = current["weights"]
        if not isinstance(current, Mapping):
            raise TaskScoringConfigError(
                f"{'.'.join(cls.CONFIG_PATH)}.weights must be a mapping"
            )

        missing = [name for name in _FACTOR_ORDER if name not in current]
        if missing:
            raise TaskScoringConfigError(
                "missing task scoring weights: " + ", ".join(missing)
            )
        unknown = sorted(str(name) for name in current if name not in _FACTOR_ORDER)
        if unknown:
            raise TaskScoringConfigError(
                "unknown task scoring weights: " + ", ".join(unknown)
            )
        return cls(**{name: current[name] for name in _FACTOR_ORDER})

    def to_dict(self) -> dict[str, float]:
        return {name: getattr(self, name) for name in _FACTOR_ORDER}


@dataclass(frozen=True)
class TaskScoringSignals:
    """Normalized task value and penalty signals in the inclusive range 0..1."""

    information_gain: float = 0.0
    coverage_value: float = 0.0
    verification_value: float = 0.0
    path_value: float = 0.0
    cost: float = 0.0
    repeat: float = 0.0
    risk: float = 0.0
    uncertainty: float = 0.0

    def __post_init__(self) -> None:
        for item in fields(self):
            value = _finite_number(
                getattr(self, item.name),
                label=f"task scoring signal {item.name}",
                error=TaskScoringSignalError,
            )
            if not 0.0 <= value <= 1.0:
                raise TaskScoringSignalError(
                    f"task scoring signal {item.name} must be between 0 and 1"
                )
            object.__setattr__(self, item.name, value)

    def to_dict(self) -> dict[str, float]:
        return {name: getattr(self, name) for name in _FACTOR_ORDER}


@dataclass(frozen=True)
class TaskScoreComponent:
    name: str
    kind: str
    signal: float
    weight: float
    contribution: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "signal": self.signal,
            "weight": self.weight,
            "contribution": self.contribution,
        }


@dataclass(frozen=True)
class TaskScore:
    task_id: str
    score: float
    components: tuple[TaskScoreComponent, ...]
    explanation: str
    schema_version: str = TASK_SCORING_SCHEMA_VERSION

    def to_trace_dict(self) -> dict[str, Any]:
        """Return a stable, audit-safe explanation for decision telemetry."""

        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "score": self.score,
            "components": [component.to_dict() for component in self.components],
            "explanation": self.explanation,
        }


class TaskScorer:
    """Apply configured weights and rank candidates with a stable tie-break."""

    def __init__(self, weights: TaskScoringWeights) -> None:
        self.weights = weights

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> TaskScorer:
        return cls(TaskScoringWeights.from_config(config))

    def score(self, task_id: str, signals: TaskScoringSignals) -> TaskScore:
        safe_task_id = str(task_id).strip()
        if not safe_task_id:
            raise TaskScoringSignalError("task_id must not be empty")
        if len(safe_task_id.encode("utf-8")) > 4_096:
            raise TaskScoringSignalError("task_id exceeds 4096 bytes")

        components: list[TaskScoreComponent] = []
        for name in _FACTOR_ORDER:
            kind = "reward" if name in _REWARD_FACTORS else "penalty"
            direction = 1.0 if kind == "reward" else -1.0
            signal = getattr(signals, name)
            weight = getattr(self.weights, name)
            contribution = round(direction * signal * weight, 6)
            components.append(
                TaskScoreComponent(
                    name=name,
                    kind=kind,
                    signal=round(signal, 6),
                    weight=round(weight, 6),
                    contribution=contribution,
                )
            )

        total = round(math.fsum(item.contribution for item in components), 6)
        explanation = ";".join(
            [f"task_score:{TASK_SCORING_SCHEMA_VERSION}", f"total={total:.6f}"]
            + [
                (
                    f"{item.name}={item.kind}({item.signal:.6f}*"
                    f"{item.weight:.6f})={item.contribution:+.6f}"
                )
                for item in components
            ]
        )
        return TaskScore(
            task_id=safe_task_id,
            score=total,
            components=tuple(components),
            explanation=explanation,
        )

    def rank(
        self,
        candidates: Iterable[tuple[str, TaskScoringSignals]],
    ) -> tuple[TaskScore, ...]:
        """Score candidates descending, breaking exact ties by task ID."""

        scored: list[TaskScore] = []
        seen: set[str] = set()
        for task_id, signals in candidates:
            score = self.score(task_id, signals)
            if score.task_id in seen:
                raise TaskScoringSignalError(
                    f"duplicate task_id in scoring batch: {score.task_id}"
                )
            seen.add(score.task_id)
            scored.append(score)
        return tuple(sorted(scored, key=lambda item: (-item.score, item.task_id)))


__all__ = [
    "TASK_SCORING_SCHEMA_VERSION",
    "TaskScore",
    "TaskScoreComponent",
    "TaskScorer",
    "TaskScoringConfigError",
    "TaskScoringSignalError",
    "TaskScoringSignals",
    "TaskScoringWeights",
]
