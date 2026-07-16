"""Versioned no-op and repeated-task planning replay.

This benchmark compares the former risk/cost-only ordering profile with the
shipped configurable :class:`~core.ai.task_scoring.TaskScorer`.  It is a
deterministic planner-frontier replay, not a claim about an external lab scan.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from config import DEFAULTS
from core.ai.task_scoring import (
    TASK_SCORING_SCHEMA_VERSION,
    TaskScorer,
    TaskScoringSignals,
    TaskScoringWeights,
)

TASK_EFFICIENCY_SCHEMA_VERSION = "1.0"
TASK_EFFICIENCY_SCENARIO_VERSION = "mission-frontier-replay-v1"
_ROUNDS = 6
_SELECTION_WIDTH = 2


@dataclass(frozen=True)
class _Candidate:
    task_id: str
    signals: TaskScoringSignals
    known_noop: bool

    def with_history(self, selected_before: set[str]) -> TaskScoringSignals:
        values = self.signals.to_dict()
        values["repeat"] = 1.0 if self.task_id in selected_before else 0.0
        return TaskScoringSignals(**values)


def run_task_efficiency_comparison(
    config: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay a fixed frontier and return deterministic comparison evidence."""

    configured = TaskScorer.from_config(DEFAULTS if config is None else config)
    baseline = TaskScorer(
        TaskScoringWeights(
            information_gain=0.0,
            coverage_value=0.0,
            verification_value=0.0,
            path_value=0.0,
            cost=1.0,
            repeat=0.0,
            risk=1.0,
            uncertainty=0.0,
        )
    )
    profiles = {
        "baseline": _replay_profile(
            "legacy-risk-time-cost-v1",
            baseline,
        ),
        "configured": _replay_profile(
            f"task-scoring-{TASK_SCORING_SCHEMA_VERSION}",
            configured,
        ),
    }
    baseline_metrics = profiles["baseline"]["metrics"]
    configured_metrics = profiles["configured"]["metrics"]
    payload: dict[str, Any] = {
        "schema_version": TASK_EFFICIENCY_SCHEMA_VERSION,
        "scenario_version": TASK_EFFICIENCY_SCENARIO_VERSION,
        "method": "deterministic_task_scorer_frontier_replay",
        "scope": (
            "Planner-selection replay over recorded candidate frontiers; "
            "no scanner, network, model provider, or external tool is invoked."
        ),
        "definitions": {
            "no_op_task": "A selected candidate marked known_noop in the recorded frontier.",
            "repeated_task": "A selected task ID that was selected in an earlier replay round.",
        },
        "input": {
            "rounds": _ROUNDS,
            "selection_width": _SELECTION_WIDTH,
            "candidates_per_round": 4,
        },
        "profiles": profiles,
        "reduction": {
            "no_op_tasks": int(
                baseline_metrics["no_op_tasks"]
                - configured_metrics["no_op_tasks"]
            ),
            "repeated_tasks": int(
                baseline_metrics["repeated_tasks"]
                - configured_metrics["repeated_tasks"]
            ),
            "no_op_rate_absolute": _round(
                baseline_metrics["no_op_rate"]
                - configured_metrics["no_op_rate"]
            ),
            "repeated_task_rate_absolute": _round(
                baseline_metrics["repeated_task_rate"]
                - configured_metrics["repeated_task_rate"]
            ),
            "no_op_rate_relative": _relative_reduction(
                baseline_metrics["no_op_rate"],
                configured_metrics["no_op_rate"],
            ),
            "repeated_task_rate_relative": _relative_reduction(
                baseline_metrics["repeated_task_rate"],
                configured_metrics["repeated_task_rate"],
            ),
        },
    }
    payload["comparison_id"] = _stable_id(payload)
    return payload


def write_task_efficiency_comparison(
    path: str | Path,
    config: Mapping[str, Any] | None = None,
) -> Path:
    """Atomically write the reproducible comparison document."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(
            run_task_efficiency_comparison(config),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, destination)
    return destination


def _replay_profile(
    profile_id: str,
    scorer: TaskScorer,
) -> dict[str, Any]:
    selected_before: set[str] = set()
    rounds: list[dict[str, Any]] = []
    selected_count = 0
    no_op_count = 0
    repeat_count = 0
    for round_number in range(1, _ROUNDS + 1):
        candidates = _frontier(round_number)
        candidates_by_id = {item.task_id: item for item in candidates}
        ranked = scorer.rank(
            (
                candidate.task_id,
                candidate.with_history(selected_before),
            )
            for candidate in candidates
        )
        selection = []
        for scored in ranked[:_SELECTION_WIDTH]:
            candidate = candidates_by_id[scored.task_id]
            repeated = scored.task_id in selected_before
            selected_count += 1
            no_op_count += int(candidate.known_noop)
            repeat_count += int(repeated)
            selection.append(
                {
                    "task_id": scored.task_id,
                    "score": scored.score,
                    "known_noop": candidate.known_noop,
                    "repeated": repeated,
                }
            )
        selected_before.update(str(item["task_id"]) for item in selection)
        rounds.append({"round": round_number, "selected": selection})

    return {
        "profile_id": profile_id,
        "weights": scorer.weights.to_dict(),
        "metrics": {
            "selected_tasks": selected_count,
            "no_op_tasks": no_op_count,
            "repeated_tasks": repeat_count,
            "no_op_rate": _rate(no_op_count, selected_count),
            "repeated_task_rate": _rate(repeat_count, selected_count),
        },
        "rounds": rounds,
    }


def _frontier(round_number: int) -> tuple[_Candidate, ...]:
    """Return two stale low-cost tasks and two useful frontier tasks."""

    return (
        _Candidate(
            "cached_external_intelligence",
            TaskScoringSignals(
                information_gain=0.05,
                cost=0.05,
                risk=0.02,
                uncertainty=0.1,
            ),
            known_noop=True,
        ),
        _Candidate(
            "unchanged_plugin_assessment",
            TaskScoringSignals(
                information_gain=0.1,
                coverage_value=0.05,
                verification_value=0.1,
                path_value=0.1,
                cost=0.1,
                risk=0.05,
                uncertainty=0.2,
            ),
            known_noop=True,
        ),
        _Candidate(
            f"verify_service_state_{round_number}",
            TaskScoringSignals(
                information_gain=0.8,
                coverage_value=0.8,
                verification_value=1.0,
                path_value=0.5,
                cost=0.35,
                risk=0.2,
                uncertainty=0.1,
            ),
            known_noop=False,
        ),
        _Candidate(
            f"map_open_coverage_{round_number}",
            TaskScoringSignals(
                information_gain=0.9,
                coverage_value=1.0,
                verification_value=0.4,
                path_value=0.6,
                cost=0.4,
                risk=0.15,
                uncertainty=0.2,
            ),
            known_noop=False,
        ),
    )


def _stable_id(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"task-efficiency://sha256/{hashlib.sha256(encoded).hexdigest()}"


def _rate(numerator: int, denominator: int) -> float:
    return _round(float(numerator) / float(denominator)) if denominator else 0.0


def _relative_reduction(baseline: float, configured: float) -> float:
    if baseline <= 0:
        return 0.0
    return _round((baseline - configured) / baseline)


def _round(value: float) -> float:
    return round(float(value), 6)


__all__ = [
    "TASK_EFFICIENCY_SCENARIO_VERSION",
    "TASK_EFFICIENCY_SCHEMA_VERSION",
    "run_task_efficiency_comparison",
    "write_task_efficiency_comparison",
]
