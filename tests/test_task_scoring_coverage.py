"""Remaining validation boundaries for deterministic task scoring."""

from __future__ import annotations

import pytest

from core.ai.task_scoring import (
    TaskScorer,
    TaskScoringConfigError,
    TaskScoringSignalError,
    TaskScoringSignals,
    TaskScoringWeights,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"strategy": {"task_scoring": []}}, "task_scoring must be a mapping"),
        (
            {"strategy": {"task_scoring": {"schema_version": "1.0"}}},
            "task_scoring.weights",
        ),
        (
            {
                "strategy": {
                    "task_scoring": {
                        "schema_version": "1.0",
                        "weights": [],
                    }
                }
            },
            "weights must be a mapping",
        ),
    ],
)
def test_nested_configuration_shapes_are_required(config, message):
    with pytest.raises(TaskScoringConfigError, match=message):
        TaskScoringWeights.from_config(config)


def test_task_identifier_must_be_nonempty_and_bounded():
    scorer = TaskScorer(
        TaskScoringWeights(
            information_gain=1,
            coverage_value=1,
            verification_value=1,
            path_value=1,
            cost=1,
            repeat=1,
            risk=1,
            uncertainty=1,
        )
    )

    with pytest.raises(TaskScoringSignalError, match="must not be empty"):
        scorer.score("  ", TaskScoringSignals())
    with pytest.raises(TaskScoringSignalError, match="exceeds 4096 bytes"):
        scorer.score("x" * 4_097, TaskScoringSignals())
