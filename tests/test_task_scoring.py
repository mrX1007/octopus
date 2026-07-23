"""Deterministic mission task scoring contracts."""

from __future__ import annotations

import json

import pytest

from config import CFG, DEFAULTS
from core.ai.task_scoring import (
    TaskScorer,
    TaskScoringConfigError,
    TaskScoringSignalError,
    TaskScoringSignals,
    TaskScoringWeights,
)

pytestmark = pytest.mark.unit


def scoring_config(**overrides: float) -> dict:
    weights = {
        "information_gain": 1.0,
        "coverage_value": 1.0,
        "verification_value": 1.0,
        "path_value": 1.0,
        "cost": 1.0,
        "repeat": 1.0,
        "risk": 1.0,
        "uncertainty": 1.0,
    }
    weights.update(overrides)
    return {
        "strategy": {
            "task_scoring": {
                "schema_version": "1.0",
                "weights": weights,
            }
        }
    }


def test_shipped_and_builtin_configuration_define_every_weight():
    shipped = TaskScoringWeights.from_config(CFG)
    builtin = TaskScoringWeights.from_config(DEFAULTS)

    assert shipped == builtin
    assert tuple(shipped.to_dict()) == (
        "information_gain",
        "coverage_value",
        "verification_value",
        "path_value",
        "cost",
        "repeat",
        "risk",
        "uncertainty",
    )


def test_score_has_all_rewards_penalties_and_stable_trace_explanation():
    scorer = TaskScorer.from_config(
        scoring_config(
            information_gain=4.0,
            coverage_value=3.0,
            verification_value=2.0,
            path_value=1.0,
            cost=2.0,
            repeat=3.0,
            risk=4.0,
            uncertainty=5.0,
        )
    )
    signals = TaskScoringSignals(
        information_gain=0.5,
        coverage_value=0.4,
        verification_value=0.3,
        path_value=0.2,
        cost=0.1,
        repeat=0.2,
        risk=0.3,
        uncertainty=0.4,
    )

    first = scorer.score("service_discovery", signals)
    second = scorer.score("service_discovery", signals)

    assert first == second
    assert first.score == pytest.approx(0.0)
    assert [item.name for item in first.components] == list(signals.to_dict())
    assert [item.kind for item in first.components] == [
        "reward",
        "reward",
        "reward",
        "reward",
        "penalty",
        "penalty",
        "penalty",
        "penalty",
    ]
    assert [item.contribution for item in first.components] == [
        2.0,
        1.2,
        0.6,
        0.2,
        -0.2,
        -0.6,
        -1.2,
        -2.0,
    ]
    expected_explanation = (
        "task_score:1.0;total=0.000000;"
        "information_gain=reward(0.500000*4.000000)=+2.000000;"
        "coverage_value=reward(0.400000*3.000000)=+1.200000;"
        "verification_value=reward(0.300000*2.000000)=+0.600000;"
        "path_value=reward(0.200000*1.000000)=+0.200000;"
        "cost=penalty(0.100000*2.000000)=-0.200000;"
        "repeat=penalty(0.200000*3.000000)=-0.600000;"
        "risk=penalty(0.300000*4.000000)=-1.200000;"
        "uncertainty=penalty(0.400000*5.000000)=-2.000000"
    )
    assert first.explanation == expected_explanation
    assert json.dumps(first.to_trace_dict(), sort_keys=True) == json.dumps(
        second.to_trace_dict(), sort_keys=True
    )


def test_weights_come_from_config_and_change_ranking_without_code_changes():
    candidates = (
        (
            "high-information-high-cost",
            TaskScoringSignals(information_gain=1.0, cost=1.0),
        ),
        (
            "lower-information-low-cost",
            TaskScoringSignals(information_gain=0.5, cost=0.0),
        ),
    )

    value_first = TaskScorer.from_config(
        scoring_config(information_gain=4.0, cost=1.0)
    ).rank(candidates)
    cost_first = TaskScorer.from_config(
        scoring_config(information_gain=1.0, cost=4.0)
    ).rank(candidates)

    assert value_first[0].task_id == "high-information-high-cost"
    assert cost_first[0].task_id == "lower-information-low-cost"


def test_ranking_uses_task_id_as_stable_tie_break_and_rejects_duplicates():
    scorer = TaskScorer.from_config(scoring_config())
    neutral = TaskScoringSignals()

    ranked = scorer.rank((("task-z", neutral), ("task-a", neutral)))

    assert [item.task_id for item in ranked] == ["task-a", "task-z"]
    with pytest.raises(TaskScoringSignalError, match="duplicate task_id"):
        scorer.rank((("same", neutral), ("same", neutral)))


@pytest.mark.parametrize(
    "config, message",
    [
        ({}, "missing task scoring config: strategy"),
        (
            {
                "strategy": {
                    "task_scoring": {
                        "schema_version": "1.0",
                        "weights": {"information_gain": 1.0},
                    }
                }
            },
            "missing task scoring weights",
        ),
        (
            scoring_config(unexpected=1.0),
            "unknown task scoring weights: unexpected",
        ),
        (
            scoring_config(cost=-1.0),
            "task scoring weight cost must be between 0 and 1000",
        ),
        (
            {
                "strategy": {
                    "task_scoring": {
                        "schema_version": "2.0",
                        "weights": {},
                    }
                }
            },
            "unsupported task scoring schema version",
        ),
    ],
)
def test_invalid_or_partial_weight_configuration_fails_closed(config, message):
    with pytest.raises(TaskScoringConfigError, match=message):
        TaskScorer.from_config(config)


@pytest.mark.parametrize(
    "signals, message",
    [
        ({"information_gain": 1.01}, "information_gain must be between 0 and 1"),
        ({"risk": -0.01}, "risk must be between 0 and 1"),
        ({"cost": float("nan")}, "cost must be a finite number"),
        ({"repeat": True}, "repeat must be a finite number"),
    ],
)
def test_invalid_signals_fail_closed(signals, message):
    with pytest.raises(TaskScoringSignalError, match=message):
        TaskScoringSignals(**signals)
