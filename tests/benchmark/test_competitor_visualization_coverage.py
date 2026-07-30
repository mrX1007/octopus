"""Hermetic branch coverage for deterministic competitor SVG rendering."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from core.benchmarks.competitors import visualization

pytestmark = [pytest.mark.unit, pytest.mark.benchmark]


def _comparison(
    *,
    matrix_id: str = "fixture-matrix",
    repetitions: int = 1,
    status_counts: dict[str, int] | None = None,
) -> dict[str, object]:
    return {
        "matrix_id": matrix_id,
        "repetitions": repetitions,
        "systems": [{"system_id": "fixture-system"}],
        "scenarios": [{"scenario_id": "fixture-scenario"}],
        "summaries": [
            {
                "system_id": "fixture-system",
                "scenario_id": "fixture-scenario",
                "status_counts": status_counts or {"succeeded": repetitions},
            }
        ],
    }


def _statistics(**overrides: object) -> dict[tuple[str, str], dict[str, object]]:
    values: dict[str, object] = {}
    values.update(overrides)
    return {("fixture-system", "fixture-scenario"): values}


def test_rendering_contract_and_metric_statistics_extraction() -> None:
    assert visualization.comparison_renderings_contract() == {
        "comparison_svg": {
            "media_type": "image/svg+xml",
            "normative": False,
            "path": "comparison.svg",
            "quality_population": "succeeded",
            "renderer_version": "1.0",
        }
    }

    statistic = {"finding_precision": {"count": 0}}
    aggregate = SimpleNamespace(metric_statistics=statistic)
    assert visualization.metric_statistics_by_pair({1: {2: aggregate}, "empty": {}}) == {("1", "2"): statistic}
    assert visualization.metric_statistics_by_pair({}) == {}

    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="invalid_metric_statistics",
    ):
        visualization.metric_statistics_by_pair({"system": {"scenario": SimpleNamespace(metric_statistics=[])}})


def test_renderer_preserves_all_outcomes_and_quality_population_semantics() -> None:
    comparison = _comparison(
        matrix_id='fixture<&"',
        repetitions=6,
        status_counts={
            "succeeded": 1,
            "failed": 1,
            "timeout": 1,
            "partial": 1,
            "invalid": 1,
            "cancelled": 1,
        },
    )
    comparison["systems"] = [{"system_id": "fixture<&-system"}]
    comparison["summaries"] = [
        {
            "system_id": "fixture<&-system",
            "scenario_id": "fixture-scenario",
            "status_counts": comparison["summaries"][0]["status_counts"],
        }
    ]
    comparison["methodology"] = {
        "execution_mode": "replay",
        "track": "framework-only",
        "fairness_profile": {
            "profile_id": "fixture-profile",
            "same_model": True,
            "same_hardware": False,
            "same_tool_versions": None,
            "same_budgets": "unknown",
        },
    }
    statistics = {
        ("fixture<&-system", "fixture-scenario"): {
            "finding_precision": {
                "count": 1,
                "minimum": 0.1,
                "median": 0.5,
                "maximum": 0.9,
            },
            "finding_recall": {
                "count": 1,
                "minimum": -1,
                "median": -0.5,
                "maximum": 0,
            },
            "evidence_completeness": {"count": 0},
            "forbidden_finding_rate": None,
        }
    }

    rendered = visualization.render_comparison_svg(comparison, statistics)

    assert "fixture&lt;&amp;&quot;" in rendered
    assert "fixture&lt;&amp;-system" in rendered
    assert "succeeded 1 | failed 1 | timeout 1 | partial 1 | invalid 1 | other 1" in rendered
    assert "-0.500 outside 0-1, n=1" in rendered
    assert "0.500 [0.100-0.900], n=1" in rendered
    assert rendered.count("N/A, n=0") == 2
    assert "same model: yes" in rendered
    assert "same hardware: no" in rendered
    assert "same tools: unspecified" in rendered
    assert "same budgets: unspecified" in rendered


def test_renderer_uses_unspecified_methodology_defaults() -> None:
    rendered = visualization.render_comparison_svg(_comparison(), _statistics())

    assert "Execution: unspecified" in rendered
    assert "Track: unspecified" in rendered
    assert "Fairness: unspecified" in rendered
    assert "other 0" not in rendered


def test_renderer_rejects_missing_identity_and_incomplete_rows() -> None:
    missing_matrix = _comparison(matrix_id="")
    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="missing_matrix_id",
    ):
        visualization.render_comparison_svg(missing_matrix, _statistics())

    missing_summary = _comparison()
    missing_summary["summaries"] = []
    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="incomplete_comparison_rows",
    ):
        visualization.render_comparison_svg(missing_summary, _statistics())

    missing_statistics = _comparison()
    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="incomplete_comparison_rows",
    ):
        visualization.render_comparison_svg(missing_statistics, {})


def test_renderer_enforces_encoded_size_limit(monkeypatch) -> None:
    original_xml = visualization._xml

    def oversized_matrix_id(value: object) -> str:
        if value == "oversized":
            return "x" * 2_097_153
        return original_xml(value)

    monkeypatch.setattr(visualization, "_xml", oversized_matrix_id)

    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="comparison_svg_too_large",
    ):
        visualization.render_comparison_svg(
            _comparison(matrix_id="oversized"),
            _statistics(),
        )


@pytest.mark.parametrize(
    ("value", "field", "error"),
    [
        ([], "system_id", "missing_system_id"),
        ([{}], "system_id", "invalid_system_id"),
        (
            [{"system_id": "same"}, {"system_id": "same"}],
            "system_id",
            "invalid_system_id",
        ),
    ],
)
def test_identity_items_reject_missing_and_duplicate_ids(value, field, error) -> None:
    with pytest.raises(visualization.ComparisonVisualizationError, match=error):
        visualization._identity_items(value, field)


@pytest.mark.parametrize(
    "value",
    [
        [{}],
        [
            {"system_id": "same", "scenario_id": "same"},
            {"system_id": "same", "scenario_id": "same"},
        ],
    ],
)
def test_summary_items_reject_missing_and_duplicate_identity(value) -> None:
    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="invalid_summary_identity",
    ):
        visualization._summary_items(value)


@pytest.mark.parametrize("value", [None, "text", b"bytes"])
def test_mapping_sequence_rejects_non_collections(value) -> None:
    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="expected_mapping_sequence",
    ):
        visualization._mapping_sequence(value)


def test_mapping_sequence_rejects_non_mapping_members() -> None:
    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="expected_mapping_sequence",
    ):
        visualization._mapping_sequence([{}, object()])


def test_integer_helpers_reject_boolean_conversion_and_bounds() -> None:
    for value in (True, None, "1", 1.5, -1):
        with pytest.raises(
            visualization.ComparisonVisualizationError,
            match="expected_nonnegative_integer",
        ):
            visualization._nonnegative_integer(value)

    assert visualization._nonnegative_integer(1.0) == 1
    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="expected_positive_integer",
    ):
        visualization._positive_integer(0)


def test_status_counts_reject_shape_and_total_but_preserve_other() -> None:
    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="invalid_status_counts",
    ):
        visualization._status_counts([], 1)

    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="status_count_total_mismatch",
    ):
        visualization._status_counts({"succeeded": 0}, 1)

    assert visualization._status_counts({"custom": 1}, 1)["other"] == 1


def test_quality_statistic_zero_count_and_non_mapping_are_missing() -> None:
    assert visualization._quality_statistic(None, succeeded=0) is None
    assert visualization._quality_statistic({"count": 0}, succeeded=0) is None


@pytest.mark.parametrize(
    ("statistic", "error"),
    [
        (
            {"count": 2, "minimum": 0, "median": 0.5, "maximum": 1},
            "metric_count_exceeds_successes",
        ),
        ({"count": 1}, "invalid_quality_statistic"),
        (
            {"count": 1, "minimum": "bad", "median": 0.5, "maximum": 1},
            "invalid_quality_statistic",
        ),
        (
            {"count": 1, "minimum": 0, "median": float("inf"), "maximum": 1},
            "invalid_quality_statistic",
        ),
        (
            {"count": 1, "minimum": 0.8, "median": 0.5, "maximum": 1},
            "invalid_quality_statistic_order",
        ),
    ],
)
def test_quality_statistic_rejects_invalid_population_and_values(
    statistic,
    error,
) -> None:
    with pytest.raises(visualization.ComparisonVisualizationError, match=error):
        visualization._quality_statistic(statistic, succeeded=1)


def test_number_formatting_covers_zero_integer_and_fraction() -> None:
    assert visualization._number(-0.0004) == "0"
    assert visualization._number(2.0) == "2"
    assert visualization._number(2.3456) == "2.346"


def test_renderer_rejects_invalid_status_count_at_public_boundary() -> None:
    comparison = deepcopy(_comparison())
    comparison["summaries"][0]["status_counts"] = None

    with pytest.raises(
        visualization.ComparisonVisualizationError,
        match="invalid_status_counts",
    ):
        visualization.render_comparison_svg(comparison, _statistics())
