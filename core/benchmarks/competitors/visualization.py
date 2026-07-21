"""Deterministic, non-normative SVG rendering for competitor comparisons."""

from __future__ import annotations

import html
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

COMPARISON_SVG_PATH = "comparison.svg"
COMPARISON_SVG_RENDERER_VERSION = "1.0"

_WIDTH = 1200
_OUTCOME_X = 200
_OUTCOME_WIDTH = 520
_QUALITY_X = 190
_QUALITY_COLUMN_WIDTH = 243
_QUALITY_AXIS_WIDTH = 142
_STATUS_ORDER = (
    ("succeeded", "Succeeded", "#0072B2"),
    ("failed", "Failed", "#D55E00"),
    ("timeout", "Timeout", "#E69F00"),
    ("partial", "Partial", "#CC79A7"),
    ("invalid", "Invalid", "#666666"),
)
_QUALITY_METRICS = (
    ("finding_precision", "Precision (higher)"),
    ("finding_recall", "Recall (higher)"),
    ("evidence_completeness", "Evidence (higher)"),
    ("forbidden_finding_rate", "Forbidden rate (lower)"),
)


class ComparisonVisualizationError(ValueError):
    """A comparison cannot be rendered without dropping or distorting data."""


def comparison_renderings_contract() -> dict[str, dict[str, Any]]:
    """Return the exact additive rendering declaration used by new bundles."""

    return {
        "comparison_svg": {
            "media_type": "image/svg+xml",
            "normative": False,
            "path": COMPARISON_SVG_PATH,
            "quality_population": "succeeded",
            "renderer_version": COMPARISON_SVG_RENDERER_VERSION,
        }
    }


def metric_statistics_by_pair(
    aggregates: Mapping[str, Mapping[str, Any]],
) -> dict[tuple[str, str], Mapping[str, Any]]:
    """Extract aggregate statistics without depending on their concrete class."""

    result: dict[tuple[str, str], Mapping[str, Any]] = {}
    for system_id, scenarios in aggregates.items():
        for scenario_id, aggregate in scenarios.items():
            statistics = getattr(aggregate, "metric_statistics", None)
            if not isinstance(statistics, Mapping):
                raise ComparisonVisualizationError("invalid_metric_statistics")
            result[(str(system_id), str(scenario_id))] = statistics
    return result


def render_comparison_svg(
    comparison: Mapping[str, Any],
    metric_statistics: Mapping[tuple[str, str], Mapping[str, Any]],
) -> str:
    """Render canonical SVG bytes from public comparison and aggregate statistics."""

    matrix_id = str(comparison.get("matrix_id") or "")
    if not matrix_id:
        raise ComparisonVisualizationError("missing_matrix_id")
    repetitions = _positive_integer(comparison.get("repetitions"))
    systems = _identity_items(comparison.get("systems"), "system_id")
    scenarios = _identity_items(comparison.get("scenarios"), "scenario_id")
    summaries = _summary_items(comparison.get("summaries"))
    expected_pairs = {
        (system_id, scenario_id)
        for scenario_id, _scenario in scenarios
        for system_id, _system in systems
    }
    if set(summaries) != expected_pairs or set(metric_statistics) != expected_pairs:
        raise ComparisonVisualizationError("incomplete_comparison_rows")

    rows_per_scenario = len(systems)
    scenario_height = 160 + (rows_per_scenario * 102)
    height = 200 + (len(scenarios) * scenario_height) + 82
    methodology = comparison.get("methodology")
    methodology = methodology if isinstance(methodology, Mapping) else {}
    fairness = methodology.get("fairness_profile")
    fairness = fairness if isinstance(fairness, Mapping) else {}

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{_WIDTH}" '
            f'height="{height}" viewBox="0 0 {_WIDTH} {height}" role="img" '
            'aria-labelledby="chart-title chart-desc">'
        ),
        "  <title id=\"chart-title\">Competitor benchmark terminal outcomes and success-only quality</title>",
        (
            "  <desc id=\"chart-desc\">Terminal outcomes include every scheduled "
            "run. Quality statistics include successful runs only, with a separate "
            "sample count for each metric. Missing telemetry is not zero. No overall "
            "score or winner is declared.</desc>"
        ),
        "  <metadata>"
        + _xml(
            json.dumps(
                {
                    "matrix_id": matrix_id,
                    "quality_metrics": [name for name, _label in _QUALITY_METRICS],
                    "quality_population": "succeeded",
                    "renderer_version": COMPARISON_SVG_RENDERER_VERSION,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        + "</metadata>",
        "  <rect width=\"1200\" height=\"100%\" fill=\"#ffffff\"/>",
        "  <style>text{font-family:Arial,Helvetica,sans-serif;fill:#17202a}.title{font-size:24px;font-weight:700}.subtitle{font-size:12px;fill:#44515c}.section{font-size:16px;font-weight:700}.label{font-size:12px;font-weight:700}.small{font-size:10px;fill:#44515c}.value{font-size:10px}.grid{stroke:#d7dde2;stroke-width:1}.axis{stroke:#69757f;stroke-width:1.2}.range{stroke:#17202a;stroke-width:3;stroke-linecap:round}</style>",
        "  <text class=\"title\" x=\"36\" y=\"42\">Competitor benchmark comparison</text>",
        f"  <text class=\"subtitle\" x=\"36\" y=\"66\">Matrix: {_xml(matrix_id)}</text>",
        (
            "  <text class=\"subtitle\" x=\"36\" y=\"88\">"
            + _xml(_methodology_line(methodology, fairness, repetitions))
            + "</text>"
        ),
        (
            "  <text class=\"subtitle\" x=\"36\" y=\"108\">"
            + _xml(_fairness_line(fairness))
            + "</text>"
        ),
        "  <text class=\"subtitle\" x=\"36\" y=\"132\">Terminal outcomes include all scheduled runs. Quality uses successful runs only; n is per metric.</text>",
        "  <text class=\"subtitle\" x=\"36\" y=\"152\">Missing telemetry is N/A, never zero. Medians and ranges are descriptive; no combined score or winner is declared.</text>",
        "  <line x1=\"36\" y1=\"171\" x2=\"1164\" y2=\"171\" class=\"grid\"/>",
    ]

    y = 200
    for scenario_id, _scenario in scenarios:
        lines.append(
            f"  <text class=\"section\" x=\"36\" y=\"{y}\">Scenario: {_xml(scenario_id)}</text>"
        )
        y += 28
        lines.append(
            f"  <text class=\"label\" x=\"36\" y=\"{y}\">Terminal outcomes (N={repetitions} per system)</text>"
        )
        y += 22
        for system_id, _system in systems:
            summary = summaries[(system_id, scenario_id)]
            counts = _status_counts(summary.get("status_counts"), repetitions)
            bar_y = y - 14
            lines.append(
                f"  <text class=\"label\" x=\"36\" y=\"{y}\">{_xml(system_id)}</text>"
            )
            cursor = float(_OUTCOME_X)
            for status, _label, color in _STATUS_ORDER:
                count = counts[status]
                width = _OUTCOME_WIDTH * count / repetitions
                if width > 0:
                    lines.append(
                        f'  <rect x="{_number(cursor)}" y="{bar_y}" width="{_number(width)}" height="18" fill="{color}"/>'
                    )
                cursor += width
            other = counts["other"]
            other_width = _OUTCOME_WIDTH * other / repetitions
            if other_width > 0:
                lines.append(
                    f'  <rect x="{_number(cursor)}" y="{bar_y}" width="{_number(other_width)}" height="18" fill="#9aa1a6"/>'
                )
            lines.append(
                f'  <rect x="{_OUTCOME_X}" y="{bar_y}" width="{_OUTCOME_WIDTH}" height="18" fill="none" stroke="#69757f"/>'
            )
            lines.append(
                f"  <text class=\"small\" x=\"734\" y=\"{y}\">{_xml(_outcome_text(counts))}</text>"
            )
            y += 34

        legend_x = _OUTCOME_X
        for _status, label, color in (*_STATUS_ORDER, ("other", "Other", "#9aa1a6")):
            lines.append(
                f'  <rect x="{legend_x}" y="{y - 11}" width="12" height="12" fill="{color}"/>'
            )
            lines.append(
                f"  <text class=\"small\" x=\"{legend_x + 17}\" y=\"{y}\">{_xml(label)}</text>"
            )
            legend_x += 92
        y += 30

        lines.append(
            f"  <text class=\"label\" x=\"36\" y=\"{y}\">Success-only quality: median, min-max range, and per-metric sample count</text>"
        )
        y += 34
        for index, (_metric, label) in enumerate(_QUALITY_METRICS):
            x = _QUALITY_X + index * _QUALITY_COLUMN_WIDTH
            lines.append(
                f"  <text class=\"small\" x=\"{x}\" y=\"{y}\">{_xml(label)}</text>"
            )
        y += 22

        for system_id, _system in systems:
            summary = summaries[(system_id, scenario_id)]
            succeeded = _status_counts(
                summary.get("status_counts"), repetitions
            )["succeeded"]
            lines.append(
                f"  <text class=\"label\" x=\"36\" y=\"{y + 22}\">{_xml(system_id)}</text>"
            )
            lines.append(
                f"  <text class=\"small\" x=\"36\" y=\"{y + 38}\">success {succeeded}/{repetitions}</text>"
            )
            statistics = metric_statistics[(system_id, scenario_id)]
            for index, (metric_name, _label) in enumerate(_QUALITY_METRICS):
                x = _QUALITY_X + index * _QUALITY_COLUMN_WIDTH
                _render_quality_cell(
                    lines,
                    x=x,
                    y=y,
                    statistic=statistics.get(metric_name),
                    succeeded=succeeded,
                )
            y += 68
        y += 24
        lines.append(
            f"  <line x1=\"36\" y1=\"{y - 8}\" x2=\"1164\" y2=\"{y - 8}\" class=\"grid\"/>"
        )

    lines.extend(
        [
            f"  <text class=\"small\" x=\"36\" y=\"{height - 46}\">Outcome bars use the common repetition denominator. Quality excludes failed, timeout, partial, and invalid runs rather than scoring them as zero.</text>",
            f"  <text class=\"small\" x=\"36\" y=\"{height - 27}\">The JSON comparison and full aggregates are normative; this deterministic SVG is a derived presentation.</text>",
            "</svg>",
            "",
        ]
    )
    rendered = "\n".join(lines)
    if len(rendered.encode("utf-8")) > 2_097_152:
        raise ComparisonVisualizationError("comparison_svg_too_large")
    return rendered


def _render_quality_cell(
    lines: list[str],
    *,
    x: int,
    y: int,
    statistic: Any,
    succeeded: int,
) -> None:
    axis_y = y + 24
    lines.append(
        f'  <line x1="{x}" y1="{axis_y}" x2="{x + _QUALITY_AXIS_WIDTH}" y2="{axis_y}" class="axis"/>'
    )
    for fraction, label in ((0.0, "0"), (0.5, ".5"), (1.0, "1")):
        tick_x = x + _QUALITY_AXIS_WIDTH * fraction
        lines.append(
            f'  <line x1="{_number(tick_x)}" y1="{axis_y - 3}" x2="{_number(tick_x)}" y2="{axis_y + 3}" class="grid"/>'
        )
        lines.append(
            f'  <text class="small" x="{_number(tick_x)}" y="{axis_y - 7}" text-anchor="middle">{label}</text>'
        )
    parsed = _quality_statistic(statistic, succeeded=succeeded)
    if parsed is None:
        lines.append(
            f'  <text class="value" x="{x}" y="{y + 50}">N/A, n=0</text>'
        )
        return
    minimum, median, maximum, count = parsed
    if not (0.0 <= minimum <= median <= maximum <= 1.0):
        lines.append(
            f'  <text class="value" x="{x}" y="{y + 50}">{_xml(_metric_number(median))} outside 0-1, n={count}</text>'
        )
        return
    minimum_x = x + _QUALITY_AXIS_WIDTH * minimum
    maximum_x = x + _QUALITY_AXIS_WIDTH * maximum
    median_x = x + _QUALITY_AXIS_WIDTH * median
    lines.append(
        f'  <line x1="{_number(minimum_x)}" y1="{axis_y}" x2="{_number(maximum_x)}" y2="{axis_y}" class="range"/>'
    )
    lines.append(
        f'  <circle cx="{_number(median_x)}" cy="{axis_y}" r="5" fill="#17202a" stroke="#ffffff" stroke-width="1.5"/>'
    )
    lines.append(
        f'  <text class="value" x="{x}" y="{y + 50}">{_metric_number(median)} [{_metric_number(minimum)}-{_metric_number(maximum)}], n={count}</text>'
    )


def _identity_items(value: Any, field: str) -> tuple[tuple[str, Mapping[str, Any]], ...]:
    items = _mapping_sequence(value)
    result: list[tuple[str, Mapping[str, Any]]] = []
    seen: set[str] = set()
    for item in items:
        identifier = str(item.get(field) or "")
        if not identifier or identifier in seen:
            raise ComparisonVisualizationError(f"invalid_{field}")
        seen.add(identifier)
        result.append((identifier, item))
    if not result:
        raise ComparisonVisualizationError(f"missing_{field}")
    return tuple(sorted(result, key=lambda pair: pair[0]))


def _summary_items(value: Any) -> dict[tuple[str, str], Mapping[str, Any]]:
    result: dict[tuple[str, str], Mapping[str, Any]] = {}
    for item in _mapping_sequence(value):
        key = (str(item.get("system_id") or ""), str(item.get("scenario_id") or ""))
        if not all(key) or key in result:
            raise ComparisonVisualizationError("invalid_summary_identity")
        result[key] = item
    return result


def _mapping_sequence(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ComparisonVisualizationError("expected_mapping_sequence")
    if any(not isinstance(item, Mapping) for item in value):
        raise ComparisonVisualizationError("expected_mapping_sequence")
    return tuple(value)


def _positive_integer(value: Any) -> int:
    parsed = _nonnegative_integer(value)
    if parsed <= 0:
        raise ComparisonVisualizationError("expected_positive_integer")
    return parsed


def _nonnegative_integer(value: Any) -> int:
    if isinstance(value, bool):
        raise ComparisonVisualizationError("expected_nonnegative_integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ComparisonVisualizationError("expected_nonnegative_integer") from exc
    if parsed != value or parsed < 0:
        raise ComparisonVisualizationError("expected_nonnegative_integer")
    return parsed


def _status_counts(value: Any, repetitions: int) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise ComparisonVisualizationError("invalid_status_counts")
    counts = {name: 0 for name, _label, _color in _STATUS_ORDER}
    other = 0
    for raw_name, raw_count in value.items():
        name = str(raw_name)
        count = _nonnegative_integer(raw_count)
        if name in counts:
            counts[name] = count
        else:
            other += count
    if sum(counts.values()) + other != repetitions:
        raise ComparisonVisualizationError("status_count_total_mismatch")
    return {**counts, "other": other}


def _quality_statistic(
    value: Any,
    *,
    succeeded: int,
) -> tuple[float, float, float, int] | None:
    if not isinstance(value, Mapping):
        return None
    count = _nonnegative_integer(value.get("count"))
    if count == 0:
        return None
    if count > succeeded:
        raise ComparisonVisualizationError("metric_count_exceeds_successes")
    try:
        minimum = float(value["minimum"])
        median = float(value["median"])
        maximum = float(value["maximum"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ComparisonVisualizationError("invalid_quality_statistic") from exc
    if not all(math.isfinite(item) for item in (minimum, median, maximum)):
        raise ComparisonVisualizationError("invalid_quality_statistic")
    if minimum > median or median > maximum:
        raise ComparisonVisualizationError("invalid_quality_statistic_order")
    return minimum, median, maximum, count


def _methodology_line(
    methodology: Mapping[str, Any],
    fairness: Mapping[str, Any],
    repetitions: int,
) -> str:
    return (
        f"Execution: {methodology.get('execution_mode') or 'unspecified'} | "
        f"Track: {methodology.get('track') or 'unspecified'} | "
        f"Fairness: {fairness.get('profile_id') or 'unspecified'} | "
        f"Repetitions: {repetitions}"
    )


def _fairness_line(fairness: Mapping[str, Any]) -> str:
    flags = (
        ("model", fairness.get("same_model")),
        ("hardware", fairness.get("same_hardware")),
        ("tools", fairness.get("same_tool_versions")),
        ("budgets", fairness.get("same_budgets")),
    )
    return "Fairness controls: " + ", ".join(
        f"same {name}: {'yes' if value is True else 'no' if value is False else 'unspecified'}"
        for name, value in flags
    )


def _outcome_text(counts: Mapping[str, int]) -> str:
    values = [f"{label.lower()} {counts[name]}" for name, label, _color in _STATUS_ORDER]
    if counts["other"]:
        values.append(f"other {counts['other']}")
    return " | ".join(values)


def _metric_number(value: float) -> str:
    return f"{value:.3f}"


def _number(value: float) -> str:
    rounded = round(float(value), 3)
    if rounded == 0:
        return "0"
    if rounded.is_integer():
        return str(int(rounded))
    return f"{rounded:.3f}".rstrip("0").rstrip(".")


def _xml(value: Any) -> str:
    return html.escape(str(value), quote=True)


__all__ = [
    "COMPARISON_SVG_PATH",
    "COMPARISON_SVG_RENDERER_VERSION",
    "ComparisonVisualizationError",
    "comparison_renderings_contract",
    "metric_statistics_by_pair",
    "render_comparison_svg",
]
