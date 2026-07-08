#!/usr/bin/env python3
"""Small, bounded context views for local LLM prompts."""

from __future__ import annotations

from typing import Any, Dict, Optional


ROLE_LIST_LIMITS = {
    "director": 8,
    "planner": 14,
    "analysis": 20,
}
STRING_LIMIT = 320


def compact_context_for_llm(context: Dict[str, Any], role: str = "generic") -> Dict[str, Any]:
    """Return a bounded, JSON-friendly context for Director/Planner/Analysis.

    The full context contains normalized graphs, typed facts, coverage data, and
    sometimes hundreds of low-level observations. Feeding all of that to a local
    reasoning model causes it to spend the response budget in hidden reasoning
    and never emit the final JSON. This view keeps the state-driving facts while
    dropping raw trace/noise buckets.
    """
    if not isinstance(context, dict):
        return {"context": _trim_value(context, role)}

    compact: Dict[str, Any] = {}
    for key in (
        "host",
        "state",
        "services",
        "ports_count",
        "open_questions",
        "coverage_gaps",
        "typed_coverage_gaps",
        "stage_gates",
        "automation_policy",
        "next_required_capability",
    ):
        if key in context:
            compact[key] = _trim_value(context[key], role)

    if isinstance(context.get("surface_states"), dict):
        compact["surface_states"] = _trim_value(context["surface_states"], role)

    target_model = context.get("target_model")
    if isinstance(target_model, dict):
        compact["target_model"] = _compact_target_model(target_model, role)

    for graph_key in ("network_graph", "asset_graph"):
        graph = context.get(graph_key)
        if isinstance(graph, dict):
            compact[graph_key] = _compact_graph(graph, role)

    return compact


def _compact_target_model(model: Dict[str, Any], role: str) -> Dict[str, Any]:
    limit = ROLE_LIST_LIMITS.get(role, 12)
    compact: Dict[str, Any] = {}
    for key in ("target", "host", "access", "unknowns", "api", "risk_analysis"):
        if key in model:
            compact[key] = _trim_value(model[key], role)

    for key in (
        "services",
        "endpoints",
        "internal_services",
        "check_results",
        "negative_facts",
    ):
        value = model.get(key)
        if isinstance(value, list):
            compact[key] = _trim_list(value, role, limit)
        elif value:
            compact[key] = _trim_value(value, role)

    security_findings = model.get("security_findings")
    if isinstance(security_findings, dict):
        compact["security_findings"] = {
            bucket: _trim_list(items, role, max(4, limit // 2))
            for bucket, items in security_findings.items()
            if items
        }

    web_app = model.get("web_app")
    if isinstance(web_app, dict):
        compact["web_app"] = {
            key: _trim_list(value, role, max(4, limit // 2))
            for key, value in web_app.items()
            if isinstance(value, list) and value
        }

    coverage = model.get("coverage")
    if isinstance(coverage, dict):
        compact["coverage"] = {
            "gaps": _trim_list(coverage.get("gaps", []), role, limit),
            "checked": _trim_list(coverage.get("checked", []), role, limit),
        }

    typed_facts = model.get("typed_facts")
    if isinstance(typed_facts, dict):
        compact["typed_fact_counts"] = {
            str(key): len(value) if isinstance(value, list) else 1
            for key, value in typed_facts.items()
            if value
        }

    return compact


def _compact_graph(graph: Dict[str, Any], role: str) -> Dict[str, Any]:
    limit = max(4, ROLE_LIST_LIMITS.get(role, 12) // 2)
    compact: Dict[str, Any] = {}
    for key in ("nodes", "edges"):
        value = graph.get(key)
        if isinstance(value, list):
            compact[f"{key}_count"] = len(value)
            compact[f"sample_{key}"] = _trim_list(value, role, limit)
    for key, value in graph.items():
        if key not in {"nodes", "edges"} and key not in compact:
            compact[key] = _trim_value(value, role)
    return compact


def _trim_list(values: Any, role: str, limit: Optional[int] = None) -> Any:
    if not isinstance(values, list):
        return _trim_value(values, role)
    limit = limit or ROLE_LIST_LIMITS.get(role, 12)
    trimmed = [_trim_value(item, role) for item in values[:limit]]
    if len(values) > limit:
        trimmed.append({"omitted_items": len(values) - limit})
    return trimmed


def _trim_value(value: Any, role: str) -> Any:
    limit = ROLE_LIST_LIMITS.get(role, 12)
    if isinstance(value, str):
        return value if len(value) <= STRING_LIMIT else value[: STRING_LIMIT - 3] + "..."
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return _trim_list(value, role, limit)
    if isinstance(value, dict):
        trimmed: Dict[str, Any] = {}
        for idx, (key, item) in enumerate(value.items()):
            if idx >= 40:
                trimmed["omitted_keys"] = len(value) - idx
                break
            trimmed[str(key)] = _trim_value(item, role)
        return trimmed
    return str(value)
