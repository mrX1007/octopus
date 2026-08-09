#!/usr/bin/env python3

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

Fact = dict[str, Any]


def fact(fact_type: str, value: str, confidence: int, session_id: str) -> Fact:
    return {
        "type": fact_type,
        "value": str(value)[:500],
        "confidence": confidence,
        "session_id": session_id,
    }


def check_result_fact(
    tool: str,
    kind: str,
    scope_type: str,
    scope_value: str,
    session_id: str,
    *,
    status: str = "completed",
    summary: Mapping[str, Any] | None = None,
    confidence: int = 90,
) -> Fact:
    """Build one deterministic, machine-readable coverage observation.

    Family parsers use this shape to report that a concrete provider actually
    assessed a bounded scope.  ``summary`` is parser-owned metadata; callers
    cannot supply arbitrary canonical fact types through it.
    """

    payload: dict[str, Any] = {
        "kind": str(kind),
        "mode": "check_only",
        "scope": {"type": str(scope_type), "value": str(scope_value)},
        "status": str(status),
        "tool": str(tool),
    }
    if summary:
        payload["summary"] = dict(summary)
    return {
        "type": "check_result",
        "value": json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
        "confidence": confidence,
        "session_id": session_id,
    }


def tool_lower(tool_name: str) -> str:
    return (tool_name or "").strip().lower()


def tool_identity(tool_name: str) -> str:
    """Resolve a command's first token to its canonical registry identity."""

    parts = str(tool_name or "").strip().split()
    raw = parts[0].casefold() if parts else ""
    if not raw:
        return ""
    try:
        import core.tools  # noqa: F401 - populate the decorator registry
        from core.tools.registry import get_tool

        tool_def = get_tool(raw)
        if tool_def is not None:
            return str(tool_def.name).strip().casefold()
    except ImportError:
        pass
    return raw


def raw_lower(raw_output: str) -> str:
    return (raw_output or "").lower()


class BaseParser:
    family = "base"

    def parse(self, tool_name: str, raw_output: str, session_id: str) -> list[Fact]:
        return []
