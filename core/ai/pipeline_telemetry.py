"""Emission-only helpers for pipeline traces, health events, and metrics."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any


def build_goal_trace(
    loop: int,
    context: Mapping[str, Any],
    decision: Mapping[str, Any],
) -> dict[str, Any]:
    """Build one goal-trace item without mutating pipeline state."""
    return {
        "loop": loop,
        "goal": decision.get("goal", "conclude"),
        "thought": decision.get("thought", ""),
        "llm_status": decision.get("llm_status", ""),
        "state": context.get("state"),
        "next_required_capability": context.get("next_required_capability"),
        "stage_gates": context.get("stage_gates") or {},
        "open_questions": context.get("open_questions") or [],
    }


def append_goal_trace(
    goal_trace: list[dict[str, Any]],
    loop: int,
    context: Mapping[str, Any],
    decision: Mapping[str, Any],
) -> dict[str, Any]:
    """Append one goal event to the injected trace list."""
    item = build_goal_trace(loop, context, decision)
    goal_trace.append(item)
    return item


def build_command_trace(
    decision: Mapping[str, Any],
    result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one command-trace item without making an execution decision."""
    item = {
        "command": decision.get("command"),
        "key": decision.get("key"),
        "action": decision.get("action"),
        "reason": decision.get("reason"),
        "prerequisite": decision.get("prerequisite", ""),
    }
    if result:
        item.update(
            {
                "failed": result.get("failed", False),
                "output_hash": result.get("output_hash", ""),
                "duplicate_output": result.get("duplicate_output", False),
                "parsed_facts": result.get("parsed_facts", 0),
                "new_facts": result.get("new_facts", 0),
                "check_status": result.get("check_status", ""),
                "facts": result.get("fact_pairs", []),
            }
        )
    return item


def append_command_trace(
    command_trace: list[dict[str, Any]],
    decision: Mapping[str, Any],
    result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one command event to the injected trace list."""
    item = build_command_trace(decision, result)
    command_trace.append(item)
    return item


def persist_llm_health(
    store_fact: Callable[[str, str, dict[str, Any], str], Any],
    scan_id: str,
    target: str,
    role: str,
    result: Mapping[str, Any] | None,
    loop: int,
) -> dict[str, Any] | None:
    """Emit one LLM health fact through an injected persistence callback."""
    result = result or {}
    status = str(result.get("llm_status", "")).strip().lower()
    if status not in {"ok", "failed", "skipped"}:
        return None
    payload: dict[str, Any] = {
        "role": role,
        "status": status,
        "loop": loop,
        "fallback": bool(result.get("fallback", False)),
    }
    if result.get("llm_error"):
        payload["error"] = str(result.get("llm_error"))
    if result.get("goal"):
        payload["goal"] = str(result.get("goal"))
    if isinstance(result.get("plan"), list):
        payload["plan_steps"] = len(result.get("plan") or [])
    if result.get("hypotheses") is not None:
        payload["hypotheses"] = int(result.get("hypotheses") or 0)
    fact = {
        "type": "llm_health",
        "value": json.dumps(payload, sort_keys=True),
        "confidence": 95 if status == "failed" else 80,
    }
    store_fact(scan_id, target, fact, f"llm:{role}")
    return fact


def print_efficiency_report(
    scan_id: str,
    target: str,
    elapsed: float,
    *,
    get_facts: Callable[[str, str], Sequence[Mapping[str, Any]]],
    task_outcomes: Sequence[Mapping[str, Any]],
    total_new_facts: int,
    goal_trace: Sequence[Mapping[str, Any]],
    command_trace: Sequence[Mapping[str, Any]],
    emit: Callable[[str], Any] = print,
) -> None:
    """Print the established efficiency summary from injected read-only state."""
    fact_total = len(get_facts(scan_id, target))
    failed = [outcome for outcome in task_outcomes if outcome["status"] == "failed"]
    blocked = [outcome for outcome in task_outcomes if outcome["status"] == "blocked"]
    no_fact = [
        outcome for outcome in task_outcomes if outcome["status"] == "no_new_facts"
    ]

    emit(
        f"[*] Efficiency report: tasks={len(task_outcomes)}, "
        f"new_facts={total_new_facts}, total_facts={fact_total}, "
        f"failed={len(failed)}, blocked={len(blocked)}, no_fact={len(no_fact)}, "
        f"elapsed={elapsed:.1f}s"
    )

    if blocked:
        preview = ", ".join(
            f"{outcome['task']}({outcome['reason']})" for outcome in blocked[:5]
        )
        emit(f"    Blocked tasks: {preview}")
    if failed:
        preview = ", ".join(outcome["task"] for outcome in failed[:5])
        emit(f"    Failed tasks: {preview}")
    if no_fact:
        preview = ", ".join(outcome["task"] for outcome in no_fact[:5])
        emit(f"    No-fact tasks: {preview}")
    if goal_trace:
        last = goal_trace[-1]
        emit(
            f"    Last goal trace: goal={last['goal']} state={last['state']} "
            f"next={last['next_required_capability']}"
        )
    if command_trace:
        skipped = [item for item in command_trace if item.get("action") == "skip"]
        emit(
            f"    Command trace: decisions={len(command_trace)}, "
            f"skipped={len(skipped)}"
        )


__all__ = [
    "append_command_trace",
    "append_goal_trace",
    "build_command_trace",
    "build_goal_trace",
    "persist_llm_health",
    "print_efficiency_report",
]
