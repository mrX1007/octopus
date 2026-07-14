"""Legacy-compatible task outcome classification and in-memory recording."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


def has_blocked_stage_fact(command_results: Sequence[Mapping[str, Any]]) -> bool:
    """Return whether command facts contain the existing missing-credential gate."""
    for command in command_results:
        for fact_type, value in command.get("fact_pairs", []):
            if fact_type == "stage_status" and str(value).endswith(
                ":blocked_missing_credentials"
            ):
                return True
    return False


def classify_task_result(task_result: Mapping[str, Any]) -> str:
    """Classify one task using the pipeline's established string statuses."""
    commands = task_result["commands"]
    parsed_facts = task_result["parsed_facts"]
    if has_blocked_stage_fact(commands):
        return "blocked"
    if commands and all(command.get("skipped") for command in commands):
        return "skipped"
    if commands and all(command["failed"] for command in commands) and parsed_facts == 0:
        return "failed"
    if parsed_facts == 0:
        return "no_new_facts"
    return "completed"


def command_result_reason(
    command_results: Sequence[Mapping[str, Any]],
    parsed_facts: int,
    new_facts: int,
) -> str:
    """Explain a command batch using the pipeline's established reason strings."""
    if not command_results:
        return "no_commands"
    if has_blocked_stage_fact(command_results):
        return "missing_credentials_or_manual_gate"
    if all(command.get("skipped") for command in command_results):
        reasons = sorted(
            {
                str(command.get("skip_reason", "skipped"))
                for command in command_results
            }
        )
        return "all_commands_skipped:" + ",".join(reasons[:3])
    failed_count = sum(1 for command in command_results if command["failed"])
    if failed_count == len(command_results) and parsed_facts == 0:
        return "all_commands_failed"
    if parsed_facts == 0:
        return "commands_ran_but_no_facts"
    if new_facts == 0:
        return "facts_seen_but_already_known"
    return f"{new_facts}_new_facts"


@dataclass(frozen=True)
class TaskOutcome:
    """Immutable task outcome with an explicit legacy-dictionary boundary."""

    agent: str
    task: str
    status: str
    reason: str
    new_facts: int
    parsed_facts: int
    commands: tuple[Mapping[str, Any], ...]
    duration: float

    def __post_init__(self) -> None:
        command_copies = tuple(
            MappingProxyType(dict(command)) for command in self.commands
        )
        object.__setattr__(self, "commands", command_copies)

    def to_legacy_dict(self) -> dict[str, Any]:
        """Return the exact dictionary shape historically exposed by AIPipeline."""
        return {
            "agent": self.agent,
            "task": self.task,
            "status": self.status,
            "reason": self.reason,
            "new_facts": self.new_facts,
            "parsed_facts": self.parsed_facts,
            "commands": [dict(command) for command in self.commands],
            "duration": self.duration,
        }


class InMemoryTaskOutcomeStore:
    """Append legacy outcome dictionaries and maintain compatibility indexes."""

    def __init__(
        self,
        task_outcomes: list[dict[str, Any]] | None = None,
        failed_commands: list[str] | None = None,
        no_fact_tasks: list[str] | None = None,
    ) -> None:
        self.task_outcomes = task_outcomes if task_outcomes is not None else []
        self.failed_commands = failed_commands if failed_commands is not None else []
        self.no_fact_tasks = no_fact_tasks if no_fact_tasks is not None else []

    def append(self, outcome: TaskOutcome) -> dict[str, Any]:
        """Persist an outcome in the old shape and update the old summary lists."""
        legacy = outcome.to_legacy_dict()
        self.task_outcomes.append(legacy)
        if outcome.status == "failed":
            self.failed_commands.extend(
                command["command"]
                for command in legacy["commands"]
                if command.get("failed")
            )
        elif outcome.status == "no_new_facts":
            self.no_fact_tasks.append(outcome.task)
        return legacy

    def record(self, outcome: TaskOutcome) -> dict[str, Any]:
        """Compatibility spelling for callers that record rather than append."""
        return self.append(outcome)


__all__ = [
    "InMemoryTaskOutcomeStore",
    "TaskOutcome",
    "classify_task_result",
    "command_result_reason",
    "has_blocked_stage_fact",
]
