"""Canonical state/dispatch/fact boundary for the evidence pipeline."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Callable

from core.ai.command_scheduler import CommandDecision, CommandScheduler
from core.ai.evidence import OutputParser
from core.ai.fact_store import FactStore
from core.ai.trace_report import TraceReporter
from core.execution import ExecutionContext, bind_execution_context

Runner = Callable[[str], Any]


@dataclass
class DispatchResult:
    """One execution result with a deliberately secret-safe representation."""

    decision: CommandDecision = field(repr=False)
    output: str = field(default="", repr=False)
    executed: bool = False

    @property
    def audit_command(self) -> str:
        return str(self.decision.to_dict().get("command", ""))

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.to_dict(),
            "executed": self.executed,
            "output_bytes": len(self.output.encode("utf-8", errors="ignore")),
        }


class PipelineRuntime:
    """Own facts, parsing, scheduling, execution, and trace construction.

    ``AIPipeline`` remains the mission-control loop; this class is its single
    stateful I/O boundary. Compatibility attributes in ``AIPipeline`` point to
    these instances, so there is no parallel dispatcher or fact repository.
    """

    def __init__(
        self,
        db_path: str = "data/facts.db",
        *,
        runner: Runner,
        fact_store: FactStore | None = None,
        scheduler: CommandScheduler | None = None,
        parser: OutputParser | None = None,
    ) -> None:
        self.facts = fact_store or FactStore(db_path)
        self.scheduler = scheduler or CommandScheduler()
        self.parser = parser or OutputParser()
        self.reporter = TraceReporter(self.facts)
        self._runner = runner

    def decide(
        self,
        command: str,
        facts: Iterable[dict[str, Any]],
        executed_keys: set[str],
        context: ExecutionContext,
    ) -> CommandDecision:
        return self.scheduler.decide(
            command,
            facts,
            executed_keys,
            execution_context=context,
        )

    def execute(self, decision: CommandDecision, context: ExecutionContext) -> DispatchResult:
        if decision.action == "skip":
            return DispatchResult(decision=decision, executed=False)
        with bind_execution_context(context):
            output = self._runner(decision.command)
        return DispatchResult(
            decision=decision,
            output=str(output if output is not None else ""),
            executed=True,
        )

    def dispatch(
        self,
        command: str,
        facts: Iterable[dict[str, Any]],
        executed_keys: set[str],
        context: ExecutionContext,
    ) -> DispatchResult:
        decision = self.decide(command, facts, executed_keys, context)
        return self.execute(decision, context)

    def parse_output(self, command: str, output: str) -> list[dict[str, Any]]:
        return self.parser.parse_tool_output(command, output)

    def ingest_output(
        self,
        scan_id: str,
        host: str,
        command: str,
        output: str,
        *,
        source: str | None = None,
    ) -> list[dict[str, Any]]:
        """Parse and persist a simple tool result through the canonical path."""
        stored: list[dict[str, Any]] = []
        for fact in self.parse_output(command, output):
            fact_id, created = self.facts.add_fact_with_status(
                scan_id,
                host,
                str(fact.get("type", "observation")),
                str(fact.get("value", "")),
                source or command,
                confidence=int(fact.get("confidence", 100) or 100),
                session_id=str(fact.get("session_id", "none")),
            )
            safe = dict(fact)
            safe_value, secret_refs = self.facts.redactor.redact_fact(
                str(safe.get("type", "")), safe.get("value", "")
            )
            safe.update({"id": fact_id, "value": safe_value, "created": created})
            if secret_refs:
                safe["secret_refs"] = list(secret_refs)
            stored.append(safe)
        return stored
