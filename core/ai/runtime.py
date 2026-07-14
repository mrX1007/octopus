"""Canonical state/dispatch/fact boundary for the evidence pipeline."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import time
from collections.abc import Iterable, Mapping
from typing import Any, Callable
from uuid import uuid4

from core.ai.command_scheduler import CommandDecision, CommandScheduler
from core.ai.evidence import OutputParser
from core.ai.fact_store import FactStore
from core.ai.mission_store import MissionStore
from core.ai.trace_report import TraceReporter
from core.execution import (
    DispatchResult,
    ExecutionContext,
    ExecutionResult,
    ExecutionStatus,
    adapt_execution_result,
    bind_execution_context,
)

Runner = Callable[[str], Any]
EXECUTION_RESULT_SCHEMA_VERSION = "1.0"


def _policy_decision_ref(decision: CommandDecision) -> str:
    """Build a non-secret stable reference to one scheduler/policy decision."""
    payload = {
        "key": decision.key,
        "action": decision.action,
        "reason": decision.reason,
        "prerequisite": decision.prerequisite,
        "policy": decision.policy,
    }
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8", "replace")
    return f"policy://sha256/{hashlib.sha256(encoded).hexdigest()}"


def _tool_name(command: str) -> str:
    parts = (command or "").strip().split(maxsplit=1)
    return parts[0] if parts else "unknown"


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
        self.missions = MissionStore(self.facts.db_path, redactor=self.facts.redactor)
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
        execution_id = uuid4().hex
        policy_ref = _policy_decision_ref(decision)
        if decision.action == "skip":
            return self._normalize_result(
                {
                    "status": ExecutionStatus.BLOCKED,
                    "error_class": "ExecutionBlocked",
                    "error_message": decision.reason,
                    "metadata": {"decision_reason": decision.reason},
                },
                decision=decision,
                context=context,
                execution_id=execution_id,
                policy_ref=policy_ref,
                duration=0.0,
                executed=False,
            )

        started = time.monotonic()
        try:
            with bind_execution_context(context):
                output = self._runner(decision.command)
        except asyncio.CancelledError as exc:
            return self._exception_result(
                exc,
                ExecutionStatus.CANCELLED,
                decision,
                context,
                execution_id,
                policy_ref,
                time.monotonic() - started,
                executed=True,
            )
        except (subprocess.TimeoutExpired, TimeoutError) as exc:
            return self._exception_result(
                exc,
                ExecutionStatus.TIMEOUT,
                decision,
                context,
                execution_id,
                policy_ref,
                time.monotonic() - started,
                executed=True,
            )
        except FileNotFoundError as exc:
            return self._exception_result(
                exc,
                ExecutionStatus.UNAVAILABLE,
                decision,
                context,
                execution_id,
                policy_ref,
                time.monotonic() - started,
                executed=False,
            )
        except Exception as exc:
            return self._exception_result(
                exc,
                ExecutionStatus.FAILED,
                decision,
                context,
                execution_id,
                policy_ref,
                time.monotonic() - started,
                executed=True,
            )
        return self._normalize_result(
            output,
            decision=decision,
            context=context,
            execution_id=execution_id,
            policy_ref=policy_ref,
            duration=time.monotonic() - started,
        )

    def _normalize_result(
        self,
        value: Any,
        *,
        decision: CommandDecision,
        context: ExecutionContext,
        execution_id: str,
        policy_ref: str,
        duration: float,
        executed: bool | None = None,
    ) -> DispatchResult:
        return adapt_execution_result(
            value,
            request_id=context.request_id,
            execution_id=execution_id,
            tool_name=_tool_name(decision.command),
            max_output_bytes=context.max_output_bytes,
            default_duration=duration,
            policy_decision_ref=policy_ref,
            executed=executed,
            decision=decision,
            redact_text=self.facts.redactor.redact_text,
            redact_data=self.facts.redactor.redact_data,
        )

    def normalize_result(
        self,
        value: Any,
        *,
        tool_name: str,
        max_output_bytes: int = 1_000_000,
        request_id: str = "",
        execution_id: str = "",
        policy_decision_ref: str = "",
    ) -> ExecutionResult:
        """Normalize a replay/plugin payload through the existing runtime adapter.

        Legacy values have no schema. Canonical payloads must use the current
        execution-result schema; unknown versions fail closed instead of being
        silently reinterpreted.
        """

        self.validate_result_schema(value)
        raw_request_id = request_id
        raw_execution_id = execution_id
        raw_policy_ref = policy_decision_ref
        if isinstance(value, Mapping):
            raw_request_id = raw_request_id or str(value.get("request_id") or "")
            raw_execution_id = raw_execution_id or str(value.get("execution_id") or "")
            raw_policy_ref = raw_policy_ref or str(value.get("policy_decision_ref") or "")

        def safe_identifier(raw: Any, kind: str) -> str:
            redacted = self.facts.redactor.redact_text(raw, kind=kind)
            encoded = redacted.encode("utf-8", "replace")
            if len(encoded) <= 4096:
                return redacted
            return encoded[:4096].decode("utf-8", "ignore")

        return adapt_execution_result(
            value,
            request_id=safe_identifier(raw_request_id, "request_id") if raw_request_id else "",
            execution_id=safe_identifier(raw_execution_id, "execution_id") if raw_execution_id else "",
            tool_name=safe_identifier(tool_name, "execution_tool"),
            max_output_bytes=max_output_bytes,
            policy_decision_ref=(
                safe_identifier(raw_policy_ref, "policy_decision_ref") if raw_policy_ref else ""
            ),
            redact_text=self.facts.redactor.redact_text,
            redact_data=self.facts.redactor.redact_data,
        )

    @staticmethod
    def validate_result_schema(value: Any) -> str:
        """Validate a replay payload without producing IDs or persistence side effects."""

        if isinstance(value, ExecutionResult):
            schema_version = value.schema_version
        elif isinstance(value, Mapping):
            schema_version = str(value.get("schema_version") or "0")
        else:
            schema_version = "0"
        if schema_version not in {"0", EXECUTION_RESULT_SCHEMA_VERSION}:
            raise ValueError(
                "Unsupported execution result schema "
                f"{schema_version!r}; supported: 0, {EXECUTION_RESULT_SCHEMA_VERSION}"
            )
        if isinstance(value, Mapping) and schema_version == EXECUTION_RESULT_SCHEMA_VERSION:
            raw_status = value.get("status")
            status = raw_status.value if isinstance(raw_status, ExecutionStatus) else str(raw_status or "")
            if status not in {item.value for item in ExecutionStatus}:
                raise ValueError(f"Unsupported canonical execution status: {status!r}")
        return schema_version

    def _exception_result(
        self,
        exc: BaseException,
        status: ExecutionStatus,
        decision: CommandDecision,
        context: ExecutionContext,
        execution_id: str,
        policy_ref: str,
        duration: float,
        *,
        executed: bool,
    ) -> DispatchResult:
        stdout = getattr(exc, "stdout", None)
        if stdout is None:
            stdout = getattr(exc, "output", "")
        stderr = getattr(exc, "stderr", "")
        return self._normalize_result(
            {
                "status": status,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": getattr(exc, "returncode", None),
                "error_class": type(exc).__name__,
                "error_message": str(exc),
                "partial": bool(stdout or stderr),
            },
            decision=decision,
            context=context,
            execution_id=execution_id,
            policy_ref=policy_ref,
            duration=duration,
            executed=executed,
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

    def parse_output(
        self,
        command: str,
        output: str | ExecutionResult,
    ) -> list[dict[str, Any]]:
        # Diagnostics are audit-only. Parsing stderr as evidence can turn a
        # failed tool's echoed examples into verified facts and follow-ups.
        output_text = output.stdout if isinstance(output, ExecutionResult) else str(output)
        return self.parser.parse_tool_output(command, output_text)

    def ingest_output(
        self,
        scan_id: str,
        host: str,
        command: str,
        output: str | ExecutionResult,
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
