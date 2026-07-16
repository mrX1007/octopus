"""Canonical state/dispatch/fact boundary for the evidence pipeline."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import subprocess
import time
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Callable
from uuid import uuid4

from core.actions import (
    ActionCatalog,
    ActionExecutor,
    ActionRequest,
    ProviderFallbackExecutor,
    ProviderRunResult,
    ProviderSelection,
    ProviderSelector,
    ProviderTelemetryStore,
    build_action_catalog,
)
from core.ai.command_scheduler import CommandDecision, CommandScheduler
from core.ai.decision_trace import DecisionTraceStore
from core.ai.evidence import OutputParser
from core.ai.fact_store import FactStore
from core.ai.mission_store import MissionStore
from core.ai.trace_report import TraceReporter
from core.execution import (
    DispatchResult,
    ExecutionCancelled,
    ExecutionContext,
    ExecutionPolicy,
    ExecutionResult,
    ExecutionStatus,
    adapt_execution_result,
    bind_execution_context,
)
from core.knowledge import GraphProjectionService, KnowledgeGraph

Runner = Callable[[str], Any]
EXECUTION_RESULT_SCHEMA_VERSION = "1.0"
logger = logging.getLogger("octopus.runtime")


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
        knowledge_graph: KnowledgeGraph | None = None,
    ) -> None:
        self.facts = fact_store or FactStore(db_path)
        self.assessments = self.facts.assessments
        self.missions = MissionStore(self.facts.db_path, redactor=self.facts.redactor)
        self.scheduler = scheduler or CommandScheduler()
        self.parser = parser or OutputParser()
        self.reporter = TraceReporter(self.facts)
        self.knowledge_graph = knowledge_graph or KnowledgeGraph(
            self._knowledge_graph_path(self.facts.db_path)
        )
        self.graph_projector = GraphProjectionService(self.facts, self.knowledge_graph)
        self._runner = runner
        self._action_catalog: ActionCatalog | None = None
        self._action_executor: ActionExecutor | None = None
        self._provider_telemetry: ProviderTelemetryStore | None = None
        self._provider_selector: ProviderSelector | None = None
        self._provider_fallback_executor: ProviderFallbackExecutor | None = None
        self._decision_trace: DecisionTraceStore | None = None

    @property
    def action_catalog(self) -> ActionCatalog:
        if self._action_catalog is None:
            self._action_catalog = build_action_catalog(
                lambda command, _context: self._runner(command)
            )
        return self._action_catalog

    @property
    def action_executor(self) -> ActionExecutor:
        if self._action_executor is None:
            policy = getattr(self.scheduler, "execution_policy", None) or ExecutionPolicy()
            self._action_executor = ActionExecutor(
                self.action_catalog,
                policy,
                redact_text=self.facts.redactor.redact_text,
                redact_data=self.facts.redactor.redact_data,
            )
        assert self._action_executor is not None
        return self._action_executor

    def execute_action(
        self,
        action_name: str,
        request: ActionRequest,
        **lifecycle_options: Any,
    ):
        """Run an existing provider through the unified lifecycle adapter."""

        return self.action_executor.run(
            action_name,
            request,
            **lifecycle_options,
        )

    @property
    def provider_telemetry(self) -> ProviderTelemetryStore:
        if self._provider_telemetry is None:
            self._provider_telemetry = ProviderTelemetryStore(
                self._provider_telemetry_path(self.facts.db_path)
            )
        return self._provider_telemetry

    @property
    def provider_selector(self) -> ProviderSelector:
        if self._provider_selector is None:
            policy = getattr(self.scheduler, "execution_policy", None) or ExecutionPolicy()
            self._provider_selector = ProviderSelector(
                self.action_catalog,
                policy,
                self.provider_telemetry,
            )
        return self._provider_selector

    @property
    def provider_fallback_executor(self) -> ProviderFallbackExecutor:
        if self._provider_fallback_executor is None:
            self._provider_fallback_executor = ProviderFallbackExecutor(
                self.provider_selector,
                self.action_executor,
                self.provider_telemetry,
            )
        return self._provider_fallback_executor

    def select_provider(
        self,
        capability: str,
        request: ActionRequest,
        candidate_names: Sequence[str],
    ) -> ProviderSelection:
        """Return a bounded, explainable provider ranking without execution."""

        return self.provider_selector.select(capability, request, candidate_names)

    def execute_with_fallback(
        self,
        capability: str,
        request: ActionRequest,
        candidate_names: Sequence[str],
        *,
        ingest: Callable[[ExecutionResult, str], Any] | None = None,
        action_options: Mapping[str, Any] | None = None,
    ) -> ProviderRunResult:
        """Execute ranked providers with retry-class and ingestion boundaries."""

        decision_trace = self.decision_trace
        result = self.provider_fallback_executor.run(
            capability,
            request,
            candidate_names,
            ingest=ingest,
            action_options=action_options,
        )
        self._record_provider_decision(decision_trace, capability, request, result)
        return result

    @property
    def decision_trace(self) -> DecisionTraceStore:
        if self._decision_trace is None:
            self._decision_trace = DecisionTraceStore(
                self._decision_trace_path(self.facts.db_path),
                redactor=self.facts.redactor,
            )
        return self._decision_trace

    @staticmethod
    def _knowledge_graph_path(fact_db_path: str) -> str:
        if fact_db_path == ":memory:":
            return ":memory:"
        normalized = os.path.normpath(fact_db_path)
        if normalized == os.path.normpath("data/facts.db"):
            return os.path.join(os.path.dirname(fact_db_path), "knowledge.db")
        stem, extension = os.path.splitext(fact_db_path)
        return f"{stem}.knowledge{extension or '.db'}"

    @staticmethod
    def _provider_telemetry_path(fact_db_path: str) -> str:
        if fact_db_path == ":memory:":
            return ":memory:"
        normalized = os.path.normpath(fact_db_path)
        if normalized == os.path.normpath("data/facts.db"):
            return os.path.join(os.path.dirname(fact_db_path), "provider-telemetry.db")
        stem, extension = os.path.splitext(fact_db_path)
        return f"{stem}.provider-telemetry{extension or '.db'}"

    @staticmethod
    def _decision_trace_path(fact_db_path: str) -> str:
        if fact_db_path == ":memory:":
            return ":memory:"
        normalized = os.path.normpath(fact_db_path)
        if normalized == os.path.normpath("data/facts.db"):
            return os.path.join(os.path.dirname(fact_db_path), "decision-trace.db")
        stem, extension = os.path.splitext(fact_db_path)
        return f"{stem}.decision-trace{extension or '.db'}"

    def _record_provider_decision(
        self,
        store: DecisionTraceStore,
        capability: str,
        request: ActionRequest,
        result: ProviderRunResult,
    ) -> None:
        actor = str(request.execution_context.actor or "")
        scan_id = actor.split(":", 1)[1] if actor.startswith("scan:") else ""
        final_report = result.final_report
        final_execution = None
        if final_report is not None:
            final_execution = final_report.execution_result or final_report.check_result
        supporting_fact_ids = list(request.evidence_fact_ids)
        assessment_refs = list(request.assessment_refs)
        source_execution_ids = list(request.source_execution_ids)
        if final_report is not None and final_report.verification_result is not None:
            verification = final_report.verification_result
            supporting_fact_ids.extend(verification.evidence_fact_ids)
            assessment_refs.extend(verification.assessment_refs)
            source_execution_ids.extend(verification.source_execution_ids)
        if final_execution is not None and final_execution.execution_id:
            source_execution_ids.append(final_execution.execution_id)
        attempt_duration = 0.0
        for attempt in result.attempts:
            attempt_execution = (
                attempt.report.execution_result or attempt.report.check_result
            )
            if attempt_execution is not None:
                attempt_duration += attempt_execution.duration
        store.record({
            "event_id": (
                f"provider:{result.selection.selection_id}:"
                f"{request.execution_context.request_id}"
            ),
            "event_type": "provider_selection",
            "scan_id": scan_id,
            "candidates": [
                item.action_id
                for item in (*result.selection.ranked, *result.selection.rejected)
            ],
            "rejected": [
                {"candidate": item.action_id, "reason": list(item.reasons)}
                for item in result.selection.rejected
            ],
            "chosen_action": result.selection.chosen_action_id or "",
            "capability_ref": capability,
            "policy_refs": (
                list(final_report.policy_decision_refs) if final_report is not None else []
            ),
            "supporting_fact_ids": supporting_fact_ids,
            "expected_outcome": {
                "status": "succeeded",
                "useful_evidence": True,
                "assessment_refs": assessment_refs,
            },
            "actual_outcome": {
                "status": final_execution.status.value if final_execution else "not_attempted",
                "attempts": len(result.attempts),
                "useful_facts": sum(item.ingestion.useful_facts for item in result.attempts),
                "duplicate_facts": sum(
                    item.ingestion.duplicate_facts for item in result.attempts
                ),
                "source_execution_ids": source_execution_ids,
            },
            "duration": attempt_duration,
            "cost": {
                "tool_calls": len(result.attempts),
                "estimated_units": float(len(result.attempts)),
            },
            "retry_count": sum(1 for item in result.attempts if item.retryable),
            "fallback_count": sum(1 for item in result.attempts if item.fallback_taken),
        })

    def project_fact_ids(self, fact_ids: Iterable[int]) -> list[dict[str, Any]]:
        """Refresh graph projections for facts whose current heads changed."""

        return [
            item.to_dict()
            for item in self.graph_projector.project_fact_ids(list(fact_ids))
        ]

    def decide(
        self,
        command: str,
        facts: Iterable[dict[str, Any]],
        executed_keys: set[str],
        context: ExecutionContext,
        retry_command_keys: Iterable[str] = (),
    ) -> CommandDecision:
        retry_keys = tuple(retry_command_keys)
        if not retry_keys:
            # Keep the injected scheduler compatibility boundary additive for
            # ordinary dispatch. Durable retry-aware schedulers receive the
            # extended contract only when a persisted grant actually exists.
            return self.scheduler.decide(
                command,
                facts,
                executed_keys,
                execution_context=context,
            )
        return self.scheduler.decide(
            command,
            facts,
            executed_keys,
            execution_context=context,
            retry_command_keys=retry_keys,
        )

    def execute(self, decision: CommandDecision, context: ExecutionContext) -> DispatchResult:
        execution_id = uuid4().hex
        policy_ref = _policy_decision_ref(decision)
        if context.cancellation.cancelled:
            return self._normalize_result(
                {
                    "status": ExecutionStatus.CANCELLED,
                    "error_class": "ExecutionCancelled",
                    "error_message": context.cancellation.reason_code,
                },
                decision=decision,
                context=context,
                execution_id=execution_id,
                policy_ref=policy_ref,
                duration=0.0,
                executed=False,
            )
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
        except ExecutionCancelled as exc:
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
        source_execution_ids = (
            (output.execution_id,)
            if isinstance(output, ExecutionResult) and output.execution_id
            else ()
        )
        for fact in self.parse_output(command, output):
            fact_id, created = self.facts.add_fact_with_status(
                scan_id,
                host,
                str(fact.get("type", "observation")),
                str(fact.get("value", "")),
                source or command,
                confidence=int(fact.get("confidence", 100) or 100),
                session_id=str(fact.get("session_id", "none")),
                source_execution_ids=source_execution_ids,
            )
            safe = dict(fact)
            safe_value, secret_refs = self.facts.redactor.redact_fact(
                str(safe.get("type", "")), safe.get("value", "")
            )
            safe.update({"id": fact_id, "value": safe_value, "created": created})
            if secret_refs:
                safe["secret_refs"] = list(secret_refs)
            stored.append(safe)
        if stored:
            try:
                projected = {
                    int(item["fact_id"]): item
                    for item in self.project_fact_ids(item["id"] for item in stored)
                }
                for item in stored:
                    item["graph_projection"] = projected.get(int(item["id"]))
            except Exception as exc:
                # Facts are authoritative and already committed. A projection
                # can be replayed safely, so do not turn a read-model outage
                # into fact loss or a duplicate tool execution.
                logger.warning("Graph projection deferred (%s)", type(exc).__name__)
        return stored
