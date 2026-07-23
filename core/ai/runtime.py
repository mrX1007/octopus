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
    ActiveRiskClass,
    PartialIngestCallback,
    PolicyDenial,
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
from core.ai.fact_store import CommandCompletionClaim, FactStore
from core.ai.mission_store import MissionStore
from core.ai.trace_report import TraceReporter
from core.execution import (
    DispatchResult,
    ExecutionCancelled,
    ExecutionContext,
    ExecutionPolicy,
    ExecutionResult,
    ExecutionStatus,
    ToolInvocation,
    adapt_execution_result,
    bind_execution_context,
)
from core.execution.normalization import command_failed, output_text
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
        self.facts.register_assessment_projection_handler(
            self.graph_projector.project_fact_ids
        )
        self.facts.drain_assessment_projection_outbox()
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
        partial_ingest: PartialIngestCallback | None = None,
        action_options: Mapping[str, Any] | None = None,
    ) -> ProviderRunResult:
        """Execute ranked providers with retry-class and ingestion boundaries."""

        decision_trace = self.decision_trace
        result = self.provider_fallback_executor.run(
            capability,
            request,
            candidate_names,
            ingest=ingest,
            partial_ingest=partial_ingest,
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

    def execute(
        self,
        decision: CommandDecision,
        context: ExecutionContext,
        *,
        facts: Iterable[dict[str, Any]] = (),
        capability: str = "",
        provider_commands: Sequence[str] = (),
        partial_result_ingest: PartialIngestCallback | None = None,
    ) -> DispatchResult:
        execution_id = uuid4().hex
        policy_ref = _policy_decision_ref(decision)
        if context.cancellation.cancelled:
            return self._normalize_result(
                {
                    "status": ExecutionStatus.CANCELLED,
                    "error_class": "ExecutionCancelled",
                    "error_message": context.cancellation.reason_code,
                    "metadata": {
                        "decision_reason": "execution_cancelled",
                        "authorization_phase": "pre_execute",
                    },
                },
                decision=decision,
                context=context,
                execution_id=execution_id,
                policy_ref=policy_ref,
                duration=0.0,
                executed=False,
            )
        if decision.action == "skip":
            denial = None
            if decision.reason.startswith("policy_denied:"):
                denial = PolicyDenial.create(
                    "scheduler",
                    decision.reason.split(":", 1)[1],
                    policy_ref,
                )
            return self._normalize_result(
                {
                    "status": ExecutionStatus.BLOCKED,
                    "error_class": "ExecutionBlocked",
                    "error_message": (
                        denial.reason_code if denial is not None else decision.reason
                    ),
                    "metadata": {
                        "decision_reason": (
                            denial.reason_code
                            if denial is not None
                            else decision.reason
                        ),
                        "policy_denial": (
                            denial.to_dict() if denial is not None else None
                        ),
                    },
                },
                decision=decision,
                context=context,
                execution_id=execution_id,
                policy_ref=policy_ref,
                duration=0.0,
                executed=False,
            )

        # Decisions can spend time in a durable mission queue.  The typed
        # invocation captured by CommandScheduler is therefore authorized
        # again at the last possible in-process boundary.  Hand-constructed
        # legacy decisions without an invocation retain the compatibility
        # runner path until their public callers are retired.
        invocation = decision.invocation
        if invocation is not None:
            final_decision = self.scheduler.execution_policy.authorize_command(
                invocation.raw_command,
                context,
            )
            policy_ref = self._execution_policy_ref(final_decision.to_dict())
            if not final_decision.allowed:
                denial = PolicyDenial.create(
                    "pre_execute",
                    final_decision.reason,
                    policy_ref,
                )
                return self._normalize_result(
                    {
                        "status": ExecutionStatus.BLOCKED,
                        "error_class": "ExecutionBlocked",
                        "error_message": denial.reason_code,
                        "metadata": {
                            "decision_reason": denial.reason_code,
                            "authorization_phase": "pre_execute",
                            "policy_denial": denial.to_dict(),
                        },
                    },
                    decision=decision,
                    context=context,
                    execution_id=execution_id,
                    policy_ref=policy_ref,
                    duration=0.0,
                    executed=False,
                )
            invocation = final_decision.invocation
            if invocation is not None and invocation.registered_name:
                return self._execute_registered_action(
                    decision,
                    context,
                    invocation,
                    execution_id=execution_id,
                    policy_ref=policy_ref,
                    facts=facts,
                    capability=capability,
                    provider_commands=provider_commands,
                    partial_result_ingest=partial_result_ingest,
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

    @staticmethod
    def _execution_policy_ref(payload: Mapping[str, Any]) -> str:
        encoded = json.dumps(
            dict(payload),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8", "replace")
        return f"policy://sha256/{hashlib.sha256(encoded).hexdigest()}"

    def _execute_registered_action(
        self,
        decision: CommandDecision,
        context: ExecutionContext,
        invocation: ToolInvocation,
        *,
        execution_id: str,
        policy_ref: str,
        facts: Iterable[dict[str, Any]],
        capability: str,
        provider_commands: Sequence[str],
        partial_result_ingest: PartialIngestCallback | None,
    ) -> DispatchResult:
        """Run a scheduler-approved registered tool through the action catalog.

        The catalog remains an adapter over the existing tool runner, but
        production dispatch now observes the same applicability, selection,
        final authorization, lifecycle, normalization, and telemetry contracts
        as explicit action calls.
        """

        target = (
            invocation.targets[0]
            if invocation.targets
            else (context.target_scope[0] if context.target_scope else "")
        )
        fact_items = tuple(dict(item) for item in facts)
        candidate_names, command_by_action = self._registered_provider_candidates(
            invocation,
            context,
            target=str(target),
            facts=fact_items,
            provider_commands=provider_commands,
        )
        request = ActionRequest(
            target=str(target),
            execution_context=context,
            command=invocation.raw_command,
            provider_commands=command_by_action,
            facts=fact_items,
        )
        started = time.monotonic()
        action_id = str(invocation.registered_name)
        run = self.execute_with_fallback(
            capability or action_id,
            request,
            candidate_names,
            partial_ingest=partial_result_ingest,
        )
        report = run.final_report
        effective = run.effective_result
        if report is not None and report.policy_decision_refs:
            policy_ref = report.policy_decision_refs[-1]

        denial = run.policy_denial

        lifecycle_metadata = {
            "action_catalog": True,
            "action_id": (
                report.descriptor.action_id
                if report is not None
                else run.selection.chosen_action_id or action_id
            ),
            "capability": run.selection.capability,
            "provider_selection_id": run.selection.selection_id,
            "provider_attempts": len(run.attempts),
            "provider_attempt_action_ids": [
                attempt.action_id for attempt in run.attempts
            ],
            "provider_attempt_command_keys": [
                self.scheduler.command_key(request.command_for(attempt.action_id))
                for attempt in run.attempts
            ],
            "provider_fallback_attempt_action_ids": [
                attempt.action_id
                for attempt in run.attempts
                if attempt.action_id != candidate_names[0]
            ],
            "provider_status": run.status.value,
            "policy_denial": denial.to_dict() if denial is not None else None,
            "action_lifecycle": (
                report.lifecycle.to_dict() if report is not None else None
            ),
        }
        if effective is None:
            rejected_reasons = tuple(
                reason for item in run.selection.rejected for reason in item.reasons
            )
            status = run.status
            reason = (
                denial.reason_code
                if denial is not None
                else rejected_reasons[0] if rejected_reasons else "provider_unavailable"
            )
            return self._normalize_result(
                {
                    "status": status,
                    "error_class": (
                        "ExecutionBlocked"
                        if status is ExecutionStatus.BLOCKED
                        else "ProviderUnavailable"
                    ),
                    "error_message": reason,
                    "metadata": lifecycle_metadata,
                },
                decision=decision,
                context=context,
                execution_id=execution_id,
                policy_ref=policy_ref,
                duration=time.monotonic() - started,
                executed=False,
            )

        payload = effective.to_dict()
        payload["error_class"] = effective.error_class
        payload["error_message"] = effective.error_message
        payload["metadata"] = {
            **dict(effective.metadata),
            **lifecycle_metadata,
        }
        return self._normalize_result(
            payload,
            decision=decision,
            context=context,
            execution_id=execution_id,
            policy_ref=policy_ref,
            duration=(
                effective.duration
                if effective.duration > 0
                else time.monotonic() - started
            ),
            executed=effective.executed,
        )

    def _registered_provider_candidates(
        self,
        invocation: ToolInvocation,
        context: ExecutionContext,
        *,
        target: str,
        facts: tuple[dict[str, Any], ...],
        provider_commands: Sequence[str],
    ) -> tuple[tuple[str, ...], dict[str, str]]:
        """Resolve safe alternative commands to canonical catalog actions.

        The already-authorized invocation is always retained. Additional
        production fallback candidates must resolve to decorator-registry
        actions and classify as read-only at the action boundary. This keeps
        active/manual-gated actions on their existing explicit path.
        """

        primary = self.action_catalog.resolve(invocation.registered_name)
        if primary is None:
            return (str(invocation.registered_name),), {}
        candidate_names = [primary.canonical_id]
        command_by_action = {primary.canonical_id: invocation.raw_command}
        primary_request = ActionRequest(
            target=target,
            execution_context=context,
            command=invocation.raw_command,
            provider_commands=command_by_action,
            facts=facts,
        )
        try:
            primary_risk = primary.adapter.active_risk_class(
                primary_request,
                "execute",
            )
        except Exception:
            primary_risk = (
                ActiveRiskClass.ACTIVE
                if primary.adapter.descriptor.requirements.active
                else ActiveRiskClass.READ_ONLY
            )
        if primary_risk is not ActiveRiskClass.READ_ONLY:
            return tuple(candidate_names), command_by_action

        for raw_command in tuple(provider_commands)[:64]:
            command = str(raw_command or "").strip()
            if not command or command == invocation.raw_command:
                continue
            preliminary = self.scheduler.execution_policy.authorize_command(
                command,
                context,
            )
            alternative_invocation = preliminary.invocation
            if (
                alternative_invocation is None
                or not alternative_invocation.registered_name
            ):
                continue
            resolved = self.action_catalog.resolve(
                alternative_invocation.registered_name
            )
            if resolved is None or resolved.canonical_id in command_by_action:
                continue
            candidate_request = ActionRequest(
                target=target,
                execution_context=context,
                command=invocation.raw_command,
                provider_commands={resolved.canonical_id: command},
                facts=facts,
            )
            try:
                risk = resolved.adapter.active_risk_class(
                    candidate_request,
                    "execute",
                )
            except Exception:
                risk = (
                    ActiveRiskClass.ACTIVE
                    if resolved.adapter.descriptor.requirements.active
                    else ActiveRiskClass.READ_ONLY
                )
            if risk is not ActiveRiskClass.READ_ONLY:
                continue
            candidate_names.append(resolved.canonical_id)
            command_by_action[resolved.canonical_id] = command

        return tuple(candidate_names), command_by_action

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

    @staticmethod
    def output_fingerprint(output: str) -> str:
        """Return the stable compatibility fingerprint used for result dedupe."""

        normalized = " ".join(str(output or "").split())
        return hashlib.sha256(normalized.encode("utf-8", "ignore")).hexdigest()

    def _persist_completion_fact(
        self,
        scan_id: str,
        host: str,
        fact: Mapping[str, Any],
        source: str,
        *,
        source_execution_ids: Sequence[str] = (),
        derived_facts: Sequence[Mapping[str, Any]] = (),
        completion_claim: CommandCompletionClaim | None = None,
    ) -> dict[str, Any]:
        """Persist one prepared fact tree without projecting a partial view."""

        prepared = dict(fact)
        safe_fact = dict(prepared)
        safe_value, secret_refs = self.facts.redactor.redact_fact(
            str(safe_fact.get("type", "")),
            safe_fact.get("value", ""),
        )
        safe_fact["value"] = safe_value
        if secret_refs:
            safe_fact["secret_refs"] = list(secret_refs)

        fact_id, created = self.facts.add_fact_with_status(
            scan_id,
            host,
            str(safe_fact.get("type", "observation")),
            str(safe_fact.get("value", "")),
            source,
            confidence=int(safe_fact.get("confidence", 100) or 100),
            session_id=str(safe_fact.get("session_id", "none")),
            source_execution_ids=tuple(source_execution_ids),
            source_identity=(
                str(safe_fact["source_identity"])
                if safe_fact.get("source_identity")
                else None
            ),
            observation_method=(
                str(safe_fact["observation_method"])
                if safe_fact.get("observation_method")
                else None
            ),
            completion_claim=completion_claim,
        )
        fact_ids = [fact_id]
        new_facts = int(created)
        safe_derived_items: list[dict[str, Any]] = []
        for derived in derived_facts:
            safe_derived = dict(derived)
            derived_value, derived_refs = self.facts.redactor.redact_fact(
                str(safe_derived.get("type", "observation")),
                safe_derived.get("value", ""),
            )
            safe_derived["value"] = derived_value
            if derived_refs:
                safe_derived["secret_refs"] = list(derived_refs)
            derived_id, derived_created = self.facts.add_fact_with_status(
                scan_id,
                host,
                str(safe_derived.get("type", "observation")),
                str(safe_derived.get("value", "")),
                f"derived:{source}",
                confidence=int(
                    safe_derived.get("confidence", prepared.get("confidence", 80))
                    or 80
                ),
                session_id=str(prepared.get("session_id", "none")),
                derived_from=[fact_id],
                source_execution_ids=tuple(source_execution_ids),
                source_identity=(
                    str(
                        safe_derived.get("source_identity")
                        or safe_fact.get("source_identity")
                    )
                    if (
                        safe_derived.get("source_identity")
                        or safe_fact.get("source_identity")
                    )
                    else None
                ),
                observation_method=(
                    str(
                        safe_derived.get("observation_method")
                        or safe_fact.get("observation_method")
                    )
                    if (
                        safe_derived.get("observation_method")
                        or safe_fact.get("observation_method")
                    )
                    else None
                ),
                completion_claim=completion_claim,
            )
            fact_ids.append(derived_id)
            new_facts += int(derived_created)
            safe_derived_items.append(safe_derived)
        return {
            "created": created,
            "new_facts": new_facts,
            "derived_facts": safe_derived_items,
            "fact": safe_fact,
            "fact_ids": list(dict.fromkeys(fact_ids)),
        }

    def _replayed_completion(
        self,
        claim: CommandCompletionClaim,
        *,
        command_result_fields: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        if claim.command_result_id is None:
            raise RuntimeError("Completed execution claim has no command result")
        persisted = self.facts.get_command_result_by_id(claim.command_result_id)
        if persisted is None:
            raise RuntimeError("Completed execution result is no longer available")
        fact_ids = tuple(dict.fromkeys(int(item) for item in claim.fact_ids))
        facts = self.facts.get_facts_by_ids(fact_ids)
        command_result = {
            "command": persisted["command"],
            "failed": persisted["failed"],
            "schema_version": persisted["schema_version"],
            "status": persisted["status"],
            "partial": persisted["partial"],
            "execution_id": persisted["execution_id"],
            "request_id": persisted["request_id"],
            "policy_decision_ref": persisted["policy_decision_ref"],
            "error_class": persisted["error_class"],
            "exit_code": persisted["exit_code"],
            "duration": persisted["duration"],
            "output_bytes": persisted["output_bytes"],
            "stderr_bytes": persisted["stderr_bytes"],
            "artifact_count": persisted["artifact_count"],
            "output_hash": persisted["output_hash"],
            "duplicate_output": True,
            "parsed_facts": persisted["parsed_facts"],
            "new_facts": 0,
            "fact_ids": list(fact_ids),
            "fact_pairs": [(fact.get("type"), fact.get("value")) for fact in facts],
        }
        if command_result_fields:
            command_result.update(dict(command_result_fields))
        return {
            "facts": facts,
            "new_facts": 0,
            "parsed_facts": int(persisted["parsed_facts"]),
            "command_result": command_result,
            "stored_base_facts": [],
            "graph_projection": [],
        }

    def complete_execution(
        self,
        scan_id: str,
        host: str,
        command_key: str,
        command: str,
        result: ExecutionResult,
        *,
        source: str | None = None,
        prepare_facts: Callable[
            [list[dict[str, Any]]], Sequence[dict[str, Any]]
        ]
        | None = None,
        normalize_fact: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
        derive_facts: Callable[
            [str, dict[str, Any], str], Sequence[dict[str, Any]]
        ]
        | None = None,
        initial_fact_ids: Iterable[int] = (),
        initial_new_facts: int = 0,
        initial_facts: Iterable[dict[str, Any]] = (),
        failed: bool | None = None,
        command_result_fields: Mapping[str, Any] | None = None,
        attempt_id: str | None = None,
        idempotency_key: str = "",
        completion_fence: CommandCompletionClaim,
        after_facts: Callable[[Sequence[dict[str, Any]]], None] | None = None,
    ) -> dict[str, Any]:
        """Commit one execution through the canonical completion ingress.

        A scan-generation fence is checked before parsing and, when an
        idempotency key is present, a durable completion claim is reserved.
        Evidence writes renew that fence; the command-result row and durable
        claim are finalized transactionally with automatic assessment and graph
        repair work. Only then is the current graph view projected and
        mission-attempt provenance advanced. ``completion_fence`` should be
        captured before external dispatch so both its scan identity and
        generation fence the returned work. The canonical ingress fails closed
        when that bound token is missing.

        ``after_facts`` is an at-least-once callback: it must be idempotent.
        A crash after its external effect but before result finalization, or a
        callback that outlives the claim lease, can cause lease recovery to
        invoke it again. Exactly-once or long-running callbacks require a
        transactional outbox and an idempotent consumer.
        """

        if not isinstance(result, ExecutionResult):
            raise TypeError("complete_execution requires an ExecutionResult")
        if not isinstance(completion_fence, CommandCompletionClaim):
            raise TypeError("complete_execution requires a bound completion_fence")
        combined_output = output_text(result)
        output_hash = self.output_fingerprint(combined_output)
        failed_value = (
            command_failed(result, combined_output) if failed is None else bool(failed)
        )
        completion_claim = self.facts.claim_command_completion(
            scan_id=scan_id,
            host=host,
            command_key=command_key,
            command=command,
            output_hash=output_hash,
            status=result.status,
            failed=failed_value,
            partial=result.partial,
            execution_id=result.execution_id,
            idempotency_key=idempotency_key,
            schema_version=result.schema_version,
            request_id=result.request_id,
            policy_decision_ref=result.policy_decision_ref,
            exit_code=result.exit_code,
            error_class=result.error_class,
            artifact_count=len(result.artifact_refs),
            completion_fence=completion_fence,
        )
        try:
            self.facts.drain_assessment_projection_outbox()
        except Exception:
            if not completion_claim.replayed:
                self.facts.release_command_completion_claim(completion_claim)
            raise
        if completion_claim.replayed:
            replayed = self._replayed_completion(
                completion_claim,
                command_result_fields=command_result_fields,
            )
            if attempt_id:
                replay_execution_ids = (
                    (result.execution_id,) if result.execution_id else ()
                )
                self.missions.record_attempt_progress(
                    attempt_id,
                    fact_ids=completion_claim.fact_ids,
                    execution_ids=replay_execution_ids,
                )
            return replayed

        try:
            parsed = [dict(item) for item in self.parse_output(command, result)]
            parsed_fact_count = len(parsed)
            prepared = (
                [dict(item) for item in prepare_facts(parsed)]
                if prepare_facts is not None
                else parsed
            )
            prepared_trees: list[
                tuple[dict[str, Any], tuple[dict[str, Any], ...]]
            ] = []
            for fact in prepared:
                fact.setdefault("source", source or command)
                normalized = (
                    dict(normalize_fact(host, dict(fact)))
                    if normalize_fact is not None
                    else dict(fact)
                )
                derived = (
                    tuple(
                        dict(item)
                        for item in derive_facts(host, normalized, source or command)
                    )
                    if derive_facts is not None
                    else ()
                )
                prepared_trees.append((normalized, derived))
        except Exception:
            self.facts.release_command_completion_claim(completion_claim)
            raise

        execution_ids = (result.execution_id,) if result.execution_id else ()
        fact_ids = [int(item) for item in initial_fact_ids]
        new_fact_count = max(0, int(initial_new_facts))
        stored_facts = [dict(item) for item in initial_facts]
        stored_base_facts: list[dict[str, Any]] = []
        self.facts.renew_command_completion_claim(completion_claim)
        for fact, (normalized, derived) in zip(prepared, prepared_trees):
            self.facts.renew_command_completion_claim(completion_claim)
            stored = self._persist_completion_fact(
                scan_id,
                host,
                normalized,
                source or command,
                source_execution_ids=execution_ids,
                derived_facts=derived,
                completion_claim=completion_claim,
            )
            new_fact_count += int(stored["new_facts"])
            fact_ids.extend(int(item) for item in stored["fact_ids"])
            stored_facts.append(dict(fact))
            stored_facts.extend(dict(item) for item in stored["derived_facts"])
            stored_base_facts.append(stored)

        if after_facts is not None:
            self.facts.renew_command_completion_claim(completion_claim)
            after_facts(tuple(prepared))
            self.facts.renew_command_completion_claim(completion_claim)

        unique_fact_ids = tuple(dict.fromkeys(fact_ids))
        self.facts.renew_command_completion_claim(completion_claim)
        _result_id, unique_output = self.facts.add_command_result(
            scan_id=scan_id,
            host=host,
            command_key=command_key,
            command=command,
            output_hash=output_hash,
            output_bytes=len(combined_output.encode("utf-8", "ignore")),
            parsed_facts=parsed_fact_count,
            new_facts=new_fact_count,
            failed=failed_value,
            execution_result=result,
            idempotency_key=idempotency_key,
            fact_ids=unique_fact_ids,
            completion_claim=completion_claim,
        )

        graph_projection: list[dict[str, Any]] = []
        if unique_fact_ids:
            try:
                graph_projection = self.project_fact_ids(unique_fact_ids)
            except Exception as exc:
                # Facts and the result are authoritative and already committed.
                # The assessment outbox repairs this read model on a later ingress.
                logger.warning("Graph projection deferred (%s)", type(exc).__name__)
        if attempt_id:
            self.missions.record_attempt_progress(
                attempt_id,
                fact_ids=unique_fact_ids,
                execution_ids=execution_ids,
            )

        command_result = {
            "command": command,
            "failed": failed_value,
            "schema_version": result.schema_version,
            "status": result.status.value,
            "partial": result.partial,
            "execution_id": result.execution_id,
            "request_id": result.request_id,
            "policy_decision_ref": result.policy_decision_ref,
            "error_class": result.error_class,
            "exit_code": result.exit_code,
            "duration": result.duration,
            "output_bytes": len(result.stdout.encode("utf-8", "ignore")),
            "stderr_bytes": len(result.stderr.encode("utf-8", "ignore")),
            "artifact_count": len(result.artifact_refs),
            "output_hash": output_hash,
            "duplicate_output": not unique_output,
            "parsed_facts": parsed_fact_count,
            "new_facts": new_fact_count,
            "fact_ids": list(unique_fact_ids),
            "fact_pairs": [
                (fact.get("type"), fact.get("value")) for fact in prepared
            ],
        }
        if command_result_fields:
            command_result.update(dict(command_result_fields))
        return {
            "facts": stored_facts,
            "new_facts": new_fact_count,
            "parsed_facts": parsed_fact_count,
            "command_result": command_result,
            "stored_base_facts": stored_base_facts,
            "graph_projection": graph_projection,
        }

    def ingest_output(
        self,
        scan_id: str,
        host: str,
        command: str,
        output: str | ExecutionResult,
        *,
        source: str | None = None,
    ) -> list[dict[str, Any]]:
        """Compatibility facade over :meth:`complete_execution`.

        Historically this method performed a second parse/fact/projection
        sequence and omitted the command result. In particular a timeout could
        therefore leave positive facts with non-degraded coverage. Both typed
        and legacy string results now cross the same completion boundary; only
        the list-shaped return value remains for compatibility callers.
        """

        execution = (
            output
            if isinstance(output, ExecutionResult)
            else self.normalize_result(output, tool_name=_tool_name(command))
        )
        key_builder = getattr(self.scheduler, "command_key", None)
        command_key = (
            str(key_builder(command))
            if callable(key_builder)
            else CommandScheduler().command_key(command)
        )
        completion = self.complete_execution(
            scan_id,
            host,
            command_key,
            command,
            execution,
            source=source or command,
            idempotency_key=(
                f"execution:{execution.execution_id}"
                if execution.execution_id
                else ""
            ),
            completion_fence=self.facts.capture_scan_completion_fence(scan_id),
        )
        projected = {
            int(item["fact_id"]): item
            for item in completion.get("graph_projection") or ()
            if item.get("fact_id") is not None
        }
        stored: list[dict[str, Any]] = []
        for item in completion.get("stored_base_facts") or ():
            fact_ids = [int(fact_id) for fact_id in item.get("fact_ids") or ()]
            safe = dict(item["fact"])
            safe.update(
                {
                    "id": fact_ids[0] if fact_ids else None,
                    "created": bool(item.get("created")),
                }
            )
            if fact_ids:
                safe["graph_projection"] = projected.get(fact_ids[0])
            stored.append(safe)
        if stored:
            return stored

        # An idempotent replay has no newly persisted base rows. Preserve the
        # historical list facade while making the replay state explicit.
        return [
            {**dict(fact), "created": False}
            for fact in completion.get("facts") or ()
        ]
