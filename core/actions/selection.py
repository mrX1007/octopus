"""Explainable provider ranking and strictly bounded fallback execution."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar

from core.execution import ExecutionPolicy, ExecutionResult, ExecutionStatus

from .catalog import ActionCatalog
from .executor import ActionExecutor
from .models import (
    ActionExecutionReport,
    ActionRequest,
    ActiveRiskClass,
    PolicyDenial,
)
from .telemetry import (
    ProviderTelemetryEvent,
    ProviderTelemetryStore,
    ProviderTelemetrySummary,
    target_class,
)

PROVIDER_SELECTION_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class ProviderDecision:
    action_id: str
    provider: str
    score: float
    rejected: bool
    reasons: tuple[str, ...]
    telemetry: ProviderTelemetrySummary
    dependency_available: bool
    scope_compatible: bool
    active_risk: float
    circuit_state: str
    active_risk_class: ActiveRiskClass = ActiveRiskClass.READ_ONLY
    policy_denial: PolicyDenial | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "provider": self.provider,
            "score": self.score,
            "rejected": self.rejected,
            "reasons": list(self.reasons),
            "telemetry": self.telemetry.to_dict(),
            "dependency_available": self.dependency_available,
            "scope_compatible": self.scope_compatible,
            "active_risk": self.active_risk,
            "active_risk_class": self.active_risk_class.value,
            "circuit_state": self.circuit_state,
            "policy_denial": (
                self.policy_denial.to_dict() if self.policy_denial else None
            ),
        }


@dataclass(frozen=True)
class ProviderCircuitState:
    state: str
    allowed: bool
    reason: str
    consecutive_unavailable: int = 0
    retry_after_seconds: float = 0.0


class ProviderCircuitBreaker:
    """Open a provider circuit after repeated recent unavailable results."""

    def __init__(
        self,
        telemetry: ProviderTelemetryStore,
        *,
        failure_threshold: int = 3,
        cooldown_seconds: float = 300.0,
    ) -> None:
        self.telemetry = telemetry
        self.failure_threshold = max(2, min(int(failure_threshold), 20))
        self.cooldown_seconds = max(1.0, min(float(cooldown_seconds), 86_400.0))

    def evaluate(
        self,
        provider_id: str,
        capability: str,
        target_kind: str,
        *,
        now: float | None = None,
    ) -> ProviderCircuitState:
        events = self.telemetry.recent_events(
            provider_id,
            capability,
            target_kind,
            limit=self.failure_threshold,
        )
        consecutive = 0
        for status, _observed_at in events:
            if status != ExecutionStatus.UNAVAILABLE.value:
                break
            consecutive += 1
        if consecutive < self.failure_threshold:
            return ProviderCircuitState("closed", True, "circuit_closed", consecutive)
        last_observed = events[0][1]
        retry_after = max(
            0.0,
            (last_observed + self.cooldown_seconds) - (time.time() if now is None else now),
        )
        if retry_after > 0:
            return ProviderCircuitState(
                "open",
                False,
                "repeated_unavailable",
                consecutive,
                retry_after,
            )
        return ProviderCircuitState(
            "half_open",
            True,
            "cooldown_elapsed_probe_allowed",
            consecutive,
            0.0,
        )


@dataclass(frozen=True)
class ProviderSelection:
    selection_id: str
    capability: str
    target_class: str
    chosen_action_id: str | None
    ranked: tuple[ProviderDecision, ...]
    rejected: tuple[ProviderDecision, ...]
    schema_version: str = PROVIDER_SELECTION_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "selection_id": self.selection_id,
            "capability": self.capability,
            "target_class": self.target_class,
            "chosen_action_id": self.chosen_action_id,
            "ranked": [item.to_dict() for item in self.ranked],
            "rejected": [item.to_dict() for item in self.rejected],
        }


class ProviderSelector:
    """Rank applicable providers using current checks and bounded history."""

    def __init__(
        self,
        catalog: ActionCatalog,
        policy: ExecutionPolicy,
        telemetry: ProviderTelemetryStore,
        circuit_breaker: ProviderCircuitBreaker | None = None,
    ) -> None:
        self.catalog = catalog
        self.policy = policy
        self.telemetry = telemetry
        self.circuit_breaker = circuit_breaker or ProviderCircuitBreaker(telemetry)

    def select(
        self,
        capability: str,
        request: ActionRequest,
        candidate_names: Sequence[str],
    ) -> ProviderSelection:
        capability = self._label(capability)
        target_kind = target_class(request.target)
        names = list(dict.fromkeys(str(item) for item in candidate_names if str(item).strip()))[:64]
        accepted: list[ProviderDecision] = []
        rejected: list[ProviderDecision] = []
        seen_action_ids: set[str] = set()
        for name in names:
            resolved = self.catalog.resolve(name)
            if resolved is None:
                rejected.append(self._unknown_decision(name, capability, target_kind))
                continue
            if resolved.canonical_id in seen_action_ids:
                continue
            seen_action_ids.add(resolved.canonical_id)
            adapter = resolved.adapter
            descriptor = adapter.descriptor
            summary = self.telemetry.summary(
                descriptor.action_id,
                capability,
                target_kind,
            )
            circuit = self.circuit_breaker.evaluate(
                descriptor.action_id,
                capability,
                target_kind,
            )
            try:
                active_risk_class = adapter.active_risk_class(request, "execute")
            except Exception:
                active_risk_class = (
                    ActiveRiskClass.ACTIVE
                    if descriptor.requirements.active
                    else ActiveRiskClass.READ_ONLY
                )
            active_risk = active_risk_class.score
            try:
                applicability = adapter.applicability(request)
            except Exception as exc:
                applicability = None
                applicability_error = f"applicability_error:{type(exc).__name__}"
            else:
                applicability_error = ""
            dependency_available = bool(applicability and applicability.applicable)
            reasons: list[str] = []
            reasons.append(f"circuit:{circuit.state}:{circuit.reason}")
            if applicability_error:
                reasons.append(applicability_error)
            if applicability is not None and not applicability.applicable:
                reasons.extend(
                    f"not_applicable:{item}"
                    for item in applicability.missing_requirements
                )

            scope_compatible = False
            policy_denial = None
            if dependency_available and circuit.allowed:
                try:
                    decision = adapter.authorize(self.policy, request, "execute")
                    scope_compatible = decision.allowed
                    if not decision.allowed:
                        policy_denial = PolicyDenial.create(
                            "selection",
                            decision.reason,
                        )
                        reasons.append(f"authorization:{policy_denial.reason_code}")
                except Exception as exc:
                    reasons.append(f"authorization_error:{type(exc).__name__}")

            hard_rejected = (
                not dependency_available
                or not scope_compatible
                or not circuit.allowed
            )
            score, score_reasons = self._score(summary, active_risk)
            if circuit.state == "half_open":
                score -= 25.0
                score_reasons.append("circuit:half_open_penalty:-25.000")
            reasons.extend(score_reasons)
            provider_decision = ProviderDecision(
                action_id=descriptor.action_id,
                provider=descriptor.provider,
                score=round(score, 6),
                rejected=hard_rejected,
                reasons=tuple(reasons),
                telemetry=summary,
                dependency_available=dependency_available,
                scope_compatible=scope_compatible,
                active_risk=active_risk,
                active_risk_class=active_risk_class,
                circuit_state=circuit.state,
                policy_denial=policy_denial,
            )
            (rejected if hard_rejected else accepted).append(provider_decision)

        accepted.sort(key=lambda item: (-item.score, item.action_id))
        rejected.sort(key=lambda item: item.action_id)
        chosen = accepted[0].action_id if accepted else None
        selection_payload = {
            "capability": capability,
            "target_class": target_kind,
            "request_id": request.execution_context.request_id,
            "candidates": [item.action_id for item in (*accepted, *rejected)],
        }
        selection_id = hashlib.sha256(
            json.dumps(selection_payload, sort_keys=True).encode("utf-8", "replace")
        ).hexdigest()
        return ProviderSelection(
            selection_id=f"selection_{selection_id[:32]}",
            capability=capability,
            target_class=target_kind,
            chosen_action_id=chosen,
            ranked=tuple(accepted),
            rejected=tuple(rejected),
        )

    def _unknown_decision(
        self,
        name: str,
        capability: str,
        target_kind: str,
    ) -> ProviderDecision:
        action_id = f"unknown:{self._label(name)}"
        return ProviderDecision(
            action_id=action_id,
            provider="unknown",
            score=0.0,
            rejected=True,
            reasons=("unknown_action",),
            telemetry=self.telemetry.summary(action_id, capability, target_kind),
            dependency_available=False,
            scope_compatible=False,
            active_risk=0.0,
            active_risk_class=ActiveRiskClass.READ_ONLY,
            circuit_state="closed",
        )

    @staticmethod
    def _score(
        summary: ProviderTelemetrySummary,
        active_risk: float,
    ) -> tuple[float, list[str]]:
        score = 50.0 - (10.0 * active_risk)
        reasons = [f"active_risk_penalty:{10.0 * active_risk:.3f}"]
        if not summary.samples:
            reasons.append("telemetry:no_samples")
            return score, reasons
        contributions = {
            "success": 20.0 * summary.success_rate,
            "dependency": 8.0 * summary.dependency_availability_rate,
            "scope": 8.0 * summary.scope_compatibility_rate,
            "parser": 8.0 * summary.parser_quality,
            "useful_yield": min(10.0, 2.0 * summary.useful_fact_yield),
            "timeouts": -20.0 * summary.timeout_rate,
            "failures": -15.0 * summary.failure_rate,
            "unavailable": -15.0 * summary.unavailable_rate,
            "duplicates": -10.0 * summary.duplicate_yield_rate,
            "duration": -min(10.0, summary.average_duration / 30.0),
        }
        for label, value in contributions.items():
            score += value
            reasons.append(f"telemetry:{label}:{value:.3f}")
        return max(-100.0, min(100.0, score)), reasons

    @staticmethod
    def _label(value: str) -> str:
        compact = "_".join(str(value or "").strip().split())
        normalized = "".join(
            char if char.isalnum() or char in "_.:/-" else "_"
            for char in compact
        )[:256]
        if not normalized:
            raise ValueError("Provider capability/name must not be empty")
        return normalized

    @staticmethod
    def _reason_code(reason: str) -> str:
        """Retain a bounded policy reason code without target-bearing detail."""

        return ProviderSelector._label(str(reason or "unknown").split(":", 1)[0])[:64]


@dataclass(frozen=True)
class IngestionOutcome:
    parsed_facts: int = 0
    useful_facts: int = 0
    duplicate_facts: int = 0
    parser_items: int = 0
    parser_errors: int = 0
    error: str = ""

    @classmethod
    def from_value(cls, value: Any) -> IngestionOutcome:
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            return cls()

        def count(name: str) -> int:
            try:
                return max(0, min(int(value.get(name, 0) or 0), 1_000_000))
            except (TypeError, ValueError):
                return 0

        return cls(
            parsed_facts=count("parsed_facts"),
            useful_facts=count("useful_facts") or count("new_facts"),
            duplicate_facts=count("duplicate_facts"),
            parser_items=count("parser_items") or count("parsed_facts"),
            parser_errors=count("parser_errors"),
            error=str(value.get("error") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "parsed_facts": self.parsed_facts,
            "useful_facts": self.useful_facts,
            "duplicate_facts": self.duplicate_facts,
            "parser_items": self.parser_items,
            "parser_errors": self.parser_errors,
            "error": self.error,
        }


class RetryClassifier:
    RETRYABLE_ERROR_CLASSES: ClassVar[frozenset[str]] = frozenset({
        "ConnectionError",
        "ConnectionResetError",
        "ProviderBusy",
        "TemporaryError",
        "TransientProviderError",
    })

    @classmethod
    def is_retryable(cls, result: ExecutionResult | None) -> bool:
        if result is None:
            return False
        if result.status in {ExecutionStatus.UNAVAILABLE, ExecutionStatus.TIMEOUT}:
            return True
        if result.status is not ExecutionStatus.FAILED:
            return False
        if result.metadata.get("retryable") is True:
            return True
        return result.error_class in cls.RETRYABLE_ERROR_CLASSES


@dataclass(frozen=True)
class ProviderAttempt:
    action_id: str
    report: ActionExecutionReport
    ingestion: IngestionOutcome
    retryable: bool
    fallback_taken: bool
    stop_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "report": self.report.to_dict(),
            "ingestion": self.ingestion.to_dict(),
            "retryable": self.retryable,
            "fallback_taken": self.fallback_taken,
            "stop_reason": self.stop_reason,
        }


@dataclass(frozen=True)
class ProviderRunResult:
    selection: ProviderSelection
    attempts: tuple[ProviderAttempt, ...]
    final_report: ActionExecutionReport | None
    trace: dict[str, Any] = field(default_factory=dict)
    schema_version: str = PROVIDER_SELECTION_SCHEMA_VERSION

    @property
    def effective_result(self) -> ExecutionResult | None:
        if self.final_report is None:
            return None
        if self.final_report.policy_denials:
            return None
        return self.final_report.execution_result or self.final_report.check_result

    @property
    def policy_denial(self) -> PolicyDenial | None:
        if self.final_report is not None and self.final_report.policy_denials:
            return self.final_report.policy_denials[-1]
        if self.attempts:
            return None
        for decision in self.selection.rejected:
            if decision.policy_denial is not None:
                return decision.policy_denial
        return None

    @property
    def status(self) -> ExecutionStatus:
        if self.policy_denial is not None:
            return ExecutionStatus.BLOCKED
        effective = self.effective_result
        if effective is not None:
            return effective.status
        return ExecutionStatus.UNAVAILABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "selection": self.selection.to_dict(),
            "attempts": [item.to_dict() for item in self.attempts],
            "final_report": self.final_report.to_dict() if self.final_report else None,
            "status": self.status.value,
            "policy_denial": (
                self.policy_denial.to_dict() if self.policy_denial else None
            ),
            "trace": dict(self.trace),
        }


IngestCallback = Callable[
    [ExecutionResult, str],
    "IngestionOutcome | Mapping[str, Any]",
]
PartialIngestCallback = Callable[
    [ExecutionResult, str, ActionRequest],
    "IngestionOutcome | Mapping[str, Any]",
]


class ProviderFallbackExecutor:
    def __init__(
        self,
        selector: ProviderSelector,
        action_executor: ActionExecutor,
        telemetry: ProviderTelemetryStore,
    ) -> None:
        self.selector = selector
        self.action_executor = action_executor
        self.telemetry = telemetry

    def run(
        self,
        capability: str,
        request: ActionRequest,
        candidate_names: Sequence[str],
        *,
        ingest: IngestCallback | None = None,
        partial_ingest: PartialIngestCallback | None = None,
        action_options: Mapping[str, Any] | None = None,
    ) -> ProviderRunResult:
        selection = self.selector.select(capability, request, candidate_names)
        attempts: list[ProviderAttempt] = []
        trace_attempts: list[dict[str, Any]] = []
        final_report = None
        ranked = selection.ranked[:8]
        for index, decision in enumerate(ranked):
            report = self.action_executor.run(
                decision.action_id,
                request,
                **dict(action_options or {}),
            )
            final_report = report
            effective = (
                None
                if report.policy_denials
                else report.execution_result or report.check_result
            )
            retryable = RetryClassifier.is_retryable(effective)
            has_more = index + 1 < len(ranked)
            output_requires_ingest = bool(
                effective
                and retryable
                and has_more
                and (effective.stdout or effective.stderr)
            )
            partial_callback_used = bool(output_requires_ingest and partial_ingest)
            if partial_callback_used:
                ingestion = self._ingest_partial(
                    effective,
                    decision.action_id,
                    request,
                    partial_ingest,
                )
            else:
                ingestion = self._ingest(effective, decision.action_id, ingest)
            partial_output_ingested = bool(
                effective
                and effective.partial
                and not ingestion.error
                and (partial_callback_used or ingest is not None)
            )
            ingest_blocked = bool(
                output_requires_ingest
                and (
                    ingestion.error
                    or (partial_ingest is None and ingest is None)
                )
            )
            fallback_taken = bool(retryable and has_more and not ingest_blocked)
            if fallback_taken:
                stop_reason = "retryable_failure_fallback"
            elif ingest_blocked:
                stop_reason = "partial_output_not_ingested"
            elif not retryable:
                stop_reason = "terminal_or_non_retryable_result"
            elif not has_more:
                stop_reason = "retryable_failure_no_provider_remaining"
            else:
                stop_reason = "stopped"
            attempt = ProviderAttempt(
                action_id=decision.action_id,
                report=report,
                ingestion=ingestion,
                retryable=retryable,
                fallback_taken=fallback_taken,
                stop_reason=stop_reason,
            )
            attempts.append(attempt)
            trace_attempts.append({
                "action_id": decision.action_id,
                "status": effective.status.value if effective else "not_attempted",
                "partial_output_ingested": partial_output_ingested,
                "retryable": retryable,
                "fallback_taken": fallback_taken,
                "reason": stop_reason,
            })
            self._record_telemetry(
                capability,
                selection.target_class,
                decision,
                effective,
                ingestion,
                retryable,
                partial_output_ingested,
            )
            if not fallback_taken:
                break

        trace = {
            "schema_version": PROVIDER_SELECTION_SCHEMA_VERSION,
            "selection_id": selection.selection_id,
            "capability": selection.capability,
            "target_class": selection.target_class,
            "chosen_action_id": selection.chosen_action_id,
            "candidate_decisions": [
                item.to_dict() for item in (*selection.ranked, *selection.rejected)
            ][:64],
            "attempts": trace_attempts,
        }
        return ProviderRunResult(
            selection=selection,
            attempts=tuple(attempts),
            final_report=final_report,
            trace=trace,
        )

    @staticmethod
    def _ingest(
        result: ExecutionResult | None,
        action_id: str,
        callback: IngestCallback | None,
    ) -> IngestionOutcome:
        if result is None or callback is None or not (result.stdout or result.stderr):
            return IngestionOutcome()
        try:
            return IngestionOutcome.from_value(callback(result, action_id))
        except Exception as exc:
            return IngestionOutcome(error=f"ingest_error:{type(exc).__name__}")

    @staticmethod
    def _ingest_partial(
        result: ExecutionResult | None,
        action_id: str,
        request: ActionRequest,
        callback: PartialIngestCallback | None,
    ) -> IngestionOutcome:
        if result is None or callback is None or not (result.stdout or result.stderr):
            return IngestionOutcome()
        try:
            return IngestionOutcome.from_value(callback(result, action_id, request))
        except Exception as exc:
            return IngestionOutcome(error=f"ingest_error:{type(exc).__name__}")

    def _record_telemetry(
        self,
        capability: str,
        target_kind: str,
        decision: ProviderDecision,
        result: ExecutionResult | None,
        ingestion: IngestionOutcome,
        retryable: bool,
        partial_output_ingested: bool,
    ) -> None:
        status = result.status.value if result else "not_attempted"
        event = ProviderTelemetryEvent(
            provider_id=decision.action_id,
            capability=capability,
            target_class=target_kind,
            status=status,
            dependency_available=decision.dependency_available,
            scope_compatible=decision.scope_compatible,
            active_risk=decision.active_risk,
            duration=result.duration if result else 0.0,
            useful_facts=ingestion.useful_facts,
            duplicate_facts=ingestion.duplicate_facts,
            parser_items=ingestion.parser_items,
            parser_errors=ingestion.parser_errors or int(bool(ingestion.error)),
            partial_output_ingested=partial_output_ingested,
            retryable=retryable,
            execution_id=result.execution_id if result else "",
        )
        try:
            self.telemetry.record(event)
        except (OSError, sqlite3.Error, ValueError):
            # Selection history is advisory; it must not rewrite an action
            # outcome or trigger another provider execution.
            return


__all__ = [
    "PROVIDER_SELECTION_SCHEMA_VERSION",
    "IngestionOutcome",
    "PartialIngestCallback",
    "ProviderAttempt",
    "ProviderCircuitBreaker",
    "ProviderCircuitState",
    "ProviderDecision",
    "ProviderFallbackExecutor",
    "ProviderRunResult",
    "ProviderSelection",
    "ProviderSelector",
    "RetryClassifier",
]
