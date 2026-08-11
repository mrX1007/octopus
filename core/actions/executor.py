"""Policy-gated orchestration for the canonical action lifecycle."""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping

from core.execution import (
    CAP_ACTIVE_TOOL,
    CancellationContext,
    ExecutionCancelled,
    ExecutionContext,
    ExecutionDecision,
    ExecutionPolicy,
    ExecutionResult,
    ExecutionStatus,
    bind_execution_context,
)

from .base import ActionAdapter, DataRedactor, TextRedactor
from .catalog import ActionCatalog
from .input_contracts import validate_typed_input
from .models import (
    ActionCheckResult,
    ActionCleanupResult,
    ActionExecutionReport,
    ActionLifecycle,
    ActionRequest,
    ActionVerificationResult,
    ApplicabilityResult,
    ApplicabilityStatus,
    AttemptStatus,
    CheckStatus,
    CleanupStatus,
    OutcomeStatus,
    PolicyDenial,
    VerificationStatus,
)


class ActionExecutor:
    """Execute an adapter while preserving every distinct lifecycle state."""

    def __init__(
        self,
        catalog: ActionCatalog,
        policy: ExecutionPolicy,
        *,
        redact_text: TextRedactor | None = None,
        redact_data: DataRedactor | None = None,
    ) -> None:
        self.catalog = catalog
        self.policy = policy
        self.redact_text = redact_text
        self.redact_data = redact_data

    def run(
        self,
        action_name: str,
        request: ActionRequest,
        *,
        run_check: bool = True,
        execute: bool = True,
        cleanup: bool = True,
    ) -> ActionExecutionReport:
        if not isinstance(request, ActionRequest):
            raise TypeError("request must be an ActionRequest")
        if not isinstance(request.execution_context, ExecutionContext):
            raise TypeError("request.execution_context must be an ExecutionContext")

        resolved = self.catalog.require(action_name)
        adapter = resolved.adapter
        lifecycle = ActionLifecycle()
        lifecycle.record(
            "candidate",
            reason=(f"alias:{resolved.requested_name}" if resolved.alias_used else "canonical_id"),
        )
        report = ActionExecutionReport(adapter.descriptor, lifecycle)

        try:
            applicability = self._request_contract_applicability(adapter, request)
        except Exception as exc:
            applicability = ApplicabilityResult(
                applicable=False,
                reasons=("request_contract_error",),
                missing_requirements=(f"request_contract_error:{type(exc).__name__}",),
            )
        if applicability.applicable:
            try:
                provider_applicability = adapter.applicability(request)
                applicability = ApplicabilityResult(
                    applicable=provider_applicability.applicable,
                    reasons=tuple(dict.fromkeys((*applicability.reasons, *provider_applicability.reasons))),
                    missing_requirements=provider_applicability.missing_requirements,
                )
            except Exception as exc:
                applicability = ApplicabilityResult(
                    applicable=False,
                    reasons=("applicability_error",),
                    missing_requirements=(f"adapter_error:{type(exc).__name__}",),
                )
        report.applicability = applicability
        lifecycle.applicability = (
            ApplicabilityStatus.APPLICABLE if applicability.applicable else ApplicabilityStatus.NOT_APPLICABLE
        )
        lifecycle.record(
            lifecycle.applicability.value,
            reason=",".join(applicability.missing_requirements),
        )
        if not applicability.applicable:
            return report

        requirements = adapter.descriptor.requirements
        if run_check and requirements.supports_check:
            decision = self._authorize(adapter, request, "check")
            decision_ref = self._policy_ref(decision, "check")
            report.policy_decision_refs.append(decision_ref)
            if not decision.allowed:
                denial = PolicyDenial.create("check", decision.reason, decision_ref)
                report.policy_denials.append(denial)
                lifecycle.check = CheckStatus.BLOCKED
                lifecycle.record("check_blocked", reason=denial.reason_code)
                return report
            try:
                with bind_execution_context(request.execution_context):
                    checked = adapter.check(request)
                if not isinstance(checked, ActionCheckResult):
                    checked = ActionCheckResult(result=checked)
                normalized_check = adapter.normalize_result(
                    checked.result,
                    request,
                    phase="check",
                    redact_text=self.redact_text,
                    redact_data=self.redact_data,
                )
                report.check_result = normalized_check
                lifecycle.check_positive = checked.applicable
                lifecycle.check = self._check_status(normalized_check)
                lifecycle.record("checked", reason=checked.reason or lifecycle.check.value)
            except Exception as exc:
                report.check_result = self._exception_result(
                    adapter,
                    request,
                    exc,
                    phase="check",
                )
                lifecycle.check = CheckStatus.FAILED
                lifecycle.record("check_failed", reason=type(exc).__name__)
                return report

            if lifecycle.check is not CheckStatus.COMPLETED:
                return report
            if lifecycle.check_positive is False:
                lifecycle.applicability = ApplicabilityStatus.NOT_APPLICABLE
                lifecycle.record("check_not_applicable")
                return report
            if requirements.positive_check_required and lifecycle.check_positive is not True:
                lifecycle.record("positive_check_required")
                return report

        if not execute:
            lifecycle.record("execution_not_requested")
            return report

        # This decision is intentionally made after applicability/check and
        # immediately before the provider call. Planner/candidate selection is
        # never an execution authorization.
        decision = self._authorize(adapter, request, "execute")
        decision_ref = self._policy_ref(decision, "execute")
        report.policy_decision_refs.append(decision_ref)
        if not decision.allowed:
            denial = PolicyDenial.create("execute", decision.reason, decision_ref)
            report.policy_denials.append(denial)
            lifecycle.attempt = AttemptStatus.BLOCKED
            lifecycle.outcome = OutcomeStatus.BLOCKED
            lifecycle.record("execution_blocked", reason=denial.reason_code)
            return report

        lifecycle.attempt = AttemptStatus.ATTEMPTED
        lifecycle.record("attempted")
        started = time.monotonic()
        try:
            with bind_execution_context(request.execution_context):
                raw_result = adapter.execute(request)
            execution_result = adapter.normalize_result(
                raw_result,
                request,
                phase="execute",
                redact_text=self.redact_text,
                redact_data=self.redact_data,
            )
        except ExecutionCancelled as exc:
            execution_result = adapter.normalize_result(
                {
                    "status": ExecutionStatus.CANCELLED,
                    "stdout": exc.stdout,
                    "stderr": exc.stderr,
                    "exit_code": exc.returncode,
                    "error_class": type(exc).__name__,
                    "error_message": exc.reason_code,
                    "partial": bool(exc.stdout or exc.stderr),
                    "executed": True,
                },
                request,
                phase="execute",
                redact_text=self.redact_text,
                redact_data=self.redact_data,
            )
        except Exception as exc:
            execution_result = self._exception_result(
                adapter,
                request,
                exc,
                phase="execute",
            )
        if execution_result.duration <= 0:
            execution_result.duration = max(0.0, time.monotonic() - started)
        report.execution_result = execution_result
        lifecycle.outcome = self._outcome(execution_result.status)
        lifecycle.record(lifecycle.outcome.value)

        if execution_result.status in {ExecutionStatus.SUCCEEDED, ExecutionStatus.PARTIAL}:
            try:
                verification = adapter.verify(request, execution_result)
                if not isinstance(verification, ActionVerificationResult):
                    verification = ActionVerificationResult(
                        verified=False,
                        reason="Adapter returned an invalid verification result.",
                    )
            except Exception as exc:
                verification = ActionVerificationResult(
                    verified=False,
                    reason=f"Verification failed: {type(exc).__name__}",
                )
            report.verification_result = verification
            lifecycle.verification = (
                VerificationStatus.VERIFIED if verification.verified else VerificationStatus.UNVERIFIED
            )
            lifecycle.record(lifecycle.verification.value, reason=verification.reason)

        if cleanup and requirements.supports_cleanup:
            lifecycle.cleanup = CleanupStatus.PENDING
            lifecycle.record("cleanup_pending")
            try:
                cleanup_result = adapter.cleanup(request, execution_result)
                if not isinstance(cleanup_result, ActionCleanupResult):
                    cleanup_result = ActionCleanupResult(
                        succeeded=False,
                        reason="Adapter returned an invalid cleanup result.",
                    )
            except Exception as exc:
                cleanup_result = ActionCleanupResult(
                    succeeded=False,
                    reason=f"Cleanup failed: {type(exc).__name__}",
                )
            report.cleanup_result = cleanup_result
            lifecycle.cleanup = CleanupStatus.SUCCEEDED if cleanup_result.succeeded else CleanupStatus.FAILED
            lifecycle.record(lifecycle.cleanup.value, reason=cleanup_result.reason)

        return report

    def _authorize(
        self,
        adapter: ActionAdapter,
        request: ActionRequest,
        phase: str,
    ) -> ExecutionDecision:
        contract = self._request_contract_applicability(adapter, request)
        if not contract.applicable:
            return ExecutionDecision(
                allowed=False,
                reason=contract.missing_requirements[0],
                context=request.execution_context,
            )

        descriptor = adapter.descriptor
        capability_decision = self.policy.check_capability_permission(
            descriptor.capability_class,
            request.execution_context,
        )
        if not capability_decision.allowed:
            return capability_decision
        stage_decision = self.policy.check_killchain_stage(
            descriptor.killchain_stage,
            request.execution_context,
        )
        if not stage_decision.allowed:
            return stage_decision

        if descriptor.manual_gate:
            context = request.execution_context
            if context.origin not in {"operator", "interactive_cli"} or not context.actor.strip():
                return ExecutionDecision(
                    allowed=False,
                    reason="manual_gate_requires_operator_context",
                    context=context,
                )
            if not context.has(CAP_ACTIVE_TOOL) or not context.approved or not context.approval_id.strip():
                return ExecutionDecision(
                    allowed=False,
                    reason="active_tool_requires_approval",
                    context=context,
                )

        credential_ref = str(getattr(request.typed_input, "credential_ref", "") or "")
        if credential_ref:
            credential_decision = self.policy.check_credential_authorization(
                credential_ref,
                request.execution_context,
            )
            if not credential_decision.allowed:
                return credential_decision
        try:
            return adapter.authorize(self.policy, request, phase)
        except Exception as exc:
            return ExecutionDecision(
                allowed=False,
                reason=f"action_invocation_invalid:{type(exc).__name__}",
                context=request.execution_context,
            )

    def _request_contract_applicability(
        self,
        adapter: ActionAdapter,
        request: ActionRequest,
    ) -> ApplicabilityResult:
        descriptor = adapter.descriptor
        missing: list[str] = []

        expected_shapes = (
            ("target", request.target, str),
            ("arguments", request.arguments, tuple),
            ("parameters", request.parameters, dict),
            ("command", request.command, str),
            ("facts", request.facts, tuple),
            ("evidence_fact_ids", request.evidence_fact_ids, tuple),
            ("assessment_refs", request.assessment_refs, tuple),
            ("source_execution_ids", request.source_execution_ids, tuple),
            ("provider_commands", request.provider_commands, dict),
            ("precondition_refs", request.precondition_refs, tuple),
        )
        for field_name, field_value, expected_type in expected_shapes:
            if not isinstance(field_value, expected_type):
                missing.append(f"blocked_by_input:request_shape:{field_name}")
        context = request.execution_context
        context_shapes = (
            ("actor", context.actor, str),
            ("origin", context.origin, str),
            ("target_scope", context.target_scope, tuple),
            ("capabilities", context.capabilities, frozenset),
            ("approved", context.approved, bool),
            ("approval_id", context.approval_id, str),
            ("request_id", context.request_id, str),
            ("max_runtime_seconds", context.max_runtime_seconds, int),
            ("max_output_bytes", context.max_output_bytes, int),
            ("cancellation", context.cancellation, CancellationContext),
        )
        for context_field_name, context_field_value, context_expected_type in context_shapes:
            if not isinstance(context_field_value, context_expected_type):
                missing.append(f"blocked_by_input:execution_context_shape:{context_field_name}")
        if isinstance(context.target_scope, tuple) and not all(isinstance(item, str) for item in context.target_scope):
            missing.append("blocked_by_input:execution_context_shape:target_scope")
        if isinstance(context.capabilities, frozenset) and not all(
            isinstance(item, str) for item in context.capabilities
        ):
            missing.append("blocked_by_input:execution_context_shape:capabilities")
        if isinstance(context.request_id, str) and not context.request_id.strip():
            missing.append("blocked_by_input:execution_context_shape:request_id")
        for limit_name, value in (
            ("max_runtime_seconds", context.max_runtime_seconds),
            ("max_output_bytes", context.max_output_bytes),
        ):
            if isinstance(value, bool) or (isinstance(value, int) and value < 0):
                missing.append(f"blocked_by_input:execution_context_shape:{limit_name}")
        if missing:
            return ApplicabilityResult(
                applicable=False,
                missing_requirements=tuple(missing),
            )

        if descriptor.input_type is not None:
            missing.extend(
                validate_typed_input(
                    request.typed_input,
                    descriptor.input_type,
                    request_target=request.target,
                )
            )

        if descriptor.manual_gate:
            if request.handle is not None:
                missing.append("blocked_by_input:ambient_handle")
            if request.command or request.provider_commands or request.arguments or request.parameters:
                missing.append("blocked_by_input:typed_input_only")

        required = descriptor.required_preconditions
        if required:
            if any(not isinstance(item, str) for item in request.precondition_refs):
                missing.append("blocked_by_input:precondition_refs")
            refs = frozenset(
                item.strip() for item in request.precondition_refs if isinstance(item, str) and item.strip()
            )
            if not refs or any(re.fullmatch(r"fact://[1-9][0-9]*", item) is None for item in refs):
                missing.append("blocked_by_input:precondition_refs")
            facts_by_ref = self._decision_facts_by_ref(request, refs)
            available = frozenset(facts_by_ref.values())
            allowed, reason = self.policy.check_preconditions(required, available)
            if not allowed:
                missing.append(reason)
            pivot_route_ref = str(getattr(request.typed_input, "pivot_route_ref", "") or "").strip()
            if pivot_route_ref and pivot_route_ref not in refs:
                missing.append("blocked_by_input:pivot_route_ref")
            elif pivot_route_ref and facts_by_ref.get(pivot_route_ref) != "confirmed_pivot":
                missing.append("blocked_by_precondition:pivot_route_ref")

        return ApplicabilityResult(
            applicable=not missing,
            reasons=("typed_runtime_contract_satisfied",) if not missing else (),
            missing_requirements=tuple(dict.fromkeys(missing)),
        )

    @staticmethod
    def _decision_facts_by_ref(
        request: ActionRequest,
        refs: frozenset[str],
    ) -> dict[str, str]:
        if not refs:
            return {}
        try:
            from core.ai.evaluated_facts import fact_is_decision_usable
            from core.ai.fact_predicates import TRUSTED, fact_trust_level
        except ImportError:
            return {}

        fact_types_by_ref: dict[str, str] = {}
        duplicate_refs: set[str] = set()
        for fact in request.facts:
            if not isinstance(fact, dict):
                continue
            try:
                usable = fact_is_decision_usable(fact)
            except (AttributeError, TypeError, ValueError):
                continue
            if not usable:
                continue
            raw_observations = fact.get("observations")
            if raw_observations is not None and not isinstance(raw_observations, (list, tuple)):
                continue
            if raw_observations and not all(isinstance(item, Mapping) for item in raw_observations):
                continue
            observations = tuple(raw_observations or ())
            has_explicit_trust = (
                all(str(item.get("trust_level") or "").strip().casefold() == TRUSTED for item in observations)
                if observations
                else str(fact.get("trust_level") or "").strip().casefold() == TRUSTED
            )
            if not has_explicit_trust or fact_trust_level(fact) != TRUSTED:
                continue
            assessment = fact.get("assessment")
            assessment = assessment if isinstance(assessment, Mapping) else {}
            assessment_status = str(assessment.get("status") or fact.get("assessment_status") or "").strip().casefold()
            if assessment_status != "verified":
                continue
            raw_ref = str(fact.get("fact_ref") or fact.get("ref") or "").strip()
            fact_id = fact.get("id")
            canonical_id_ref = (
                f"fact://{fact_id}"
                if isinstance(fact_id, int) and not isinstance(fact_id, bool) and fact_id > 0
                else ""
            )
            if raw_ref and re.fullmatch(r"fact://[1-9][0-9]*", raw_ref) is None:
                continue
            if raw_ref and canonical_id_ref and raw_ref != canonical_id_ref:
                continue
            raw_ref = raw_ref or canonical_id_ref
            if raw_ref not in refs:
                continue
            fact_target = str(fact.get("host") or fact.get("target") or "").strip()
            request_target = str(request.target or "").strip()
            if request_target and (not fact_target or fact_target.casefold() != request_target.casefold()):
                continue
            fact_type = str(fact.get("type") or fact.get("fact_type") or "").strip()
            if fact_type:
                if raw_ref in fact_types_by_ref:
                    duplicate_refs.add(raw_ref)
                    fact_types_by_ref.pop(raw_ref, None)
                elif raw_ref not in duplicate_refs:
                    fact_types_by_ref[raw_ref] = fact_type
        return {ref: fact_type for ref, fact_type in fact_types_by_ref.items() if ref not in duplicate_refs}

    @staticmethod
    def _policy_ref(decision: ExecutionDecision, phase: str) -> str:
        payload = {"phase": phase, "decision": decision.to_dict()}
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8", "replace")
        return f"policy://sha256/{hashlib.sha256(encoded).hexdigest()}"

    def _exception_result(
        self,
        adapter: ActionAdapter,
        request: ActionRequest,
        exc: Exception,
        *,
        phase: str,
    ) -> ExecutionResult:
        return adapter.normalize_result(
            {
                "status": "failed",
                "error_class": type(exc).__name__,
                "error_message": str(exc),
                "executed": phase == "execute",
            },
            request,
            phase=phase,
            redact_text=self.redact_text,
            redact_data=self.redact_data,
        )

    @staticmethod
    def _check_status(result: ExecutionResult) -> CheckStatus:
        if result.status is ExecutionStatus.UNAVAILABLE:
            return CheckStatus.UNAVAILABLE
        if result.status in {
            ExecutionStatus.FAILED,
            ExecutionStatus.TIMEOUT,
            ExecutionStatus.CANCELLED,
            ExecutionStatus.BLOCKED,
        }:
            return CheckStatus.FAILED
        return CheckStatus.COMPLETED

    @staticmethod
    def _outcome(status: ExecutionStatus) -> OutcomeStatus:
        return {
            ExecutionStatus.SUCCEEDED: OutcomeStatus.SUCCEEDED,
            ExecutionStatus.FAILED: OutcomeStatus.FAILED,
            ExecutionStatus.PARTIAL: OutcomeStatus.PARTIAL,
            ExecutionStatus.TIMEOUT: OutcomeStatus.TIMEOUT,
            ExecutionStatus.UNAVAILABLE: OutcomeStatus.UNAVAILABLE,
            ExecutionStatus.CANCELLED: OutcomeStatus.CANCELLED,
            ExecutionStatus.BLOCKED: OutcomeStatus.BLOCKED,
        }[status]


__all__ = ["ActionExecutor"]
