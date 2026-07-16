"""Policy-gated orchestration for the canonical action lifecycle."""

from __future__ import annotations

import hashlib
import json
import time

from core.execution import (
    ExecutionCancelled,
    ExecutionDecision,
    ExecutionPolicy,
    ExecutionResult,
    ExecutionStatus,
    bind_execution_context,
)

from .base import ActionAdapter, DataRedactor, TextRedactor
from .catalog import ActionCatalog
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
        resolved = self.catalog.require(action_name)
        adapter = resolved.adapter
        lifecycle = ActionLifecycle()
        lifecycle.record(
            "candidate",
            reason=(f"alias:{resolved.requested_name}" if resolved.alias_used else "canonical_id"),
        )
        report = ActionExecutionReport(adapter.descriptor, lifecycle)

        try:
            applicability = adapter.applicability(request)
        except Exception as exc:
            applicability = ApplicabilityResult(
                applicable=False,
                reasons=("applicability_error",),
                missing_requirements=(f"adapter_error:{type(exc).__name__}",),
            )
        report.applicability = applicability
        lifecycle.applicability = (
            ApplicabilityStatus.APPLICABLE
            if applicability.applicable
            else ApplicabilityStatus.NOT_APPLICABLE
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
            report.policy_decision_refs.append(self._policy_ref(decision, "check"))
            if not decision.allowed:
                lifecycle.check = CheckStatus.BLOCKED
                lifecycle.record("check_blocked", reason=decision.reason)
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
        report.policy_decision_refs.append(self._policy_ref(decision, "execute"))
        if not decision.allowed:
            lifecycle.attempt = AttemptStatus.BLOCKED
            lifecycle.outcome = OutcomeStatus.BLOCKED
            lifecycle.record("execution_blocked", reason=decision.reason)
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
                VerificationStatus.VERIFIED
                if verification.verified
                else VerificationStatus.UNVERIFIED
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
            lifecycle.cleanup = (
                CleanupStatus.SUCCEEDED
                if cleanup_result.succeeded
                else CleanupStatus.FAILED
            )
            lifecycle.record(lifecycle.cleanup.value, reason=cleanup_result.reason)

        return report

    def _authorize(
        self,
        adapter: ActionAdapter,
        request: ActionRequest,
        phase: str,
    ) -> ExecutionDecision:
        try:
            return adapter.authorize(self.policy, request, phase)
        except Exception as exc:
            return ExecutionDecision(
                allowed=False,
                reason=f"action_invocation_invalid:{type(exc).__name__}",
                context=request.execution_context,
            )

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
