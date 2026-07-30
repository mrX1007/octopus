"""Hermetic defensive-path coverage for policy-gated action execution."""

from __future__ import annotations

import pytest

from core.actions.base import ActionAdapter
from core.actions.catalog import ActionCatalog
from core.actions.executor import ActionExecutor
from core.actions.models import (
    ActionCheckResult,
    ActionCleanupResult,
    ActionDescriptor,
    ActionKind,
    ActionRequest,
    ActionRequirements,
    ActionVerificationResult,
    ApplicabilityResult,
    ApplicabilityStatus,
    AttemptStatus,
    CheckStatus,
    CleanupStatus,
    VerificationStatus,
)
from core.execution import (
    ExecutionContext,
    ExecutionDecision,
    ExecutionPolicy,
    ExecutionResult,
    ExecutionStatus,
)

_DEFAULT = object()

pytestmark = [pytest.mark.contract, pytest.mark.security]


class BoundaryAdapter(ActionAdapter):
    def __init__(
        self,
        action_id: str,
        *,
        requirements: ActionRequirements | None = None,
        applicability_error: Exception | None = None,
        authorization_errors: frozenset[str] = frozenset(),
        denied_phases: frozenset[str] = frozenset(),
        check_value=_DEFAULT,
        check_error: Exception | None = None,
        execute_value=_DEFAULT,
        verify_value=_DEFAULT,
        verify_error: Exception | None = None,
        cleanup_value=_DEFAULT,
        cleanup_error: Exception | None = None,
    ) -> None:
        self.descriptor = ActionDescriptor(
            action_id=action_id,
            name=action_id,
            kind=ActionKind.REGISTERED_TOOL,
            provider="fixture",
            requirements=requirements or ActionRequirements(),
        )
        self.applicability_error = applicability_error
        self.authorization_errors = authorization_errors
        self.denied_phases = denied_phases
        self.check_value = check_value
        self.check_error = check_error
        self.execute_value = execute_value
        self.verify_value = verify_value
        self.verify_error = verify_error
        self.cleanup_value = cleanup_value
        self.cleanup_error = cleanup_error

    def applicability(self, request: ActionRequest) -> ApplicabilityResult:
        del request
        if self.applicability_error is not None:
            raise self.applicability_error
        return ApplicabilityResult(True, reasons=("fixture",))

    def invocation(self, request: ActionRequest, phase: str):
        return self.registered_invocation(
            f"{self.descriptor.name} {request.target} --phase {phase}",
            self.descriptor.name,
        )

    def authorize(self, policy, request: ActionRequest, phase: str):
        del policy
        if phase in self.authorization_errors:
            raise RuntimeError(f"{phase} authorization fixture")
        allowed = phase not in self.denied_phases
        return ExecutionDecision(
            allowed=allowed,
            reason="allowed" if allowed else "fixture denied",
            context=request.execution_context,
        )

    def check(self, request: ActionRequest):
        del request
        if self.check_error is not None:
            raise self.check_error
        if self.check_value is _DEFAULT:
            return ActionCheckResult(
                result={"status": "succeeded"},
                applicable=True,
                reason="fixture check",
            )
        return self.check_value

    def execute(self, request: ActionRequest):
        del request
        if self.execute_value is _DEFAULT:
            return {"status": "succeeded", "duration": 2.0}
        return self.execute_value

    def verify(self, request: ActionRequest, result: ExecutionResult):
        del request, result
        if self.verify_error is not None:
            raise self.verify_error
        if self.verify_value is _DEFAULT:
            return ActionVerificationResult(False, "fixture unverified")
        return self.verify_value

    def cleanup(self, request: ActionRequest, result: ExecutionResult | None):
        del request, result
        if self.cleanup_error is not None:
            raise self.cleanup_error
        if self.cleanup_value is _DEFAULT:
            return ActionCleanupResult(True, "fixture cleanup")
        return self.cleanup_value


def _request() -> ActionRequest:
    return ActionRequest(
        "example.com",
        ExecutionContext.automatic(
            target_scope=("example.com",),
            actor="executor-coverage",
            origin="test",
        ),
    )


def _run(adapter: BoundaryAdapter, **options):
    catalog = ActionCatalog()
    catalog.register(adapter)
    executor = ActionExecutor(catalog, ExecutionPolicy())
    return executor.run(adapter.descriptor.action_id, _request(), **options)


def test_applicability_exception_is_a_typed_not_applicable_report() -> None:
    report = _run(
        BoundaryAdapter(
            "fixture:applicability-error",
            applicability_error=RuntimeError("fixture"),
        )
    )

    assert report.lifecycle.applicability is ApplicabilityStatus.NOT_APPLICABLE
    assert report.applicability is not None
    assert report.applicability.reasons == ("applicability_error",)
    assert report.applicability.missing_requirements == (
        "adapter_error:RuntimeError",
    )


def test_check_authorization_exception_fails_closed_before_provider_call() -> None:
    report = _run(
        BoundaryAdapter(
            "fixture:check-authorization-error",
            requirements=ActionRequirements(supports_check=True),
            authorization_errors=frozenset({"check"}),
        )
    )

    assert report.lifecycle.check is CheckStatus.BLOCKED
    assert report.lifecycle.attempt is AttemptStatus.NOT_ATTEMPTED
    assert len(report.policy_decision_refs) == 1
    assert report.policy_denials[0].reason_code == "action_invocation_invalid"


def test_legacy_check_payload_is_wrapped_and_check_only_run_stops_cleanly() -> None:
    report = _run(
        BoundaryAdapter(
            "fixture:legacy-check",
            requirements=ActionRequirements(supports_check=True),
            check_value={"status": "succeeded", "stdout": "checked"},
        ),
        execute=False,
    )

    assert report.lifecycle.check is CheckStatus.COMPLETED
    assert report.lifecycle.check_positive is None
    assert report.check_result is not None
    assert report.check_result.stdout == "checked"
    assert report.lifecycle.attempt is AttemptStatus.NOT_ATTEMPTED


def test_check_exception_is_normalized_and_stops_execution() -> None:
    report = _run(
        BoundaryAdapter(
            "fixture:check-error",
            requirements=ActionRequirements(supports_check=True),
            check_error=ValueError("check failure"),
        )
    )

    assert report.lifecycle.check is CheckStatus.FAILED
    assert report.check_result is not None
    assert report.check_result.status is ExecutionStatus.FAILED
    assert report.check_result.error_class == "ValueError"
    assert report.check_result.executed is False


def test_noncompleted_check_and_positive_check_requirement_exit_paths() -> None:
    unavailable = _run(
        BoundaryAdapter(
            "fixture:unavailable-check",
            requirements=ActionRequirements(supports_check=True),
            check_value=ActionCheckResult(
                result={"status": "unavailable"},
                applicable=True,
            ),
        )
    )
    assert unavailable.lifecycle.check is CheckStatus.UNAVAILABLE
    assert unavailable.lifecycle.attempt is AttemptStatus.NOT_ATTEMPTED

    positive_required = _run(
        BoundaryAdapter(
            "fixture:positive-required",
            requirements=ActionRequirements(
                supports_check=True,
                positive_check_required=True,
            ),
            check_value=ActionCheckResult(
                result={"status": "succeeded"},
                applicable=None,
            ),
        )
    )
    assert positive_required.lifecycle.check is CheckStatus.COMPLETED
    assert positive_required.lifecycle.check_positive is None
    assert positive_required.lifecycle.attempt is AttemptStatus.NOT_ATTEMPTED


def test_positive_duration_and_invalid_or_raising_verification_paths() -> None:
    invalid = _run(
        BoundaryAdapter(
            "fixture:invalid-verification",
            verify_value=object(),
        )
    )
    assert invalid.execution_result is not None
    assert invalid.execution_result.duration == 2.0
    assert invalid.lifecycle.verification is VerificationStatus.UNVERIFIED
    assert invalid.verification_result is not None
    assert "invalid verification" in invalid.verification_result.reason

    raised = _run(
        BoundaryAdapter(
            "fixture:raising-verification",
            verify_error=RuntimeError("verification fixture"),
        )
    )
    assert raised.lifecycle.verification is VerificationStatus.UNVERIFIED
    assert raised.verification_result is not None
    assert raised.verification_result.reason == "Verification failed: RuntimeError"


def test_invalid_or_raising_cleanup_results_fail_without_relabeling_outcome() -> None:
    requirements = ActionRequirements(supports_cleanup=True)
    invalid = _run(
        BoundaryAdapter(
            "fixture:invalid-cleanup",
            requirements=requirements,
            execute_value={"status": "failed", "duration": 2.0},
            cleanup_value=object(),
        )
    )
    assert invalid.lifecycle.cleanup is CleanupStatus.FAILED
    assert invalid.cleanup_result is not None
    assert "invalid cleanup" in invalid.cleanup_result.reason

    raised = _run(
        BoundaryAdapter(
            "fixture:raising-cleanup",
            requirements=requirements,
            execute_value={"status": "failed", "duration": 2.0},
            cleanup_error=RuntimeError("cleanup fixture"),
        )
    )
    assert raised.lifecycle.cleanup is CleanupStatus.FAILED
    assert raised.cleanup_result is not None
    assert raised.cleanup_result.reason == "Cleanup failed: RuntimeError"


def test_check_status_maps_unavailable_failures_and_completed_results() -> None:
    assert ActionExecutor._check_status(
        ExecutionResult(status=ExecutionStatus.UNAVAILABLE)
    ) is CheckStatus.UNAVAILABLE
    for status in (
        ExecutionStatus.FAILED,
        ExecutionStatus.TIMEOUT,
        ExecutionStatus.CANCELLED,
        ExecutionStatus.BLOCKED,
    ):
        assert ActionExecutor._check_status(ExecutionResult(status=status)) is (
            CheckStatus.FAILED
        )
    assert ActionExecutor._check_status(
        ExecutionResult(status=ExecutionStatus.SUCCEEDED)
    ) is CheckStatus.COMPLETED
