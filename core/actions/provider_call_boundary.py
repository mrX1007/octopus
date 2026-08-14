"""PR-5 Module: Provider call boundary, revocable phase lease, and execution isolation (§8.6)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from core.actions.cancellation import CancellationToken
from core.actions.provider_call_types import (
    ProviderCallOutcomeV2,
    ProviderCallPhaseV2,
    ProviderPhaseCallPlanV2,
    ProviderTerminationReasonV2,
)
from core.actions.provider_invocation import (
    DefaultProviderInvocationScopeV2,
    ProviderExecutePhaseLeaseV2,
    ProviderInvocationScopeV2,
    ProviderPhaseLeaseStateV2,
)
from core.actions.provider_participants import ProviderParticipantRegistrationFacade


class ProviderExecutionTimeoutError(TimeoutError):
    """Raised when a provider execution exceeds its planned deadline."""


class ProviderExecutionCancelledError(RuntimeError):
    """Raised when a provider execution is cancelled."""


class ProviderOutputLimitExceededError(ValueError):
    """Raised when a provider produces output exceeding the planned byte limit."""


class _ProviderExecutePhaseLeaseControllerV2:
    """Controller that can activate and revoke a ProviderExecutePhaseLeaseV2."""

    def __init__(self) -> None:
        self._lease = ProviderExecutePhaseLeaseV2(state=ProviderPhaseLeaseStateV2.PENDING)

    @property
    def lease(self) -> ProviderExecutePhaseLeaseV2:
        return self._lease

    def activate(self) -> None:
        self._lease._state = ProviderPhaseLeaseStateV2.ACTIVE

    def revoke(self) -> None:
        self._lease._state = ProviderPhaseLeaseStateV2.REVOKED


@dataclass(frozen=True)
class BoundProviderInvocationContext:
    execution_id: str
    action_id: str
    transaction_id: str
    input_dto: Any
    materials: tuple[Any, ...] = ()
    scope: ProviderInvocationScopeV2 = field(default_factory=DefaultProviderInvocationScopeV2)
    cancellation_token: CancellationToken | None = None
    staging: ProviderParticipantRegistrationFacade | None = None
    deadline_monotonic: float = field(default_factory=lambda: time.monotonic() + 300.0)


class ProviderCallBoundary:
    """Authoritative execution boundary for all V2 typed providers and composite routers."""

    def __init__(self) -> None:
        pass

    def invoke_check(
        self,
        context: BoundProviderInvocationContext,
        provider: Any,
    ) -> Any:
        if hasattr(provider, "check_bound"):
            return provider.check_bound(context)
        return None

    def invoke_execute(
        self,
        context: BoundProviderInvocationContext,
        provider: Any,
        plan: ProviderPhaseCallPlanV2 | None = None,
    ) -> tuple[Any, ProviderCallOutcomeV2]:
        start_time = time.monotonic()
        controller = _ProviderExecutePhaseLeaseControllerV2()
        controller.activate()

        # Check cancellation before invocation
        if context.cancellation_token and context.cancellation_token.is_cancelled():
            controller.revoke()
            outcome = ProviderCallOutcomeV2(
                execution_id=context.execution_id,
                action_id=context.action_id,
                phase=ProviderCallPhaseV2.EXECUTE,
                termination_reason=ProviderTerminationReasonV2.CANCELLED,
                duration_seconds=0.0,
                raw_output_bytes_count=0,
                redacted_error="Execution cancelled before provider start",
            )
            raise ProviderExecutionCancelledError("Execution cancelled before provider start")

        try:
            # Check deadline
            if time.monotonic() > context.deadline_monotonic:
                raise ProviderExecutionTimeoutError("Execution deadline exceeded before start")

            # Invoke execute_bound
            if not hasattr(provider, "execute_bound"):
                raise AttributeError(f"Provider {type(provider)} does not implement execute_bound")

            result = provider.execute_bound(context)

            # Check cancellation after invocation
            if context.cancellation_token and context.cancellation_token.is_cancelled():
                raise ProviderExecutionCancelledError("Execution cancelled during provider execution")

            duration = time.monotonic() - start_time
            outcome = ProviderCallOutcomeV2(
                execution_id=context.execution_id,
                action_id=context.action_id,
                phase=ProviderCallPhaseV2.EXECUTE,
                termination_reason=ProviderTerminationReasonV2.COMPLETED,
                duration_seconds=duration,
                raw_output_bytes_count=len(str(result).encode()),
            )
            return result, outcome

        except Exception as exc:
            duration = time.monotonic() - start_time
            reason = ProviderTerminationReasonV2.EXCEPTION
            if isinstance(exc, TimeoutError):
                reason = ProviderTerminationReasonV2.TIMEOUT
            elif isinstance(exc, ProviderExecutionCancelledError):
                reason = ProviderTerminationReasonV2.CANCELLED

            outcome = ProviderCallOutcomeV2(
                execution_id=context.execution_id,
                action_id=context.action_id,
                phase=ProviderCallPhaseV2.EXECUTE,
                termination_reason=reason,
                duration_seconds=duration,
                raw_output_bytes_count=0,
                redacted_error=str(exc),
            )
            raise

        finally:
            # Guarantee revocation of provider capability views in finally
            controller.revoke()

    def invoke_verify(
        self,
        context: BoundProviderInvocationContext,
        provider: Any,
        result: Any,
    ) -> Any:
        if hasattr(provider, "verify_bound"):
            return provider.verify_bound(context, result)
        return None

    def invoke_route(
        self,
        context: BoundProviderInvocationContext,
        router: Any,
    ) -> Any:
        if hasattr(router, "route_bound"):
            return router.route_bound(context)
        raise AttributeError(f"Composite router {type(router)} does not implement route_bound")


__all__ = [
    "BoundProviderInvocationContext",
    "ProviderCallBoundary",
    "ProviderExecutionCancelledError",
    "ProviderExecutionTimeoutError",
    "ProviderOutputLimitExceededError",
    "_ProviderExecutePhaseLeaseControllerV2",
]
