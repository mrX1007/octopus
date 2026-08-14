"""PR-5 Module: Intent bound owner factories (§8.3)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from core.actions.execution_recovery_types import ApprovalGraphRecoveryRefV2


@dataclass(frozen=True)
class ExecutorCheckoutRequestBundle:
    execution_id: str
    action_id: str
    target: str
    requested_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckoutOwnerCreationSpecV2:
    request: ExecutorCheckoutRequestBundle
    request_digest: str


@dataclass(frozen=True)
class InvocationScopeCreationSpecV2:
    execution_id: str
    transaction_id: str
    cleanup_registry_revision: int
    spec_digest: str


@dataclass(frozen=True)
class ApprovalGraphCreationSpecV2:
    root_action_id: str
    execution_graph_id: str
    approval_ref: str | None
    approval_revision: int | None
    spec_digest: str


@dataclass(frozen=True)
class AttemptReservationCreationSpecV2:
    graph_recovery_ref: ApprovalGraphRecoveryRefV2
    attempt_group_id: str
    concrete_action_id: str
    spec_digest: str


class IntentBoundOwnerFactory:
    """Factory creating intent-bound resource owners."""

    def create_checkout_spec(self, request: ExecutorCheckoutRequestBundle) -> CheckoutOwnerCreationSpecV2:
        raw = json.dumps(
            {"execution_id": request.execution_id, "action_id": request.action_id}, sort_keys=True
        ).encode()
        digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        return CheckoutOwnerCreationSpecV2(request=request, request_digest=digest)


__all__ = [
    "ApprovalGraphCreationSpecV2",
    "AttemptReservationCreationSpecV2",
    "CheckoutOwnerCreationSpecV2",
    "ExecutorCheckoutRequestBundle",
    "IntentBoundOwnerFactory",
    "InvocationScopeCreationSpecV2",
]
