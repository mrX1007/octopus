"""Executor-owned V2 execution budgets and unforgeable budget leases."""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn, Protocol, runtime_checkable

from core.actions.cancellation import (
    CancellationToken,
    ExecutorCancellationController,
    ExecutorCancellationToken,
)

if TYPE_CHECKING:
    from core.actions.child_execution import RootExecutionAuthorityBundleV2
    from core.actions.request_v2 import BoundedActionRequestV2Envelope
    from core.auth.ingress_leases import ChildIngressLease, IngressInvocationLease


class ExecutionBudgetExhaustedError(RuntimeError):
    """Raised when a child cannot be admitted inside its parent budget."""


class ExecutionBudgetLeaseInvalidError(RuntimeError):
    """Raised when an executor boundary receives a forged or stale lease."""


@dataclass(frozen=True, repr=False)
class ExecutionBudget:
    absolute_deadline_monotonic: float
    max_output_bytes: int
    max_child_depth: int
    cancellation_token: CancellationToken

    def __post_init__(self) -> None:
        if not math.isfinite(self.absolute_deadline_monotonic):
            raise ValueError("execution budget deadline must be finite")
        if isinstance(self.max_output_bytes, bool) or self.max_output_bytes <= 0:
            raise ValueError("execution budget output limit must be positive")
        if isinstance(self.max_child_depth, bool) or self.max_child_depth < 0:
            raise ValueError("execution budget child depth cannot be negative")

    def __reduce__(self) -> NoReturn:
        raise TypeError("ExecutionBudget is executor-owned and non-serializable")


@dataclass(frozen=True)
class ExecutionLineage:
    root_execution_id: str
    parent_execution_id: str | None
    execution_graph_id: str
    child_depth: int

    def __post_init__(self) -> None:
        if not self.root_execution_id or not self.execution_graph_id:
            raise ValueError("execution lineage requires root and graph identities")
        if isinstance(self.child_depth, bool) or self.child_depth < 0:
            raise ValueError("execution lineage child depth cannot be negative")
        if self.child_depth == 0 and self.parent_execution_id is not None:
            raise ValueError("root lineage cannot have a parent execution")
        if self.child_depth > 0 and not self.parent_execution_id:
            raise ValueError("child lineage requires a parent execution")


class _ExecutionBudgetConstructionTokenV2:
    pass


@dataclass(frozen=True, init=False, repr=False)
class ExecutionBudgetLeaseV2:
    lease_id: str
    ingress_lease_id: str
    request_id: str
    budget: ExecutionBudget
    parent_budget_lease_id: str | None
    policy_revision: int
    lease_digest: str

    def __init__(self) -> None:
        raise TypeError("execution budget leases are authority-issued only")

    @classmethod
    def _from_authority(
        cls,
        *,
        _token: _ExecutionBudgetConstructionTokenV2,
        lease_id: str,
        ingress_lease_id: str,
        request_id: str,
        budget: ExecutionBudget,
        parent_budget_lease_id: str | None,
        policy_revision: int,
        lease_digest: str,
    ) -> ExecutionBudgetLeaseV2:
        if _token is not _BUDGET_CONSTRUCTION_TOKEN:
            raise TypeError("execution budget lease construction denied")
        instance = object.__new__(cls)
        object.__setattr__(instance, "lease_id", lease_id)
        object.__setattr__(instance, "ingress_lease_id", ingress_lease_id)
        object.__setattr__(instance, "request_id", request_id)
        object.__setattr__(instance, "budget", budget)
        object.__setattr__(instance, "parent_budget_lease_id", parent_budget_lease_id)
        object.__setattr__(instance, "policy_revision", policy_revision)
        object.__setattr__(instance, "lease_digest", lease_digest)
        return instance

    def __reduce__(self) -> NoReturn:
        raise TypeError("ExecutionBudgetLeaseV2 is non-serializable")


_BUDGET_CONSTRUCTION_TOKEN = _ExecutionBudgetConstructionTokenV2()


@runtime_checkable
class ExecutionBudgetLeaseRegistryV2(Protocol):
    def register(self, lease: ExecutionBudgetLeaseV2) -> None: ...

    def require_current(self, lease_id: str) -> ExecutionBudgetLeaseV2: ...


class InMemoryExecutionBudgetLeaseRegistryV2:
    """Authority-side identity registry; structural copies are rejected."""

    def __init__(self) -> None:
        self._leases: dict[str, ExecutionBudgetLeaseV2] = {}
        self._lock = threading.RLock()

    def register(self, lease: ExecutionBudgetLeaseV2) -> None:
        if type(lease) is not ExecutionBudgetLeaseV2:
            raise TypeError("only exact budget leases may be registered")
        with self._lock:
            if lease.lease_id in self._leases:
                raise ValueError("duplicate execution budget lease id")
            self._leases[lease.lease_id] = lease

    def require_current(self, lease_id: str) -> ExecutionBudgetLeaseV2:
        with self._lock:
            try:
                return self._leases[lease_id]
            except KeyError as exc:
                raise ExecutionBudgetLeaseInvalidError("unknown execution budget lease") from exc


@runtime_checkable
class ExecutionBudgetAuthorityV2(Protocol):
    def issue_root(
        self,
        *,
        ingress_lease: IngressInvocationLease,
        bounded_envelope: BoundedActionRequestV2Envelope,
    ) -> RootExecutionAuthorityBundleV2: ...

    def narrow_child(
        self,
        *,
        parent: ExecutionBudgetLeaseV2,
        child_request_id: str,
        child_action_id: str,
    ) -> ExecutionBudgetLeaseV2: ...

    def validate_root(
        self,
        lease: ExecutionBudgetLeaseV2,
        *,
        ingress_lease: IngressInvocationLease,
        request_id: str,
    ) -> ExecutionBudget: ...

    def validate_child(
        self,
        lease: ExecutionBudgetLeaseV2,
        *,
        parent: ExecutionBudgetLeaseV2,
        child_lease: ChildIngressLease,
        child_action_id: str,
    ) -> ExecutionBudget: ...


@dataclass(frozen=True)
class _IssuedBudgetMetadata:
    lease: ExecutionBudgetLeaseV2
    child_action_id: str | None


class OwnedExecutionBudgetAuthorityV2:
    """Sole production issuer of root and narrowed child budget leases."""

    def __init__(
        self,
        *,
        max_runtime_seconds: float = 300.0,
        max_output_bytes: int = 10 * 1024 * 1024,
        max_child_depth: int = 5,
        policy_revision: int = 1,
        lease_registry: ExecutionBudgetLeaseRegistryV2 | None = None,
    ) -> None:
        if not math.isfinite(max_runtime_seconds) or max_runtime_seconds <= 0:
            raise ValueError("max_runtime_seconds must be finite and positive")
        if isinstance(max_output_bytes, bool) or max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if isinstance(max_child_depth, bool) or max_child_depth < 0:
            raise ValueError("max_child_depth cannot be negative")
        if isinstance(policy_revision, bool) or policy_revision <= 0:
            raise ValueError("policy_revision must be positive")
        self._max_runtime_seconds = max_runtime_seconds
        self._max_output_bytes = max_output_bytes
        self._max_child_depth = max_child_depth
        self._policy_revision = policy_revision
        self._lease_registry = lease_registry or InMemoryExecutionBudgetLeaseRegistryV2()
        self._metadata: dict[str, _IssuedBudgetMetadata] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _digest(
        *,
        lease_id: str,
        ingress_lease_id: str,
        request_id: str,
        budget: ExecutionBudget,
        parent_budget_lease_id: str | None,
        policy_revision: int,
        child_action_id: str | None,
    ) -> str:
        payload = {
            "schema": "execution-budget-lease/2.0",
            "lease_id": lease_id,
            "ingress_lease_id": ingress_lease_id,
            "request_id": request_id,
            "absolute_deadline_monotonic": budget.absolute_deadline_monotonic,
            "max_output_bytes": budget.max_output_bytes,
            "max_child_depth": budget.max_child_depth,
            "cancellation_token_id": budget.cancellation_token.token_id,
            "parent_budget_lease_id": parent_budget_lease_id,
            "policy_revision": policy_revision,
            "child_action_id": child_action_id,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def _mint(
        self,
        *,
        ingress_lease_id: str,
        request_id: str,
        budget: ExecutionBudget,
        parent_budget_lease_id: str | None,
        child_action_id: str | None,
    ) -> ExecutionBudgetLeaseV2:
        lease_id = f"budget-{uuid.uuid4().hex}"
        digest = self._digest(
            lease_id=lease_id,
            ingress_lease_id=ingress_lease_id,
            request_id=request_id,
            budget=budget,
            parent_budget_lease_id=parent_budget_lease_id,
            policy_revision=self._policy_revision,
            child_action_id=child_action_id,
        )
        lease = ExecutionBudgetLeaseV2._from_authority(
            _token=_BUDGET_CONSTRUCTION_TOKEN,
            lease_id=lease_id,
            ingress_lease_id=ingress_lease_id,
            request_id=request_id,
            budget=budget,
            parent_budget_lease_id=parent_budget_lease_id,
            policy_revision=self._policy_revision,
            lease_digest=digest,
        )
        with self._lock:
            self._lease_registry.register(lease)
            self._metadata[lease_id] = _IssuedBudgetMetadata(lease=lease, child_action_id=child_action_id)
        return lease

    def issue_root(
        self,
        *,
        ingress_lease: IngressInvocationLease,
        bounded_envelope: BoundedActionRequestV2Envelope,
    ) -> RootExecutionAuthorityBundleV2:
        from core.actions.child_execution import RootExecutionAuthorityBundleV2
        from core.auth.ingress_leases import IngressInvocationLease

        if type(ingress_lease) is not IngressInvocationLease:
            raise ExecutionBudgetLeaseInvalidError("root budget requires an exact ingress lease")
        if bounded_envelope.request_id != ingress_lease.bound_request_id:
            raise ExecutionBudgetLeaseInvalidError("root budget request/ingress mismatch")
        controller = ExecutorCancellationController(f"cancel-{uuid.uuid4().hex}")
        budget = ExecutionBudget(
            absolute_deadline_monotonic=time.monotonic() + self._max_runtime_seconds,
            max_output_bytes=self._max_output_bytes,
            max_child_depth=self._max_child_depth,
            cancellation_token=controller.token,
        )
        lease = self._mint(
            ingress_lease_id=ingress_lease.lease_id,
            request_id=bounded_envelope.request_id,
            budget=budget,
            parent_budget_lease_id=None,
            child_action_id=None,
        )
        return RootExecutionAuthorityBundleV2._from_authority(
            budget_lease=lease,
            cancellation_controller=controller,
        )

    def narrow_child(
        self,
        *,
        parent: ExecutionBudgetLeaseV2,
        child_request_id: str,
        child_action_id: str,
    ) -> ExecutionBudgetLeaseV2:
        parent_budget = self._validate_registered(parent)
        if parent_budget.max_child_depth <= 0:
            raise ExecutionBudgetExhaustedError("maximum execution graph depth reached")
        if time.monotonic() >= parent_budget.absolute_deadline_monotonic:
            raise ExecutionBudgetExhaustedError("parent execution deadline expired")
        child_budget = ExecutionBudget(
            absolute_deadline_monotonic=parent_budget.absolute_deadline_monotonic,
            max_output_bytes=parent_budget.max_output_bytes,
            max_child_depth=parent_budget.max_child_depth - 1,
            cancellation_token=parent_budget.cancellation_token,
        )
        return self._mint(
            ingress_lease_id=parent.ingress_lease_id,
            request_id=child_request_id,
            budget=child_budget,
            parent_budget_lease_id=parent.lease_id,
            child_action_id=child_action_id,
        )

    def _validate_registered(self, lease: ExecutionBudgetLeaseV2) -> ExecutionBudget:
        if type(lease) is not ExecutionBudgetLeaseV2:
            raise ExecutionBudgetLeaseInvalidError("forged execution budget lease type")
        current = self._lease_registry.require_current(lease.lease_id)
        if current is not lease:
            raise ExecutionBudgetLeaseInvalidError("copied execution budget lease denied")
        metadata = self._metadata.get(lease.lease_id)
        if metadata is None or metadata.lease is not lease:
            raise ExecutionBudgetLeaseInvalidError("budget lease has no issuer metadata")
        expected = self._digest(
            lease_id=lease.lease_id,
            ingress_lease_id=lease.ingress_lease_id,
            request_id=lease.request_id,
            budget=lease.budget,
            parent_budget_lease_id=lease.parent_budget_lease_id,
            policy_revision=lease.policy_revision,
            child_action_id=metadata.child_action_id,
        )
        if lease.policy_revision != self._policy_revision or lease.lease_digest != expected:
            raise ExecutionBudgetLeaseInvalidError("execution budget lease integrity mismatch")
        if type(lease.budget.cancellation_token) is not ExecutorCancellationToken:
            raise ExecutionBudgetLeaseInvalidError("forged cancellation token denied")
        return lease.budget

    def validate_root(
        self,
        lease: ExecutionBudgetLeaseV2,
        *,
        ingress_lease: IngressInvocationLease,
        request_id: str,
    ) -> ExecutionBudget:
        budget = self._validate_registered(lease)
        if lease.parent_budget_lease_id is not None:
            raise ExecutionBudgetLeaseInvalidError("child budget supplied at root boundary")
        if lease.ingress_lease_id != ingress_lease.lease_id or lease.request_id != request_id:
            raise ExecutionBudgetLeaseInvalidError("root budget identity mismatch")
        return budget

    def validate_child(
        self,
        lease: ExecutionBudgetLeaseV2,
        *,
        parent: ExecutionBudgetLeaseV2,
        child_lease: ChildIngressLease,
        child_action_id: str,
    ) -> ExecutionBudget:
        budget = self._validate_registered(lease)
        parent_budget = self._validate_registered(parent)
        metadata = self._metadata[lease.lease_id]
        if lease.parent_budget_lease_id != parent.lease_id:
            raise ExecutionBudgetLeaseInvalidError("child budget parent mismatch")
        if lease.request_id != child_lease.bound_child_request_id:
            raise ExecutionBudgetLeaseInvalidError("child budget request mismatch")
        if metadata.child_action_id != child_action_id:
            raise ExecutionBudgetLeaseInvalidError("child budget action mismatch")
        if budget.cancellation_token is not parent_budget.cancellation_token:
            raise ExecutionBudgetLeaseInvalidError("child cancellation token mismatch")
        if budget.absolute_deadline_monotonic > parent_budget.absolute_deadline_monotonic:
            raise ExecutionBudgetLeaseInvalidError("child deadline widened")
        if budget.max_output_bytes > parent_budget.max_output_bytes:
            raise ExecutionBudgetLeaseInvalidError("child output limit widened")
        if budget.max_child_depth >= parent_budget.max_child_depth:
            raise ExecutionBudgetLeaseInvalidError("child depth was not narrowed")
        return budget

    def _validate_child_current(
        self,
        lease: ExecutionBudgetLeaseV2,
        *,
        child_lease: ChildIngressLease,
        child_action_id: str,
    ) -> ExecutionBudget:
        """Validate a bridge lease against its authority-held parent object."""

        if type(lease) is not ExecutionBudgetLeaseV2 or not lease.parent_budget_lease_id:
            raise ExecutionBudgetLeaseInvalidError("child budget has no parent binding")
        parent = self._lease_registry.require_current(lease.parent_budget_lease_id)
        return self.validate_child(
            lease,
            parent=parent,
            child_lease=child_lease,
            child_action_id=child_action_id,
        )


__all__ = [
    "ExecutionBudget",
    "ExecutionBudgetAuthorityV2",
    "ExecutionBudgetExhaustedError",
    "ExecutionBudgetLeaseInvalidError",
    "ExecutionBudgetLeaseRegistryV2",
    "ExecutionBudgetLeaseV2",
    "ExecutionLineage",
    "InMemoryExecutionBudgetLeaseRegistryV2",
    "OwnedExecutionBudgetAuthorityV2",
]
