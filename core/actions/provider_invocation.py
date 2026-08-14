"""Provider invocation scope, phase lease, and transient handle contracts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Literal, Protocol, runtime_checkable

class ProviderTransientKindV2(str, Enum):
    ARTIFACT = "artifact"
    REMOTE_FORWARD = "remote_forward"
    ROUTE_STREAM = "route_stream"
    PROCESS = "process"
    TEMPORARY_FILE = "temporary_file"

class ProviderPhaseLeaseStateV2(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"

class CleanupDescriptorKindV2(str, Enum):
    CLOSE_TRANSIENT = "close_transient"
    RELEASE_CHECKOUT = "release_checkout"
    RELEASE_RESERVATION = "release_reservation"
    CLOSE_LOCAL_IPC = "close_local_ipc"

@dataclass(frozen=True)
class RecoverableCleanupDescriptorV2:
    cleanup_id: str
    kind: CleanupDescriptorKindV2
    registry_id: str
    resource_ref: str
    expected_revision: int | None
    idempotency_key: str
    descriptor_digest: str

@dataclass(frozen=True)
class BackendOwnedTransientReceiptV2:
    backend_registry_id: str
    backend_handle_ref: str
    transient_kind: ProviderTransientKindV2
    cleanup_descriptor: RecoverableCleanupDescriptorV2
    receipt_digest: str

@dataclass(frozen=True)
class ProviderTransientRegistrationV2:
    creation_receipt: BackendOwnedTransientReceiptV2

class ProviderExecutePhaseLeaseV2:
    """Read-only capability view; providers cannot change its state."""

    def __init__(self, state: ProviderPhaseLeaseStateV2 = ProviderPhaseLeaseStateV2.ACTIVE) -> None:
        self._state = state

    @property
    def state(self) -> ProviderPhaseLeaseStateV2:
        return self._state

    @property
    def active(self) -> bool:
        return self._state == ProviderPhaseLeaseStateV2.ACTIVE

    def require_active(self) -> None:
        if not self.active:
            raise RuntimeError(f"ProviderExecutePhaseLease is not active (state={self._state})")

class PhaseBoundTransientRefV2:
    """Final provider view; no raw backend handle or public constructor."""

    def __init__(
        self,
        transient_id: str,
        transient_kind: ProviderTransientKindV2,
        phase_lease: ProviderExecutePhaseLeaseV2,
    ) -> None:
        self._transient_id = transient_id
        self._transient_kind = transient_kind
        self._phase_lease = phase_lease

    @property
    def transient_id(self) -> str:
        return self._transient_id

    @property
    def transient_kind(self) -> ProviderTransientKindV2:
        return self._transient_kind

    @property
    def phase_lease(self) -> ProviderExecutePhaseLeaseV2:
        return self._phase_lease

    def require_active(self) -> None:
        self._phase_lease.require_active()

@runtime_checkable
class ProviderInvocationScopeV2(Protocol):
    """Provider-visible view: closed resource descriptors only."""

    @property
    def phase_lease(self) -> ProviderExecutePhaseLeaseV2: ...
    def register_transient(
        self,
        request: ProviderTransientRegistrationV2,
    ) -> PhaseBoundTransientRefV2: ...

class DefaultProviderInvocationScopeV2:
    """Concrete implementation of ProviderInvocationScopeV2."""

    def __init__(self, phase_lease: ProviderExecutePhaseLeaseV2 | None = None) -> None:
        self._phase_lease = phase_lease or ProviderExecutePhaseLeaseV2()
        self._registered: dict[str, PhaseBoundTransientRefV2] = {}

    @property
    def phase_lease(self) -> ProviderExecutePhaseLeaseV2:
        return self._phase_lease

    def register_transient(
        self,
        request: ProviderTransientRegistrationV2,
    ) -> PhaseBoundTransientRefV2:
        self._phase_lease.require_active()
        receipt = request.creation_receipt
        t_ref = PhaseBoundTransientRefV2(
            transient_id=receipt.backend_handle_ref,
            transient_kind=receipt.transient_kind,
            phase_lease=self._phase_lease,
        )
        self._registered[t_ref.transient_id] = t_ref
        return t_ref
