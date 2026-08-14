"""TypedActionAdapterV2 protocol and bound execution contexts (§12.2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from core.actions.provider_results import ProviderResultFoundationV2
from core.actions.request_v2 import ActionRequestV2


@dataclass(frozen=True)
class BoundProviderCheckContext:
    request: ActionRequestV2


@dataclass(frozen=True)
class BoundProviderInvocationContext:
    request: ActionRequestV2
    # PR-4 exposes no provider material view. PR-5 replaces this deliberately
    # empty compatibility slot with the phase-leased BoundMaterialBundle.
    materials: tuple[()] = ()
    transaction_id: str = "tx-default"

    def __post_init__(self) -> None:
        if self.materials != ():
            raise ValueError("provider_materials_require_phase_leased_pr5_bundle")


@dataclass(frozen=True)
class BoundProviderVerificationContext:
    request: ActionRequestV2
    result: ProviderResultFoundationV2


@runtime_checkable
class TypedActionAdapterV2(Protocol):
    action_id: str
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool: ...

    def execute_bound(self, context: BoundProviderInvocationContext) -> ProviderResultFoundationV2: ...

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool: ...


__all__ = [
    "BoundProviderCheckContext",
    "BoundProviderInvocationContext",
    "BoundProviderVerificationContext",
    "TypedActionAdapterV2",
]
