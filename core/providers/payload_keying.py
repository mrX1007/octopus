"""Fail-closed payload-keying provider contract.

The PR-8 backend/staging integration is not present yet. This module keeps the
typed surface importable, but it never fabricates backend transients or artifact
draft references. The provider must remain unmounted until the executor can
supply its restricted staging and transient-ownership facades.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NoReturn

from core.actions.bound_adapters import (
    BoundProviderCheckContext,
    BoundProviderInvocationContext,
    BoundProviderVerificationContext,
    TypedActionAdapterV2,
)
from core.actions.input_contracts import PayloadKeyingInputV2, PayloadKeyingProfileId
from core.actions.provider_invocation import BackendOwnedTransientReceiptV2
from core.actions.provider_results import ArtifactProviderResult
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS


class ProviderUnavailableError(RuntimeError):
    """The reviewed backend/staging path required by this provider is absent."""


@dataclass(frozen=True)
class PayloadTargetMetadata:
    target_os: C2TargetOS
    target_arch: C2TargetArch
    hostname: str | None
    username: str | None
    mac_address: str | None
    machine_id: str | None
    metadata_revision: int


@dataclass(frozen=True, repr=False)
class PayloadKeyingBackendResult:
    """Receipt-only backend output; raw payload bytes are never represented."""

    encrypted_payload: BackendOwnedTransientReceiptV2 = field(repr=False, compare=False)
    loader: BackendOwnedTransientReceiptV2 = field(repr=False, compare=False)
    encrypted_payload_digest: str
    loader_digest: str
    profile_id: PayloadKeyingProfileId

    def __repr__(self) -> str:
        return "PayloadKeyingBackendResult(<redacted>)"


def key_payload(
    payload_bytes: bytes,
    profile: PayloadKeyingProfileId,
    target_metadata: PayloadTargetMetadata,
) -> NoReturn:
    """Reject direct calls until a reviewed owned-transient backend is wired."""

    del payload_bytes, profile, target_metadata
    raise ProviderUnavailableError("payload_keying_provider_unavailable")


class PayloadKeyingAdapter(TypedActionAdapterV2):
    """Typed, deliberately unavailable adapter for ``payload_keying``."""

    action_id: str = "plugin:payload_keying"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return (
            type(context) is BoundProviderCheckContext
            and context.request.action_id == self.action_id
            and type(context.request.typed_input) is PayloadKeyingInputV2
        )

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> ArtifactProviderResult:
        del context
        raise ProviderUnavailableError("payload_keying_staging_unavailable")

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        del context
        return False


__all__ = [
    "C2TargetArch",
    "C2TargetOS",
    "PayloadKeyingAdapter",
    "PayloadKeyingBackendResult",
    "PayloadKeyingProfileId",
    "PayloadTargetMetadata",
    "ProviderUnavailableError",
    "key_payload",
]
