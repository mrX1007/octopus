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
    """Typed adapter for ``payload_keying``."""

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
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("payload_keying_staging_unavailable")

        import time
        from core.actions.provider_participants import ParticipantRegistrationRefV2
        from core.actions.provider_results import (
            ArtifactKind,
            ArtifactProviderResult,
            NonSensitiveArtifactDraftRefV2,
            ProviderOutcomeV2,
            ProviderProvenanceV2,
            ProviderResultHeaderV2,
            StagedArtifactV2,
        )

        header = ProviderResultHeaderV2(
            schema_version="2.0",
            provider_id=self.action_id,
            outcome=ProviderOutcomeV2.SUCCEEDED,
            reason_codes=(),
            duration_ms=10,
            provenance=ProviderProvenanceV2(
                implementation_id=self.action_id,
                implementation_version="2.0",
                request_digest="payload_keying_req_digest",
                started_at=time.time(),
                completed_at=time.time(),
            ),
        )
        tx_id = getattr(context, "transaction_id", "tx-keying-1")
        artifact_draft = NonSensitiveArtifactDraftRefV2(
            transaction_id=tx_id,
            draft_id=f"draft_keying_{tx_id}",
            artifact_kind=ArtifactKind.ENCRYPTED_PAYLOAD,
            content_digest="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            size=0,
            media_type="application/octet-stream",
            target=getattr(context, "target", None),
        )
        registration = ParticipantRegistrationRefV2(
            participant_id="payload_keying_provider",
            registration_id=f"reg_{tx_id}",
            role="artifact_provider",
        )
        return ArtifactProviderResult(
            header=header,
            artifacts=(StagedArtifactV2(artifact_draft_ref=artifact_draft, registration_ref=registration),),
        )

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


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
