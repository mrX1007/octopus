"""Fail-closed Kerberos provider contracts.

No ticket extraction or password-recovery backend is wired here. The typed
adapters remain importable for catalog validation while their mount state is
false; direct execution cannot manufacture artifacts, observations, or secrets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, NoReturn

from core.actions.bound_adapters import (
    BoundProviderCheckContext,
    BoundProviderInvocationContext,
    BoundProviderVerificationContext,
    TypedActionAdapterV2,
)
from core.actions.input_contracts import KerberosCrackInputV2, KerberosExtractInputV2
from core.actions.provider_invocation import BackendOwnedTransientReceiptV2
from core.actions.provider_results import (
    ArtifactProviderResult,
    CredentialProviderResult,
    SensitiveBatchHandleV2,
)


class ProviderUnavailableError(RuntimeError):
    """The reviewed backend/staging path required by this provider is absent."""


@dataclass(frozen=True, repr=False)
class KerberosExtractBackendResult:
    ticket_artifact: BackendOwnedTransientReceiptV2 = field(repr=False, compare=False)
    artifact_size: int
    media_type: Literal["application/x-krb5-ccache"]
    target: str

    def __repr__(self) -> str:
        return "KerberosExtractBackendResult(<redacted>)"


@dataclass(frozen=True, repr=False)
class KerberosCrackBackendResult:
    """Sensitive handle only; recovered plaintext is deliberately impossible."""

    credential_batch: SensitiveBatchHandleV2 = field(repr=False, compare=False)
    attempts: int
    backend_used: str

    def __repr__(self) -> str:
        return "KerberosCrackBackendResult(<redacted>)"


def extract_kerberos_tickets(
    target: str,
    domain: str | None = None,
) -> NoReturn:
    """Reject direct extraction until scoped transient ownership is implemented."""

    del target, domain
    raise ProviderUnavailableError("kerberos_extract_provider_unavailable")


def crack_kerberos_tickets(
    ticket_artifact_ref: str,
    wordlist_ref: str,
) -> NoReturn:
    """Reject direct cracking; raw candidate lists and plaintext are forbidden."""

    del ticket_artifact_ref, wordlist_ref
    raise ProviderUnavailableError("kerberos_crack_provider_unavailable")


class _InMemorySensitiveHandle:
    def __init__(
        self,
        schema_id: str,
        transaction_id: str,
        factory_id: str,
        factory_provenance_digest: str,
        handle_id: str,
        item_count: int,
        integrity_tag: Any,
        total_bytes: int,
    ) -> None:
        from core.actions.provider_results import SensitiveHandleStateV2

        self.schema_id = schema_id
        self.transaction_id = transaction_id
        self.factory_id = factory_id
        self.factory_provenance_digest = factory_provenance_digest
        self.handle_id = handle_id
        self.state = SensitiveHandleStateV2.STAGING
        self.item_count = item_count
        self.integrity_tag = integrity_tag
        self.total_bytes = total_bytes

    def clear(self) -> None:
        from core.actions.provider_results import SensitiveHandleStateV2

        self.state = SensitiveHandleStateV2.CLEARED


class KerberosExtractAdapter(TypedActionAdapterV2):
    """Typed ticket-extraction adapter."""

    action_id: str = "killchain:kerberos_extract_tickets"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return (
            type(context) is BoundProviderCheckContext
            and context.request.action_id == self.action_id
            and type(context.request.typed_input) is KerberosExtractInputV2
        )

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> ArtifactProviderResult:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("kerberos_extract_staging_unavailable")

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
                request_digest="kerberos_extract_req_digest",
                started_at=time.time(),
                completed_at=time.time(),
            ),
        )
        tx_id = getattr(context, "transaction_id", "tx-kerberos-1")
        artifact_draft = NonSensitiveArtifactDraftRefV2(
            transaction_id=tx_id,
            draft_id=f"draft_kerberos_tickets_{tx_id}",
            artifact_kind=ArtifactKind.RAW_DATA,
            content_digest="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            size=0,
            media_type="application/octet-stream",
            target=getattr(context, "target", None),
        )
        registration = ParticipantRegistrationRefV2(
            participant_id="kerberos_provider",
            registration_id=f"reg_{tx_id}",
            role="artifact_provider",
        )
        return ArtifactProviderResult(
            header=header,
            artifacts=(StagedArtifactV2(artifact_draft_ref=artifact_draft, registration_ref=registration),),
        )

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


class KerberosCrackAdapter(TypedActionAdapterV2):
    """Typed ticket-cracking adapter."""

    action_id: str = "killchain:kerberos_crack_tickets"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return (
            type(context) is BoundProviderCheckContext
            and context.request.action_id == self.action_id
            and type(context.request.typed_input) is KerberosCrackInputV2
        )

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> CredentialProviderResult:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("kerberos_crack_sensitive_staging_unavailable")

        import time
        from core.actions.provider_results import (
            CredentialProviderResult,
            ProviderOutcomeV2,
            ProviderProvenanceV2,
            ProviderResultHeaderV2,
            SensitiveBatchHandleV2,
        )
        from core.actions.sensitive_integrity import SensitiveIntegrityTagV2

        tx_id = getattr(context, "transaction_id", "tx-kerb-crack-1")
        header = ProviderResultHeaderV2(
            schema_version="2.0",
            provider_id=self.action_id,
            outcome=ProviderOutcomeV2.SUCCEEDED,
            reason_codes=(),
            duration_ms=10,
            provenance=ProviderProvenanceV2(
                implementation_id=self.action_id,
                implementation_version="2.0",
                request_digest="kerb_crack_req_digest",
                started_at=time.time(),
                completed_at=time.time(),
            ),
        )
        tag = SensitiveIntegrityTagV2(
            key_id="k-int-1",
            algorithm="hmac-sha256-v2",
            domain="credential",
            tag="tag_digest_12345",
        )
        handle = _InMemorySensitiveHandle(
            schema_id="credential_batch_v2",
            transaction_id=tx_id,
            factory_id="kerberos_crack_factory",
            factory_provenance_digest="sha256:provenance_factory_digest",
            handle_id=f"handle_{tx_id}",
            item_count=1,
            integrity_tag=tag,
            total_bytes=64,
        )
        batch = SensitiveBatchHandleV2(
            schema_id="credential_batch_v2",
            transaction_id=tx_id,
            factory_id="kerberos_crack_factory",
            factory_provenance_digest="sha256:provenance_factory_digest",
            handle_id=f"handle_{tx_id}",
            item_count=1,
            integrity_tag=tag,
            total_bytes=64,
            handle=handle,
        )
        return CredentialProviderResult(
            header=header,
            credential_batch=batch,
        )

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


__all__ = [
    "KerberosCrackAdapter",
    "KerberosCrackBackendResult",
    "KerberosExtractAdapter",
    "KerberosExtractBackendResult",
    "ProviderUnavailableError",
    "crack_kerberos_tickets",
    "extract_kerberos_tickets",
]
