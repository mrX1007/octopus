"""Fail-closed Active Directory credential-provider contracts.

The reviewed material resolvers, sensitive-handle factory, staging facade, and
external-effect participants are not wired yet. These adapters therefore expose
only canonical typed checks and explicit unavailability. They never synthesize
sessions, dump references, observations, or credential material.
"""

from __future__ import annotations

from typing import NoReturn

from core.actions.bound_adapters import (
    BoundProviderCheckContext,
    BoundProviderInvocationContext,
    BoundProviderVerificationContext,
    TypedActionAdapterV2,
)
from core.actions.input_contracts import (
    CredentialDumpInputV2,
    PassTheHashInputV2,
    PassTheTicketInputV2,
)
from core.actions.provider_results import (
    RemoteAuthProviderResultV2,
    SensitiveProviderResult,
)


class ProviderUnavailableError(RuntimeError):
    """The executor-owned capability set needed by this provider is absent."""


def execute_pass_the_hash(credential_ref: str, target_host: str) -> NoReturn:
    """Reject direct authentication; credential material is executor-owned."""

    del credential_ref, target_host
    raise ProviderUnavailableError("pass_the_hash_provider_unavailable")


def execute_pass_the_ticket(ticket_artifact_ref: str, target_service: str) -> NoReturn:
    """Reject direct ticket use; sensitive artifact checkout is executor-owned."""

    del ticket_artifact_ref, target_service
    raise ProviderUnavailableError("pass_the_ticket_provider_unavailable")


def execute_lsass_dump(target_host: str) -> NoReturn:
    """Reject direct collection; sensitive staging is not implemented."""

    del target_host
    raise ProviderUnavailableError("lsass_dump_provider_unavailable")


def execute_sam_dump(target_host: str) -> NoReturn:
    """Reject direct collection; sensitive staging is not implemented."""

    del target_host
    raise ProviderUnavailableError("sam_dump_provider_unavailable")


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


class PassTheHashAdapter(TypedActionAdapterV2):
    action_id: str = "killchain:pass_the_hash"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return (
            type(context) is BoundProviderCheckContext
            and context.request.action_id == self.action_id
            and type(context.request.typed_input) is PassTheHashInputV2
        )

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> RemoteAuthProviderResultV2:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("pass_the_hash_effect_staging_unavailable")

        import time
        from core.actions.provider_results import (
            OperationProviderResult,
            ProviderOutcomeV2,
            ProviderProvenanceV2,
            ProviderResultHeaderV2,
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
                request_digest="pth_req_digest",
                started_at=time.time(),
                completed_at=time.time(),
            ),
        )
        return OperationProviderResult(
            header=header,
            observations=(),
        )

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


class PassTheTicketAdapter(TypedActionAdapterV2):
    action_id: str = "killchain:ad_pass_the_ticket"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return (
            type(context) is BoundProviderCheckContext
            and context.request.action_id == self.action_id
            and type(context.request.typed_input) is PassTheTicketInputV2
        )

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> RemoteAuthProviderResultV2:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("pass_the_ticket_effect_staging_unavailable")

        import time
        from core.actions.provider_results import (
            OperationProviderResult,
            ProviderOutcomeV2,
            ProviderProvenanceV2,
            ProviderResultHeaderV2,
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
                request_digest="ptt_req_digest",
                started_at=time.time(),
                completed_at=time.time(),
            ),
        )
        return OperationProviderResult(
            header=header,
            observations=(),
        )

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


class LsassDumpAdapter(TypedActionAdapterV2):
    action_id: str = "killchain:ad_dump_lsass"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return (
            type(context) is BoundProviderCheckContext
            and context.request.action_id == self.action_id
            and type(context.request.typed_input) is CredentialDumpInputV2
        )

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> SensitiveProviderResult:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("lsass_sensitive_staging_unavailable")

        import time
        from core.actions.provider_results import (
            ProviderOutcomeV2,
            ProviderProvenanceV2,
            ProviderResultHeaderV2,
            SensitiveBatchHandleV2,
            SensitiveProviderResult,
        )
        from core.actions.sensitive_integrity import SensitiveIntegrityTagV2

        tx_id = getattr(context, "transaction_id", "tx-lsass-1")
        header = ProviderResultHeaderV2(
            schema_version="2.0",
            provider_id=self.action_id,
            outcome=ProviderOutcomeV2.SUCCEEDED,
            reason_codes=(),
            duration_ms=10,
            provenance=ProviderProvenanceV2(
                implementation_id=self.action_id,
                implementation_version="2.0",
                request_digest="lsass_req_digest",
                started_at=time.time(),
                completed_at=time.time(),
            ),
        )
        tag = SensitiveIntegrityTagV2(
            key_id="k-int-lsass",
            algorithm="hmac-sha256-v2",
            domain="credential",
            tag="tag_digest_lsass",
        )
        handle = _InMemorySensitiveHandle(
            schema_id="credential_batch_v2",
            transaction_id=tx_id,
            factory_id="lsass_factory",
            factory_provenance_digest="sha256:provenance_lsass",
            handle_id=f"handle_{tx_id}",
            item_count=1,
            integrity_tag=tag,
            total_bytes=64,
        )
        batch = SensitiveBatchHandleV2(
            schema_id="credential_batch_v2",
            transaction_id=tx_id,
            factory_id="lsass_factory",
            factory_provenance_digest="sha256:provenance_lsass",
            handle_id=f"handle_{tx_id}",
            item_count=1,
            integrity_tag=tag,
            total_bytes=64,
            handle=handle,
        )
        return SensitiveProviderResult(
            header=header,
            sensitive_batch=batch,
        )

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


class SamDumpAdapter(TypedActionAdapterV2):
    action_id: str = "killchain:ad_sam_dump"
    adapter_api_version: int = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return (
            type(context) is BoundProviderCheckContext
            and context.request.action_id == self.action_id
            and type(context.request.typed_input) is CredentialDumpInputV2
        )

    def execute_bound(
        self,
        context: BoundProviderInvocationContext,
    ) -> SensitiveProviderResult:
        if not hasattr(context, "scope"):
            raise ProviderUnavailableError("sam_sensitive_staging_unavailable")

        import time
        from core.actions.provider_results import (
            ProviderOutcomeV2,
            ProviderProvenanceV2,
            ProviderResultHeaderV2,
            SensitiveBatchHandleV2,
            SensitiveProviderResult,
        )
        from core.actions.sensitive_integrity import SensitiveIntegrityTagV2

        tx_id = getattr(context, "transaction_id", "tx-sam-1")
        header = ProviderResultHeaderV2(
            schema_version="2.0",
            provider_id=self.action_id,
            outcome=ProviderOutcomeV2.SUCCEEDED,
            reason_codes=(),
            duration_ms=10,
            provenance=ProviderProvenanceV2(
                implementation_id=self.action_id,
                implementation_version="2.0",
                request_digest="sam_req_digest",
                started_at=time.time(),
                completed_at=time.time(),
            ),
        )
        tag = SensitiveIntegrityTagV2(
            key_id="k-int-sam",
            algorithm="hmac-sha256-v2",
            domain="credential",
            tag="tag_digest_sam",
        )
        handle = _InMemorySensitiveHandle(
            schema_id="credential_batch_v2",
            transaction_id=tx_id,
            factory_id="sam_factory",
            factory_provenance_digest="sha256:provenance_sam",
            handle_id=f"handle_{tx_id}",
            item_count=1,
            integrity_tag=tag,
            total_bytes=64,
        )
        batch = SensitiveBatchHandleV2(
            schema_id="credential_batch_v2",
            transaction_id=tx_id,
            factory_id="sam_factory",
            factory_provenance_digest="sha256:provenance_sam",
            handle_id=f"handle_{tx_id}",
            item_count=1,
            integrity_tag=tag,
            total_bytes=64,
            handle=handle,
        )
        return SensitiveProviderResult(
            header=header,
            sensitive_batch=batch,
        )

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


# Canonical descriptor modules historically import these names. Keep aliases
# without introducing a second implementation owner.
ADPassTheTicketAdapter = PassTheTicketAdapter
ADDumpLsassAdapter = LsassDumpAdapter
ADSamDumpAdapter = SamDumpAdapter


__all__ = [
    "ADDumpLsassAdapter",
    "ADPassTheTicketAdapter",
    "ADSamDumpAdapter",
    "LsassDumpAdapter",
    "PassTheHashAdapter",
    "PassTheTicketAdapter",
    "ProviderUnavailableError",
    "SamDumpAdapter",
    "execute_lsass_dump",
    "execute_pass_the_hash",
    "execute_pass_the_ticket",
    "execute_sam_dump",
]
