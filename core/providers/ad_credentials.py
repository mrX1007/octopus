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
        del context
        raise ProviderUnavailableError("pass_the_hash_effect_staging_unavailable")

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        del context
        return False


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
        del context
        raise ProviderUnavailableError("pass_the_ticket_effect_staging_unavailable")

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        del context
        return False


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
        del context
        raise ProviderUnavailableError("lsass_sensitive_staging_unavailable")

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        del context
        return False


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
        del context
        raise ProviderUnavailableError("sam_sensitive_staging_unavailable")

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        del context
        return False


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
