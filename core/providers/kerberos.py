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
        del context
        raise ProviderUnavailableError("kerberos_extract_staging_unavailable")

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        del context
        return False


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
        del context
        raise ProviderUnavailableError("kerberos_crack_sensitive_staging_unavailable")

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        del context
        return False


__all__ = [
    "KerberosCrackAdapter",
    "KerberosCrackBackendResult",
    "KerberosExtractAdapter",
    "KerberosExtractBackendResult",
    "ProviderUnavailableError",
    "crack_kerberos_tickets",
    "extract_kerberos_tickets",
]
