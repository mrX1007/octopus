"""Unforgeable leases for authenticated ingress invocations.

The lease is deliberately only a set of immutable claims. Its authority comes
from object identity in :class:`IngressSessionStore`, not from those claims or
from ``lease_id``. Keeping validation and lifecycle state in the store also
means that revoking a session invalidates every outstanding lease immediately.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn, SupportsIndex

from core.auth.types import IngressKind


class IngressLeaseError(RuntimeError):
    """Base class for ingress-lease validation failures."""


class IngressLeaseConsumedError(IngressLeaseError):
    """Raised when a lease is checked out or consumed more than once."""


class IngressLeaseInvalidError(IngressLeaseError):
    """Raised when a lease is not valid for the current ingress invocation."""


_INGRESS_LEASE_ISSUER_TOKEN = object()


@dataclass(frozen=True, repr=False, init=False)
class IngressInvocationLease:
    """Single-invocation, store-issued ingress authority.

    Construction is intentionally private. Even if a caller copies every
    public field, the resulting value cannot pass the store's object-identity
    and canonical-claim checks.
    """

    lease_id: str
    ingress_session_ref: str
    ingress_session_revision: int
    principal_ref: str
    principal_revision: int

    ingress_kind: IngressKind
    authenticated_peer_id: str
    authenticated_peer_uid: int | None
    authenticated_peer_gid: int | None
    authenticated_peer_pid: int | None

    transport_instance_id: str
    transport_binding_digest: str
    invocation_nonce_digest: str
    bound_request_id: str
    issued_at: float
    expires_at: float

    def __init__(
        self,
        issuer_token: object,
        *,
        lease_id: str,
        ingress_session_ref: str,
        ingress_session_revision: int,
        principal_ref: str,
        principal_revision: int,
        ingress_kind: IngressKind,
        authenticated_peer_id: str,
        authenticated_peer_uid: int | None,
        authenticated_peer_gid: int | None,
        authenticated_peer_pid: int | None,
        transport_instance_id: str,
        transport_binding_digest: str,
        invocation_nonce_digest: str,
        bound_request_id: str,
        issued_at: float,
        expires_at: float,
    ) -> None:
        if issuer_token is not _INGRESS_LEASE_ISSUER_TOKEN:
            raise IngressLeaseInvalidError("Ingress invocation lease is store-issued only")

        object.__setattr__(self, "lease_id", lease_id)
        object.__setattr__(self, "ingress_session_ref", ingress_session_ref)
        object.__setattr__(self, "ingress_session_revision", ingress_session_revision)
        object.__setattr__(self, "principal_ref", principal_ref)
        object.__setattr__(self, "principal_revision", principal_revision)
        object.__setattr__(self, "ingress_kind", ingress_kind)
        object.__setattr__(self, "authenticated_peer_id", authenticated_peer_id)
        object.__setattr__(self, "authenticated_peer_uid", authenticated_peer_uid)
        object.__setattr__(self, "authenticated_peer_gid", authenticated_peer_gid)
        object.__setattr__(self, "authenticated_peer_pid", authenticated_peer_pid)
        object.__setattr__(self, "transport_instance_id", transport_instance_id)
        object.__setattr__(self, "transport_binding_digest", transport_binding_digest)
        object.__setattr__(self, "invocation_nonce_digest", invocation_nonce_digest)
        object.__setattr__(self, "bound_request_id", bound_request_id)
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)

    def __copy__(self) -> NoReturn:
        raise TypeError("IngressInvocationLease cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        del memo
        raise TypeError("IngressInvocationLease cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("IngressInvocationLease cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("IngressInvocationLease cannot be serialized")

    def __getstate__(self) -> NoReturn:
        raise TypeError("IngressInvocationLease cannot be serialized")


def _issue_ingress_invocation_lease(
    *,
    lease_id: str,
    ingress_session_ref: str,
    ingress_session_revision: int,
    principal_ref: str,
    principal_revision: int,
    ingress_kind: IngressKind,
    authenticated_peer_id: str,
    authenticated_peer_uid: int | None,
    authenticated_peer_gid: int | None,
    authenticated_peer_pid: int | None,
    transport_instance_id: str,
    transport_binding_digest: str,
    invocation_nonce_digest: str,
    bound_request_id: str,
    issued_at: float,
    expires_at: float,
) -> IngressInvocationLease:
    """Module-private constructor used only by the canonical ingress store."""

    return IngressInvocationLease(
        _INGRESS_LEASE_ISSUER_TOKEN,
        lease_id=lease_id,
        ingress_session_ref=ingress_session_ref,
        ingress_session_revision=ingress_session_revision,
        principal_ref=principal_ref,
        principal_revision=principal_revision,
        ingress_kind=ingress_kind,
        authenticated_peer_id=authenticated_peer_id,
        authenticated_peer_uid=authenticated_peer_uid,
        authenticated_peer_gid=authenticated_peer_gid,
        authenticated_peer_pid=authenticated_peer_pid,
        transport_instance_id=transport_instance_id,
        transport_binding_digest=transport_binding_digest,
        invocation_nonce_digest=invocation_nonce_digest,
        bound_request_id=bound_request_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )


@dataclass(frozen=True, repr=False, init=False)
class ChildIngressLease:
    """Store-derived, single-invocation child ingress authority."""

    lease_id: str
    lease_revision: int
    parent_ingress_lease_id: str
    root_execution_id: str
    ingress_session_ref: str
    ingress_session_revision: int
    principal_ref: str
    principal_revision: int
    authenticated_peer_id: str
    authenticated_peer_uid: int | None
    authenticated_peer_gid: int | None
    authenticated_peer_pid: int | None
    transport_instance_id: str
    transport_binding_digest: str
    bound_child_request_id: str
    parent_execution_id: str
    execution_graph_id: str
    child_depth: int
    issued_at: float
    expires_at: float

    def __init__(
        self,
        issuer_token: object,
        *,
        lease_id: str,
        lease_revision: int,
        parent_ingress_lease_id: str,
        root_execution_id: str,
        ingress_session_ref: str,
        ingress_session_revision: int,
        principal_ref: str,
        principal_revision: int,
        authenticated_peer_id: str,
        authenticated_peer_uid: int | None,
        authenticated_peer_gid: int | None,
        authenticated_peer_pid: int | None,
        transport_instance_id: str,
        transport_binding_digest: str,
        bound_child_request_id: str,
        parent_execution_id: str,
        execution_graph_id: str,
        child_depth: int,
        issued_at: float,
        expires_at: float,
    ) -> None:
        if issuer_token is not _INGRESS_LEASE_ISSUER_TOKEN:
            raise IngressLeaseInvalidError("Child ingress lease is store-issued only")

        object.__setattr__(self, "lease_id", lease_id)
        object.__setattr__(self, "lease_revision", lease_revision)
        object.__setattr__(self, "parent_ingress_lease_id", parent_ingress_lease_id)
        object.__setattr__(self, "root_execution_id", root_execution_id)
        object.__setattr__(self, "ingress_session_ref", ingress_session_ref)
        object.__setattr__(self, "ingress_session_revision", ingress_session_revision)
        object.__setattr__(self, "principal_ref", principal_ref)
        object.__setattr__(self, "principal_revision", principal_revision)
        object.__setattr__(self, "authenticated_peer_id", authenticated_peer_id)
        object.__setattr__(self, "authenticated_peer_uid", authenticated_peer_uid)
        object.__setattr__(self, "authenticated_peer_gid", authenticated_peer_gid)
        object.__setattr__(self, "authenticated_peer_pid", authenticated_peer_pid)
        object.__setattr__(self, "transport_instance_id", transport_instance_id)
        object.__setattr__(self, "transport_binding_digest", transport_binding_digest)
        object.__setattr__(self, "bound_child_request_id", bound_child_request_id)
        object.__setattr__(self, "parent_execution_id", parent_execution_id)
        object.__setattr__(self, "execution_graph_id", execution_graph_id)
        object.__setattr__(self, "child_depth", child_depth)
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)

    def __copy__(self) -> NoReturn:
        raise TypeError("ChildIngressLease cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        del memo
        raise TypeError("ChildIngressLease cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("ChildIngressLease cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("ChildIngressLease cannot be serialized")

    def __getstate__(self) -> NoReturn:
        raise TypeError("ChildIngressLease cannot be serialized")


def _issue_child_ingress_lease(
    *,
    lease_id: str,
    lease_revision: int,
    parent_ingress_lease_id: str,
    root_execution_id: str,
    ingress_session_ref: str,
    ingress_session_revision: int,
    principal_ref: str,
    principal_revision: int,
    authenticated_peer_id: str,
    authenticated_peer_uid: int | None,
    authenticated_peer_gid: int | None,
    authenticated_peer_pid: int | None,
    transport_instance_id: str,
    transport_binding_digest: str,
    bound_child_request_id: str,
    parent_execution_id: str,
    execution_graph_id: str,
    child_depth: int,
    issued_at: float,
    expires_at: float,
) -> ChildIngressLease:
    """Module-private child constructor used only by the canonical store."""

    return ChildIngressLease(
        _INGRESS_LEASE_ISSUER_TOKEN,
        lease_id=lease_id,
        lease_revision=lease_revision,
        parent_ingress_lease_id=parent_ingress_lease_id,
        root_execution_id=root_execution_id,
        ingress_session_ref=ingress_session_ref,
        ingress_session_revision=ingress_session_revision,
        principal_ref=principal_ref,
        principal_revision=principal_revision,
        authenticated_peer_id=authenticated_peer_id,
        authenticated_peer_uid=authenticated_peer_uid,
        authenticated_peer_gid=authenticated_peer_gid,
        authenticated_peer_pid=authenticated_peer_pid,
        transport_instance_id=transport_instance_id,
        transport_binding_digest=transport_binding_digest,
        bound_child_request_id=bound_child_request_id,
        parent_execution_id=parent_execution_id,
        execution_graph_id=execution_graph_id,
        child_depth=child_depth,
        issued_at=issued_at,
        expires_at=expires_at,
    )


__all__ = [
    "ChildIngressLease",
    "IngressInvocationLease",
    "IngressLeaseConsumedError",
    "IngressLeaseError",
    "IngressLeaseInvalidError",
]
