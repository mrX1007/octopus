"""Request-local proof of the currently authenticated ingress transport."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterator

from core.auth.types import IngressChannelBinding, IngressKind

if TYPE_CHECKING:
    from core.auth.ingress_leases import IngressInvocationLease


@dataclass(frozen=True, repr=False)
class CurrentIngressTransportContext:
    channel_binding: IngressChannelBinding
    authenticated_peer_id: str | None = None
    invocation_nonce: str | bytes | None = field(default=None, repr=False, compare=False)
    ingress_kind: IngressKind | None = None


_CURRENT_INGRESS_TRANSPORT: ContextVar[CurrentIngressTransportContext | None] = ContextVar(
    "_CURRENT_INGRESS_TRANSPORT",
    default=None,
)

# Retained only for V1 call sites during migration.  The V2 executor never
# obtains authority from this value; its public root API requires an explicit
# opaque lease and re-resolves it in the canonical store.
_LEGACY_CURRENT_INGRESS_LEASE: ContextVar[IngressInvocationLease | None] = ContextVar(
    "_LEGACY_CURRENT_INGRESS_LEASE",
    default=None,
)


def get_current_ingress_transport_context() -> CurrentIngressTransportContext | None:
    return _CURRENT_INGRESS_TRANSPORT.get()


@contextmanager
def bind_current_ingress_transport_context(
    context: CurrentIngressTransportContext,
) -> Iterator[None]:
    if type(context) is not CurrentIngressTransportContext:
        raise TypeError("current ingress transport context must be canonical")
    token: Token[CurrentIngressTransportContext | None] = _CURRENT_INGRESS_TRANSPORT.set(context)
    try:
        yield
    finally:
        _CURRENT_INGRESS_TRANSPORT.reset(token)


def get_current_ingress_lease() -> IngressInvocationLease | None:
    """Legacy-only accessor; forbidden as V2 execution authority."""

    return _LEGACY_CURRENT_INGRESS_LEASE.get()


def set_current_ingress_lease(lease: IngressInvocationLease | None) -> None:
    """Legacy compatibility setter; the V2 root wrapper ignores it."""

    _LEGACY_CURRENT_INGRESS_LEASE.set(lease)


__all__ = [
    "CurrentIngressTransportContext",
    "bind_current_ingress_transport_context",
    "get_current_ingress_lease",
    "get_current_ingress_transport_context",
    "set_current_ingress_lease",
]
