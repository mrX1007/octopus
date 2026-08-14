"""Current peer, channel, request and ingress-kind binding tests."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from core.auth.ingress import IngressSession
from core.auth.ingress_leases import IngressInvocationLease, IngressLeaseInvalidError
from core.auth.ingress_store import IngressSessionStore
from core.auth.types import IngressChannelBinding, IngressKind, Principal, PrincipalRole

pytestmark = pytest.mark.unit


def _binding(
    uid: int = 501,
    gid: int = 20,
    pid: int = 9001,
    transport: str = "unix-socket:42",
    channel: str = "tls-exporter:binding-42",
) -> IngressChannelBinding:
    return IngressChannelBinding(uid, gid, pid, transport, channel)


def _issued() -> tuple[IngressSessionStore, IngressChannelBinding, IngressInvocationLease]:
    binding = _binding()
    principal = Principal("principal:1", "Operator", PrincipalRole.OPERATOR, revision=7)
    session = IngressSession("session:1", principal, binding, revision=4)
    store = IngressSessionStore()
    store.register_session(session)
    lease = store.issue_invocation_lease(
        session.session_id,
        "request:42",
        binding,
        ingress_kind=IngressKind.HTTP_API,
        authenticated_peer_id="peer:mtls-client-42",
        invocation_nonce="nonce:42",
    )
    return store, binding, lease


@pytest.mark.parametrize(
    "wrong_binding",
    [
        _binding(uid=502),
        _binding(gid=21),
        _binding(pid=9002),
    ],
    ids=("uid", "gid", "pid"),
)
def test_peer_uid_gid_pid_mismatch_denied(
    wrong_binding: IngressChannelBinding,
) -> None:
    store, _, lease = _issued()

    with pytest.raises(IngressLeaseInvalidError):
        store.resolve_invocation_lease(
            lease,
            "request:42",
            wrong_binding,
            authenticated_peer_id="peer:mtls-client-42",
            invocation_nonce="nonce:42",
            ingress_kind=IngressKind.HTTP_API,
        )


def test_transport_instance_mismatch_denied() -> None:
    store, _, lease = _issued()
    with pytest.raises(IngressLeaseInvalidError):
        store.resolve_invocation_lease(
            lease,
            "request:42",
            _binding(transport="unix-socket:other"),
            authenticated_peer_id="peer:mtls-client-42",
            invocation_nonce="nonce:42",
            ingress_kind=IngressKind.HTTP_API,
        )


def test_channel_binding_mismatch_denied() -> None:
    store, _, lease = _issued()
    with pytest.raises(IngressLeaseInvalidError):
        store.resolve_invocation_lease(
            lease,
            "request:42",
            _binding(channel="tls-exporter:other"),
            authenticated_peer_id="peer:mtls-client-42",
            invocation_nonce="nonce:42",
            ingress_kind=IngressKind.HTTP_API,
        )


def test_request_id_binding_mismatch_denied() -> None:
    store, binding, lease = _issued()
    with pytest.raises(IngressLeaseInvalidError):
        store.resolve_invocation_lease(
            lease,
            "request:other",
            binding,
            authenticated_peer_id="peer:mtls-client-42",
            invocation_nonce="nonce:42",
            ingress_kind=IngressKind.HTTP_API,
        )


@pytest.mark.parametrize(
    "attempt",
    [
        lambda store, binding, lease: store.resolve_invocation_lease(
            lease,
            "request:42",
            binding,
            authenticated_peer_id="peer:mtls-client-other",
            invocation_nonce="nonce:42",
            ingress_kind=IngressKind.HTTP_API,
        ),
        lambda store, binding, lease: store.resolve_invocation_lease(
            lease,
            "request:42",
            binding,
            authenticated_peer_id="peer:mtls-client-42",
            invocation_nonce="nonce:other",
            ingress_kind=IngressKind.HTTP_API,
        ),
        lambda store, binding, lease: store.resolve_invocation_lease(
            lease,
            "request:42",
            binding,
            authenticated_peer_id="peer:mtls-client-42",
            invocation_nonce="nonce:42",
            ingress_kind=IngressKind.C2_CONTROL,
        ),
    ],
    ids=("authenticated-peer-id", "nonce", "ingress-kind"),
)
def test_resolve_rejects_non_channel_invocation_binding_mismatch(
    attempt: Callable[
        [IngressSessionStore, IngressChannelBinding, IngressInvocationLease],
        IngressSession,
    ],
) -> None:
    store, binding, lease = _issued()
    with pytest.raises(IngressLeaseInvalidError):
        attempt(store, binding, lease)


def test_copied_session_ref_without_current_channel_denied() -> None:
    _, binding, lease = _issued()
    copied_session_store = IngressSessionStore()
    copied_session_store.register_session(
        IngressSession(
            "session:1",
            Principal("principal:1", "Operator", PrincipalRole.OPERATOR, revision=7),
            binding,
            revision=4,
        )
    )

    with pytest.raises(IngressLeaseInvalidError):
        copied_session_store.resolve_invocation_lease(
            lease,
            "request:42",
            binding,
            authenticated_peer_id="peer:mtls-client-42",
            invocation_nonce="nonce:42",
        )


def test_current_binding_and_nonce_resolve_successfully() -> None:
    store, binding, lease = _issued()

    session = store.resolve_invocation_lease(
        lease,
        "request:42",
        binding,
        authenticated_peer_id="peer:mtls-client-42",
        invocation_nonce="nonce:42",
        ingress_kind=IngressKind.HTTP_API,
    )

    assert session.session_id == lease.ingress_session_ref
    assert session.principal.principal_id == lease.principal_ref
    store.consume_invocation_lease(lease)
