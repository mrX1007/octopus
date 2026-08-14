"""Exact trust-chain tests for authenticated ingress invocation leases."""

from __future__ import annotations

import copy
import pickle
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, fields

import pytest

from core.auth.ingress import IngressSession
from core.auth.ingress_leases import (
    ChildIngressLease,
    IngressInvocationLease,
    IngressLeaseConsumedError,
    IngressLeaseInvalidError,
)
from core.auth.ingress_store import IngressSessionStore
from core.auth.types import IngressChannelBinding, IngressKind, Principal, PrincipalRole

pytestmark = pytest.mark.unit


EXPECTED_LEASE_FIELDS = (
    "lease_id",
    "ingress_session_ref",
    "ingress_session_revision",
    "principal_ref",
    "principal_revision",
    "ingress_kind",
    "authenticated_peer_id",
    "authenticated_peer_uid",
    "authenticated_peer_gid",
    "authenticated_peer_pid",
    "transport_instance_id",
    "transport_binding_digest",
    "invocation_nonce_digest",
    "bound_request_id",
    "issued_at",
    "expires_at",
)

EXPECTED_CHILD_LEASE_FIELDS = (
    "lease_id",
    "lease_revision",
    "parent_ingress_lease_id",
    "root_execution_id",
    "ingress_session_ref",
    "ingress_session_revision",
    "principal_ref",
    "principal_revision",
    "authenticated_peer_id",
    "authenticated_peer_uid",
    "authenticated_peer_gid",
    "authenticated_peer_pid",
    "transport_instance_id",
    "transport_binding_digest",
    "bound_child_request_id",
    "parent_execution_id",
    "execution_graph_id",
    "child_depth",
    "issued_at",
    "expires_at",
)


def _binding(
    *,
    uid: int = 1000,
    gid: int = 1000,
    pid: int = 1234,
    transport: str = "tty:7",
    channel: str = "channel-secret-material",
) -> IngressChannelBinding:
    return IngressChannelBinding(uid, gid, pid, transport, channel)


def _session(
    binding: IngressChannelBinding,
    *,
    session_revision: int = 1,
    principal_revision: int = 1,
    revoked: bool = False,
) -> IngressSession:
    principal = Principal(
        principal_id="principal:operator-1",
        name="Operator",
        role=PrincipalRole.OPERATOR,
        revision=principal_revision,
    )
    return IngressSession(
        session_id="session:authenticated-1",
        principal=principal,
        channel_binding=binding,
        revision=session_revision,
        revoked=revoked,
    )


def _issued(
    *,
    now: float = 1_000.0,
    ttl: float = 60.0,
    nonce: str = "nonce:request-1",
) -> tuple[IngressSessionStore, IngressSession, IngressChannelBinding, IngressInvocationLease, list[float]]:
    clock = [now]
    binding = _binding()
    session = _session(binding)
    store = IngressSessionStore(clock=lambda: clock[0])
    store.register_session(session, expires_at=now + 300.0)
    lease = store.issue_invocation_lease(
        session.session_id,
        "request:1",
        binding,
        ttl,
        ingress_kind=IngressKind.INTERACTIVE_CLI,
        authenticated_peer_id="peer:tty-user-1",
        invocation_nonce=nonce,
    )
    return store, session, binding, lease, clock


def test_ingress_invocation_lease_has_exact_frozen_plan_fields() -> None:
    _, _, _, lease, _ = _issued()

    assert tuple(field.name for field in fields(IngressInvocationLease)) == EXPECTED_LEASE_FIELDS
    assert lease.ingress_session_ref == "session:authenticated-1"
    assert lease.principal_ref == "principal:operator-1"
    assert lease.bound_request_id == "request:1"
    with pytest.raises(FrozenInstanceError):
        lease.bound_request_id = "request:forged"  # type: ignore[misc]


def test_forged_lease_object_denied() -> None:
    with pytest.raises(TypeError):
        IngressInvocationLease(  # type: ignore[call-arg]
            lease_id="lease:forged",
            ingress_session_ref="session:authenticated-1",
            ingress_session_revision=1,
            principal_ref="principal:operator-1",
            principal_revision=1,
            ingress_kind=IngressKind.INTERACTIVE_CLI,
            authenticated_peer_id="peer:tty-user-1",
            authenticated_peer_uid=1000,
            authenticated_peer_gid=1000,
            authenticated_peer_pid=1234,
            transport_instance_id="tty:7",
            transport_binding_digest="sha256:" + "0" * 64,
            invocation_nonce_digest="sha256:" + "1" * 64,
            bound_request_id="request:1",
            issued_at=1_000.0,
            expires_at=1_060.0,
        )

    with pytest.raises(IngressLeaseInvalidError, match="store-issued only"):
        IngressInvocationLease(
            object(),
            lease_id="lease:forged",
            ingress_session_ref="session:authenticated-1",
            ingress_session_revision=1,
            principal_ref="principal:operator-1",
            principal_revision=1,
            ingress_kind=IngressKind.INTERACTIVE_CLI,
            authenticated_peer_id="peer:tty-user-1",
            authenticated_peer_uid=1000,
            authenticated_peer_gid=1000,
            authenticated_peer_pid=1234,
            transport_instance_id="tty:7",
            transport_binding_digest="sha256:" + "0" * 64,
            invocation_nonce_digest="sha256:" + "1" * 64,
            bound_request_id="request:1",
            issued_at=1_000.0,
            expires_at=1_060.0,
        )


def test_ingress_lease_not_decodable_from_request() -> None:
    _, _, _, lease, _ = _issued(nonce="raw-nonce-must-not-leak")
    rendered = repr(lease)

    assert lease.lease_id not in rendered
    assert lease.principal_ref not in rendered
    assert "channel-secret-material" not in rendered
    assert "raw-nonce-must-not-leak" not in rendered
    assert lease.transport_binding_digest.startswith("sha256:")
    assert lease.invocation_nonce_digest.startswith("sha256:")
    assert lease.transport_binding_digest != "channel-secret-material"
    assert lease.invocation_nonce_digest != "raw-nonce-must-not-leak"
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(lease)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(lease)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(lease)


def test_v2_requires_current_ingress_invocation_lease() -> None:
    store, session, binding, lease, _ = _issued()

    resolved_session = store.resolve_invocation_lease(
        lease,
        "request:1",
        binding,
        authenticated_peer_id="peer:tty-user-1",
        invocation_nonce="nonce:request-1",
        ingress_kind=IngressKind.INTERACTIVE_CLI,
    )
    assert resolved_session is session

    with pytest.raises(IngressLeaseConsumedError, match="already been used"):
        store.resolve_invocation_lease(
            lease,
            "request:1",
            binding,
            authenticated_peer_id="peer:tty-user-1",
            invocation_nonce="nonce:request-1",
        )

    store.consume_invocation_lease(lease)
    with pytest.raises(IngressLeaseConsumedError, match="already been consumed"):
        store.consume_invocation_lease(lease)


def test_lease_cannot_be_consumed_before_resolution() -> None:
    store, _, _, lease, _ = _issued()
    with pytest.raises(IngressLeaseInvalidError, match="was not resolved"):
        store.consume_invocation_lease(lease)


def test_consumed_lease_denied() -> None:
    store, _, binding, lease, _ = _issued()
    store.resolve_invocation_lease(
        lease,
        "request:1",
        binding,
        authenticated_peer_id="peer:tty-user-1",
        invocation_nonce="nonce:request-1",
    )
    store.consume_invocation_lease(lease)

    with pytest.raises(IngressLeaseConsumedError):
        store.resolve_invocation_lease(
            lease,
            "request:1",
            binding,
            authenticated_peer_id="peer:tty-user-1",
            invocation_nonce="nonce:request-1",
        )


def test_stale_lease_denied() -> None:
    store, _, binding, lease, clock = _issued(ttl=10.0)
    clock[0] = 1_010.0

    with pytest.raises(IngressLeaseInvalidError):
        store.resolve_invocation_lease(
            lease,
            "request:1",
            binding,
            authenticated_peer_id="peer:tty-user-1",
            invocation_nonce="nonce:request-1",
        )

    session_clock = [2_000.0]
    session_store = IngressSessionStore(clock=lambda: session_clock[0])
    session = _session(binding)
    session_store.register_session(session, expires_at=2_005.0)
    session_lease = session_store.issue_invocation_lease(
        session.session_id,
        "request:2",
        binding,
        invocation_nonce="nonce:request-2",
    )
    session_clock[0] = 2_005.0
    with pytest.raises(IngressLeaseInvalidError):
        session_store.resolve_invocation_lease(
            session_lease,
            "request:2",
            binding,
            invocation_nonce="nonce:request-2",
        )


def test_revoked_session_denied() -> None:
    store, session, binding, lease, _ = _issued()
    store.revoke_session(session.session_id)

    with pytest.raises(IngressLeaseInvalidError):
        store.resolve_invocation_lease(
            lease,
            "request:1",
            binding,
            authenticated_peer_id="peer:tty-user-1",
            invocation_nonce="nonce:request-1",
        )


def test_principal_must_match_ingress_session() -> None:
    store, session, binding, lease, _ = _issued()
    updated = _session(binding, session_revision=2, principal_revision=2)
    store.register_session(updated, expires_at=1_300.0)

    assert updated.session_id == session.session_id
    with pytest.raises(IngressLeaseInvalidError):
        store.resolve_invocation_lease(
            lease,
            "request:1",
            binding,
            authenticated_peer_id="peer:tty-user-1",
            invocation_nonce="nonce:request-1",
        )


def test_invocation_nonce_cannot_be_reissued_or_mismatched() -> None:
    store, session, binding, lease, _ = _issued()
    with pytest.raises(IngressLeaseInvalidError, match="nonce has already been used"):
        store.issue_invocation_lease(
            session.session_id,
            "request:2",
            binding,
            invocation_nonce="nonce:request-1",
        )

    with pytest.raises(IngressLeaseInvalidError):
        store.resolve_invocation_lease(
            lease,
            "request:1",
            binding,
            authenticated_peer_id="peer:tty-user-1",
            invocation_nonce="nonce:wrong",
        )


def test_concurrent_resolution_has_exactly_one_winner() -> None:
    store, _, binding, lease, _ = _issued()

    def resolve() -> bool:
        try:
            store.resolve_invocation_lease(
                lease,
                "request:1",
                binding,
                authenticated_peer_id="peer:tty-user-1",
                invocation_nonce="nonce:request-1",
            )
        except IngressLeaseConsumedError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        winners = list(pool.map(lambda _: resolve(), range(32)))

    assert winners.count(True) == 1
    assert winners.count(False) == 31
    store.consume_invocation_lease(lease)


def test_child_ingress_lease_exact_fields_and_single_use() -> None:
    store, session, binding, root, _ = _issued()
    store.resolve_invocation_lease(
        root,
        "request:1",
        binding,
        authenticated_peer_id="peer:tty-user-1",
        invocation_nonce="nonce:request-1",
    )
    child = store.derive_child_invocation_lease(
        root,
        child_request_id="request:child-1",
        root_execution_id="execution:root",
        parent_execution_id="execution:root",
        execution_graph_id="graph:1",
        child_depth=1,
    )

    assert tuple(field.name for field in fields(ChildIngressLease)) == EXPECTED_CHILD_LEASE_FIELDS
    assert child.lease_revision == 1
    assert child.parent_ingress_lease_id == root.lease_id
    assert child.ingress_session_ref == root.ingress_session_ref
    assert child.principal_ref == root.principal_ref
    assert child.transport_binding_digest == root.transport_binding_digest
    assert not hasattr(child, "session")
    assert child.lease_id not in repr(child)

    resolved = store.resolve_invocation_lease(
        child,
        "request:child-1",
        binding,
        authenticated_peer_id="peer:tty-user-1",
        root_execution_id="execution:root",
        parent_execution_id="execution:root",
        execution_graph_id="graph:1",
        child_depth=1,
    )
    assert resolved is session
    with pytest.raises(IngressLeaseConsumedError):
        store.resolve_invocation_lease(
            child,
            "request:child-1",
            binding,
            authenticated_peer_id="peer:tty-user-1",
            root_execution_id="execution:root",
            parent_execution_id="execution:root",
            execution_graph_id="graph:1",
            child_depth=1,
        )
    store.consume_invocation_lease(child)
    store.consume_invocation_lease(root)


def test_child_ingress_lease_derived_by_executor_only() -> None:
    store, _, _, root, _ = _issued()

    with pytest.raises(TypeError):
        ChildIngressLease()  # type: ignore[call-arg]
    with pytest.raises(IngressLeaseInvalidError, match="not active"):
        store.derive_child_invocation_lease(
            root,
            child_request_id="request:child-1",
            root_execution_id="execution:root",
            parent_execution_id="execution:root",
            execution_graph_id="graph:1",
            child_depth=1,
        )


def test_child_ingress_lineage_request_and_depth_are_bound() -> None:
    store, _, binding, root, _ = _issued()
    store.resolve_invocation_lease(
        root,
        "request:1",
        binding,
        authenticated_peer_id="peer:tty-user-1",
        invocation_nonce="nonce:request-1",
    )
    with pytest.raises(IngressLeaseInvalidError, match="lineage"):
        store.derive_child_invocation_lease(
            root,
            child_request_id="request:bad-depth",
            root_execution_id="execution:root",
            parent_execution_id="execution:root",
            execution_graph_id="graph:1",
            child_depth=2,
        )

    first = store.derive_child_invocation_lease(
        root,
        child_request_id="request:child-1",
        root_execution_id="execution:root",
        parent_execution_id="execution:root",
        execution_graph_id="graph:1",
        child_depth=1,
    )
    with pytest.raises(IngressLeaseInvalidError):
        store.resolve_invocation_lease(
            first,
            "request:child-1",
            binding,
            authenticated_peer_id="peer:tty-user-1",
            root_execution_id="execution:root",
            parent_execution_id="execution:root",
            execution_graph_id="graph:other",
            child_depth=1,
        )
    with pytest.raises(IngressLeaseInvalidError):
        store.resolve_invocation_lease(
            first,
            "request:wrong",
            binding,
            authenticated_peer_id="peer:tty-user-1",
            root_execution_id="execution:root",
            parent_execution_id="execution:root",
            execution_graph_id="graph:1",
            child_depth=1,
        )
    store.resolve_invocation_lease(
        first,
        "request:child-1",
        binding,
        authenticated_peer_id="peer:tty-user-1",
        root_execution_id="execution:root",
        parent_execution_id="execution:root",
        execution_graph_id="graph:1",
        child_depth=1,
    )
    with pytest.raises(IngressLeaseInvalidError, match="lineage"):
        store.derive_child_invocation_lease(
            first,
            child_request_id="request:child-2",
            root_execution_id="execution:other",
            parent_execution_id="execution:child-1",
            execution_graph_id="graph:1",
            child_depth=2,
        )

    second = store.derive_child_invocation_lease(
        first,
        child_request_id="request:child-2",
        root_execution_id="execution:root",
        parent_execution_id="execution:child-1",
        execution_graph_id="graph:1",
        child_depth=2,
    )
    assert second.parent_ingress_lease_id == first.lease_id
    assert second.root_execution_id == first.root_execution_id
    assert second.execution_graph_id == first.execution_graph_id
    assert second.child_depth == first.child_depth + 1


def test_revoked_session_denies_derived_child_lease() -> None:
    store, session, binding, root, _ = _issued()
    store.resolve_invocation_lease(
        root,
        "request:1",
        binding,
        authenticated_peer_id="peer:tty-user-1",
        invocation_nonce="nonce:request-1",
    )
    child = store.derive_child_invocation_lease(
        root,
        child_request_id="request:child-1",
        root_execution_id="execution:root",
        parent_execution_id="execution:root",
        execution_graph_id="graph:1",
        child_depth=1,
    )
    store.revoke_session(session.session_id)

    with pytest.raises(IngressLeaseInvalidError):
        store.resolve_invocation_lease(
            child,
            "request:child-1",
            binding,
            authenticated_peer_id="peer:tty-user-1",
            root_execution_id="execution:root",
            parent_execution_id="execution:root",
            execution_graph_id="graph:1",
            child_depth=1,
        )
