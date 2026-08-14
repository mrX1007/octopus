"""Canonical, thread-safe ingress session and invocation-lease store."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
from dataclasses import dataclass, fields
from enum import Enum
from typing import Callable

from core.auth.ingress import IngressSession
from core.auth.ingress_leases import (
    ChildIngressLease,
    IngressInvocationLease,
    IngressLeaseConsumedError,
    IngressLeaseInvalidError,
    _issue_child_ingress_lease,
    _issue_ingress_invocation_lease,
)
from core.auth.types import IngressChannelBinding, IngressKind


class _LeaseState(str, Enum):
    ISSUED = "issued"
    RESOLVED = "resolved"
    CONSUMED = "consumed"


@dataclass(frozen=True)
class _SessionRecord:
    session: IngressSession
    expires_at: float | None


@dataclass
class _LeaseRecord:
    lease: IngressInvocationLease | ChildIngressLease
    canonical_claims: tuple[object, ...]
    state: _LeaseState = _LeaseState.ISSUED


def _require_nonblank(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-blank string")
    return value


def _require_revision(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _require_peer_component(value: int | None, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer or None")
    return value


def _digest_tagged(value: str | bytes, tag: bytes) -> str:
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes):
        encoded = value
    else:
        raise TypeError("digest input must be str or bytes")
    return "sha256:" + hashlib.sha256(tag + b"\x00" + encoded).hexdigest()


def _transport_binding_digest(binding: IngressChannelBinding) -> str:
    return _digest_tagged(binding.channel_binding, b"ingress-transport-binding/1")


def _invocation_nonce_digest(nonce: str | bytes) -> str:
    return _digest_tagged(nonce, b"ingress-invocation-nonce/1")


def _derived_authenticated_peer_id(binding: IngressChannelBinding) -> str:
    return f"os-peer:{binding.peer_uid}:{binding.peer_gid}:{binding.peer_pid}"


def _claims(lease: IngressInvocationLease | ChildIngressLease) -> tuple[object, ...]:
    return tuple(getattr(lease, field.name) for field in fields(type(lease)))


class IngressSessionStore:
    """Owns canonical sessions and the single-use lease lifecycle.

    ``resolve_invocation_lease`` atomically checks out a lease for exactly one
    invocation. The executor must call ``consume_invocation_lease`` from its
    outer ``finally`` block after a successful checkout.
    """

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        self._sessions: dict[str, _SessionRecord] = {}
        self._leases: dict[str, _LeaseRecord] = {}
        self._nonce_owners: dict[str, str] = {}

    def register_session(
        self,
        session: IngressSession,
        *,
        expires_at: float | None = None,
    ) -> None:
        """Register a canonical authenticated session.

        Re-registering the exact same immutable record is idempotent. A
        replacement must advance the session revision, which invalidates every
        lease issued from an older revision.
        """

        _require_nonblank(session.session_id, "session_id")
        _require_revision(session.revision, "session revision")
        _require_nonblank(session.principal.principal_id, "principal_ref")
        _require_revision(session.principal.revision, "principal revision")
        self._validate_binding_shape(session.channel_binding)
        if expires_at is not None and (not math.isfinite(expires_at) or expires_at <= self._clock()):
            raise ValueError("session expires_at must be a future finite timestamp")

        with self._lock:
            current = self._sessions.get(session.session_id)
            if current is not None:
                if current.session == session and current.expires_at == expires_at:
                    return
                if session.revision <= current.session.revision:
                    raise IngressLeaseInvalidError("Ingress session revision did not advance")
            self._sessions[session.session_id] = _SessionRecord(session, expires_at)

    def revoke_session(self, session_id: str) -> None:
        """Revoke a session and advance its revision atomically."""

        with self._lock:
            current = self._sessions.get(session_id)
            if current is None:
                return
            session = current.session
            if session.revoked:
                return
            revoked = IngressSession(
                session_id=session.session_id,
                principal=session.principal,
                channel_binding=session.channel_binding,
                revision=session.revision + 1,
                revoked=True,
            )
            self._sessions[session_id] = _SessionRecord(revoked, current.expires_at)

    def issue_invocation_lease(
        self,
        session_id: str,
        request_id: str,
        channel_binding: IngressChannelBinding,
        ttl_seconds: float = 300.0,
        *,
        ingress_kind: IngressKind = IngressKind.INTERACTIVE_CLI,
        authenticated_peer_id: str | None = None,
        invocation_nonce: str | bytes | None = None,
    ) -> IngressInvocationLease:
        """Issue a lease after a reviewed adapter authenticated the invocation."""

        _require_nonblank(session_id, "session_id")
        _require_nonblank(request_id, "request_id")
        self._validate_binding_shape(channel_binding)
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
            raise ValueError("ttl_seconds must be a positive finite number")
        if not math.isfinite(float(ttl_seconds)) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a positive finite number")
        if not isinstance(ingress_kind, IngressKind):
            raise ValueError("ingress_kind must be an IngressKind")

        peer_id = authenticated_peer_id or _derived_authenticated_peer_id(channel_binding)
        _require_nonblank(peer_id, "authenticated_peer_id")
        nonce = invocation_nonce if invocation_nonce is not None else secrets.token_bytes(32)
        nonce_digest = _invocation_nonce_digest(nonce)
        binding_digest = _transport_binding_digest(channel_binding)

        with self._lock:
            now = self._clock()
            session_record = self._require_active_session(session_id, now)
            session = session_record.session
            if session.channel_binding != channel_binding:
                raise IngressLeaseInvalidError("Ingress invocation lease is invalid")
            if nonce_digest in self._nonce_owners:
                raise IngressLeaseInvalidError("Ingress invocation nonce has already been used")

            expires_at = now + float(ttl_seconds)
            if session_record.expires_at is not None:
                expires_at = min(expires_at, session_record.expires_at)
            lease_id = "lease:" + secrets.token_urlsafe(24)
            lease = _issue_ingress_invocation_lease(
                lease_id=lease_id,
                ingress_session_ref=session.session_id,
                ingress_session_revision=session.revision,
                principal_ref=session.principal.principal_id,
                principal_revision=session.principal.revision,
                ingress_kind=ingress_kind,
                authenticated_peer_id=peer_id,
                authenticated_peer_uid=_require_peer_component(
                    channel_binding.peer_uid,
                    "peer_uid",
                ),
                authenticated_peer_gid=_require_peer_component(
                    channel_binding.peer_gid,
                    "peer_gid",
                ),
                authenticated_peer_pid=_require_peer_component(
                    channel_binding.peer_pid,
                    "peer_pid",
                ),
                transport_instance_id=channel_binding.transport_instance,
                transport_binding_digest=binding_digest,
                invocation_nonce_digest=nonce_digest,
                bound_request_id=request_id,
                issued_at=now,
                expires_at=expires_at,
            )
            self._leases[lease_id] = _LeaseRecord(
                lease=lease,
                canonical_claims=_claims(lease),
            )
            self._nonce_owners[nonce_digest] = lease_id
            return lease

    def derive_child_invocation_lease(
        self,
        parent_lease: IngressInvocationLease | ChildIngressLease,
        *,
        child_request_id: str,
        root_execution_id: str,
        parent_execution_id: str,
        execution_graph_id: str,
        child_depth: int,
        ttl_seconds: float | None = None,
    ) -> ChildIngressLease:
        """Derive a child authority from the currently resolved parent only.

        The child inherits all authenticated identity and channel claims. A
        nested child must retain the same root/graph and increase depth by
        exactly one; a first-level child starts at depth one.
        """

        if not isinstance(parent_lease, (IngressInvocationLease, ChildIngressLease)):
            raise IngressLeaseInvalidError("Parent ingress invocation lease is invalid")
        _require_nonblank(child_request_id, "child_request_id")
        _require_nonblank(root_execution_id, "root_execution_id")
        _require_nonblank(parent_execution_id, "parent_execution_id")
        _require_nonblank(execution_graph_id, "execution_graph_id")
        if isinstance(child_depth, bool) or not isinstance(child_depth, int) or child_depth < 1:
            raise ValueError("child_depth must be a positive integer")
        if ttl_seconds is not None:
            if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
                raise ValueError("ttl_seconds must be a positive finite number or None")
            if not math.isfinite(float(ttl_seconds)) or ttl_seconds <= 0:
                raise ValueError("ttl_seconds must be a positive finite number or None")

        with self._lock:
            parent_record = self._require_canonical_lease_record(parent_lease)
            if parent_record.state is not _LeaseState.RESOLVED:
                raise IngressLeaseInvalidError("Parent ingress invocation lease is not active")

            now = self._clock()
            if now < parent_lease.issued_at or now >= parent_lease.expires_at:
                raise IngressLeaseInvalidError("Parent ingress invocation lease is invalid")
            session_record = self._require_active_session(
                parent_lease.ingress_session_ref,
                now,
            )
            session = session_record.session
            if (
                session.revision != parent_lease.ingress_session_revision
                or session.principal.principal_id != parent_lease.principal_ref
                or session.principal.revision != parent_lease.principal_revision
            ):
                raise IngressLeaseInvalidError("Parent ingress invocation lease is invalid")

            if isinstance(parent_lease, IngressInvocationLease):
                if child_depth != 1 or parent_execution_id != root_execution_id:
                    raise IngressLeaseInvalidError("Child ingress lineage is invalid")
            else:
                if (
                    child_depth != parent_lease.child_depth + 1
                    or root_execution_id != parent_lease.root_execution_id
                    or execution_graph_id != parent_lease.execution_graph_id
                ):
                    raise IngressLeaseInvalidError("Child ingress lineage is invalid")

            expires_at = parent_lease.expires_at
            if ttl_seconds is not None:
                expires_at = min(expires_at, now + float(ttl_seconds))
            if now >= expires_at:
                raise IngressLeaseInvalidError("Child ingress invocation lease is invalid")

            lease_id = "child-lease:" + secrets.token_urlsafe(24)
            child = _issue_child_ingress_lease(
                lease_id=lease_id,
                lease_revision=1,
                parent_ingress_lease_id=parent_lease.lease_id,
                root_execution_id=root_execution_id,
                ingress_session_ref=parent_lease.ingress_session_ref,
                ingress_session_revision=parent_lease.ingress_session_revision,
                principal_ref=parent_lease.principal_ref,
                principal_revision=parent_lease.principal_revision,
                authenticated_peer_id=parent_lease.authenticated_peer_id,
                authenticated_peer_uid=parent_lease.authenticated_peer_uid,
                authenticated_peer_gid=parent_lease.authenticated_peer_gid,
                authenticated_peer_pid=parent_lease.authenticated_peer_pid,
                transport_instance_id=parent_lease.transport_instance_id,
                transport_binding_digest=parent_lease.transport_binding_digest,
                bound_child_request_id=child_request_id,
                parent_execution_id=parent_execution_id,
                execution_graph_id=execution_graph_id,
                child_depth=child_depth,
                issued_at=now,
                expires_at=expires_at,
            )
            self._leases[lease_id] = _LeaseRecord(
                lease=child,
                canonical_claims=_claims(child),
            )
            return child

    def resolve_invocation_lease(
        self,
        lease: IngressInvocationLease | ChildIngressLease,
        request_id: str,
        channel_binding: IngressChannelBinding,
        *,
        authenticated_peer_id: str | None = None,
        invocation_nonce: str | bytes | None = None,
        ingress_kind: IngressKind | None = None,
        root_execution_id: str | None = None,
        parent_execution_id: str | None = None,
        execution_graph_id: str | None = None,
        child_depth: int | None = None,
    ) -> IngressSession:
        """Atomically validate and check out ``lease`` for one invocation.

        The returned session is the canonical current store record. Passing a
        copied set of claims or only a lease ID is insufficient. Supplying the
        raw current invocation nonce is strongly preferred; when an ingress
        adapter generated its nonce inside ``issue_invocation_lease``, the
        store-issued object identity and the unique reserved digest are used as
        the nonce proof.
        """

        if not isinstance(lease, (IngressInvocationLease, ChildIngressLease)):
            raise IngressLeaseInvalidError("Ingress invocation lease is invalid")
        _require_nonblank(request_id, "request_id")
        self._validate_binding_shape(channel_binding)
        peer_id = authenticated_peer_id or _derived_authenticated_peer_id(channel_binding)

        with self._lock:
            record = self._require_canonical_lease_record(lease)
            if record.state is not _LeaseState.ISSUED:
                raise IngressLeaseConsumedError("Ingress invocation lease has already been used")

            now = self._clock()
            session_record = self._require_active_session(lease.ingress_session_ref, now)
            session = session_record.session
            valid = (
                now >= lease.issued_at
                and now < lease.expires_at
                and session.revision == lease.ingress_session_revision
                and session.principal.principal_id == lease.principal_ref
                and session.principal.revision == lease.principal_revision
                and hmac.compare_digest(lease.authenticated_peer_id, peer_id)
                and lease.authenticated_peer_uid == channel_binding.peer_uid
                and lease.authenticated_peer_gid == channel_binding.peer_gid
                and lease.authenticated_peer_pid == channel_binding.peer_pid
                and hmac.compare_digest(
                    lease.transport_instance_id,
                    channel_binding.transport_instance,
                )
                and hmac.compare_digest(
                    lease.transport_binding_digest,
                    _transport_binding_digest(channel_binding),
                )
            )
            if isinstance(lease, IngressInvocationLease):
                expected_nonce_owner = self._nonce_owners.get(lease.invocation_nonce_digest)
                valid = (
                    valid
                    and hmac.compare_digest(lease.bound_request_id, request_id)
                    and expected_nonce_owner == lease.lease_id
                )
                if ingress_kind is not None:
                    valid = valid and ingress_kind is lease.ingress_kind
                if invocation_nonce is not None:
                    valid = valid and hmac.compare_digest(
                        lease.invocation_nonce_digest,
                        _invocation_nonce_digest(invocation_nonce),
                    )
            else:
                valid = valid and hmac.compare_digest(
                    lease.bound_child_request_id,
                    request_id,
                )
                parent_record = self._leases.get(lease.parent_ingress_lease_id)
                valid = (
                    valid
                    and root_execution_id is not None
                    and hmac.compare_digest(lease.root_execution_id, root_execution_id)
                    and parent_execution_id is not None
                    and hmac.compare_digest(
                        lease.parent_execution_id,
                        parent_execution_id,
                    )
                    and execution_graph_id is not None
                    and hmac.compare_digest(
                        lease.execution_graph_id,
                        execution_graph_id,
                    )
                    and child_depth == lease.child_depth
                    and parent_record is not None
                    and parent_record.canonical_claims == _claims(parent_record.lease)
                )
            if not valid:
                raise IngressLeaseInvalidError("Ingress invocation lease is invalid")

            record.state = _LeaseState.RESOLVED
            return session

    def consume_invocation_lease(
        self,
        lease: IngressInvocationLease | ChildIngressLease,
    ) -> None:
        """Consume a checked-out lease from the executor's outer ``finally``."""

        if not isinstance(lease, (IngressInvocationLease, ChildIngressLease)):
            raise IngressLeaseInvalidError("Ingress invocation lease is invalid")
        with self._lock:
            record = self._require_canonical_lease_record(lease)
            if record.state is _LeaseState.CONSUMED:
                raise IngressLeaseConsumedError("Ingress invocation lease has already been consumed")
            if record.state is not _LeaseState.RESOLVED:
                raise IngressLeaseInvalidError("Ingress invocation lease was not resolved")
            record.state = _LeaseState.CONSUMED

    def _require_canonical_lease_record(
        self,
        lease: IngressInvocationLease | ChildIngressLease,
    ) -> _LeaseRecord:
        record = self._leases.get(lease.lease_id)
        if (
            record is None
            or record.lease is not lease
            or type(record.lease) is not type(lease)
            or record.canonical_claims != _claims(lease)
        ):
            raise IngressLeaseInvalidError("Ingress invocation lease is invalid")
        return record

    def _require_active_session(self, session_id: str, now: float) -> _SessionRecord:
        record = self._sessions.get(session_id)
        if record is None or record.session.revoked or (record.expires_at is not None and now >= record.expires_at):
            raise IngressLeaseInvalidError("Ingress invocation lease is invalid")
        return record

    @staticmethod
    def _validate_binding_shape(binding: IngressChannelBinding) -> None:
        if not isinstance(binding, IngressChannelBinding):
            raise TypeError("channel_binding must be an IngressChannelBinding")
        _require_peer_component(binding.peer_uid, "peer_uid")
        _require_peer_component(binding.peer_gid, "peer_gid")
        _require_peer_component(binding.peer_pid, "peer_pid")
        _require_nonblank(binding.transport_instance, "transport_instance")
        _require_nonblank(binding.channel_binding, "channel_binding")


_GLOBAL_INGRESS_SESSION_STORE = IngressSessionStore()


def get_ingress_session_store() -> IngressSessionStore:
    return _GLOBAL_INGRESS_SESSION_STORE


__all__ = [
    "IngressSessionStore",
    "get_ingress_session_store",
]
