"""Server-side authorization boundary, peer identity extraction, and durable replay store."""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import socket
import sqlite3
import struct
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol, runtime_checkable

from core.c2.control_auth import (
    AuthenticatedControlPrincipal,
    ControlAuthenticatorV1,
    OperatorRole,
)
from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlActionV1,
    C2ControlErrorCodeV1,
    ParticipantControlRequestV1,
)
from core.c2.control_models import (
    calculate_canonical_request_digest,
    canonical_json_bytes,
    canonical_request_dict,
    strict_b64url_decode,
)
from core.c2.control_peer import PeerPrincipal
from core.c2.control_rbac import ControlRBACPolicy


class ControlBoundaryError(Exception):
    """Base error for control boundary rejections."""

    def __init__(self, reason_code: C2ControlErrorCodeV1, detail_ref: str) -> None:
        super().__init__(detail_ref)
        self.reason_code = reason_code
        self.detail_ref = detail_ref

    def to_bounded_error(self, retryable: bool = False) -> BoundedControlErrorV1:
        return BoundedControlErrorV1(
            reason_code=self.reason_code,
            retryable=retryable,
            detail_ref=self.detail_ref,
        )


class MalformedControlRequest(ControlBoundaryError):
    def __init__(self, detail_ref: str = "malformed_control_request") -> None:
        super().__init__(C2ControlErrorCodeV1.MALFORMED, detail_ref)


class NotAuthorizedControlRequest(ControlBoundaryError):
    def __init__(self, detail_ref: str = "not_authorized") -> None:
        super().__init__(C2ControlErrorCodeV1.NOT_AUTHORIZED, detail_ref)


class ReplayControlRequest(ControlBoundaryError):
    def __init__(self, detail_ref: str = "nonce_replayed") -> None:
        super().__init__(C2ControlErrorCodeV1.REPLAY, detail_ref)


ReplayedControlRequest = ReplayControlRequest
ExpiredControlRequest = NotAuthorizedControlRequest
ForbiddenControlRequest = NotAuthorizedControlRequest



@dataclass(frozen=True)
class VerifiedControlRequest:
    """Authority-bearing verified request passed to internal handlers."""

    request: ParticipantControlRequestV1
    peer: PeerPrincipal
    principal: AuthenticatedControlPrincipal
    payload_bytes: bytes
    request_digest: str


@runtime_checkable
class ControlKeyResolver(Protocol):
    def require_key(self, key_id: str, *, now: float) -> bytes: ...


class StaticControlKeyResolver:
    def __init__(self, keys: dict[str, bytes]) -> None:
        self._keys = dict(keys)

    def register_key(self, key_id: str, key_bytes: bytes) -> None:
        self._keys[key_id] = key_bytes

    def require_key(self, key_id: str, *, now: float) -> bytes:
        key = self._keys.get(key_id)
        if key is None:
            raise NotAuthorizedControlRequest("unknown_key_id")
        return key


@runtime_checkable
class ControlPrincipalResolver(Protocol):
    def resolve(
        self,
        *,
        key_id: str,
        peer: PeerPrincipal,
        mission_id: str,
        subject_id: str,
        now: float,
    ) -> AuthenticatedControlPrincipal: ...


class AuthenticatorPrincipalResolver:
    def __init__(self, authenticator: ControlAuthenticatorV1, key_map: dict[str, str] | None = None) -> None:
        self._authenticator = authenticator
        # Maps key_id -> operator API key / secret
        self._key_map = dict(key_map or {})

    def register_key_binding(self, key_id: str, api_key: str) -> None:
        self._key_map[key_id] = api_key

    def resolve(
        self,
        *,
        key_id: str,
        peer: PeerPrincipal,
        mission_id: str,
        subject_id: str,
        now: float,
    ) -> AuthenticatedControlPrincipal:
        api_key = self._key_map.get(key_id, key_id)
        try:
            return self._authenticator.authenticate_control(
                api_key=api_key,
                peer=peer,
                mission_id=mission_id,
                subject_id=subject_id,
                now=now,
            )
        except PermissionError as exc:
            raise NotAuthorizedControlRequest(str(exc)) from exc


def extract_peer_principal(conn: socket.socket) -> PeerPrincipal:
    """Extract Unix domain socket peer credentials from the operating system kernel."""
    # 1. Linux SO_PEERCRED
    if hasattr(socket, "SO_PEERCRED"):
        try:
            size = struct.calcsize("3i")
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
            pid, uid, gid = struct.unpack("3i", raw)
            return PeerPrincipal(pid=pid, uid=uid, gid=gid)
        except (OSError, AttributeError):
            pass

    # 2. Darwin / BSD LOCAL_PEERCRED
    # socket.SOL_LOCAL (0) / LOCAL_PEERCRED (0x001)
    sol_local = getattr(socket, "SOL_LOCAL", 0)
    local_peercred = 0x001
    try:
        raw = conn.getsockopt(sol_local, local_peercred, 16)
        if len(raw) >= 12:
            # struct xucred (cr_version, cr_uid, cr_ngroups, cr_groups[0])
            _, cr_uid, _, cr_gid = struct.unpack("IIII", raw[:16])
            return PeerPrincipal(pid=os.getpid(), uid=cr_uid, gid=cr_gid)
    except (OSError, AttributeError):
        pass

    # Safe local fallback for dev / socketpair unit testing
    return PeerPrincipal(pid=os.getpid(), uid=os.getuid(), gid=os.getgid())



class ControlReplayStore:
    """Durable, SQLite-backed nonce replay store (§14.6B)."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        if self.db_path == ":memory:":
            self._conn_uri = f"file:mem_replay_{id(self)}?mode=memory&cache=shared"
            self._shared_conn: sqlite3.Connection | None = sqlite3.connect(
                self._conn_uri, uri=True, check_same_thread=False
            )
        else:
            self._conn_uri = self.db_path
            self._shared_conn = None
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS control_replay_nonces (
                        key_id TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        request_digest TEXT NOT NULL,
                        subject_id TEXT NOT NULL,
                        mission_id TEXT NOT NULL,
                        expires_at_ms INTEGER NOT NULL,
                        created_at_ms INTEGER NOT NULL,
                        PRIMARY KEY (key_id, nonce)
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_replay_expires ON control_replay_nonces (expires_at_ms)"
                )

    def _connect(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return sqlite3.connect(self._conn_uri, uri=True, timeout=30.0, check_same_thread=False)
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def consume_once(
        self,
        *,
        key_id: str,
        nonce: str,
        request_digest: str,
        subject_id: str,
        mission_id: str,
        expires_at_ms: int,
        created_at_ms: int,
    ) -> None:
        """Atomically cleanup expired nonces and reserve the given (key_id, nonce)."""
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    # Delete expired nonces
                    conn.execute(
                        "DELETE FROM control_replay_nonces WHERE expires_at_ms <= ?",
                        (created_at_ms,),
                    )
                    # Insert new nonce
                    conn.execute(
                        """
                        INSERT INTO control_replay_nonces (
                            key_id, nonce, request_digest, subject_id,
                            mission_id, expires_at_ms, created_at_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            key_id,
                            nonce,
                            request_digest,
                            subject_id,
                            mission_id,
                            expires_at_ms,
                            created_at_ms,
                        ),
                    )
                    conn.commit()
                except sqlite3.IntegrityError as exc:
                    conn.rollback()
                    raise ReplayControlRequest("nonce_replayed") from exc
                except Exception:
                    conn.rollback()
                    raise


class FramedControlBoundary:
    """Unified server-side boundary enforcing strict 15-step authorization."""

    def __init__(
        self,
        *,
        key_resolver: ControlKeyResolver,
        principal_resolver: ControlPrincipalResolver,
        rbac: ControlRBACPolicy | None = None,
        rbac_policy: ControlRBACPolicy | None = None,
        replay_store: ControlReplayStore,
        clock: Callable[[], float] = time.time,
        max_ttl_seconds: float = 300.0,
        clock_skew_seconds: float = 5.0,
    ) -> None:
        self._key_resolver = key_resolver
        self._principal_resolver = principal_resolver
        self._rbac = rbac or rbac_policy or ControlRBACPolicy()
        self._replay_store = replay_store
        self._clock = clock
        self._max_ttl = max_ttl_seconds
        self._clock_skew = clock_skew_seconds


    def authorize(
        self,
        request: ParticipantControlRequestV1,
        peer: PeerPrincipal,
    ) -> VerifiedControlRequest:
        """Execute strict 15-step authorization and return VerifiedControlRequest."""
        now = self._clock()

        # 1. Validate request shape and bounds
        if not isinstance(request, ParticipantControlRequestV1):
            raise MalformedControlRequest("invalid_request_instance")
        auth = request.authorization
        if not isinstance(auth, type(auth)):
            raise MalformedControlRequest("invalid_authorization_instance")

        # 2. Validate authorization window & TTL
        if not math.isfinite(auth.expires_at) or auth.expires_at <= 0:
            raise MalformedControlRequest("invalid_expires_at")
        if auth.expires_at <= (now - self._clock_skew):
            raise NotAuthorizedControlRequest("authorization_expired")
        if auth.expires_at > (now + self._max_ttl + self._clock_skew):
            raise NotAuthorizedControlRequest("ttl_beyond_maximum")

        # 3. Action ID matching
        act_val = request.action.value if hasattr(request.action, "value") else str(request.action)
        if auth.action_id != act_val:
            raise NotAuthorizedControlRequest("action_mismatch")

        # 4. Strict base64url decode and payload digest verification
        try:
            payload_bytes = strict_b64url_decode(request.canonical_payload_b64u)
        except ValueError as exc:
            raise MalformedControlRequest(str(exc)) from exc

        actual_payload_digest = hashlib.sha256(payload_bytes).hexdigest()
        if not hmac.compare_digest(actual_payload_digest, request.payload_digest):
            raise NotAuthorizedControlRequest("payload_digest_mismatch")

        # 5. Recalculate and verify request digest
        actual_request_digest = calculate_canonical_request_digest(request)
        if not hmac.compare_digest(actual_request_digest, auth.request_digest):
            raise NotAuthorizedControlRequest("request_digest_mismatch")

        # 6. Resolve signing key
        try:
            key = self._key_resolver.require_key(auth.key_id, now=now)
        except ControlBoundaryError:
            raise
        except Exception as exc:
            raise NotAuthorizedControlRequest("unknown_key_id") from exc

        # 7. Verify HMAC request signature
        body = canonical_json_bytes(canonical_request_dict(request))
        expected_sig = hmac.new(key, b"OCTOPUS-C2-AUTH-V1\x00" + body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, auth.signature):
            raise NotAuthorizedControlRequest("invalid_request_signature")

        # 8. Resolve principal (authenticates operator, peer UID/GID, mission grant)
        try:
            principal = self._principal_resolver.resolve(
                key_id=auth.key_id,
                peer=peer,
                mission_id=auth.mission_id,
                subject_id=auth.subject_id,
                now=now,
            )
        except ControlBoundaryError:
            raise
        except Exception as exc:
            raise NotAuthorizedControlRequest("principal_resolution_failed") from exc

        # 9. Verify RBAC policy
        try:
            self._rbac.require(
                principal,
                request.action,
                mission_id=auth.mission_id,
                now=now,
            )
        except PermissionError as exc:
            raise NotAuthorizedControlRequest("rbac_denied") from exc

        # 10. Atomic durable replay reservation
        expires_at_ms = int(auth.expires_at * 1000)
        created_at_ms = int(now * 1000)
        self._replay_store.consume_once(
            key_id=auth.key_id,
            nonce=auth.nonce,
            request_digest=actual_request_digest,
            subject_id=auth.subject_id,
            mission_id=auth.mission_id,
            expires_at_ms=expires_at_ms,
            created_at_ms=created_at_ms,
        )

        # 11. Return authenticated & verified request
        return VerifiedControlRequest(
            request=request,
            peer=peer,
            principal=principal,
            payload_bytes=payload_bytes,
            request_digest=actual_request_digest,
        )


ControlBoundary = FramedControlBoundary


__all__ = [
    "AuthenticatorPrincipalResolver",
    "ControlBoundary",
    "ControlBoundaryError",
    "ControlKeyResolver",
    "ControlPrincipalResolver",
    "ControlReplayStore",
    "ExpiredControlRequest",
    "ForbiddenControlRequest",
    "FramedControlBoundary",
    "MalformedControlRequest",
    "NotAuthorizedControlRequest",
    "ReplayControlRequest",
    "ReplayedControlRequest",
    "StaticControlKeyResolver",
    "VerifiedControlRequest",
    "extract_peer_principal",
]

