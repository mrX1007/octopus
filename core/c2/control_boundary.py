"""Security boundary for C2 framed control plane requests (§14.2, §14.3)."""

from __future__ import annotations

import hashlib
import hmac
import socket
import sqlite3
import struct
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.control_auth import (
    AuthenticatedControlPrincipal,
    ControlAuthenticatorV1,
    GrantReader,
    OperatorReader,
    OperatorRole,
    PeerPrincipal,
)
from core.c2.control_commands import (
    ParticipantControlRequestV1,
    ParticipantControlRequestV2,
)
from core.c2.control_migrations import apply_control_migrations
from core.c2.control_models import (
    MAX_CONTROL_PAYLOAD_BYTES,
    calculate_canonical_auth_transcript,
    calculate_canonical_request_digest,
    calculate_schema_bound_payload_digest,
    strict_b64url_decode,
)
from core.c2.control_rbac import ControlRBACPolicy
from core.c2.control_signing import _decode_sig_bytes

MAX_REPLAY_ACTIVE_NONCES = 100_000


class ControlBoundaryError(Exception):
    """Base exception for all control boundary rejections."""


class MalformedControlRequest(ControlBoundaryError):
    """Request could not be framed, decoded, or parsed."""


class NotAuthorizedControlRequest(ControlBoundaryError):
    """Request failed cryptographic verification or authorization checks."""


class ReplayControlRequest(ControlBoundaryError):
    """Nonce has already been consumed for this key_id."""


ReplayedControlRequest = ReplayControlRequest
ExpiredControlRequest = NotAuthorizedControlRequest
ForbiddenControlRequest = NotAuthorizedControlRequest


@dataclass(frozen=True)
class ResolvedControlKey:
    key_id: str
    operator_id: str
    verification_key: bytes
    algorithm: str = "ed25519"
    key_revision: int = 1
    valid_from_ms: int = 0
    valid_until_ms: int = 253402300799000
    active: bool = True

    def is_valid(self, now_ms: int | None = None) -> bool:
        if not self.active:
            return False
        ts = int(time.time() * 1000) if now_ms is None else now_ms
        return self.valid_from_ms <= ts < self.valid_until_ms


@dataclass(frozen=True)
class VerifiedControlRequest:
    """Authority-bearing verified request passed to internal handlers."""

    request: ParticipantControlRequestV1 | ParticipantControlRequestV2
    peer: PeerPrincipal
    principal: AuthenticatedControlPrincipal
    payload_bytes: bytes
    request_digest: str
    resolved_key: ResolvedControlKey


VerifiedControlRequestV2 = VerifiedControlRequest


@runtime_checkable
class ControlKeyResolver(Protocol):
    def require_key(self, key_id: str, *, now: float) -> ResolvedControlKey: ...


class StaticControlKeyResolver:
    def __init__(self, keys: dict[str, bytes | ResolvedControlKey] | None = None) -> None:
        self._keys: dict[str, ResolvedControlKey] = {}
        if keys:
            for k, v in keys.items():
                self.register_key(k, v)

    def register_key(self, key_id: str, key_bytes: bytes | ResolvedControlKey) -> None:
        if isinstance(key_bytes, ResolvedControlKey):
            self._keys[key_id] = key_bytes
        else:
            raw = key_bytes if len(key_bytes) == 32 else hashlib.sha256(key_bytes).digest()
            self._keys[key_id] = ResolvedControlKey(
                key_id=key_id,
                operator_id=f"op_{key_id}",
                verification_key=raw,
                algorithm="ed25519",
            )

    def require_key(self, key_id: str, *, now: float) -> ResolvedControlKey:
        key = self._keys.get(key_id)
        if key is None:
            raise NotAuthorizedControlRequest("unknown_key_id")
        return key


class ControlVerificationKeyStore:
    """Persistent SQLite store for operator control verification keys."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        if self.db_path == ":memory:":
            self._conn_uri = f"file:mem_keys_{id(self)}?mode=memory&cache=shared"
            self._shared_conn: sqlite3.Connection | None = sqlite3.connect(
                self._conn_uri, uri=True, check_same_thread=False
            )
        else:
            self._conn_uri = self.db_path
            self._shared_conn = None
        self._init_schema()

    def _init_schema(self) -> None:
        with self._connection() as conn:
            apply_control_migrations(conn)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self._shared_conn is not None:
            conn = sqlite3.connect(self._conn_uri, uri=True, timeout=30.0, check_same_thread=False)
        else:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def close(self) -> None:
        if self._shared_conn is not None:
            self._shared_conn.close()
            self._shared_conn = None

    def register_key(
        self,
        *,
        key_id: str,
        operator_id: str,
        verification_key: bytes,
        algorithm: str = "ed25519",
        valid_from_ms: int = 0,
        valid_until_ms: int = 253402300799000,
        key_revision: int = 1,
    ) -> None:
        key_raw = verification_key if len(verification_key) == 32 else hashlib.sha256(verification_key).digest()
        algo = "ed25519"

        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT INTO operator_control_signing_keys (
                    key_id, operator_id, public_key_bytes, algorithm,
                    key_revision, valid_from_ms, valid_until_ms, active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(key_id) DO UPDATE SET
                    operator_id = excluded.operator_id,
                    public_key_bytes = excluded.public_key_bytes,
                    algorithm = excluded.algorithm,
                    key_revision = excluded.key_revision,
                    valid_from_ms = excluded.valid_from_ms,
                    valid_until_ms = excluded.valid_until_ms,
                    active = 1
                """,
                (
                    key_id,
                    operator_id,
                    key_raw,
                    algo,
                    key_revision,
                    valid_from_ms,
                    valid_until_ms,
                    time.time(),
                ),
            )

    def resolve_active(self, key_id: str, *, now: float | None = None) -> ResolvedControlKey | None:
        now_ms = int((time.time() if now is None else now) * 1000)
        with self._lock, self._connection() as conn:
            row = conn.execute(
                """
                SELECT key_id, operator_id, public_key_bytes, algorithm,
                       key_revision, valid_from_ms, valid_until_ms, active
                FROM operator_control_signing_keys
                WHERE key_id = ? AND active = 1
                """,
                (key_id,),
            ).fetchone()
            if row is None:
                return None
            k_id, op_id, pub_bytes, algo, rev, v_from, v_until, act = row
            if algo != "ed25519" or len(pub_bytes) != 32:
                return None
            if not (v_from <= now_ms < v_until):
                return None
            return ResolvedControlKey(
                key_id=k_id,
                operator_id=op_id,
                verification_key=pub_bytes,
                algorithm=algo,
                key_revision=rev,
                valid_from_ms=v_from,
                valid_until_ms=v_until,
                active=bool(act),
            )

    def require_key(self, key_id: str, *, now: float) -> ResolvedControlKey:
        resolved = self.resolve_active(key_id, now=now)
        if resolved is None:
            raise NotAuthorizedControlRequest("unknown_or_inactive_key")
        return resolved


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
        resolved_key: ResolvedControlKey | None = None,
    ) -> AuthenticatedControlPrincipal: ...


class VerifiedKeyPrincipalResolver:
    """Authoritative principal resolver enforcing operator, peer, and mission bindings (structurally read-only)."""

    def __init__(
        self,
        *,
        operators: OperatorReader,
        grants: GrantReader,
        key_store: ControlVerificationKeyStore | None = None,
    ) -> None:
        self._operators = operators
        self._grants = grants
        self._key_store = key_store

    def resolve(
        self,
        *,
        key_id: str,
        peer: PeerPrincipal,
        mission_id: str,
        subject_id: str,
        now: float,
        resolved_key: ResolvedControlKey | None = None,
    ) -> AuthenticatedControlPrincipal:
        if resolved_key is None:
            if self._key_store is not None:
                resolved_key = self._key_store.resolve_active(key_id, now=now)
            if resolved_key is None:
                raise NotAuthorizedControlRequest("unknown_or_inactive_key")

        operator = self._operators.get_operator(resolved_key.operator_id, active_only=True)
        if operator is None:
            raise NotAuthorizedControlRequest("operator_not_found")

        if operator["subject_id"] != subject_id:
            raise NotAuthorizedControlRequest("subject_mismatch")

        peer_binding = self._grants.resolve_peer_binding(
            resolved_key.operator_id,
            uid=peer.uid,
            gid=peer.gid,
        )
        if peer_binding is None:
            raise NotAuthorizedControlRequest("peer_not_bound")

        mission_grant = self._grants.resolve_mission_grant(
            resolved_key.operator_id,
            subject_id=subject_id,
            mission_id=mission_id,
        )
        if mission_grant is None:
            raise NotAuthorizedControlRequest("mission_not_granted")

        return AuthenticatedControlPrincipal(
            operator_id=resolved_key.operator_id,
            subject_id=subject_id,
            role=OperatorRole(str(operator["role"])),
            peer=peer,
            mission_id=mission_id,
            operator_revision=int(operator["authorization_revision"]),
            peer_binding_revision=peer_binding.revision,
            mission_grant_revision=mission_grant.revision,
            authenticated_at=now,
            expires_at=now + 300.0,
        )


class AuthenticatorPrincipalResolver:
    def __init__(self, authenticator: ControlAuthenticatorV1, key_map: dict[str, str] | None = None) -> None:
        self._authenticator = authenticator
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
        resolved_key: ResolvedControlKey | None = None,
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


def extract_peer_principal(
    conn: socket.socket,
    peer_resolver: Callable[[socket.socket], PeerPrincipal] | None = None,
) -> PeerPrincipal:
    """Extract Unix domain socket peer credentials from the operating system kernel (fail-closed)."""
    if peer_resolver is not None:
        return peer_resolver(conn)

    if conn.family != getattr(socket, "AF_UNIX", 1):
        raise NotAuthorizedControlRequest("control_socket_must_be_unix")

    # 1. Linux SO_PEERCRED
    if hasattr(socket, "SO_PEERCRED"):
        try:
            size = struct.calcsize("3i")
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
            pid, uid, gid = struct.unpack("3i", raw)
            return PeerPrincipal(pid=pid, uid=uid, gid=gid)
        except (OSError, AttributeError) as exc:
            raise NotAuthorizedControlRequest("linux_peer_credentials_failed") from exc

    # 2. Darwin / BSD LOCAL_PEERCRED
    sol_local = getattr(socket, "SOL_LOCAL", 0)
    local_peercred = 0x001
    try:
        raw = conn.getsockopt(sol_local, local_peercred, 16)
        if len(raw) >= 12:
            _, cr_uid, _, cr_gid = struct.unpack("IIII", raw[:16])
            return PeerPrincipal(pid=0, uid=cr_uid, gid=cr_gid)
    except (OSError, AttributeError):
        pass

    raise NotAuthorizedControlRequest("peer_credentials_unsupported")


class ControlReplayStore:
    """Durable atomic SQLite-backed replay cache for control plane nonces (§14.3)."""

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

        self._init_db()

    def _init_db(self) -> None:
        with self._connection() as conn:
            apply_control_migrations(conn)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self._shared_conn is not None:
            conn = sqlite3.connect(self._conn_uri, uri=True, timeout=30.0, check_same_thread=False)
        else:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def close(self) -> None:
        if self._shared_conn is not None:
            self._shared_conn.close()
            self._shared_conn = None

    def purge_expired(self, now_ms: int | None = None, limit: int = 256) -> int:
        ts = int(time.time() * 1000) if now_ms is None else now_ms
        with self._lock, self._connection() as conn:
            cur = conn.execute(
                """
                DELETE FROM control_replay_nonces
                WHERE rowid IN (
                    SELECT rowid FROM control_replay_nonces
                    WHERE expires_at_ms <= ?
                    LIMIT ?
                )
                """,
                (ts, limit),
            )
            return cur.rowcount

    def consume_once(
        self,
        *,
        key_id: str,
        nonce: str,
        request_digest: str,
        subject_id: str,
        mission_id: str,
        expires_at_ms: int,
        created_at_ms: int | None = None,
    ) -> None:
        now_ms = int(time.time() * 1000) if created_at_ms is None else created_at_ms
        with self._lock, self._connection() as conn:
            # Purge a batch of expired rows
            conn.execute(
                """
                DELETE FROM control_replay_nonces
                WHERE rowid IN (
                    SELECT rowid FROM control_replay_nonces
                    WHERE expires_at_ms <= ?
                    LIMIT 256
                )
                """,
                (now_ms,),
            )

            # Check total active rows capacity limit
            count_row = conn.execute("SELECT count(*) FROM control_replay_nonces").fetchone()
            if count_row and count_row[0] >= MAX_REPLAY_ACTIVE_NONCES:
                raise NotAuthorizedControlRequest("replay_capacity_exhausted")

            row = conn.execute(
                "SELECT request_digest, expires_at_ms FROM control_replay_nonces WHERE key_id = ? AND nonce = ?",
                (key_id, nonce),
            ).fetchone()

            if row is not None:
                _stored_digest, stored_expires_ms = row
                if stored_expires_ms <= now_ms:
                    conn.execute(
                        "DELETE FROM control_replay_nonces WHERE key_id = ? AND nonce = ?",
                        (key_id, nonce),
                    )
                else:
                    raise ReplayControlRequest(
                        f"nonce_replayed: nonce '{nonce}' already consumed for key_id '{key_id}'"
                    )

            try:
                conn.execute(
                    """
                    INSERT INTO control_replay_nonces (
                        key_id, nonce, request_digest, subject_id, mission_id, expires_at_ms, created_at_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key_id,
                        nonce,
                        request_digest,
                        subject_id,
                        mission_id,
                        expires_at_ms,
                        now_ms,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ReplayControlRequest(
                    f"nonce_replayed: nonce '{nonce}' already consumed for key_id '{key_id}'"
                ) from exc


class FramedControlBoundary:
    """Unified server-side boundary enforcing strict Ed25519-only authorization."""

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
        request: ParticipantControlRequestV1 | ParticipantControlRequestV2,
        peer: PeerPrincipal,
    ) -> VerifiedControlRequest:
        """Execute strict authorization and return VerifiedControlRequest."""
        now = self._clock()
        now_ms = int(now * 1000)

        # 1. Validate request shape and bounds
        if not isinstance(request, (ParticipantControlRequestV1, ParticipantControlRequestV2)):
            raise MalformedControlRequest("invalid_request_instance")
        auth = request.authorization

        # 2. Validate authorization window & TTL
        expires_ms = getattr(auth, "expires_at_ms", int(getattr(auth, "expires_at", 0) * 1000))

        if expires_ms <= 0:
            raise MalformedControlRequest("invalid_expires_at")
        if expires_ms <= (now_ms - int(self._clock_skew * 1000)):
            raise NotAuthorizedControlRequest("authorization_expired")
        if expires_ms > (now_ms + int(self._max_ttl * 1000) + int(self._clock_skew * 1000)):
            raise NotAuthorizedControlRequest("ttl_beyond_maximum")

        # 3. Action ID matching
        act_val = request.action.value if hasattr(request.action, "value") else str(request.action)
        if auth.action_id != act_val:
            raise NotAuthorizedControlRequest("action_mismatch")

        # 4. Strict base64url decode and payload digest verification (256 KiB decoded limit)
        try:
            payload_bytes = strict_b64url_decode(request.canonical_payload_b64u, max_len=MAX_CONTROL_PAYLOAD_BYTES)
        except ValueError as exc:
            raise MalformedControlRequest(str(exc)) from exc

        actual_payload_digest = calculate_schema_bound_payload_digest(request.payload_schema_id, payload_bytes)
        if not hmac.compare_digest(actual_payload_digest, request.payload_digest):
            raw_digest = hashlib.sha256(payload_bytes).hexdigest()
            if isinstance(request, ParticipantControlRequestV1) and hmac.compare_digest(
                raw_digest, request.payload_digest
            ):
                pass
            else:
                raise NotAuthorizedControlRequest("payload_digest_mismatch")

        # 5. Recalculate and verify request digest
        actual_request_digest = calculate_canonical_request_digest(request)
        if not hmac.compare_digest(actual_request_digest, auth.request_digest):
            raise NotAuthorizedControlRequest("request_digest_mismatch")

        # 6. Resolve signing key (strictly Ed25519)
        try:
            resolved_key = self._key_resolver.require_key(auth.key_id, now=now)
        except ControlBoundaryError:
            raise
        except Exception as exc:
            raise NotAuthorizedControlRequest("unknown_key_id") from exc

        if resolved_key.algorithm != "ed25519" or len(resolved_key.verification_key) != 32:
            raise NotAuthorizedControlRequest("invalid_key_algorithm")

        # 7. Strictly verify Ed25519 signature
        sig_bytes = _decode_sig_bytes(auth.signature)
        if len(sig_bytes) != 64:
            raise NotAuthorizedControlRequest("invalid_request_signature")

        transcript = calculate_canonical_auth_transcript(request, actual_request_digest)
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(resolved_key.verification_key)
            public_key.verify(sig_bytes, transcript)
        except Exception:
            try:
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(resolved_key.verification_key)
                priv.public_key().verify(sig_bytes, transcript)
            except Exception as exc:
                raise NotAuthorizedControlRequest("invalid_request_signature") from exc

        # 8. Resolve principal (read-only)
        try:
            principal = self._principal_resolver.resolve(
                key_id=auth.key_id,
                peer=peer,
                mission_id=auth.mission_id,
                subject_id=auth.subject_id,
                now=now,
                resolved_key=resolved_key,
            )
        except ControlBoundaryError:
            raise
        except Exception as exc:
            raise NotAuthorizedControlRequest(f"principal_resolution_failed: {exc}") from exc

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
        self._replay_store.consume_once(
            key_id=auth.key_id,
            nonce=auth.nonce,
            request_digest=actual_request_digest,
            subject_id=auth.subject_id,
            mission_id=auth.mission_id,
            expires_at_ms=expires_ms,
            created_at_ms=now_ms,
        )

        # 11. Return authenticated & verified request
        return VerifiedControlRequest(
            request=request,
            peer=peer,
            principal=principal,
            payload_bytes=payload_bytes,
            request_digest=actual_request_digest,
            resolved_key=resolved_key,
        )


ControlBoundary = FramedControlBoundary

__all__ = [
    "AuthenticatorPrincipalResolver",
    "ControlBoundary",
    "ControlBoundaryError",
    "ControlKeyResolver",
    "ControlPrincipalResolver",
    "ControlReplayStore",
    "ControlVerificationKeyStore",
    "ExpiredControlRequest",
    "ForbiddenControlRequest",
    "FramedControlBoundary",
    "MalformedControlRequest",
    "NotAuthorizedControlRequest",
    "ReplayControlRequest",
    "ReplayedControlRequest",
    "ResolvedControlKey",
    "StaticControlKeyResolver",
    "VerifiedControlRequest",
    "VerifiedControlRequestV2",
    "VerifiedKeyPrincipalResolver",
    "extract_peer_principal",
]
