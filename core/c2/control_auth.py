"""Fail-closed construction and fencing of C2 control principals."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from core.c2.control_commands import C2ControlAction
from core.c2.control_peer import PeerPrincipal
from core.secrets import SecretValue


class OperatorRole(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    READONLY = "readonly"


@dataclass(frozen=True)
class AuthenticatedOperator:
    operator_id: str
    subject_id: str
    name: str
    role: OperatorRole
    active: bool
    authorization_revision: int
    allowed_peer_uids: tuple[int, ...]
    allowed_peer_gids: tuple[int, ...]


@dataclass(frozen=True)
class AuthenticatedControlPrincipal:
    operator_id: str
    subject_id: str
    role: OperatorRole
    peer: PeerPrincipal
    mission_id: str
    operator_revision: int
    peer_binding_revision: int
    mission_grant_revision: int
    authenticated_at: float
    expires_at: float


@dataclass(frozen=True)
class VerifiedMutationAuthority:
    """Immutable verified mutation authority required for all state mutations (§14.3, §14.4)."""

    operator_id: str
    subject_id: str
    mission_id: str
    peer_pid: int
    peer_uid: int
    peer_gid: int
    key_id: str
    key_revision: int
    operator_revision: int
    peer_binding_revision: int
    mission_grant_revision: int
    request_digest: str
    authorization_issued_at_ms: int
    authorization_expires_at_ms: int
    transaction_id: str = ""
    participant_id: str = ""
    action_id: str = ""


@runtime_checkable
class OperatorReader(Protocol):
    def get_operator(self, operator_id: str, *, active_only: bool = True) -> dict[str, Any] | None: ...
    def authenticate(self, api_key: str | SecretValue) -> dict[str, Any] | None: ...


@runtime_checkable
class ControlKeyReader(Protocol):
    def resolve_active(self, key_id: str, *, now: float | None = None) -> Any | None: ...
    def require_key(self, key_id: str, *, now: float) -> Any: ...


@runtime_checkable
class PeerBindingReader(Protocol):
    def resolve_peer_binding(self, operator_id: str, *, uid: int, gid: int) -> Any | None: ...
    def allowed_peers(self, operator_id: str) -> list[Any]: ...


@runtime_checkable
class MissionGrantReader(Protocol):
    def resolve_mission_grant(self, operator_id: str, *, subject_id: str, mission_id: str) -> Any | None: ...


@runtime_checkable
class GrantReader(Protocol):
    def resolve_peer_binding(self, operator_id: str, *, uid: int, gid: int) -> Any | None: ...
    def resolve_mission_grant(self, operator_id: str, *, subject_id: str, mission_id: str) -> Any | None: ...
    def allowed_peers(self, operator_id: str) -> list[Any]: ...


class AuthorityFence:
    """Verifies authority revisions directly against the database connection inside a write transaction (§14.3)."""

    @staticmethod
    def verify_current(
        conn: Any,
        authority: VerifiedMutationAuthority,
        resolved_key: Any = None,
        now_ms: int | None = None,
    ) -> None:
        if type(authority) is not VerifiedMutationAuthority and not isinstance(authority, VerifiedMutationAuthority):
            raise TypeError("authority must be an exact VerifiedMutationAuthority instance")

        op_id = authority.operator_id
        subj_id = authority.subject_id
        mis_id = authority.mission_id
        p_uid = authority.peer_uid
        p_gid = authority.peer_gid
        k_id = authority.key_id
        k_rev = authority.key_revision
        op_rev = authority.operator_revision
        pb_rev = authority.peer_binding_revision
        mg_rev = authority.mission_grant_revision

        cursor = conn.cursor()
        current_ts = int(time.time() * 1000) if now_ms is None else now_ms

        # 0. Validity window of the authority itself
        if authority.authorization_issued_at_ms > current_ts or current_ts >= authority.authorization_expires_at_ms:
            raise PermissionError("authority_validity_window_expired")

        # 1. Operators table & active operator checks
        cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='operators'")
        if not cursor.fetchone()[0]:
            raise PermissionError("operators_table_missing")

        cursor.execute(
            "SELECT active, authorization_revision, subject_id FROM operators WHERE operator_id = ?",
            (op_id,),
        )
        row = cursor.fetchone()
        if not row or not row[0]:
            raise PermissionError("operator_authority_stale_or_revoked")
        if str(row[2]) != subj_id:
            raise PermissionError("operator_subject_mismatch")
        if int(row[1]) != op_rev:
            raise PermissionError("operator_authority_stale_or_revoked")

        # 2. Key checks: operator_control_signing_keys table & key row MUST exist and be active
        cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='operator_control_signing_keys'")
        if not cursor.fetchone()[0]:
            raise PermissionError("signing_keys_table_missing")

        cursor.execute(
            """
            SELECT active, key_revision, operator_id, algorithm, public_key_bytes, valid_from_ms, valid_until_ms
            FROM operator_control_signing_keys WHERE key_id = ?
            """,
            (k_id,),
        )
        key_row = cursor.fetchone()
        if key_row is None:
            raise PermissionError("key_authority_missing_or_revoked")
        if not key_row[0] or int(key_row[1]) != k_rev:
            raise PermissionError("key_authority_stale_or_revoked")
        if str(key_row[2]) != op_id:
            raise PermissionError("key_operator_mismatch")
        if str(key_row[3]).lower() != "ed25519":
            raise PermissionError("key_algorithm_invalid")
        if len(bytes(key_row[4])) != 32:
            raise PermissionError("key_bytes_invalid")
        if not (int(key_row[5]) <= current_ts < int(key_row[6])):
            raise PermissionError("key_validity_expired")

        # 3. Peer binding checks: operator_peer_bindings & operator_peer_binding_revisions MUST exist
        cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='operator_peer_bindings'")
        if not cursor.fetchone()[0]:
            raise PermissionError("peer_bindings_table_missing")

        cursor.execute(
            "SELECT active FROM operator_peer_bindings WHERE operator_id = ? AND peer_uid = ? AND peer_gid = ?",
            (op_id, p_uid, p_gid),
        )
        pb_row = cursor.fetchone()
        if not pb_row or not pb_row[0]:
            raise PermissionError("peer_binding_stale_or_revoked")

        cursor.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='operator_peer_binding_revisions'"
        )
        if not cursor.fetchone()[0]:
            raise PermissionError("peer_binding_revisions_table_missing")

        cursor.execute(
            "SELECT revision FROM operator_peer_binding_revisions WHERE operator_id = ?",
            (op_id,),
        )
        pbr_row = cursor.fetchone()
        if not pbr_row or int(pbr_row[0]) != pb_rev:
            raise PermissionError("peer_binding_stale_or_revoked")

        # 4. Mission checks: control_missions MUST exist and mission active
        cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='control_missions'")
        if not cursor.fetchone()[0]:
            raise PermissionError("missions_table_missing")

        cursor.execute(
            "SELECT active FROM control_missions WHERE mission_id = ?",
            (mis_id,),
        )
        m_row = cursor.fetchone()
        if not m_row or not m_row[0]:
            raise PermissionError("mission_inactive_or_revoked")

        # 5. Mission grant checks: operator_mission_grants & operator_mission_grant_revisions MUST exist
        cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='operator_mission_grants'")
        if not cursor.fetchone()[0]:
            raise PermissionError("mission_grants_table_missing")

        cursor.execute(
            "SELECT active FROM operator_mission_grants WHERE operator_id = ? AND subject_id = ? AND mission_id = ?",
            (op_id, subj_id, mis_id),
        )
        mg_row = cursor.fetchone()
        if not mg_row or not mg_row[0]:
            raise PermissionError("mission_grant_stale_or_revoked")

        cursor.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='operator_mission_grant_revisions'"
        )
        if not cursor.fetchone()[0]:
            raise PermissionError("mission_grant_revisions_table_missing")

        cursor.execute(
            "SELECT revision FROM operator_mission_grant_revisions WHERE operator_id = ?",
            (op_id,),
        )
        mgr_row = cursor.fetchone()
        if not mgr_row or int(mgr_row[0]) != mg_rev:
            raise PermissionError("mission_grant_stale_or_revoked")


_HEALTH_ACTIONS = {"ping", "version", "readiness"}
_READ_ACTIONS = {"list_agents", "list_results"}
_ADMIN_ONLY_ACTIONS = {
    "purge_results",
    "manage_operators_list",
    "manage_operators_create",
    "manage_operators_deactivate",
    "manage_operators_rotate",
    "sync_operator_peer_bindings",
    "revoke_operator_peer_binding",
    "sync_operator_mission_grants",
    "revoke_operator_mission_grant",
}
_KNOWN_ACTIONS = {action.value for action in C2ControlAction}


class ControlAuthenticatorV1:
    """Authenticate API key, OS peer, subject, mission, and revisions."""

    def __init__(
        self,
        operators: OperatorReader,
        grants: GrantReader,
        *,
        default_ttl_seconds: float = 300.0,
    ) -> None:
        if default_ttl_seconds <= 0:
            raise ValueError("principal TTL must be positive")
        self._operators = operators
        self._grants = grants
        self._default_ttl = float(default_ttl_seconds)
        self._issued: dict[int, AuthenticatedControlPrincipal] = {}
        self._lock = threading.RLock()
        if hasattr(grants, "bind_principal_validator"):
            grants.bind_principal_validator(self.is_current_principal)

    def authenticate_control(
        self,
        *,
        api_key: str | SecretValue,
        peer: PeerPrincipal,
        mission_id: str,
        subject_id: str,
        now: float | None = None,
        claimed_operator_id: str | None = None,
        claimed_role: str | OperatorRole | None = None,
        claimed_name: str | None = None,
    ) -> AuthenticatedControlPrincipal:
        """Construct a principal after every authoritative binding succeeds."""

        if any(value is not None for value in (claimed_operator_id, claimed_role, claimed_name)):
            raise PermissionError("request-supplied operator identity/role/name is forbidden")
        if not isinstance(peer, PeerPrincipal):
            raise TypeError("peer must be a server-observed PeerPrincipal")
        if not isinstance(mission_id, str) or not mission_id:
            raise PermissionError("mission binding is required")
        if not isinstance(subject_id, str) or not subject_id:
            raise PermissionError("subject binding is required")
        record = self._operators.authenticate(api_key)
        if record is None:
            raise PermissionError("operator API-key verification failed")
        if not bool(record["active"]):
            raise PermissionError("operator is inactive")
        operator_id = str(record["operator_id"])
        authoritative_subject = str(record["subject_id"])
        if subject_id != authoritative_subject:
            raise PermissionError("request subject does not match authenticated operator")
        peer_binding = self._grants.resolve_peer_binding(
            operator_id,
            uid=peer.uid,
            gid=peer.gid,
        )
        if peer_binding is None:
            raise PermissionError("no active binding for authenticated peer UID/GID")
        mission_grant = self._grants.resolve_mission_grant(
            operator_id,
            subject_id=authoritative_subject,
            mission_id=mission_id,
        )
        if mission_grant is None:
            raise PermissionError("no active mission grant for authenticated subject")
        timestamp = time.time() if now is None else float(now)
        principal = AuthenticatedControlPrincipal(
            operator_id=operator_id,
            subject_id=authoritative_subject,
            role=OperatorRole(str(record["role"])),
            peer=peer,
            mission_id=mission_id,
            operator_revision=int(record["authorization_revision"]),
            peer_binding_revision=peer_binding.revision,
            mission_grant_revision=mission_grant.revision,
            authenticated_at=timestamp,
            expires_at=timestamp + self._default_ttl,
        )
        with self._lock:
            self._issued[id(principal)] = principal
        return principal

    def authenticate_peer(
        self,
        peer: PeerPrincipal,
        mission_id: str,
        api_key: str | SecretValue,
        *,
        subject_id: str,
        now: float | None = None,
        claimed_operator_id: str | None = None,
        claimed_role: str | OperatorRole | None = None,
        claimed_name: str | None = None,
    ) -> AuthenticatedControlPrincipal:
        """Compatibility spelling for the canonical authentication boundary."""

        return self.authenticate_control(
            api_key=api_key,
            peer=peer,
            mission_id=mission_id,
            subject_id=subject_id,
            now=now,
            claimed_operator_id=claimed_operator_id,
            claimed_role=claimed_role,
            claimed_name=claimed_name,
        )

    def authenticated_operator(
        self,
        api_key: str | SecretValue,
    ) -> AuthenticatedOperator:
        """Resolve stored operator identity without constructing a principal."""

        record = self._operators.authenticate(api_key)
        if record is None:
            raise PermissionError("operator API-key verification failed")
        peers = self._grants.allowed_peers(str(record["operator_id"]))
        return AuthenticatedOperator(
            operator_id=str(record["operator_id"]),
            subject_id=str(record["subject_id"]),
            name=str(record["name"]),
            role=OperatorRole(str(record["role"])),
            active=bool(record["active"]),
            authorization_revision=int(record["authorization_revision"]),
            allowed_peer_uids=tuple(sorted({binding.uid for binding in peers})),
            allowed_peer_gids=tuple(sorted({binding.gid for binding in peers})),
        )

    @staticmethod
    def is_expired(
        principal: AuthenticatedControlPrincipal,
        now: float | None = None,
    ) -> bool:
        timestamp = time.time() if now is None else float(now)
        return timestamp >= principal.expires_at

    def is_current_principal(
        self,
        principal: AuthenticatedControlPrincipal,
        now: float | None = None,
    ) -> bool:
        if not isinstance(principal, AuthenticatedControlPrincipal):
            return False
        with self._lock:
            if self._issued.get(id(principal)) is not principal:
                return False
        if self.is_expired(principal, now):
            with self._lock:
                self._issued.pop(id(principal), None)
            return False
        operator = self._operators.get_operator(principal.operator_id, active_only=True)
        if operator is None:
            return False
        if str(operator["subject_id"]) != principal.subject_id:
            return False
        if str(operator["role"]) != principal.role.value:
            return False
        if int(operator["authorization_revision"]) != principal.operator_revision:
            return False
        peer_binding = self._grants.resolve_peer_binding(
            principal.operator_id,
            uid=principal.peer.uid,
            gid=principal.peer.gid,
        )
        if peer_binding is None or peer_binding.revision != principal.peer_binding_revision:
            return False
        mission_grant = self._grants.resolve_mission_grant(
            principal.operator_id,
            subject_id=principal.subject_id,
            mission_id=principal.mission_id,
        )
        return mission_grant is not None and mission_grant.revision == principal.mission_grant_revision

    def require_current_principal(
        self,
        principal: AuthenticatedControlPrincipal,
        now: float | None = None,
    ) -> None:
        if not self.is_current_principal(principal, now):
            raise PermissionError("control principal is expired, revoked, or stale")

    def check_permission(
        self,
        principal: AuthenticatedControlPrincipal,
        action: C2ControlAction | str,
        now: float | None = None,
    ) -> bool:
        if not self.is_current_principal(principal, now):
            return False
        action_value = action.value if isinstance(action, C2ControlAction) else str(action)
        if action_value not in _KNOWN_ACTIONS:
            return False
        if principal.role is OperatorRole.ADMIN:
            return True
        if principal.role is OperatorRole.READONLY:
            return action_value in _HEALTH_ACTIONS | _READ_ACTIONS
        if principal.role is OperatorRole.OPERATOR:
            return action_value not in _ADMIN_ONLY_ACTIONS
        return False


__all__ = [
    "AuthenticatedControlPrincipal",
    "AuthenticatedOperator",
    "AuthorityFence",
    "ControlAuthenticatorV1",
    "GrantReader",
    "OperatorReader",
    "OperatorRole",
    "VerifiedMutationAuthority",
]
