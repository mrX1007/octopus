"""Fail-closed construction and fencing of C2 control principals."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum

from core.c2.control_commands import C2ControlActionV1
from core.c2.control_peer import PeerPrincipal
from core.c2.grant_service import GrantService
from core.c2.operators import OperatorManager
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
_KNOWN_ACTIONS = {action.value for action in C2ControlActionV1}


class ControlAuthenticatorV1:
    """Authenticate API key, OS peer, subject, mission, and revisions.

    Neither an operator identifier nor a role supplied by a request is accepted
    as authority. The verified API key selects the persistent operator record.
    """

    def __init__(
        self,
        operators: OperatorManager,
        grants: GrantService,
        *,
        default_ttl_seconds: float = 300.0,
    ) -> None:
        if default_ttl_seconds <= 0:
            raise ValueError("principal TTL must be positive")
        if operators.db_path != grants.db_path:
            raise ValueError("operator and grant stores must use the same database")
        self._operators = operators
        self._grants = grants
        self._default_ttl = float(default_ttl_seconds)
        self._issued: dict[int, AuthenticatedControlPrincipal] = {}
        self._lock = threading.RLock()
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
        return (
            mission_grant is not None
            and mission_grant.revision == principal.mission_grant_revision
        )

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
        action: C2ControlActionV1 | str,
        now: float | None = None,
    ) -> bool:
        if not self.is_current_principal(principal, now):
            return False
        action_value = action.value if isinstance(action, C2ControlActionV1) else str(action)
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
    "ControlAuthenticatorV1",
    "OperatorRole",
]
