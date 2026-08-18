"""Closed, fail-closed RBAC policy for authenticated C2 control principals."""

from __future__ import annotations

import math
import time
from collections.abc import Callable

from core.c2.control_auth import AuthenticatedControlPrincipal, OperatorRole
from core.c2.control_commands import C2ControlAction
from core.c2.control_peer import PeerPrincipal

_ADMIN_ONLY_ACTIONS = frozenset(
    {
        C2ControlAction.PURGE_RESULTS,
        C2ControlAction.MANAGE_OPERATORS_LIST,
        C2ControlAction.MANAGE_OPERATORS_CREATE,
        C2ControlAction.MANAGE_OPERATORS_DEACTIVATE,
        C2ControlAction.MANAGE_OPERATORS_ROTATE,
        C2ControlAction.SYNC_OPERATOR_PEER_BINDINGS,
        C2ControlAction.REVOKE_OPERATOR_PEER_BINDING,
        C2ControlAction.SYNC_OPERATOR_MISSION_GRANTS,
        C2ControlAction.REVOKE_OPERATOR_MISSION_GRANT,
    }
)

_READONLY_ACTIONS = frozenset(
    {
        C2ControlAction.PING,
        C2ControlAction.VERSION,
        C2ControlAction.READINESS,
        C2ControlAction.LIST_AGENTS,
        C2ControlAction.LIST_RESULTS,
    }
)


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _bounded_identity(value: object) -> bool:
    return type(value) is str and 0 < len(value) <= 512


class ControlRBACPolicy:
    """Evaluate the exact PR-14 action matrix against a bound principal.

    This policy validates authentication freshness and mission binding as well
    as the role matrix. Resource ACL checks remain the responsibility of the
    service that owns the referenced resource.
    """

    __slots__ = ("_clock",)

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock

    def evaluate(
        self,
        principal: AuthenticatedControlPrincipal,
        action: C2ControlAction | str,
        resource_ref: str | None = None,
        *,
        mission_id: str | None = None,
        now: float | None = None,
    ) -> bool:
        """Return ``True`` only for an exact, fresh and mission-bound grant."""

        if type(principal) is not AuthenticatedControlPrincipal:
            return False

        try:
            closed_action = (
                action if type(action) is C2ControlAction else C2ControlAction(action) if type(action) is str else None
            )
        except ValueError:
            return False
        if closed_action is None:
            return False

        checked_at = self._clock() if now is None else now
        if type(checked_at) not in (int, float) or not math.isfinite(float(checked_at)):
            return False
        if not self._valid_principal(principal, float(checked_at)):
            return False

        if mission_id is not None and (not _bounded_identity(mission_id) or mission_id != principal.mission_id):
            return False
        if resource_ref is not None and not _bounded_identity(resource_ref):
            return False

        if principal.role is OperatorRole.ADMIN:
            return True
        if principal.role is OperatorRole.OPERATOR:
            return closed_action not in _ADMIN_ONLY_ACTIONS
        if principal.role is OperatorRole.READONLY:
            return closed_action in _READONLY_ACTIONS
        return False

    def require(
        self,
        principal: AuthenticatedControlPrincipal,
        action: C2ControlAction | str,
        resource_ref: str | None = None,
        *,
        mission_id: str | None = None,
        now: float | None = None,
    ) -> None:
        """Raise one bounded denial for all authentication/RBAC failures."""

        if not self.evaluate(
            principal,
            action,
            resource_ref,
            mission_id=mission_id,
            now=now,
        ):
            raise PermissionError("not_authorized")

    @staticmethod
    def _valid_principal(principal: AuthenticatedControlPrincipal, checked_at: float) -> bool:
        peer = principal.peer
        if type(peer) is not PeerPrincipal:
            return False
        if not all(
            _positive_int(revision)
            for revision in (
                principal.operator_revision,
                principal.peer_binding_revision,
                principal.mission_grant_revision,
            )
        ):
            return False
        if not all(
            _bounded_identity(identity)
            for identity in (
                principal.operator_id,
                principal.subject_id,
                principal.mission_id,
            )
        ):
            return False
        if type(principal.role) is not OperatorRole:
            return False
        if any(type(value) is not int or value < 0 for value in (peer.pid, peer.uid, peer.gid)):
            return False
        if type(principal.authenticated_at) not in (int, float) or type(principal.expires_at) not in (int, float):
            return False
        authenticated_at = float(principal.authenticated_at)
        expires_at = float(principal.expires_at)
        if not math.isfinite(authenticated_at) or not math.isfinite(expires_at):
            return False
        return authenticated_at <= checked_at < expires_at


__all__ = ["ControlRBACPolicy"]
