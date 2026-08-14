"""Authenticated application boundary for administrative C2 result control.

Operational actions are intentionally absent. They must enter through the typed
``ActionExecutor`` lifecycle and cannot use this service as a control-plane
bypass.
"""

from __future__ import annotations

from core.c2.control_auth import AuthenticatedControlPrincipal
from core.c2.control_commands import C2ControlActionV1
from core.c2.control_rbac import ControlRBACPolicy
from core.c2.result_models import (
    AgentPageV1,
    PurgeResultV1,
    ResultAckBatchV1,
    ResultAckRequestV1,
    ResultPageV1,
)
from core.c2.result_service import C2ControlResultServiceV1


class C2ApplicationService:
    """Expose only mission-bound result reads and administrative mutations."""

    __slots__ = ("_policy", "_result_service")

    def __init__(
        self,
        result_service: C2ControlResultServiceV1,
        *,
        policy: ControlRBACPolicy | None = None,
    ) -> None:
        if not isinstance(result_service, C2ControlResultServiceV1):
            raise TypeError("result_service must implement C2ControlResultServiceV1")
        self._result_service = result_service
        self._policy = policy or ControlRBACPolicy()

    def list_agents(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        *,
        cursor: str | None,
        limit: int,
    ) -> AgentPageV1:
        self._policy.require(
            principal,
            C2ControlActionV1.LIST_AGENTS,
            mission_id=mission_id,
        )
        return self._result_service.list_agents(
            principal,
            mission_id,
            cursor=cursor,
            limit=limit,
        )

    def list_results(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        agent_ref: str,
        *,
        cursor: str | None,
        limit: int,
    ) -> ResultPageV1:
        self._policy.require(
            principal,
            C2ControlActionV1.LIST_RESULTS,
            agent_ref,
            mission_id=mission_id,
        )
        return self._result_service.list_results(
            principal,
            mission_id,
            agent_ref,
            cursor=cursor,
            limit=limit,
        )

    def ack_results(
        self,
        principal: AuthenticatedControlPrincipal,
        request: ResultAckRequestV1,
    ) -> ResultAckBatchV1:
        if type(request) is not ResultAckRequestV1:
            raise TypeError("request must be ResultAckRequestV1")
        self._policy.require(
            principal,
            C2ControlActionV1.ACK_RESULTS,
            request.agent_ref,
            mission_id=request.mission_id,
        )
        return self._result_service.ack_results(principal, request)

    def purge_results(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        *,
        before: float,
        limit: int,
    ) -> PurgeResultV1:
        self._policy.require(
            principal,
            C2ControlActionV1.PURGE_RESULTS,
            mission_id=mission_id,
        )
        return self._result_service.purge_results(
            principal,
            mission_id,
            before=before,
            limit=limit,
        )


__all__ = ["C2ApplicationService"]
