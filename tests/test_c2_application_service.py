"""C2ApplicationService is the authenticated administrative result boundary."""

from __future__ import annotations

import pytest

from core.c2.application_service import C2ApplicationService
from core.c2.control_auth import AuthenticatedControlPrincipal, OperatorRole
from core.c2.control_peer import PeerPrincipal
from core.c2.control_rbac import ControlRBACPolicy
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.c2.result_models import (
    AgentSummaryV1,
    ResultAckRequestV1,
    ResultAckSelectionV1,
    ResultRecordStatusV1,
    ResultSummaryV1,
)
from core.c2.result_service import C2ResultServiceV1

pytestmark = pytest.mark.unit
NOW = 2_000.0


def _principal(role: OperatorRole = OperatorRole.ADMIN) -> AuthenticatedControlPrincipal:
    return AuthenticatedControlPrincipal(
        operator_id="operator:1",
        subject_id="subject:1",
        role=role,
        peer=PeerPrincipal(pid=20, uid=1000, gid=1000),
        mission_id="mission:1",
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        authenticated_at=NOW - 1.0,
        expires_at=NOW + 100.0,
    )


def _application() -> C2ApplicationService:
    policy = ControlRBACPolicy(clock=lambda: NOW)
    results = C2ResultServiceV1(clock=lambda: NOW, policy=policy)
    results.register_agent(
        AgentSummaryV1(
            agent_ref="agent:1",
            mission_id="mission:1",
            revision=1,
            state="active",
            hostname="host-1",
            os=C2TargetOS.LINUX,
            arch=C2TargetArch.AMD64,
            last_seen=NOW - 1.0,
        ),
        owner_subject_id="subject:1",
    )
    results.store_result(
        ResultSummaryV1(
            result_ref="result:1",
            task_ref="task:1",
            agent_ref="agent:1",
            mission_id="mission:1",
            revision=1,
            status=ResultRecordStatusV1.SUCCEEDED,
            result_schema_id="schema:result:1",
            completed_at=NOW - 100.0,
            acknowledged=False,
        ),
        owner_subject_id="subject:1",
    )
    return C2ApplicationService(results, policy=policy)


def test_admin_ack_purge_use_application_service() -> None:
    application = _application()
    principal = _principal()
    request = ResultAckRequestV1(
        mission_id="mission:1",
        agent_ref="agent:1",
        selections=(
            ResultAckSelectionV1(result_ref="result:1", expected_revision=1),
        ),
    )

    batch = application.ack_results(principal, request)
    assert tuple(record.result_ref for record in batch.acknowledgements) == (
        "result:1",
    )
    purged = application.purge_results(
        principal,
        "mission:1",
        before=NOW,
        limit=1,
    )
    assert purged.purged_count == 1


def test_application_service_reads_are_mission_scoped() -> None:
    application = _application()
    readonly = _principal(OperatorRole.READONLY)

    agents = application.list_agents(
        readonly, "mission:1", cursor=None, limit=10
    )
    results = application.list_results(
        readonly,
        "mission:1",
        "agent:1",
        cursor=None,
        limit=10,
    )
    assert tuple(item.agent_ref for item in agents.items) == ("agent:1",)
    assert tuple(item.result_ref for item in results.items) == ("result:1",)

    with pytest.raises(PermissionError, match="not_authorized"):
        application.list_results(
            readonly,
            "mission:other",
            "agent:1",
            cursor=None,
            limit=10,
        )


def test_application_service_cannot_queue_task_or_create_channel() -> None:
    application = _application()
    forbidden_operational_surface = (
        "queue_task",
        "queue_typed_task",
        "issue_enrollment",
        "reserve_enrollment_for_build",
        "create_channel",
        "create_dns_channel",
        "deploy",
        "cleanup",
        "cancel_task",
        "prepare_c2_resource",
        "commit_c2_resource",
        "finalize_c2_resource_visibility",
        "abort_c2_resource",
        "query_c2_resource",
        "execute_action",
        "send_request",
    )
    for method_name in forbidden_operational_surface:
        assert not hasattr(application, method_name)


def test_readonly_cannot_use_application_ack_or_purge() -> None:
    application = _application()
    readonly = _principal(OperatorRole.READONLY)
    request = ResultAckRequestV1(
        mission_id="mission:1",
        agent_ref="agent:1",
        selections=(
            ResultAckSelectionV1(result_ref="result:1", expected_revision=1),
        ),
    )

    with pytest.raises(PermissionError, match="not_authorized"):
        application.ack_results(readonly, request)
    with pytest.raises(PermissionError, match="not_authorized"):
        application.purge_results(
            readonly, "mission:1", before=NOW, limit=1
        )
