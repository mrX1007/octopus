"""Mission, ACL, ACK and retention semantics for C2 result control."""

from __future__ import annotations

from dataclasses import replace

import pytest

from core.c2.agent_task_models import AgentTaskDeliveryAckV12
from core.c2.control_auth import AuthenticatedControlPrincipal, OperatorRole
from core.c2.control_peer import PeerPrincipal
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
NOW = 1_000.0


def _principal(
    *,
    subject_id: str = "subject:owner",
    mission_id: str = "mission:one",
    role: OperatorRole = OperatorRole.ADMIN,
    expires_at: float = NOW + 100.0,
) -> AuthenticatedControlPrincipal:
    return AuthenticatedControlPrincipal(
        operator_id=f"operator:{subject_id}",
        subject_id=subject_id,
        role=role,
        peer=PeerPrincipal(pid=10, uid=1000, gid=1000),
        mission_id=mission_id,
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        authenticated_at=NOW - 100.0,
        expires_at=expires_at,
    )


def _agent(
    agent_ref: str = "agent:one", mission_id: str = "mission:one"
) -> AgentSummaryV1:
    return AgentSummaryV1(
        agent_ref=agent_ref,
        mission_id=mission_id,
        revision=1,
        state="active",
        hostname=f"{agent_ref}-host",
        os=C2TargetOS.LINUX,
        arch=C2TargetArch.AMD64,
        last_seen=NOW - 1.0,
    )


def _result(
    result_ref: str,
    *,
    agent_ref: str = "agent:one",
    mission_id: str = "mission:one",
    completed_at: float = NOW - 10.0,
    status: ResultRecordStatusV1 = ResultRecordStatusV1.SUCCEEDED,
) -> ResultSummaryV1:
    return ResultSummaryV1(
        result_ref=result_ref,
        task_ref=f"task:{result_ref}",
        agent_ref=agent_ref,
        mission_id=mission_id,
        revision=1,
        status=status,
        result_schema_id="schema:c2-result:1",
        completed_at=completed_at,
        acknowledged=False,
    )


def _service() -> C2ResultServiceV1:
    return C2ResultServiceV1(clock=lambda: NOW)


def test_readonly_cannot_list_agents_from_other_mission() -> None:
    service = _service()
    service.register_agent(_agent(), owner_subject_id="subject:reader")
    reader = _principal(
        subject_id="subject:reader",
        mission_id="mission:other",
        role=OperatorRole.READONLY,
    )

    with pytest.raises(PermissionError, match="not_authorized"):
        service.list_agents(reader, "mission:one", cursor=None, limit=10)


def test_agent_listing_requires_explicit_resource_acl() -> None:
    service = _service()
    service.register_agent(_agent("agent:owned"), owner_subject_id="subject:owner")
    service.register_agent(
        _agent("agent:shared"),
        owner_subject_id="subject:other",
        permitted_subject_ids=("subject:owner",),
    )
    service.register_agent(
        _agent("agent:private"), owner_subject_id="subject:other"
    )
    service.register_agent(
        _agent("agent:legacy"), owner_subject_id=None
    )

    page = service.list_agents(
        _principal(), "mission:one", cursor=None, limit=10
    )
    assert tuple(item.agent_ref for item in page.items) == (
        "agent:owned",
        "agent:shared",
    )


def test_readonly_cannot_list_results_from_other_mission() -> None:
    service = _service()
    service.register_agent(_agent(), owner_subject_id="subject:reader")
    service.store_result(_result("result:one"), owner_subject_id="subject:reader")
    reader = _principal(
        subject_id="subject:reader",
        mission_id="mission:other",
        role=OperatorRole.READONLY,
    )

    with pytest.raises(PermissionError, match="not_authorized"):
        service.list_results(
            reader,
            "mission:one",
            "agent:one",
            cursor=None,
            limit=10,
        )


def test_agent_id_does_not_bypass_mission_acl() -> None:
    service = _service()
    service.register_agent(_agent(), owner_subject_id="subject:reader")
    service.store_result(_result("result:one"), owner_subject_id="subject:reader")
    other_mission_reader = _principal(
        subject_id="subject:reader",
        mission_id="mission:other",
        role=OperatorRole.READONLY,
    )

    page = service.list_results(
        other_mission_reader,
        "mission:other",
        "agent:one",
        cursor=None,
        limit=10,
    )
    assert page.items == ()


def test_list_results_requires_agent_and_result_resource_acl() -> None:
    service = _service()
    service.register_agent(
        _agent(),
        owner_subject_id="subject:other",
        permitted_subject_ids=("subject:reader",),
    )
    service.store_result(
        _result("result:private"), owner_subject_id="subject:other"
    )
    service.store_result(
        _result("result:shared"),
        owner_subject_id="subject:other",
        permitted_subject_ids=("subject:reader",),
    )
    reader = _principal(subject_id="subject:reader", role=OperatorRole.READONLY)

    page = service.list_results(
        reader, "mission:one", "agent:one", cursor=None, limit=10
    )
    assert tuple(item.result_ref for item in page.items) == ("result:shared",)


def test_list_results_does_not_delete_or_mutate() -> None:
    service = _service()
    service.register_agent(_agent(), owner_subject_id="subject:owner")
    original = _result("result:one")
    service.store_result(original, owner_subject_id="subject:owner")
    principal = _principal(role=OperatorRole.READONLY)

    first = service.list_results(
        principal, "mission:one", "agent:one", cursor=None, limit=10
    )
    second = service.list_results(
        principal, "mission:one", "agent:one", cursor=None, limit=10
    )
    assert first == second
    assert first.items == (original,)


def test_ack_results_is_explicit_mutation_and_retains_result_row() -> None:
    service = _service()
    service.register_agent(_agent(), owner_subject_id="subject:owner")
    original = _result("result:one")
    service.store_result(original, owner_subject_id="subject:owner")
    principal = _principal(role=OperatorRole.OPERATOR)
    request = ResultAckRequestV1(
        mission_id="mission:one",
        agent_ref="agent:one",
        selections=(
            ResultAckSelectionV1(result_ref="result:one", expected_revision=1),
        ),
    )

    batch = service.ack_results(principal, request)
    assert len(batch.acknowledgements) == 1
    assert batch.rejected_refs == ()
    assert batch.acknowledgements[0].acknowledged_by_subject_id == "subject:owner"

    page = service.list_results(
        principal, "mission:one", "agent:one", cursor=None, limit=10
    )
    assert page.items == (replace(original, acknowledged=True),)

    replay = service.ack_results(principal, request)
    assert replay == batch


def test_ack_results_rejects_delivery_ack_payload_and_revision_mismatch() -> None:
    service = _service()
    service.register_agent(_agent(), owner_subject_id="subject:owner")
    service.store_result(_result("result:one"), owner_subject_id="subject:owner")
    principal = _principal(role=OperatorRole.OPERATOR)
    delivery_ack = AgentTaskDeliveryAckV12(
        schema_version="12.0",
        task_id="task:one",
        delivery_attempt=1,
        received_at=NOW,
    )

    with pytest.raises(TypeError, match="ResultAckRequestV1"):
        service.ack_results(principal, delivery_ack)  # type: ignore[arg-type]

    rejected = service.ack_results(
        principal,
        ResultAckRequestV1(
            mission_id="mission:one",
            agent_ref="agent:one",
            selections=(
                ResultAckSelectionV1(
                    result_ref="result:one", expected_revision=2
                ),
            ),
        ),
    )
    assert rejected.acknowledgements == ()
    assert rejected.rejected_refs == ("result:one",)


def test_ack_results_denies_readonly_and_expired_principals() -> None:
    service = _service()
    service.register_agent(_agent(), owner_subject_id="subject:owner")
    service.store_result(_result("result:one"), owner_subject_id="subject:owner")
    request = ResultAckRequestV1(
        mission_id="mission:one",
        agent_ref="agent:one",
        selections=(
            ResultAckSelectionV1(result_ref="result:one", expected_revision=1),
        ),
    )

    with pytest.raises(PermissionError, match="not_authorized"):
        service.ack_results(_principal(role=OperatorRole.READONLY), request)
    with pytest.raises(PermissionError, match="not_authorized"):
        service.ack_results(
            _principal(role=OperatorRole.ADMIN, expires_at=NOW), request
        )


def test_purge_results_bounded_admin_only() -> None:
    service = _service()
    service.register_agent(_agent(), owner_subject_id="subject:owner")
    for index, completed_at in enumerate((100.0, 200.0, 300.0), start=1):
        service.store_result(
            _result(f"result:{index}", completed_at=completed_at),
            owner_subject_id="subject:owner",
        )
    request = ResultAckRequestV1(
        mission_id="mission:one",
        agent_ref="agent:one",
        selections=tuple(
            ResultAckSelectionV1(result_ref=f"result:{index}", expected_revision=1)
            for index in range(1, 4)
        ),
    )
    admin = _principal()
    service.ack_results(admin, request)

    with pytest.raises(PermissionError, match="not_authorized"):
        service.purge_results(
            _principal(role=OperatorRole.OPERATOR),
            "mission:one",
            before=500.0,
            limit=1,
        )

    first = service.purge_results(
        admin, "mission:one", before=500.0, limit=1
    )
    assert first.purged_count == 1
    assert first.next_cursor == "result:2"
    remaining = service.list_results(
        admin, "mission:one", "agent:one", cursor=None, limit=10
    )
    assert tuple(item.result_ref for item in remaining.items) == (
        "result:2",
        "result:3",
    )

    second = service.purge_results(
        admin, "mission:one", before=500.0, limit=100
    )
    assert second.purged_count == 2
    assert second.next_cursor is None


def test_unacknowledged_and_legacy_unassigned_rows_are_not_purged_or_visible() -> None:
    service = _service()
    service.register_agent(_agent(), owner_subject_id="subject:owner")
    service.store_result(
        _result("result:unacknowledged", completed_at=100.0),
        owner_subject_id="subject:owner",
    )
    service.store_result(
        _result(
            "result:legacy",
            completed_at=100.0,
            status=ResultRecordStatusV1.LEGACY_UNASSIGNED,
        ),
        owner_subject_id="subject:owner",
    )
    admin = _principal()

    page = service.list_results(
        admin, "mission:one", "agent:one", cursor=None, limit=10
    )
    assert tuple(item.result_ref for item in page.items) == (
        "result:unacknowledged",
    )
    purged = service.purge_results(
        admin, "mission:one", before=500.0, limit=100
    )
    assert purged.purged_count == 0


def test_page_and_purge_limits_are_strictly_bounded() -> None:
    service = _service()
    with pytest.raises(ValueError, match="between 1 and 100"):
        service.list_agents(_principal(), "mission:one", cursor=None, limit=101)
    with pytest.raises(ValueError, match="between 1 and 100"):
        service.purge_results(
            _principal(), "mission:one", before=NOW, limit=0
        )
