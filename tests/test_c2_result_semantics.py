"""Exact PR-14 control page/result DTO contracts."""

from __future__ import annotations

from dataclasses import fields

import pytest

from core.c2 import result_models
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.c2.result_models import (
    AgentPageV1,
    AgentSummaryV1,
    PurgeResultV1,
    ResultAckBatchV1,
    ResultPageV1,
    ResultRecordStatusV1,
    ResultSummaryV1,
)

pytestmark = pytest.mark.unit


def _field_names(model: type[object]) -> tuple[str, ...]:
    return tuple(field.name for field in fields(model))


def test_c2_control_page_and_result_dtos_exact_fields() -> None:
    assert _field_names(AgentSummaryV1) == (
        "agent_ref",
        "mission_id",
        "revision",
        "state",
        "hostname",
        "os",
        "arch",
        "last_seen",
    )
    assert _field_names(AgentPageV1) == ("items", "next_cursor")
    assert _field_names(ResultSummaryV1) == (
        "result_ref",
        "task_ref",
        "agent_ref",
        "mission_id",
        "revision",
        "status",
        "result_schema_id",
        "completed_at",
        "acknowledged",
    )
    assert _field_names(ResultPageV1) == ("items", "next_cursor")
    assert _field_names(ResultAckBatchV1) == (
        "acknowledgements",
        "rejected_refs",
    )
    assert _field_names(PurgeResultV1) == ("purged_count", "next_cursor")


def test_no_bare_agent_page_result_page_purge_result_aliases() -> None:
    for forbidden_name in ("AgentPage", "ResultPage", "PurgeResult"):
        assert not hasattr(result_models, forbidden_name)


def test_result_record_status_is_closed_and_includes_legacy_unassigned() -> None:
    assert tuple(status.value for status in ResultRecordStatusV1) == (
        "succeeded",
        "failed",
        "partial",
        "cancelled",
        "timed_out",
        "unsupported_operation",
        "invalid_payload",
        "legacy_unassigned",
    )


def test_page_dtos_accept_only_exact_summary_variants() -> None:
    agent = AgentSummaryV1(
        agent_ref="agent:1",
        mission_id="mission:1",
        revision=1,
        state="active",
        hostname="host-1",
        os=C2TargetOS.LINUX,
        arch=C2TargetArch.AMD64,
        last_seen=10.0,
    )
    result = ResultSummaryV1(
        result_ref="result:1",
        task_ref="task:1",
        agent_ref=agent.agent_ref,
        mission_id=agent.mission_id,
        revision=1,
        status=ResultRecordStatusV1.SUCCEEDED,
        result_schema_id="schema:result:1",
        completed_at=11.0,
        acknowledged=False,
    )
    assert AgentPageV1(items=(agent,), next_cursor=None).items == (agent,)
    assert ResultPageV1(items=(result,), next_cursor=None).items == (result,)

    with pytest.raises(ValueError):
        AgentPageV1(items=(object(),), next_cursor=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ResultPageV1(items=(object(),), next_cursor=None)  # type: ignore[arg-type]
