"""Operator result ACK models are separate from agent delivery receipts."""

from __future__ import annotations

from dataclasses import fields

import pytest

from core.c2.agent_task_models import AgentTaskDeliveryAckV12
from core.c2.result_models import (
    ResultAckBatchV1,
    ResultAcknowledgementRecordV1,
    ResultAckRequestV1,
    ResultAckSelectionV1,
)

pytestmark = pytest.mark.unit


def _field_names(model: type[object]) -> tuple[str, ...]:
    return tuple(field.name for field in fields(model))


def test_result_ack_models_have_exact_fields() -> None:
    assert _field_names(ResultAckSelectionV1) == (
        "result_ref",
        "expected_revision",
    )
    assert _field_names(ResultAckRequestV1) == (
        "mission_id",
        "agent_ref",
        "selections",
    )
    assert _field_names(ResultAcknowledgementRecordV1) == (
        "result_ref",
        "result_revision",
        "acknowledged_by_subject_id",
        "acknowledged_at",
        "acknowledgement_revision",
    )
    assert _field_names(ResultAckBatchV1) == (
        "acknowledgements",
        "rejected_refs",
    )


def test_result_ack_model_is_distinct_from_task_delivery_ack() -> None:
    delivery = AgentTaskDeliveryAckV12(
        schema_version="12.0",
        task_id="task:1",
        delivery_attempt=1,
        received_at=10.0,
    )
    selection = ResultAckSelectionV1(result_ref="result:1", expected_revision=1)
    request = ResultAckRequestV1(
        mission_id="mission:1",
        agent_ref="agent:1",
        selections=(selection,),
    )
    assert type(delivery) is not type(request)
    assert not hasattr(request, "task_id")
    assert not hasattr(request, "delivery_attempt")


def test_ack_results_requires_result_ref_revision() -> None:
    with pytest.raises(TypeError):
        ResultAckSelectionV1(result_ref="result:1")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        ResultAckSelectionV1(result_ref="result:1", expected_revision=0)
    with pytest.raises(ValueError):
        ResultAckSelectionV1(result_ref="", expected_revision=1)


def test_ack_batch_size_is_bounded() -> None:
    selections = tuple(ResultAckSelectionV1(result_ref=f"result:{index}", expected_revision=1) for index in range(101))
    with pytest.raises(ValueError, match="bounded batch"):
        ResultAckRequestV1(
            mission_id="mission:1",
            agent_ref="agent:1",
            selections=selections,
        )
