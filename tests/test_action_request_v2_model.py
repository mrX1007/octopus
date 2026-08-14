"""Canonical post-decoding V2 request model tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields

import pytest

from core.actions.input_contracts import PayloadKeyingInputV2, PayloadKeyingProfileId
from core.actions.request_v2 import ActionRequestV2

pytestmark = pytest.mark.unit


def _request() -> ActionRequestV2:
    return ActionRequestV2(
        request_id="request-1",
        action_id="plugin:payload_keying",
        mission_ref="mission://1",
        approval_ref="approval://1",
        precondition_fact_refs=("fact://1",),
        idempotency_key=None,
        typed_input=PayloadKeyingInputV2(
            payload_ref="artifact://payload/1",
            profile_id=PayloadKeyingProfileId.HOSTNAME,
            target_metadata_ref=None,
        ),
    )


def test_action_request_v2_exact_fields() -> None:
    assert tuple(item.name for item in fields(ActionRequestV2)) == (
        "request_id",
        "action_id",
        "mission_ref",
        "approval_ref",
        "precondition_fact_refs",
        "idempotency_key",
        "typed_input",
        "schema_version",
    )


def test_action_request_v2_is_frozen() -> None:
    request = _request()
    with pytest.raises(FrozenInstanceError):
        request.request_id = "forged"  # type: ignore[misc]


def test_action_request_v2_contains_no_authority_or_runtime_state() -> None:
    field_names = {item.name for item in fields(ActionRequestV2)}
    assert field_names.isdisjoint(
        {
            "principal_ref",
            "subject_id",
            "role",
            "ingress_session_ref",
            "budget",
            "lineage",
            "command",
            "parameters",
            "targets",
        }
    )
