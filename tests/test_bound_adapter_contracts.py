"""Tests for AdapterApiVersion and TypedActionAdapterV2 protocol."""

from __future__ import annotations

import pytest

from core.actions.bound_adapters import (
    BoundProviderCheckContext,
    BoundProviderInvocationContext,
    BoundProviderVerificationContext,
    TypedActionAdapterV2,
)
from core.actions.input_contracts import PayloadKeyingInputV2, PayloadKeyingProfileId
from core.actions.provider_results import (
    OperationProviderResult,
    ProviderOutcomeV2,
    ProviderProvenanceV2,
    ProviderResultFoundationV2,
    ProviderResultHeaderV2,
)
from core.actions.request_v2 import ActionRequestV2

pytestmark = pytest.mark.unit


class DummyV2Adapter:
    action_id = "plugin:payload_keying"
    adapter_api_version = 2

    def check_bound(self, context: BoundProviderCheckContext) -> bool:
        return True

    def execute_bound(self, context: BoundProviderInvocationContext) -> ProviderResultFoundationV2:
        return OperationProviderResult(
            header=ProviderResultHeaderV2(
                schema_version="2.0",
                provider_id="provider:test",
                outcome=ProviderOutcomeV2.SUCCEEDED,
                reason_codes=(),
                duration_ms=0,
                provenance=ProviderProvenanceV2(
                    implementation_id="provider:test",
                    implementation_version="1.0.0",
                    request_digest="sha256:request",
                    started_at=1.0,
                    completed_at=1.0,
                ),
            ),
            observations=(),
        )

    def verify_bound(self, context: BoundProviderVerificationContext) -> bool:
        return True


def test_typed_action_adapter_v2_protocol() -> None:
    adapter = DummyV2Adapter()
    assert isinstance(adapter, TypedActionAdapterV2)

    req = ActionRequestV2(
        request_id="r-1",
        action_id="plugin:payload_keying",
        mission_ref="m-1",
        approval_ref=None,
        precondition_fact_refs=(),
        idempotency_key=None,
        typed_input=PayloadKeyingInputV2("artifact://payload/1", PayloadKeyingProfileId.HOSTNAME, None),
    )
    ctx = BoundProviderInvocationContext(req, ())
    res = adapter.execute_bound(ctx)
    assert isinstance(res, OperationProviderResult)
    assert res.header.outcome is ProviderOutcomeV2.SUCCEEDED
