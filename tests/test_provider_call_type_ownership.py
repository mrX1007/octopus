"""Tests for provider_call_types module ownership."""

import pytest

from core.actions.provider_call_types import ProviderCallPhaseV2, ProviderPhaseCallPlanV2


@pytest.mark.unit
def test_call_plan_digest():
    plan = ProviderPhaseCallPlanV2(
        execution_id="exec-1",
        action_id="test:act",
        phase=ProviderCallPhaseV2.EXECUTE,
        timeout_seconds=30.0,
        max_output_bytes=1024,
    )
    digest = plan.canonical_digest()
    assert digest.startswith("sha256:")
