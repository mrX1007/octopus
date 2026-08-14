"""Tests for cleanup operation context."""
import pytest
from core.actions.cleanup_operation_context import (
    CleanupOperationContextV2,
    ParticipantRetryPolicyV2,
)

@pytest.mark.unit
def test_cleanup_operation_context():
    ctx = CleanupOperationContextV2(
        operation_attempt_id="op-1",
        subject_digest="sha256:sub",
        authority_revision=1,
        issued_at_monotonic=10.0,
        absolute_deadline_monotonic=20.0,
        retry_policy=ParticipantRetryPolicyV2(),
        authority_digest="sha256:auth",
    )
    assert ctx.operation_attempt_id == "op-1"
