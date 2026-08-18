"""Unit tests for cleanup_operation_context.py."""

from __future__ import annotations

import pytest

from core.actions.cleanup_operation_context import (
    CleanupRecoveryPolicyV2,
    CleanupRecoverySubjectV2,
    DefaultCleanupOperationAuthorityV2,
    canonical_cleanup_subject_digest,
)

pytestmark = pytest.mark.unit


def test_cleanup_operation_context_and_authority():
    subject = CleanupRecoverySubjectV2(
        owner_kind="session",
        owner_reference="sess://1",
        owner_revision=1,
        idempotency_key="key-1",
        subject_digest="",
    )
    digest = canonical_cleanup_subject_digest(subject)
    valid_subject = CleanupRecoverySubjectV2(
        owner_kind="session",
        owner_reference="sess://1",
        owner_revision=1,
        idempotency_key="key-1",
        subject_digest=digest,
    )

    policy = CleanupRecoveryPolicyV2(
        policy_id="pol-1",
        max_attempts=3,
        total_budget_ms=5000,
        per_attempt_deadline_ms=1000,
        policy_digest="sha256:d",
    )

    auth = DefaultCleanupOperationAuthorityV2(authority_revision=1)
    ctx = auth.issue_live(
        subject=valid_subject,
        operation_attempt_id="att-1",
        policy=policy,
    )
    assert ctx.operation_attempt_id == "att-1"

    rec_ctx = auth.issue_recovery(
        subject=valid_subject,
        operation_attempt_id="att-1",
        policy=policy,
    )
    assert rec_ctx.operation_attempt_id == "att-1"

    # Validate
    auth.validate(ctx, subject=valid_subject)

    # Validate mismatch
    diff_subject = CleanupRecoverySubjectV2(
        owner_kind="session",
        owner_reference="sess://2",
        owner_revision=1,
        idempotency_key="key-2",
        subject_digest="sha256:DIFFERENT",
    )
    with pytest.raises(ValueError, match="CleanupOperationContext subject_digest mismatch"):
        auth.validate(ctx, subject=diff_subject)
