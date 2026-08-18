"""Unit tests for execution_commit_types.py."""

from __future__ import annotations

import pytest

from core.actions.execution_commit_types import (
    ExecutionCommitDecisionBindingV2,
    ExecutionCommitRecordV2,
    ExecutionCommitStateV2,
    canonical_execution_commit_decision_binding_digest,
)

pytestmark = pytest.mark.unit


def test_decision_binding_and_record_validations():
    # Effect binding mismatch
    with pytest.raises(ValueError, match="commit_effect_binding_fields_all_or_none"):
        ExecutionCommitDecisionBindingV2(
            no_return_admission_reference="ref://1",
            no_return_admission_revision=1,
            no_return_admission_digest="sha256:d",
            decision_identity_digest="sha256:id",
            external_effect_participant_id="p1",
            external_effect_registration_digest=None,  # mismatch
            binding_digest="sha256:b",
        )

    dummy_binding = object.__new__(ExecutionCommitDecisionBindingV2)
    object.__setattr__(dummy_binding, "no_return_admission_reference", "ref://1")
    object.__setattr__(dummy_binding, "no_return_admission_revision", 1)
    object.__setattr__(dummy_binding, "no_return_admission_digest", "sha256:d")
    object.__setattr__(dummy_binding, "decision_identity_digest", "sha256:id")
    object.__setattr__(dummy_binding, "external_effect_participant_id", None)
    object.__setattr__(dummy_binding, "external_effect_registration_digest", None)
    valid_digest = canonical_execution_commit_decision_binding_digest(dummy_binding)

    valid_binding = ExecutionCommitDecisionBindingV2(
        no_return_admission_reference="ref://1",
        no_return_admission_revision=1,
        no_return_admission_digest="sha256:d",
        decision_identity_digest="sha256:id",
        external_effect_participant_id=None,
        external_effect_registration_digest=None,
        binding_digest=valid_digest,
    )

    # Digest mismatch
    with pytest.raises(ValueError, match="commit_decision_binding_digest_mismatch"):
        ExecutionCommitDecisionBindingV2(
            no_return_admission_reference="ref://1",
            no_return_admission_revision=1,
            no_return_admission_digest="sha256:d",
            decision_identity_digest="sha256:id",
            external_effect_participant_id=None,
            external_effect_registration_digest=None,
            binding_digest="sha256:WRONG",
        )

    # Record committed path without binding
    with pytest.raises(ValueError, match="commit_state_requires_admission_binding"):
        ExecutionCommitRecordV2(
            transaction_id="tx-1",
            revision=1,
            state=ExecutionCommitStateV2.COMMITTED,
            external_effect_fenced=True,
            decision_digest=None,
            commit_decision_binding=None,
            updated_at=100.0,
        )

    # Record committed path with digest mismatch
    with pytest.raises(ValueError, match="commit_decision_digest_mismatch"):
        ExecutionCommitRecordV2(
            transaction_id="tx-1",
            revision=1,
            state=ExecutionCommitStateV2.COMMITTED,
            external_effect_fenced=True,
            decision_digest="sha256:WRONG",
            commit_decision_binding=valid_binding,
            updated_at=100.0,
        )

    # Record open state with binding
    with pytest.raises(ValueError, match="precommit_or_abort_state_forbids_decision_binding"):
        ExecutionCommitRecordV2(
            transaction_id="tx-1",
            revision=1,
            state=ExecutionCommitStateV2.OPEN,
            external_effect_fenced=False,
            decision_digest=valid_digest,
            commit_decision_binding=valid_binding,
            updated_at=100.0,
        )

    # Record in doubt with only digest
    with pytest.raises(ValueError, match="in_doubt_decision_fields_all_or_none"):
        ExecutionCommitRecordV2(
            transaction_id="tx-1",
            revision=1,
            state=ExecutionCommitStateV2.IN_DOUBT,
            external_effect_fenced=False,
            decision_digest="sha256:d",
            commit_decision_binding=None,
            updated_at=100.0,
        )
