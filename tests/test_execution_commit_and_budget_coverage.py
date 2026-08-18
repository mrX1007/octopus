"""Comprehensive unit tests for execution budget, execution commit types, and execution commit participants."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from core.actions.cancellation import ExecutorCancellationController
from core.actions.execution_budget import (
    ExecutionBudget,
    ExecutionBudgetLeaseInvalidError,
    ExecutionLineage,
    InMemoryExecutionBudgetLeaseRegistryV2,
    OwnedExecutionBudgetAuthorityV2,
)
from core.actions.execution_commit_participants import (
    ExecutionResultStoreParticipant,
    ParticipantKindV2,
    ParticipantStateV2,
    ParticipantVisibilityModeV2,
)
from core.actions.execution_commit_types import (
    ExecutionCommitDecisionBindingV2,
    ExecutionCommitRecordV2,
    ExecutionCommitStateV2,
    canonical_execution_commit_decision_binding_digest,
)

pytestmark = pytest.mark.unit


def test_execution_budget_models():
    ctrl = ExecutorCancellationController("cancel-1")
    budget = ExecutionBudget(
        absolute_deadline_monotonic=time.monotonic() + 100.0,
        max_output_bytes=1024,
        max_child_depth=2,
        cancellation_token=ctrl.token,
    )
    assert budget.max_output_bytes == 1024

    with pytest.raises(ValueError, match="execution budget deadline must be finite"):
        ExecutionBudget(
            absolute_deadline_monotonic=float("inf"),
            max_output_bytes=1024,
            max_child_depth=2,
            cancellation_token=ctrl.token,
        )

    with pytest.raises(ValueError, match="execution budget output limit must be positive"):
        ExecutionBudget(
            absolute_deadline_monotonic=100.0,
            max_output_bytes=0,
            max_child_depth=2,
            cancellation_token=ctrl.token,
        )

    with pytest.raises(TypeError, match="non-serializable"):
        budget.__reduce__()


def test_execution_lineage():
    root = ExecutionLineage(
        root_execution_id="root-1",
        parent_execution_id=None,
        execution_graph_id="graph-1",
        child_depth=0,
    )
    assert root.child_depth == 0

    child = ExecutionLineage(
        root_execution_id="root-1",
        parent_execution_id="root-1",
        execution_graph_id="graph-1",
        child_depth=1,
    )
    assert child.parent_execution_id == "root-1"

    with pytest.raises(ValueError, match="root lineage cannot have a parent execution"):
        ExecutionLineage(
            root_execution_id="root-1",
            parent_execution_id="some-parent",
            execution_graph_id="graph-1",
            child_depth=0,
        )

    with pytest.raises(ValueError, match="child lineage requires a parent execution"):
        ExecutionLineage(
            root_execution_id="root-1",
            parent_execution_id=None,
            execution_graph_id="graph-1",
            child_depth=1,
        )


def test_in_memory_budget_lease_registry():
    reg = InMemoryExecutionBudgetLeaseRegistryV2()
    with pytest.raises(TypeError, match="only exact budget leases may be registered"):
        reg.register("not_a_lease")  # type: ignore

    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="unknown execution budget lease"):
        reg.require_current("nonexistent")


def test_execution_commit_decision_binding_and_record():
    dummy = object.__new__(ExecutionCommitDecisionBindingV2)
    object.__setattr__(dummy, "no_return_admission_reference", "nra://1")
    object.__setattr__(dummy, "no_return_admission_revision", 1)
    object.__setattr__(dummy, "no_return_admission_digest", "sha256:nra")
    object.__setattr__(dummy, "decision_identity_digest", "sha256:dec")
    object.__setattr__(dummy, "external_effect_participant_id", "eff-1")
    object.__setattr__(dummy, "external_effect_registration_digest", "sha256:eff")
    object.__setattr__(dummy, "binding_digest", "")
    b_digest = canonical_execution_commit_decision_binding_digest(dummy)
    binding = ExecutionCommitDecisionBindingV2(
        no_return_admission_reference="nra://1",
        no_return_admission_revision=1,
        no_return_admission_digest="sha256:nra",
        decision_identity_digest="sha256:dec",
        external_effect_participant_id="eff-1",
        external_effect_registration_digest="sha256:eff",
        binding_digest=b_digest,
    )
    assert binding.binding_digest == b_digest

    rec = ExecutionCommitRecordV2(
        transaction_id="tx-1",
        revision=1,
        state=ExecutionCommitStateV2.COMMITTED,
        external_effect_fenced=True,
        decision_digest=b_digest,
        commit_decision_binding=binding,
        updated_at=100.0,
    )
    assert rec.state == ExecutionCommitStateV2.COMMITTED

    # Precommit state forbids decision binding
    with pytest.raises(ValueError, match="precommit_or_abort_state_forbids_decision_binding"):
        ExecutionCommitRecordV2(
            transaction_id="tx-1",
            revision=1,
            state=ExecutionCommitStateV2.OPEN,
            external_effect_fenced=False,
            decision_digest=b_digest,
            commit_decision_binding=binding,
            updated_at=100.0,
        )


def test_execution_result_store_participant():
    mock_store = MagicMock()
    mock_draft = MagicMock()
    mock_draft.normalized_draft_digest = "sha256:draft"
    mock_store.stage_draft.return_value = mock_draft

    part = ExecutionResultStoreParticipant(
        result_store=mock_store,
        exec_res=MagicMock(),
        transaction_id="tx-123",
    )
    assert part.participant_id == "res-store-tx-123"
    assert part.kind == ParticipantKindV2.EXECUTION_RESULT
    assert part.visibility_mode == ParticipantVisibilityModeV2.EXPLICIT_FINALIZE

    prep = part.prepare("tx-123")
    assert prep.state == ParticipantStateV2.PREPARED
    assert prep.prepared_digest == "sha256:draft"

    comm = part.commit_hidden("tx-123")
    assert comm.committed_digest == "sha256:draft"

    fin = part.finalize_visibility("tx-123")
    assert fin.finalized_digest == "sha256:draft"

    rb = part.rollback("tx-123")
    assert rb.rolled_back is True

    rec = part.reconcile("tx-123")
    assert rec == ParticipantStateV2.ROLLED_BACK


def test_owned_execution_budget_authority_validations():
    # Constructor validation errors
    with pytest.raises(ValueError, match="max_runtime_seconds must be finite and positive"):
        OwnedExecutionBudgetAuthorityV2(max_runtime_seconds=-1.0)

    with pytest.raises(ValueError, match="max_output_bytes must be positive"):
        OwnedExecutionBudgetAuthorityV2(max_output_bytes=0)

    with pytest.raises(ValueError, match="max_child_depth cannot be negative"):
        OwnedExecutionBudgetAuthorityV2(max_child_depth=-1)

    with pytest.raises(ValueError, match="policy_revision must be positive"):
        OwnedExecutionBudgetAuthorityV2(policy_revision=0)

    # validate_root and validate_child on forged/stale lease
    authority = OwnedExecutionBudgetAuthorityV2()
    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="forged execution budget lease type"):
        authority._validate_registered("not_a_lease")  # type: ignore
