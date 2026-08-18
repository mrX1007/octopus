"""Comprehensive unit test coverage for execution_budget.py error paths and validations."""

from __future__ import annotations

import time
from unittest.mock import MagicMock
import pytest

from core.actions.cancellation import (
    ExecutorCancellationController,
    ExecutorCancellationToken,
)
from core.actions.execution_budget import (
    ExecutionBudget,
    ExecutionBudgetExhaustedError,
    ExecutionBudgetLeaseInvalidError,
    ExecutionLineage,
    OwnedExecutionBudgetAuthorityV2,
)
from core.auth.ingress_leases import IngressInvocationLease

pytestmark = pytest.mark.unit


def test_execution_budget_and_lineage_models():
    token = ExecutorCancellationController("canc-1").token

    # Non finite deadline
    with pytest.raises(ValueError, match="deadline must be finite"):
        ExecutionBudget(
            absolute_deadline_monotonic=float("nan"),
            max_output_bytes=100,
            max_child_depth=2,
            cancellation_token=token,
        )

    # Invalid max output bytes
    with pytest.raises(ValueError, match="output limit must be positive"):
        ExecutionBudget(
            absolute_deadline_monotonic=1000.0,
            max_output_bytes=0,
            max_child_depth=2,
            cancellation_token=token,
        )

    with pytest.raises(ValueError, match="output limit must be positive"):
        ExecutionBudget(
            absolute_deadline_monotonic=1000.0,
            max_output_bytes=True,  # type: ignore
            max_child_depth=2,
            cancellation_token=token,
        )

    # Invalid child depth
    with pytest.raises(ValueError, match="child depth cannot be negative"):
        ExecutionBudget(
            absolute_deadline_monotonic=1000.0,
            max_output_bytes=100,
            max_child_depth=-1,
            cancellation_token=token,
        )

    budget = ExecutionBudget(
        absolute_deadline_monotonic=1000.0,
        max_output_bytes=100,
        max_child_depth=2,
        cancellation_token=token,
    )
    with pytest.raises(TypeError, match="non-serializable"):
        budget.__reduce__()

    # ExecutionLineage validations
    with pytest.raises(ValueError, match="requires root and graph identities"):
        ExecutionLineage(
            root_execution_id="",
            parent_execution_id=None,
            execution_graph_id="g1",
            child_depth=0,
        )

    with pytest.raises(ValueError, match="child depth cannot be negative"):
        ExecutionLineage(
            root_execution_id="r1",
            parent_execution_id=None,
            execution_graph_id="g1",
            child_depth=-1,
        )

    with pytest.raises(ValueError, match="root lineage cannot have a parent execution"):
        ExecutionLineage(
            root_execution_id="r1",
            parent_execution_id="p1",
            execution_graph_id="g1",
            child_depth=0,
        )

    with pytest.raises(ValueError, match="child lineage requires a parent execution"):
        ExecutionLineage(
            root_execution_id="r1",
            parent_execution_id=None,
            execution_graph_id="g1",
            child_depth=1,
        )


def test_in_memory_lease_registry_and_authority_validations():
    from core.actions.execution_budget import (
        InMemoryExecutionBudgetLeaseRegistryV2,
    )

    reg = InMemoryExecutionBudgetLeaseRegistryV2()
    with pytest.raises(TypeError, match="only exact budget leases may be registered"):
        reg.register("not_a_lease")  # type: ignore

    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="unknown execution budget lease"):
        reg.require_current("nonexistent_lease_id")

    # Authority constructor validations
    with pytest.raises(ValueError, match="max_runtime_seconds must be finite and positive"):
        OwnedExecutionBudgetAuthorityV2(max_runtime_seconds=-1.0)

    with pytest.raises(ValueError, match="max_output_bytes must be positive"):
        OwnedExecutionBudgetAuthorityV2(max_output_bytes=0)

    with pytest.raises(ValueError, match="max_child_depth cannot be negative"):
        OwnedExecutionBudgetAuthorityV2(max_child_depth=-1)

    with pytest.raises(ValueError, match="policy_revision must be positive"):
        OwnedExecutionBudgetAuthorityV2(policy_revision=0)

    # Authority root & narrow child operations
    auth = OwnedExecutionBudgetAuthorityV2(max_child_depth=1)
    ingress_lease = object.__new__(IngressInvocationLease)
    object.__setattr__(ingress_lease, "lease_id", "ing-lease-1")
    object.__setattr__(ingress_lease, "bound_request_id", "req-1")

    env = MagicMock()
    env.request_id = "req-1"

    root_bundle = auth.issue_root(ingress_lease=ingress_lease, bounded_envelope=env)
    root_lease = root_bundle.budget_lease

    # Duplicate register in registry
    with pytest.raises(ValueError, match="duplicate execution budget lease id"):
        auth._lease_registry.register(root_lease)

    # Validate root success & identity mismatch
    auth.validate_root(root_lease, ingress_lease=ingress_lease, request_id="req-1")
    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="root budget identity mismatch"):
        auth.validate_root(root_lease, ingress_lease=ingress_lease, request_id="req-DIFF")

    # Narrow child
    child_lease = auth.narrow_child(
        parent=root_lease,
        child_request_id="req-child-1",
        child_action_id="act.child",
    )
    assert child_lease.budget.max_child_depth == 0

    # Narrowing child from depth 0 raises Exhausted
    with pytest.raises(ExecutionBudgetExhaustedError, match="maximum execution graph depth reached"):
        auth.narrow_child(
            parent=child_lease,
            child_request_id="req-child-2",
            child_action_id="act.child2",
        )

    # Validate child against parent
    from core.auth.ingress_leases import ChildIngressLease

    child_ingress = object.__new__(ChildIngressLease)
    object.__setattr__(child_ingress, "lease_id", "child-ing-1")
    object.__setattr__(child_ingress, "bound_child_request_id", "req-child-1")

    auth.validate_child(
        child_lease,
        parent=root_lease,
        child_lease=child_ingress,
        child_action_id="act.child",
    )

    # Validate child action mismatch
    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="child budget action mismatch"):
        auth.validate_child(
            child_lease,
            parent=root_lease,
            child_lease=child_ingress,
            child_action_id="act.WRONG",
        )

    # Validate child parent mismatch
    other_root = auth.issue_root(
        ingress_lease=ingress_lease,
        bounded_envelope=MagicMock(request_id="req-1"),
    ).budget_lease
    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="child budget parent mismatch"):
        auth.validate_child(
            child_lease,
            parent=other_root,
            child_lease=child_ingress,
            child_action_id="act.child",
        )

    # _validate_child_current helper
    auth._validate_child_current(
        child_lease,
        child_lease=child_ingress,
        child_action_id="act.child",
    )

    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="child budget has no parent binding"):
        auth._validate_child_current(
            root_lease,
            child_lease=child_ingress,
            child_action_id="act.child",
        )


def test_budget_authority_validation_branches():
    from core.auth.ingress_store import IngressSessionStore
    from core.auth.types import IngressChannelBinding, IngressKind, Principal, PrincipalRole

    auth = OwnedExecutionBudgetAuthorityV2()
    ctrl = ExecutorCancellationController("canc-1")
    token = ctrl.token

    root_budget = ExecutionBudget(
        absolute_deadline_monotonic=time.monotonic() + 100.0,
        max_output_bytes=1000,
        max_child_depth=2,
        cancellation_token=token,
    )

    store = IngressSessionStore()
    from core.auth.ingress import IngressSession

    binding = IngressChannelBinding(1000, 1000, 1234, "tty:7", "channel-secret")
    principal = Principal(
        principal_id="principal:operator-1",
        name="Operator",
        role=PrincipalRole.OPERATOR,
        revision=1,
    )
    session = IngressSession(
        session_id="session:1",
        principal=principal,
        channel_binding=binding,
        revision=1,
    )
    store.register_session(session)
    ingress_lease = store.issue_invocation_lease(
        session.session_id,
        "req-1",
        binding,
    )

    bundle = auth.issue_root(
        ingress_lease=ingress_lease,
        bounded_envelope=MagicMock(request_id="req-1"),
    )
    # issue_root invalid ingress lease type
    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="root budget requires an exact ingress lease"):
        auth.issue_root(
            ingress_lease="not_a_lease",  # type: ignore
            bounded_envelope=MagicMock(request_id="req-1"),
        )

    # issue_root request_id mismatch
    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="root budget request/ingress mismatch"):
        auth.issue_root(
            ingress_lease=ingress_lease,
            bounded_envelope=MagicMock(request_id="wrong-req"),
        )

    root_lease = bundle.budget_lease

    # validate_root mismatch
    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="root budget identity mismatch"):
        auth.validate_root(
            root_lease,
            ingress_lease=ingress_lease,
            request_id="wrong-req-id",
        )

    # _validate_child_current errors
    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="child budget has no parent binding"):
        auth._validate_child_current(
            root_lease,  # root lease has no parent_budget_lease_id
            child_lease=MagicMock(),
            child_action_id="act-1",
        )

    # Child lease at root boundary
    child_lease = auth.narrow_child(
        parent=root_lease,
        child_request_id="req-child-x",
        child_action_id="act.x",
    )
    with pytest.raises(ExecutionBudgetLeaseInvalidError, match="child budget supplied at root boundary"):
        auth.validate_root(
            child_lease,
            ingress_lease=ingress_lease,
            request_id="req-child-x",
        )
