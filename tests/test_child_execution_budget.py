from __future__ import annotations

import pickle
import time

import pytest

from core.actions.cancellation import ExecutorCancellationController
from core.actions.execution_budget import ExecutionBudget, ExecutionLineage

pytestmark = pytest.mark.unit


def test_execution_budget_exact_fields() -> None:
    controller = ExecutorCancellationController("token-1")
    budget = ExecutionBudget(
        absolute_deadline_monotonic=time.monotonic() + 60,
        max_output_bytes=1024,
        max_child_depth=5,
        cancellation_token=controller.token,
    )
    assert set(budget.__dataclass_fields__) == {
        "absolute_deadline_monotonic",
        "max_output_bytes",
        "max_child_depth",
        "cancellation_token",
    }
    with pytest.raises(TypeError, match="non-serializable"):
        pickle.dumps(budget)


def test_execution_lineage_rejects_root_with_parent() -> None:
    with pytest.raises(ValueError, match="root lineage"):
        ExecutionLineage(
            root_execution_id="exec-root",
            parent_execution_id="exec-parent",
            execution_graph_id="graph-1",
            child_depth=0,
        )
