"""PR-6 child re-entry boundary ratchets."""

from __future__ import annotations

import ast
import inspect
from types import SimpleNamespace
from typing import get_args
from unittest.mock import MagicMock

import pytest

from core.actions.child_execution import ChildExecutionBridge, RootExecutionBridge
from core.actions.execution_budget import ExecutionLineage
from core.actions.executor import (
    ActionExecutor,
    ExecutionBridge,
    V2ExecutionSource,
    V2ExecutionUnavailableError,
)
from core.actions.input_contracts import C2CleanupInputV2
from core.actions.request_v2 import ActionRequestV2, BoundedActionRequestV2Envelope
from core.c2.resource_types import C2CleanupReason

pytestmark = [pytest.mark.unit, pytest.mark.contract]


def _request(
    *,
    action_id: str = "plugin:leaf",
    request_id: str = "request-child",
) -> ActionRequestV2:
    return ActionRequestV2(
        request_id=request_id,
        action_id=action_id,
        mission_ref="mission://one",
        approval_ref="approval://one",
        precondition_fact_refs=(),
        idempotency_key=None,
        typed_input=C2CleanupInputV2(
            resource_ref="resource://one",
            reason=C2CleanupReason.OPERATOR_REQUEST,
        ),
    )


def _bridge(
    *,
    selected_action_id: str = "plugin:leaf",
    bound_request_id: str = "request-child",
    root_execution_id: str = "execution-root",
    parent_execution_id: str = "execution-parent",
    execution_graph_id: str = "graph-one",
    child_depth: int = 1,
    lineage_root_execution_id: str | None = None,
    lineage_parent_execution_id: str | None = None,
    lineage_execution_graph_id: str | None = None,
    lineage_child_depth: int | None = None,
) -> ChildExecutionBridge:
    ingress = SimpleNamespace(
        bound_child_request_id=bound_request_id,
        root_execution_id=root_execution_id,
        parent_execution_id=parent_execution_id,
        execution_graph_id=execution_graph_id,
        child_depth=child_depth,
    )
    return ChildExecutionBridge(
        ingress_lease=ingress,  # type: ignore[arg-type]
        budget_lease=object(),  # type: ignore[arg-type]
        lineage=ExecutionLineage(
            root_execution_id=lineage_root_execution_id or root_execution_id,
            parent_execution_id=(
                lineage_parent_execution_id if lineage_parent_execution_id is not None else parent_execution_id
            ),
            execution_graph_id=lineage_execution_graph_id or execution_graph_id,
            child_depth=(lineage_child_depth if lineage_child_depth is not None else child_depth),
        ),
        approval_graph_lease=object(),  # type: ignore[arg-type]
        selected_child_action_id=selected_action_id,
        parent_decision_trace_ref="trace://parent",
    )


def _executor() -> ActionExecutor:
    return ActionExecutor(catalog=MagicMock(), policy=MagicMock())


def test_pr6_adds_execution_bridge_and_v2_execution_source_aliases() -> None:
    assert set(get_args(V2ExecutionSource)) == {
        BoundedActionRequestV2Envelope,
        ActionRequestV2,
    }
    assert set(get_args(ExecutionBridge)) == {
        RootExecutionBridge,
        ChildExecutionBridge,
    }


def test_pr6_adds_child_overload_to_single_run_v2_internal() -> None:
    source = ast.parse(inspect.getsource(ActionExecutor))
    methods = [
        node
        for node in ast.walk(source)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_run_v2_internal"
    ]
    assert len(methods) == 3
    assert (
        sum(
            any(isinstance(decorator, ast.Name) and decorator.id == "overload" for decorator in method.decorator_list)
            for method in methods
        )
        == 2
    )


def test_child_reentry_action_identity_equality_required() -> None:
    with pytest.raises(V2ExecutionUnavailableError, match="child_action_identity_mismatch"):
        _executor()._run_v2_internal(
            "plugin:leaf",
            _request(action_id="plugin:different"),
            bridge=_bridge(),
        )
    with pytest.raises(V2ExecutionUnavailableError, match="child_action_identity_mismatch"):
        _executor()._run_v2_internal(
            "plugin:leaf",
            _request(),
            bridge=_bridge(selected_action_id="plugin:different"),
        )


def test_child_reentry_request_id_matches_lease() -> None:
    with pytest.raises(V2ExecutionUnavailableError, match="child_request_lease_mismatch"):
        _executor()._run_v2_internal(
            "plugin:leaf",
            _request(request_id="request-other"),
            bridge=_bridge(),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("lineage_root_execution_id", "execution-other"),
        ("lineage_parent_execution_id", "execution-other"),
        ("lineage_execution_graph_id", "graph-other"),
        ("lineage_child_depth", 2),
    ),
)
def test_child_reentry_lineage_matches_lease(field: str, value: object) -> None:
    with pytest.raises(V2ExecutionUnavailableError, match="child_lineage_lease_mismatch"):
        _executor()._run_v2_internal(
            "plugin:leaf",
            _request(),
            bridge=_bridge(**{field: value}),  # type: ignore[arg-type]
        )


def test_child_identity_mismatch_happens_before_catalog_or_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog_lookup = MagicMock(side_effect=AssertionError("catalog lookup occurred"))
    monkeypatch.setattr(
        "core.actions.schema_bindings.get_v2_schema_binding",
        catalog_lookup,
    )
    with pytest.raises(V2ExecutionUnavailableError, match="child_action_identity_mismatch"):
        _executor()._run_v2_internal(
            "plugin:leaf",
            _request(action_id="plugin:different"),
            bridge=_bridge(),
        )
    catalog_lookup.assert_not_called()
