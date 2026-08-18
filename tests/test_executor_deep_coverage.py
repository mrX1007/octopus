"""Unit tests for ActionExecutor edge cases and validations."""

from __future__ import annotations

import pytest

from core.actions.catalog import ActionCatalog
from core.actions.executor import ActionExecutor
from core.actions.models import ActionRequest
from core.actions.request_v2 import ActionRequestV2EnvelopeDecoder
from core.auth.ingress_store import IngressSessionStore
from core.execution import ExecutionContext, ExecutionPolicy

pytestmark = pytest.mark.unit


def test_action_executor_constructor_validations():
    cat = ActionCatalog()
    pol = ExecutionPolicy()

    # Ingress store invalid
    with pytest.raises(TypeError, match="V2 executor requires the canonical ingress store"):
        ActionExecutor(catalog=cat, policy=pol, ingress_store="not_a_store")  # type: ignore

    # Decoder invalid
    with pytest.raises(TypeError, match="V2 executor requires the canonical bounded request decoder"):
        ActionExecutor(catalog=cat, policy=pol, request_v2_decoder="not_a_decoder")  # type: ignore

    # Budget authority invalid
    with pytest.raises(TypeError, match="V2 executor requires the owned budget authority"):
        ActionExecutor(catalog=cat, policy=pol, budget_authority="not_an_authority")  # type: ignore


def test_action_executor_run_request_validations():
    cat = ActionCatalog()
    pol = ExecutionPolicy()
    executor = ActionExecutor(catalog=cat, policy=pol)

    # Request invalid type
    with pytest.raises(TypeError, match="request must be an ActionRequest"):
        executor.run("custom:test", "not_a_request")  # type: ignore

    # ExecutionContext invalid type
    bad_req = object.__new__(ActionRequest)
    object.__setattr__(bad_req, "execution_context", "not_a_context")
    with pytest.raises(TypeError, match="request.execution_context must be an ExecutionContext"):
        executor.run("custom:test", bad_req)


def test_action_executor_request_contract_applicability_errors():
    cat = ActionCatalog(include_manual_gated=True)
    pol = ExecutionPolicy()
    executor = ActionExecutor(catalog=cat, policy=pol)

    ctx_bad_limit = ExecutionContext(
        actor="operator",
        origin="cli",
        target_scope=("10.0.0.1",),
        max_runtime_seconds=-10,  # negative limit
    )
    req = ActionRequest(
        target="10.0.0.1",
        execution_context=ctx_bad_limit,
    )
    report = executor.run("plugin:payload_keying", req)
    assert report.applicability.applicable is False
    assert any("max_runtime_seconds" in reason for reason in report.applicability.missing_requirements)


def test_action_executor_evaluate_policy_branches():
    from core.actions.models import ActionDescriptor, ActionKind

    class ManualGatedAdapter:
        descriptor = ActionDescriptor(
            action_id="custom:manual",
            name="Manual Action",
            kind=ActionKind.PLUGIN,
            provider="test",
            killchain_stage="exploitation",
            capability_class="read_only",
            manual_gate=True,
        )

        def authorize(self, policy, request, phase):
            from core.execution.policy import ExecutionDecision

            return ExecutionDecision(allowed=True, context=request.execution_context)

    cat = ActionCatalog()
    pol = ExecutionPolicy()
    executor = ActionExecutor(catalog=cat, policy=pol)

    adapter = ManualGatedAdapter()

    # Manual gate with non-operator origin
    ctx_service = ExecutionContext(
        actor="svc",
        origin="service",
        target_scope=("10.0.0.1",),
        capabilities=frozenset({"registered_tool"}),
    )
    req_svc = ActionRequest(target="10.0.0.1", execution_context=ctx_service)
    dec1 = executor._authorize(adapter, req_svc, phase="pre_execution")  # type: ignore
    assert dec1.allowed is False
    assert dec1.reason == "manual_gate_requires_operator_context"

    # Manual gate with operator origin but unapproved
    ctx_unapproved = ExecutionContext(
        actor="operator",
        origin="operator",
        target_scope=("10.0.0.1",),
        capabilities=frozenset({"registered_tool"}),
        approved=False,
    )
    req_unapp = ActionRequest(target="10.0.0.1", execution_context=ctx_unapproved)
    dec2 = executor._authorize(adapter, req_unapp, phase="pre_execution")  # type: ignore
    assert dec2.allowed is False
    assert dec2.reason == "active_tool_requires_approval"

    # Capability denied when context lacks CAP_REGISTERED_TOOL
    ctx_no_cap = ExecutionContext(
        actor="operator",
        origin="operator",
        target_scope=("10.0.0.1",),
        capabilities=frozenset(),
    )
    req_no_cap = ActionRequest(target="10.0.0.1", execution_context=ctx_no_cap)
    dec3 = executor._authorize(adapter, req_no_cap, phase="pre_execution")  # type: ignore
    assert dec3.allowed is False
    assert "capability_denied" in dec3.reason

    # Stage denied (when capability_class is empty)
    class StageOnlyAdapter:
        descriptor = ActionDescriptor(
            action_id="custom:stage",
            name="Stage Action",
            kind=ActionKind.PLUGIN,
            provider="test",
            killchain_stage="exploitation",
            capability_class="",
            manual_gate=False,
        )

    dec4 = executor._authorize(StageOnlyAdapter(), req_no_cap, phase="pre_execution")  # type: ignore
    assert dec4.allowed is False
    assert "stage_denied" in dec4.reason
