"""Deep coverage unit tests for executor.py V2 dispatch paths and error branches."""

from __future__ import annotations

import json

import pytest

from core.actions.catalog import ActionCatalog
from core.actions.child_execution import (
    RootExecutionBridge,
)
from core.actions.execution_budget import (
    ExecutionLineage,
    OwnedExecutionBudgetAuthorityV2,
)
from core.actions.executor import ActionExecutor, V2ExecutionUnavailableError
from core.actions.request_v2 import (
    ActionRequestV2EnvelopeDecoder,
)
from core.auth.ingress import IngressSession
from core.auth.ingress_store import IngressSessionStore
from core.auth.types import IngressChannelBinding, Principal, PrincipalRole
from core.execution.policy import ExecutionPolicy

pytestmark = pytest.mark.unit


def _setup_executor_and_root_bridge():
    binding = IngressChannelBinding(
        peer_uid=1000,
        peer_gid=1000,
        peer_pid=42,
        transport_instance="tty-1",
        channel_binding="channel-1",
    )
    store = IngressSessionStore()
    store.register_session(
        IngressSession(
            session_id="session-1",
            principal=Principal(
                principal_id="principal-1",
                name="operator",
                role=PrincipalRole.OPERATOR,
            ),
            channel_binding=binding,
        )
    )
    lease = store.issue_invocation_lease("session-1", "request-1", binding)
    store.resolve_invocation_lease(lease, "request-1", binding)

    envelope = ActionRequestV2EnvelopeDecoder.decode(
        json.dumps(
            {
                "schema_version": "2.0",
                "request_id": "request-1",
                "mission_ref": "mission-1",
                "approval_ref": None,
                "precondition_fact_refs": [],
                "idempotency_key": None,
                "typed_input": {
                    "schema_id": "octopus:input:ad_dump_lsass:2.0",
                    "credential_ref": "credential://1",
                    "target": "10.0.0.1",
                },
            }
        ).encode("utf-8")
    )
    authority = OwnedExecutionBudgetAuthorityV2()
    bundle = authority.issue_root(ingress_lease=lease, bounded_envelope=envelope)
    lineage = ExecutionLineage(
        root_execution_id="exec-1",
        parent_execution_id=None,
        execution_graph_id="graph-1",
        child_depth=0,
    )
    bridge = RootExecutionBridge(ingress_lease=lease, authority=bundle, lineage=lineage)
    executor = ActionExecutor(
        catalog=ActionCatalog(),
        policy=ExecutionPolicy(),
        ingress_store=store,
        budget_authority=authority,
    )
    return executor, envelope, bridge


def test_executor_constructor_type_checks():
    with pytest.raises(TypeError, match="canonical ingress store"):
        ActionExecutor(
            catalog=ActionCatalog(),
            policy=ExecutionPolicy(),
            ingress_store="invalid",  # type: ignore
        )
    with pytest.raises(TypeError, match="canonical bounded request decoder"):
        ActionExecutor(
            catalog=ActionCatalog(),
            policy=ExecutionPolicy(),
            request_v2_decoder="invalid",  # type: ignore
        )
    with pytest.raises(TypeError, match="owned budget authority"):
        ActionExecutor(
            catalog=ActionCatalog(),
            policy=ExecutionPolicy(),
            budget_authority="invalid",  # type: ignore
        )


def test_execute_v2_root_provider_not_mounted():
    executor, envelope, bridge = _setup_executor_and_root_bridge()
    # ad_dump_lsass is not mounted in production V2
    with pytest.raises(V2ExecutionUnavailableError, match="provider_not_mounted"):
        executor._run_v2_internal(
            "killchain:ad_dump_lsass",
            source=envelope,
            bridge=bridge,
        )


def test_execute_v2_root_request_mismatch():
    executor, _envelope, bridge = _setup_executor_and_root_bridge()
    wrong_envelope = ActionRequestV2EnvelopeDecoder.decode(
        json.dumps(
            {
                "schema_version": "2.0",
                "request_id": "different-request-id",
                "mission_ref": "mission-1",
                "approval_ref": None,
                "precondition_fact_refs": [],
                "idempotency_key": None,
                "typed_input": {
                    "schema_id": "octopus:input:ad_dump_lsass:2.0",
                    "credential_ref": "credential://1",
                    "target": "10.0.0.1",
                },
            }
        ).encode("utf-8")
    )
    with pytest.raises(V2ExecutionUnavailableError, match="root_request_lease_mismatch"):
        executor._run_v2_internal(
            "killchain:ad_dump_lsass",
            source=wrong_envelope,
            bridge=bridge,
        )


def test_execute_v2_invalid_bridge_type():
    executor, envelope, _ = _setup_executor_and_root_bridge()
    with pytest.raises(TypeError, match="V2 execution requires either root envelope"):
        executor._run_v2_internal(
            "killchain:ad_dump_lsass",
            source=envelope,
            bridge="invalid_bridge",  # type: ignore
        )


def test_run_v2_validations():
    executor, _, bridge = _setup_executor_and_root_bridge()
    with pytest.raises(ValueError, match="action_id must be a non-empty canonical string"):
        executor.run_v2("", b"{}", ingress_lease=bridge.ingress_lease)

    with pytest.raises(Exception, match="exact store-issued ingress lease"):
        executor.run_v2("killchain:ad_dump_lsass", b"{}", ingress_lease="invalid")  # type: ignore
