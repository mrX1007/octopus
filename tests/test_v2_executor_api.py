"""Exact public V2 executor root-boundary tests."""

from __future__ import annotations

import inspect
import json
from unittest.mock import MagicMock

import pytest

from core.actions.executor import ActionExecutor, V2ExecutionUnavailableError
from core.auth.ingress import IngressSession
from core.auth.ingress_context import (
    CurrentIngressTransportContext,
    bind_current_ingress_transport_context,
    set_current_ingress_lease,
)
from core.auth.ingress_leases import IngressLeaseConsumedError, IngressLeaseInvalidError
from core.auth.ingress_store import IngressSessionStore
from core.auth.types import IngressChannelBinding, IngressKind, Principal, PrincipalRole

pytestmark = pytest.mark.unit


def _fixture(*, lease_request_id: str = "request-1", envelope_request_id: str = "request-1"):
    binding = IngressChannelBinding(
        peer_uid=1000,
        peer_gid=1000,
        peer_pid=44,
        transport_instance="tty-1",
        channel_binding="channel-1",
    )
    store = IngressSessionStore()
    store.register_session(
        IngressSession(
            session_id="session-1",
            principal=Principal(
                principal_id="principal-1",
                name="Operator",
                role=PrincipalRole.OPERATOR,
            ),
            channel_binding=binding,
        )
    )
    lease = store.issue_invocation_lease(
        "session-1",
        lease_request_id,
        binding,
        ingress_kind=IngressKind.INTERACTIVE_CLI,
        invocation_nonce="nonce-1",
    )
    envelope = json.dumps(
        {
            "schema_version": "2.0",
            "request_id": envelope_request_id,
            "mission_ref": "mission-1",
            "approval_ref": None,
            "precondition_fact_refs": [],
            "idempotency_key": None,
            "typed_input": {
                "schema_id": "octopus:input:c2_cleanup:2.0",
                "resource_ref": "c2-resource://resource-1",
                "reason": "operator-request",
            },
        },
        separators=(",", ":"),
    ).encode()
    executor = ActionExecutor(
        catalog=MagicMock(),
        policy=MagicMock(),
        ingress_store=store,
    )
    context = CurrentIngressTransportContext(
        channel_binding=binding,
        invocation_nonce="nonce-1",
        ingress_kind=IngressKind.INTERACTIVE_CLI,
    )
    return executor, store, lease, envelope, binding, context


def test_v2_has_one_public_root_and_one_internal_execution_api() -> None:
    signature = inspect.signature(ActionExecutor.run_v2)
    assert tuple(signature.parameters) == (
        "self",
        "action_id",
        "serialized_envelope",
        "ingress_lease",
    )
    assert signature.parameters["ingress_lease"].kind is inspect.Parameter.KEYWORD_ONLY
    assert callable(ActionExecutor._run_v2_internal)


def test_run_v2_requires_current_authenticated_transport_proof() -> None:
    executor, _, lease, envelope, _, _ = _fixture()
    with pytest.raises(IngressLeaseInvalidError, match="transport proof"):
        executor.run_v2("c2:c2_cleanup", envelope, ingress_lease=lease)


def test_run_v2_validates_request_id_and_does_not_consume_unresolved_lease() -> None:
    executor, store, lease, envelope, binding, context = _fixture(
        lease_request_id="wrong-request",
    )
    with bind_current_ingress_transport_context(context), pytest.raises(IngressLeaseInvalidError):
        executor.run_v2("c2:c2_cleanup", envelope, ingress_lease=lease)

    # Failed resolution leaves the lease ISSUED; the correct request can still
    # resolve it.  Consumption belongs only to a checked-out invocation.
    store.resolve_invocation_lease(
        lease,
        "wrong-request",
        binding,
        invocation_nonce="nonce-1",
        ingress_kind=IngressKind.INTERACTIVE_CLI,
    )
    store.consume_invocation_lease(lease)


def test_run_v2_consumes_resolved_lease_in_outer_finally() -> None:
    executor, store, lease, envelope, binding, context = _fixture()
    with bind_current_ingress_transport_context(context):
        outcome = executor.run_v2("c2:c2_cleanup", envelope, ingress_lease=lease)
        assert outcome is not None

    with pytest.raises(IngressLeaseConsumedError):
        store.resolve_invocation_lease(
            lease,
            "request-1",
            binding,
            invocation_nonce="nonce-1",
        )


def test_legacy_contextvar_lease_is_not_v2_authority() -> None:
    executor, _, lease, envelope, _, _ = _fixture()
    set_current_ingress_lease(lease)
    try:
        with pytest.raises(IngressLeaseInvalidError, match="transport proof"):
            executor.run_v2("c2:c2_cleanup", envelope, ingress_lease=lease)
    finally:
        set_current_ingress_lease(None)
