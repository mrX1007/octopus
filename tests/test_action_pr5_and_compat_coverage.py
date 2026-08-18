"""Unit test coverage for intent_bound_owner_factories, managed_resources, participant_authority, policy_snapshots, sensitive_artifact_envelope, target_schemas, and v1_compat."""

from __future__ import annotations

import pytest

from core.actions.intent_bound_owner_factories import (
    ApprovalGraphCreationSpecV2,
    ExecutorCheckoutRequestBundle,
    IntentBoundOwnerFactory,
    InvocationScopeCreationSpecV2,
)
from core.actions.managed_resources import (
    ManagedResourceKind,
    ManagedResourceManagerV2,
    ManagedResourceStageRequestV2,
)
from core.actions.participant_authority import (
    DefaultParticipantExecutionAuthorityFactoryV2,
    canonical_participant_authority_digest,
)
from core.actions.policy_snapshots import (
    ActionPolicyRequestHeaderV2,
)
from core.actions.sensitive_artifact_envelope import (
    SensitiveArtifactEnvelopeV2,
)
from core.actions.sensitive_integrity import SensitiveIntegrityTagV2
from core.actions.target_schemas import (
    get_all_v2_target_schemas,
    require_v2_target_schema,
)
from core.actions.v1_compat import compat_v1

pytestmark = pytest.mark.unit


def test_intent_bound_owner_factory():
    factory = IntentBoundOwnerFactory()
    bundle = ExecutorCheckoutRequestBundle(
        execution_id="exec-1",
        action_id="act-1",
        target="10.0.0.1",
        requested_refs=("ref-1",),
    )
    spec = factory.create_checkout_spec(bundle)
    assert spec.request == bundle
    assert spec.request_digest.startswith("sha256:")

    inv_spec = InvocationScopeCreationSpecV2(
        execution_id="exec-1",
        transaction_id="tx-1",
        cleanup_registry_revision=1,
        spec_digest="sha256:d",
    )
    assert inv_spec.execution_id == "exec-1"

    app_spec = ApprovalGraphCreationSpecV2(
        root_action_id="act-1",
        execution_graph_id="graph-1",
        approval_ref=None,
        approval_revision=None,
        spec_digest="sha256:d",
    )
    assert app_spec.root_action_id == "act-1"


def test_managed_resource_manager():
    manager = ManagedResourceManagerV2()
    req = ManagedResourceStageRequestV2(
        resource_id="res-1",
        resource_kind=ManagedResourceKind.SESSION,
        descriptor={"host": "10.0.0.1"},
        retained=True,
    )
    handle = manager.register(req)
    assert handle.resource_id == "res-1"
    assert handle.resource_ref == "resource:session:res-1"
    assert handle.is_active is True

    retrieved = manager.get(handle.resource_ref)
    assert retrieved == handle
    assert manager.get("nonexistent") is None


def test_participant_authority_factory_and_digest():
    factory = DefaultParticipantExecutionAuthorityFactoryV2()
    binding = factory.issue(
        creation_ref="creation://1",
        transaction_id="tx-1",
        intent_ref="intent://1",
        checkout_ref="checkout://1",
        coordinator_ref="coord://1",
    )
    assert binding.transaction_id == "tx-1"
    digest = canonical_participant_authority_digest(binding)
    assert binding.authority_digest == digest


def test_policy_request_header_and_snapshot():
    hdr = ActionPolicyRequestHeaderV2(
        schema_version="2.0",
        request_id="req-1",
        action_id="act-1",
        root_action_id="act-1",
        parent_action_id=None,
        execution_graph_id="graph-1",
        capability_class="cap1",
        killchain_stage="recon",
        operation_id="op-1",
    )
    assert hdr.action_id == "act-1"

    with pytest.raises(ValueError, match="policy header schema version is unsupported"):
        ActionPolicyRequestHeaderV2(
            schema_version="1.0",
            request_id="req-1",
            action_id="act-1",
            root_action_id="act-1",
            parent_action_id=None,
            execution_graph_id="graph-1",
            capability_class="cap1",
            killchain_stage=None,
            operation_id=None,
        )


def test_sensitive_artifact_envelope():
    tag = SensitiveIntegrityTagV2(
        domain="artifact",
        key_id="k-1",
        algorithm="hmac-sha256-v2",
        tag="0" * 64,
    )
    env = SensitiveArtifactEnvelopeV2(
        artifact_id="art-1",
        encrypted_payload=b"encrypted_data",
        encryption_algorithm="AES-GCM",
        integrity_tag=tag,
    )
    assert env.envelope_digest.startswith("sha256:")


def test_target_schemas_inventory():
    schemas = get_all_v2_target_schemas()
    assert len(schemas) == 20

    first = schemas[0]
    matched = require_v2_target_schema(first.action_id, first.input_schema_id)
    assert matched == first

    with pytest.raises(KeyError, match="no exact V2 target schema"):
        require_v2_target_schema("nonexistent", "nonexistent")


def test_v1_compat_wrapper():
    res1 = compat_v1({"target_host": "10.0.0.1", "foo": "bar"})
    assert res1["target"] == "10.0.0.1"

    res2 = compat_v1({"target": "10.0.0.2", "target_host": "10.0.0.1"})
    assert res2["target"] == "10.0.0.2"
