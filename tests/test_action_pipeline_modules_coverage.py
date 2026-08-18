"""Unit tests for action pipeline modules (drafts, commit store, composite, decoders, versions)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.actions.adapter_versions import AdapterApiVersion
from core.actions.composite_execution import (
    CompositeChildExecutionReceiptV2,
    CompositeExecutionTracker,
    CompositeRouterContext,
)
from core.actions.execution_commit_store import (
    CommittedExecutionMarkerV2,
    DefaultExecutionCommitStoreV2,
)
from core.actions.execution_drafts import (
    ArtifactDraftRefV2,
    AuditOutboxDraftRefV2,
    DecisionTraceDraftRefV2,
    DraftReferenceKindV2,
    ManagedResourceDraftRefV2,
    ObservationDraftRefV2,
    SensitiveBatchDraftRefV2,
)
from core.actions.legacy_descriptor_decoder import decode_legacy_descriptor_to_v2
from core.actions.models import LegacyActionDescriptorV1

pytestmark = pytest.mark.unit


def test_adapter_api_version():
    assert AdapterApiVersion.V1 == 1
    assert AdapterApiVersion.V2 == 2


def test_legacy_descriptor_decoder():
    from core.actions.models import ActionKind

    legacy = LegacyActionDescriptorV1(
        action_id="c2:c2_deploy",
        name="Legacy Deploy",
        kind=ActionKind.KILLCHAIN,
        provider="c2_deploy",
    )
    v2_desc, mount_spec = decode_legacy_descriptor_to_v2(legacy)
    assert v2_desc.action_id == "c2:c2_deploy"
    assert v2_desc.schema_version == "2.0"
    assert mount_spec.action_id == "c2:c2_deploy"


def test_composite_execution():
    tracker = CompositeExecutionTracker(graph_id="g1", root_action_id="root_act")
    assert tracker.graph_id == "g1"
    assert tracker.root_action_id == "root_act"

    mock_report = MagicMock()
    receipt = CompositeChildExecutionReceiptV2(
        parent_execution_id="p1",
        child_execution_id="c1",
        child_action_id="child_act",
        report=mock_report,
    )
    assert receipt.parent_execution_id == "p1"
    assert receipt.report is mock_report

    mock_executor = MagicMock()
    mock_executor.run_v2.return_value = mock_report

    ctx = CompositeRouterContext(
        execution_id="exec_1",
        action_id="composite_act",
        transaction_id="tx_1",
        input_dto={"key": "val"},
        executor=mock_executor,
    )
    assert ctx.execution_id == "exec_1"
    assert ctx.action_id == "composite_act"
    assert ctx.transaction_id == "tx_1"
    assert ctx.child_reports == ()

    mock_child_envelope = MagicMock()
    rep = ctx.dispatch_child(mock_child_envelope)
    assert rep is mock_report
    assert ctx.child_reports == (mock_report,)


def test_execution_drafts():
    assert DraftReferenceKindV2.ARTIFACT == "artifact_draft"
    assert DraftReferenceKindV2.SENSITIVE_BATCH == "sensitive_batch_draft"
    assert DraftReferenceKindV2.MANAGED_RESOURCE == "managed_resource_draft"
    assert DraftReferenceKindV2.OBSERVATION == "observation_draft"
    assert DraftReferenceKindV2.FACT == "fact_draft"
    assert DraftReferenceKindV2.AUDIT_OUTBOX == "audit_outbox_draft"
    assert DraftReferenceKindV2.DECISION_TRACE == "decision_trace_draft"
    assert DraftReferenceKindV2.EXTERNAL_EFFECT_OUTPUT == "external_effect_output_draft"

    a_ref = ArtifactDraftRefV2(transaction_id="t1", draft_id="d1", artifact_schema_id="s1", payload_digest="sha256:abc")
    assert a_ref.transaction_id == "t1"

    o_ref = ObservationDraftRefV2(
        transaction_id="t1", draft_id="d1", observation_schema_id="s1", payload_digest="sha256:abc"
    )
    assert o_ref.transaction_id == "t1"

    s_ref = SensitiveBatchDraftRefV2(transaction_id="t1", draft_id="d1", batch_digest="sha256:abc")
    assert s_ref.transaction_id == "t1"

    m_ref = ManagedResourceDraftRefV2(
        transaction_id="t1", draft_id="d1", resource_kind="r1", resource_digest="sha256:abc"
    )
    assert m_ref.transaction_id == "t1"

    au_ref = AuditOutboxDraftRefV2(transaction_id="t1", draft_id="d1", event_schema_id="s1", event_digest="sha256:abc")
    assert au_ref.transaction_id == "t1"

    dt_ref = DecisionTraceDraftRefV2(
        transaction_id="t1", draft_id="d1", trace_schema_id="decision-trace/2.0", trace_digest="sha256:abc"
    )
    assert dt_ref.transaction_id == "t1"


def test_execution_commit_store():
    store = DefaultExecutionCommitStoreV2()
    marker = store.persist_committed_marker(
        transaction_id="tx_123",
        execution_id="exec_123",
        finalization_ref="fin_ref",
        fence_ref="fence_ref",
    )
    assert marker.marker_id == "marker:tx_123"
    assert marker.marker_digest.startswith("sha256:")

    req_marker = store.require_current_marker(marker)
    assert req_marker == marker

    # Missing marker
    missing_marker = CommittedExecutionMarkerV2(
        marker_id="marker:missing",
        transaction_id="tx_missing",
        execution_id="exec_missing",
        finalization_ref="fin",
        fence_ref="fence",
        marker_digest="",
    )
    with pytest.raises(KeyError, match="not found"):
        store.require_current_marker(missing_marker)
