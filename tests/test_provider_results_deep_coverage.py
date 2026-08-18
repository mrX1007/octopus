"""Unit tests for edge cases and validations in provider_results.py."""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from core.actions.execution_results_v2 import ExecutionStatusV2
from core.actions.provider_results import (
    PartialCommitPolicySnapshotV2,
    PartialCommitRuleV2,
    ProviderOutcomeNormalizationV2,
    ProviderOutcomeNormalizerV2,
    ProviderOutcomeV2,
    ProviderProvenanceV2,
    ProviderResultHeaderV2,
    ProviderResultKind,
    SensitiveBatchHandleV2,
    _require_unique_non_empty,
    canonical_partial_commit_policy_digest,
)

pytestmark = pytest.mark.unit


def test_helper_unique_non_empty():
    with pytest.raises(ValueError, match="test_field_must_be_non_empty"):
        _require_unique_non_empty("test_field", ())

    with pytest.raises(ValueError, match="test_field_contains_empty_value"):
        _require_unique_non_empty("test_field", ("",))

    with pytest.raises(ValueError, match="test_field_contains_duplicates"):
        _require_unique_non_empty("test_field", ("a", "a"))


def test_normalization_and_policy_snapshots():
    with pytest.raises(TypeError, match="provider_outcome_normalization_construction_denied"):
        ProviderOutcomeNormalizationV2._from_normalizer(
            _token="bad_token",  # type: ignore
            provider_outcome=ProviderOutcomeV2.SUCCEEDED,
            execution_status=ExecutionStatusV2.SUCCEEDED,
            commit_eligible=True,
            partial_disposition=None,
        )

    # PartialCommitPolicySnapshotV2 revision < 1
    rule1 = PartialCommitRuleV2("act-1", ProviderResultKind.ARTIFACT, ("r1",))
    with pytest.raises(ValueError, match="partial_commit_policy_revision_invalid"):
        PartialCommitPolicySnapshotV2(
            policy_id="pol-1",
            revision=0,
            rules=(rule1,),
            policy_digest="sha256:d1",
        )

    # Duplicate rule in snapshot
    with pytest.raises(ValueError, match="partial_commit_policy_duplicate_rule"):
        PartialCommitPolicySnapshotV2(
            policy_id="pol-1",
            revision=1,
            rules=(rule1, rule1),
            policy_digest="sha256:d1",
        )


def test_outcome_normalizer_outcomes():
    class MockRegistry:
        def assert_current(self, snapshot):
            pass

    policy_mock = MagicMock()
    registry = MockRegistry()
    normalizer = ProviderOutcomeNormalizerV2(policy=policy_mock, registry=registry)  # type: ignore

    rule1 = PartialCommitRuleV2("act-1", ProviderResultKind.ARTIFACT, ("r1",))
    valid_snapshot = PartialCommitPolicySnapshotV2(
        policy_id="pol-1",
        revision=1,
        rules=(rule1,),
        policy_digest="",
    )
    valid_digest = canonical_partial_commit_policy_digest(valid_snapshot)
    snapshot = PartialCommitPolicySnapshotV2(
        policy_id="pol-1",
        revision=1,
        rules=(rule1,),
        policy_digest=valid_digest,
    )

    # Digest mismatch
    bad_snapshot = PartialCommitPolicySnapshotV2(
        policy_id="pol-1",
        revision=1,
        rules=(rule1,),
        policy_digest="sha256:wrong",
    )
    with pytest.raises(ValueError, match="partial_commit_policy_digest_mismatch"):
        normalizer.normalize(
            action_id="act-1",
            result_kind=ProviderResultKind.ARTIFACT,
            outcome=ProviderOutcomeV2.UNAVAILABLE,
            reason_codes=(),
            partial_policy=bad_snapshot,
        )

    # UNAVAILABLE
    res_unavail = normalizer.normalize(
        action_id="act-1",
        result_kind=ProviderResultKind.ARTIFACT,
        outcome=ProviderOutcomeV2.UNAVAILABLE,
        reason_codes=(),
        partial_policy=snapshot,
    )
    assert res_unavail.execution_status == ExecutionStatusV2.UNAVAILABLE
    assert res_unavail.commit_eligible is False

    # TIMED_OUT
    res_timeout = normalizer.normalize(
        action_id="act-1",
        result_kind=ProviderResultKind.ARTIFACT,
        outcome=ProviderOutcomeV2.TIMED_OUT,
        reason_codes=(),
        partial_policy=snapshot,
    )
    assert res_timeout.execution_status == ExecutionStatusV2.TIMED_OUT
    assert res_timeout.commit_eligible is False

    # CANCELLED
    res_cancel = normalizer.normalize(
        action_id="act-1",
        result_kind=ProviderResultKind.ARTIFACT,
        outcome=ProviderOutcomeV2.CANCELLED,
        reason_codes=(),
        partial_policy=snapshot,
    )
    assert res_cancel.execution_status == ExecutionStatusV2.CANCELLED
    assert res_cancel.commit_eligible is False


def test_provenance_and_headers():
    with pytest.raises(ValueError, match="provider_provenance_timestamp_not_finite"):
        ProviderProvenanceV2(
            implementation_id="impl-1",
            implementation_version="1.0",
            request_digest="sha256:d",
            started_at=float("nan"),
            completed_at=100.0,
        )

    with pytest.raises(ValueError, match="provider_provenance_timestamp_invalid"):
        ProviderProvenanceV2(
            implementation_id="impl-1",
            implementation_version="1.0",
            request_digest="sha256:d",
            started_at=-1.0,
            completed_at=100.0,
        )

    with pytest.raises(ValueError, match="provider_provenance_timestamp_invalid"):
        ProviderProvenanceV2(
            implementation_id="impl-1",
            implementation_version="1.0",
            request_digest="sha256:d",
            started_at=100.0,
            completed_at=50.0,
        )

    prov = ProviderProvenanceV2(
        implementation_id="impl-1",
        implementation_version="1.0",
        request_digest="sha256:d",
        started_at=10.0,
        completed_at=20.0,
    )

    with pytest.raises(ValueError, match="provider_result_schema_version_invalid"):
        ProviderResultHeaderV2(
            schema_version="1.0",  # type: ignore
            provider_id="prov-1",
            outcome=ProviderOutcomeV2.SUCCEEDED,
            reason_codes=(),
            duration_ms=10,
            provenance=prov,
        )

    with pytest.raises(ValueError, match="provider_result_outcome_invalid"):
        ProviderResultHeaderV2(
            schema_version="2.0",
            provider_id="prov-1",
            outcome="NOT_AN_OUTCOME",  # type: ignore
            reason_codes=(),
            duration_ms=10,
            provenance=prov,
        )

    with pytest.raises(ValueError, match="provider_result_duration_invalid"):
        ProviderResultHeaderV2(
            schema_version="2.0",
            provider_id="prov-1",
            outcome=ProviderOutcomeV2.SUCCEEDED,
            reason_codes=(),
            duration_ms=-1,
            provenance=prov,
        )


def test_sensitive_batch_handle_validations():
    with pytest.raises(TypeError, match="sensitive_batch_handle_implementation_invalid"):
        SensitiveBatchHandleV2(
            schema_id="s1",
            transaction_id="tx-1",
            factory_id="f1",
            factory_provenance_digest="sha256:d",
            handle_id="h1",
            item_count=1,
            total_bytes=10,
            integrity_tag=MagicMock(),
            handle="not_a_handle",  # type: ignore
        )


def test_partial_outcomes_and_handle_repr():
    from core.actions.provider_results import (
        PartialCommitDispositionV2,
        PartialCommitPolicySnapshotV2,
        PartialCommitRuleV2,
        ProviderOutcomeNormalizerV2,
        ProviderOutcomeV2,
        ProviderResultKind,
        canonical_partial_commit_policy_digest,
    )

    class MockRegistry:
        def assert_current(self, snapshot):
            pass

    rule = PartialCommitRuleV2("act-1", ProviderResultKind.ARTIFACT, ("r1",))
    snap_base = PartialCommitPolicySnapshotV2(
        policy_id="pol-1",
        revision=1,
        rules=(rule,),
        policy_digest="",
    )
    digest = canonical_partial_commit_policy_digest(snap_base)
    snap = PartialCommitPolicySnapshotV2(
        policy_id="pol-1",
        revision=1,
        rules=(rule,),
        policy_digest=digest,
    )

    # Policy accepts partial
    policy_accept = MagicMock()
    policy_accept.decide.return_value = PartialCommitDispositionV2.ACCEPT
    normalizer1 = ProviderOutcomeNormalizerV2(policy=policy_accept, registry=MockRegistry())  # type: ignore
    norm1 = normalizer1.normalize(
        action_id="act-1",
        result_kind=ProviderResultKind.ARTIFACT,
        outcome=ProviderOutcomeV2.PARTIAL,
        reason_codes=("r1",),
        partial_policy=snap,
    )
    assert norm1.commit_eligible is True
    assert norm1.execution_status == ExecutionStatusV2.PARTIAL

    # Policy denies partial
    policy_deny = MagicMock()
    policy_deny.decide.return_value = PartialCommitDispositionV2.REJECT
    normalizer2 = ProviderOutcomeNormalizerV2(policy=policy_deny, registry=MockRegistry())  # type: ignore
    norm2 = normalizer2.normalize(
        action_id="act-1",
        result_kind=ProviderResultKind.ARTIFACT,
        outcome=ProviderOutcomeV2.PARTIAL,
        reason_codes=("r1",),
        partial_policy=snap,
    )
    assert norm2.commit_eligible is False
    assert norm2.execution_status == ExecutionStatusV2.FAILED
