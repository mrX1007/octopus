"""Comprehensive unit test coverage for trusted_facts, request_v2, and reference_authorization."""

from __future__ import annotations

import json
import pytest

from core.actions.reference_authorization import (
    ReferenceAuthorizationError,
    ReferenceAuthorizationSnapshot,
    assert_reference_authorized,
)
from core.actions.reference_snapshots import CredentialReferenceSnapshot
from core.actions.request_v2 import (
    ActionRequestV2,
    ActionRequestV2EnvelopeDecoder,
    ActionRequestV2EnvelopeValidationError,
    BoundedActionRequestV2Envelope,
    BoundedTypedInputPayloadV2,
)
from core.actions.target_scope import (
    ExtractedActionTarget,
    TargetKind,
    TargetRole,
    TargetScopeCanonicalizer,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.actions.trusted_facts import (
    AssessmentStatus,
    EvidenceCoverageStatus,
    FactFreshnessStatus,
    StoredFactRecord,
    TrustedFactDecoder,
    TrustedFactSnapshot,
    TrustedFactTrustLevelV2,
    TrustedFactType,
    canonical_stored_fact_payload_digest,
)
from core.auth.types import SubjectType
from core.credentials import CredentialAuthKind

pytestmark = pytest.mark.unit


def test_trusted_fact_decoder_and_digest():
    record_raw = StoredFactRecord(
        schema_version="2.0",
        fact_ref="fact://1",
        revision=1,
        mission_id="m1",
        target="10.0.0.1",
        fact_type="confirmed_ad_access",
        assessment_status="verified",
        trust_level="trusted",
        freshness_status="fresh",
        coverage_status="complete",
        source_execution_ids=("exec-1",),
        payload_digest="",
        expires_at=None,
    )
    digest = canonical_stored_fact_payload_digest(record_raw)
    assert digest.startswith("sha256:")

    valid_record = StoredFactRecord(
        schema_version="2.0",
        fact_ref="fact://1",
        revision=1,
        mission_id="m1",
        target="10.0.0.1",
        fact_type="confirmed_ad_access",
        assessment_status="verified",
        trust_level="trusted",
        freshness_status="fresh",
        coverage_status="complete",
        source_execution_ids=("exec-1",),
        payload_digest=digest,
        expires_at=None,
    )

    decoder = TrustedFactDecoder()
    snap = decoder.decode(valid_record, expected_ref="fact://1")
    assert snap.fact_ref == "fact://1"
    assert snap.satisfies_positive_precondition is True

    # Error conditions
    with pytest.raises(ValueError, match="trusted fact reference mismatch"):
        decoder.decode(valid_record, expected_ref="fact://wrong")

    with pytest.raises(ValueError, match="trusted fact payload digest mismatch"):
        bad_digest_record = StoredFactRecord(
            schema_version="2.0",
            fact_ref="fact://1",
            revision=1,
            mission_id="m1",
            target="10.0.0.1",
            fact_type="confirmed_ad_access",
            assessment_status="verified",
            trust_level="trusted",
            freshness_status="fresh",
            coverage_status="complete",
            source_execution_ids=("exec-1",),
            payload_digest="sha256:wrong",
            expires_at=None,
        )
        decoder.decode(bad_digest_record, expected_ref="fact://1")


def test_action_request_v2_envelope_decoder_errors():
    # Non-bytes
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="Envelope must be serialized bytes"):
        ActionRequestV2EnvelopeDecoder.decode("not bytes")  # type: ignore

    # Non-JSON
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="Invalid JSON envelope"):
        ActionRequestV2EnvelopeDecoder.decode(b"{invalid-json")

    # Forbidden authority field
    forbidden_payload = {
        "schema_version": "2.0",
        "request_id": "req-1",
        "mission_ref": "m-1",
        "approval_ref": None,
        "precondition_fact_refs": [],
        "idempotency_key": None,
        "typed_input": {"schema_id": "octopus:input:test:2.0"},
        "approved": True,  # Authority field!
    }
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="Forbidden authority field"):
        ActionRequestV2EnvelopeDecoder.decode(json.dumps(forbidden_payload).encode("utf-8"))

    # Missing fields
    missing_payload = {
        "schema_version": "2.0",
        "request_id": "req-1",
    }
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="Missing envelope fields"):
        ActionRequestV2EnvelopeDecoder.decode(json.dumps(missing_payload).encode("utf-8"))

    # Unsupported schema_version
    bad_schema = {
        "schema_version": "1.0",
        "request_id": "req-1",
        "mission_ref": "m-1",
        "approval_ref": None,
        "precondition_fact_refs": [],
        "idempotency_key": None,
        "typed_input": {"schema_id": "octopus:input:test:2.0"},
    }
    with pytest.raises(ActionRequestV2EnvelopeValidationError, match="Unsupported schema_version"):
        ActionRequestV2EnvelopeDecoder.decode(json.dumps(bad_schema).encode("utf-8"))


def test_reference_authorization_assert_authorized():
    target = TargetScopeCanonicalizer.canonicalize("10.0.0.1", role=TargetRole.PRIMARY)
    scope = TargetScopeSnapshot(
        schema_version="2.0",
        revision=1,
        rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
    )
    auth = ReferenceAuthorizationSnapshot(
        schema_version="2.0",
        reference="cred://1",
        authorization_revision=1,
        mission_id="m1",
        owner_subject_id="s1",
        owner_subject_type=SubjectType.OPERATOR,
        permitted_subject_ids=("s1", "s2"),
        permitted_action_ids=("act1",),
        permitted_capabilities=("cap1",),
        authorization_scope=scope,
        created_by_request_id="req1",
        delegated_by_subject_id=None,
        expires_at=2000.0,
    )
    metadata = CredentialReferenceSnapshot(
        reference="cred://1",
        revision=1,
        authorization=auth,
        target="10.0.0.1",
        service="ssh",
        username="root",
        domain="",
        auth_kind=CredentialAuthKind.PASSWORD,
        port=22,
        verified=True,
        expires_at=2000.0,
    )

    # Valid authorization
    assert_reference_authorized(
        metadata,
        expected_metadata_revision=1,
        expected_authorization_revision=1,
        mission_id="m1",
        subject_id="s1",
        action_id="act1",
        required_capability="cap1",
        targets=(target,),
        now=1000.0,
    )

    # Subject denied
    with pytest.raises(ReferenceAuthorizationError, match="reference_subject_denied"):
        assert_reference_authorized(
            metadata,
            expected_metadata_revision=1,
            expected_authorization_revision=1,
            mission_id="m1",
            subject_id="unauthorized_sub",
            action_id="act1",
            required_capability="cap1",
            targets=(target,),
            now=1000.0,
        )

    # Action denied
    with pytest.raises(ReferenceAuthorizationError, match="reference_action_denied"):
        assert_reference_authorized(
            metadata,
            expected_metadata_revision=1,
            expected_authorization_revision=1,
            mission_id="m1",
            subject_id="s1",
            action_id="unauthorized_action",
            required_capability="cap1",
            targets=(target,),
            now=1000.0,
        )

    # Expired
    with pytest.raises(ReferenceAuthorizationError, match="reference_authorization_expired"):
        assert_reference_authorized(
            metadata,
            expected_metadata_revision=1,
            expected_authorization_revision=1,
            mission_id="m1",
            subject_id="s1",
            action_id="act1",
            required_capability="cap1",
            targets=(target,),
            now=3000.0,
        )


def test_trusted_fact_snapshot_and_decoder_edge_cases():
    decoder = TrustedFactDecoder()

    # Non StoredFactRecord decode
    with pytest.raises(TypeError, match="stored fact must be an exact StoredFactRecord"):
        decoder.decode("not_a_record", expected_ref="fact://1")  # type: ignore

    # Non StoredFactRecord canonical digest
    with pytest.raises(TypeError, match="stored fact must be an exact StoredFactRecord"):
        canonical_stored_fact_payload_digest("not_a_record")  # type: ignore

    # Schema version unsupported
    bad_schema = StoredFactRecord(
        schema_version="1.0",
        fact_ref="fact://1",
        revision=1,
        mission_id="m1",
        target="10.0.0.1",
        fact_type="confirmed_ad_access",
        assessment_status="verified",
        trust_level="trusted",
        freshness_status="fresh",
        coverage_status="complete",
        source_execution_ids=("exec-1",),
        payload_digest="",
        expires_at=None,
    )
    with pytest.raises(ValueError, match="trusted fact schema version is unsupported"):
        decoder.decode(bad_schema, expected_ref="fact://1")

    # Invalid revision
    bad_rev = StoredFactRecord(
        schema_version="2.0",
        fact_ref="fact://1",
        revision=0,
        mission_id="m1",
        target="10.0.0.1",
        fact_type="confirmed_ad_access",
        assessment_status="verified",
        trust_level="trusted",
        freshness_status="fresh",
        coverage_status="complete",
        source_execution_ids=("exec-1",),
        payload_digest="",
        expires_at=None,
    )
    with pytest.raises(ValueError, match="trusted fact revision is invalid"):
        decoder.decode(bad_rev, expected_ref="fact://1")

    # Duplicate source execution ids
    bad_sources = StoredFactRecord(
        schema_version="2.0",
        fact_ref="fact://1",
        revision=1,
        mission_id="m1",
        target="10.0.0.1",
        fact_type="confirmed_ad_access",
        assessment_status="verified",
        trust_level="trusted",
        freshness_status="fresh",
        coverage_status="complete",
        source_execution_ids=("exec-1", "exec-1"),
        payload_digest="",
        expires_at=None,
    )
    with pytest.raises(ValueError, match="trusted fact source executions contain duplicates"):
        decoder.decode(bad_sources, expected_ref="fact://1")
