"""Unit tests for edge cases and validations in reference_authorization.py."""

from __future__ import annotations

import pytest

from core.actions.reference_authorization import (
    ReferenceAuthorizationError,
    ReferenceAuthorizationSnapshot,
    _require_non_empty,
    _require_unique_strings,
    assert_reference_authorized,
)
from core.actions.reference_snapshots import CredentialReferenceSnapshot
from core.actions.target_scope import (
    ExtractedActionTarget,
    TargetKind,
    TargetRole,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.types import SubjectType
from core.credentials import CredentialAuthKind

pytestmark = pytest.mark.unit


def test_reference_authorization_helpers_and_snapshot_errors():
    with pytest.raises(ValueError, match="reference_authorization_name_invalid"):
        _require_non_empty("name", "")

    with pytest.raises(ValueError, match="reference_authorization_name_invalid"):
        _require_unique_strings("name", ["not_a_tuple"])  # type: ignore

    scope = TargetScopeSnapshot(
        schema_version="2.0",
        revision=1,
        rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
    )

    with pytest.raises(ValueError, match="reference_authorization_schema_version_unsupported"):
        ReferenceAuthorizationSnapshot(
            schema_version="1.0",
            reference="cred://1",
            authorization_revision=1,
            mission_id="m-1",
            owner_subject_id="s-1",
            owner_subject_type=SubjectType.OPERATOR,
            permitted_subject_ids=("s-1",),
            permitted_action_ids=("act-1",),
            permitted_capabilities=("cap1",),
            authorization_scope=scope,
            created_by_request_id="req-1",
            delegated_by_subject_id=None,
            expires_at=2000.0,
        )

    with pytest.raises(ValueError, match="reference_authorization_revision_invalid"):
        ReferenceAuthorizationSnapshot(
            schema_version="2.0",
            reference="cred://1",
            authorization_revision=0,
            mission_id="m-1",
            owner_subject_id="s-1",
            owner_subject_type=SubjectType.OPERATOR,
            permitted_subject_ids=("s-1",),
            permitted_action_ids=("act-1",),
            permitted_capabilities=("cap1",),
            authorization_scope=scope,
            created_by_request_id="req-1",
            delegated_by_subject_id=None,
            expires_at=2000.0,
        )

    with pytest.raises(ValueError, match="reference_authorization_scope_invalid"):
        ReferenceAuthorizationSnapshot(
            schema_version="2.0",
            reference="cred://1",
            authorization_revision=1,
            mission_id="m-1",
            owner_subject_id="s-1",
            owner_subject_type=SubjectType.OPERATOR,
            permitted_subject_ids=("s-1",),
            permitted_action_ids=("act-1",),
            permitted_capabilities=("cap1",),
            authorization_scope="not_a_scope",  # type: ignore
            created_by_request_id="req-1",
            delegated_by_subject_id=None,
            expires_at=2000.0,
        )

    with pytest.raises(ValueError, match="reference_authorization_delegated_by_subject_id_invalid"):
        ReferenceAuthorizationSnapshot(
            schema_version="2.0",
            reference="cred://1",
            authorization_revision=1,
            mission_id="m-1",
            owner_subject_id="s-1",
            owner_subject_type=SubjectType.OPERATOR,
            permitted_subject_ids=("s-1",),
            permitted_action_ids=("act-1",),
            permitted_capabilities=("cap1",),
            authorization_scope=scope,
            created_by_request_id="req-1",
            delegated_by_subject_id="",
            expires_at=2000.0,
        )

    with pytest.raises(ValueError, match="reference_authorization_expiry_invalid"):
        ReferenceAuthorizationSnapshot(
            schema_version="2.0",
            reference="cred://1",
            authorization_revision=1,
            mission_id="m-1",
            owner_subject_id="s-1",
            owner_subject_type=SubjectType.OPERATOR,
            permitted_subject_ids=("s-1",),
            permitted_action_ids=("act-1",),
            permitted_capabilities=("cap1",),
            authorization_scope=scope,
            created_by_request_id="req-1",
            delegated_by_subject_id=None,
            expires_at=float("nan"),
        )


def test_assert_reference_authorized_validations():
    scope = TargetScopeSnapshot(
        schema_version="2.0",
        revision=1,
        rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
    )
    auth = ReferenceAuthorizationSnapshot(
        schema_version="2.0",
        reference="cred://1",
        authorization_revision=1,
        mission_id="m-1",
        owner_subject_id="s-1",
        owner_subject_type=SubjectType.OPERATOR,
        permitted_subject_ids=("s-1",),
        permitted_action_ids=("act-1",),
        permitted_capabilities=("cap1",),
        authorization_scope=scope,
        created_by_request_id="req-1",
        delegated_by_subject_id=None,
        expires_at=2000.0,
    )
    meta = CredentialReferenceSnapshot(
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
    target = ExtractedActionTarget(role=TargetRole.PRIMARY, kind=TargetKind.IPV4, normalized_value="10.0.0.1")

    with pytest.raises(ReferenceAuthorizationError, match="reference_mission_id_invalid"):
        assert_reference_authorized(
            meta,
            expected_metadata_revision=1,
            expected_authorization_revision=1,
            mission_id="",
            subject_id="s-1",
            action_id="act-1",
            required_capability="cap1",
            targets=(target,),
        )

    with pytest.raises(ReferenceAuthorizationError, match="reference_targets_invalid"):
        assert_reference_authorized(
            meta,
            expected_metadata_revision=1,
            expected_authorization_revision=1,
            mission_id="m-1",
            subject_id="s-1",
            action_id="act-1",
            required_capability="cap1",
            targets=["not_a_tuple"],  # type: ignore
        )

    with pytest.raises(ReferenceAuthorizationError, match="reference_authorization_time_invalid"):
        assert_reference_authorized(
            meta,
            expected_metadata_revision=1,
            expected_authorization_revision=1,
            mission_id="m-1",
            subject_id="s-1",
            action_id="act-1",
            required_capability="cap1",
            targets=(target,),
            now=float("nan"),
        )
