"""Fail-closed reference ACL and revision tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from core.actions.reference_authorization import (
    ReferenceAuthorizationError,
    ReferenceAuthorizationSnapshot,
    assert_reference_authorized,
)
from core.actions.reference_snapshots import CredentialReferenceSnapshot
from core.actions.target_scope import (
    NetworkProtocol,
    TargetKind,
    TargetRole,
    TargetScopeCanonicalizer,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.types import SubjectType
from core.credentials import CredentialAuthKind

pytestmark = pytest.mark.unit


def _target(address: str = "192.0.2.10"):
    return TargetScopeCanonicalizer.canonicalize(
        address,
        role=TargetRole.PRIMARY,
        port=22,
        protocol=NetworkProtocol.SSH,
    )


def _scope() -> TargetScopeSnapshot:
    return TargetScopeSnapshot(
        schema_version="2.0",
        revision=1,
        rules=(
            TargetScopeRule(
                role=TargetRole.PRIMARY,
                kind=TargetKind.IPV4,
                normalized_value="192.0.2.10",
                port=22,
                protocol=NetworkProtocol.SSH,
            ),
        ),
    )


def _authorization(**overrides: object) -> ReferenceAuthorizationSnapshot:
    values: dict[str, object] = {
        "schema_version": "2.0",
        "reference": "credential://one",
        "authorization_revision": 2,
        "mission_id": "mission-1",
        "owner_subject_id": "owner-1",
        "owner_subject_type": SubjectType.OPERATOR,
        "permitted_subject_ids": ("delegate-1",),
        "permitted_action_ids": ("ssh:connect",),
        "permitted_capabilities": ("remote_session",),
        "authorization_scope": _scope(),
        "created_by_request_id": "request-1",
        "delegated_by_subject_id": None,
        "expires_at": 200.0,
    }
    values.update(overrides)
    return ReferenceAuthorizationSnapshot(**values)  # type: ignore[arg-type]


def _metadata(**overrides: object) -> CredentialReferenceSnapshot:
    values: dict[str, object] = {
        "reference": "credential://one",
        "revision": 3,
        "authorization": _authorization(),
        "target": "192.0.2.10",
        "service": "ssh",
        "username": "alice",
        "domain": "",
        "auth_kind": CredentialAuthKind.PASSWORD,
        "port": 22,
        "verified": True,
        "expires_at": 180.0,
    }
    values.update(overrides)
    return CredentialReferenceSnapshot(**values)  # type: ignore[arg-type]


def _assert(metadata: CredentialReferenceSnapshot, *, subject_id: str = "owner-1", **overrides: object) -> None:
    values: dict[str, object] = {
        "expected_metadata_revision": 3,
        "expected_authorization_revision": 2,
        "mission_id": "mission-1",
        "subject_id": subject_id,
        "action_id": "ssh:connect",
        "required_capability": "remote_session",
        "targets": (_target(),),
        "now": 100.0,
    }
    values.update(overrides)
    assert_reference_authorized(metadata, **values)  # type: ignore[arg-type]


def test_authorization_snapshot_is_exact_and_frozen() -> None:
    snapshot = _authorization()
    with pytest.raises(FrozenInstanceError):
        snapshot.mission_id = "other"  # type: ignore[misc]


@pytest.mark.parametrize("subject_id", ["owner-1", "delegate-1"])
def test_owner_and_permitted_subject_can_use_reference(subject_id: str) -> None:
    _assert(_metadata(), subject_id=subject_id)


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"subject_id": "stranger"}, "reference_subject_denied"),
        ({"mission_id": "other-mission"}, "reference_mission_mismatch"),
        ({"action_id": "ssh:other"}, "reference_action_denied"),
        ({"required_capability": "other"}, "reference_capability_denied"),
        ({"targets": (_target("192.0.2.11"),)}, "reference_scope_denied"),
        ({"expected_metadata_revision": 2}, "reference_metadata_revision_mismatch"),
        ({"expected_authorization_revision": 1}, "reference_authorization_revision_mismatch"),
    ],
)
def test_acl_and_revision_mismatches_fail_closed(overrides: dict[str, object], code: str) -> None:
    with pytest.raises(ReferenceAuthorizationError, match=code):
        _assert(_metadata(), **overrides)


def test_authorization_expiry_fails_closed() -> None:
    metadata = _metadata(authorization=_authorization(expires_at=99.0), expires_at=None)
    with pytest.raises(ReferenceAuthorizationError, match="reference_authorization_expired"):
        _assert(metadata)


def test_metadata_expiry_fails_closed() -> None:
    with pytest.raises(ReferenceAuthorizationError, match="reference_metadata_expired"):
        _assert(_metadata(expires_at=99.0))


def test_identity_is_rechecked_by_authorizer() -> None:
    metadata = _metadata()
    object.__setattr__(metadata, "authorization", replace(metadata.authorization, reference="credential://other"))
    with pytest.raises(ReferenceAuthorizationError, match="reference_authorization_identity_mismatch"):
        _assert(metadata)


def test_unknown_or_duplicate_acl_values_are_rejected() -> None:
    with pytest.raises(ValueError, match="permitted_action_ids_duplicate"):
        _authorization(permitted_action_ids=("ssh:connect", "ssh:connect"))
    with pytest.raises(ValueError, match="owner_subject_type"):
        _authorization(owner_subject_type="operator")
