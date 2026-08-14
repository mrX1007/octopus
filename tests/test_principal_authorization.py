"""Exact principal authorization snapshot tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from core.auth.principals import PrincipalAuthorizationSnapshot
from core.auth.types import SubjectType

pytestmark = pytest.mark.unit


def _snapshot() -> PrincipalAuthorizationSnapshot:
    return PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="principal://one",
        revision=3,
        subject_id="subject-1",
        subject_type=SubjectType.OPERATOR,
        active=True,
        roles=("operator",),
        capabilities=("capability-1",),
        authenticated_at=10.0,
        expires_at=20.0,
    )


def test_principal_authorization_snapshot_exact_fields() -> None:
    snapshot = _snapshot()
    assert set(snapshot.__dataclass_fields__) == {
        "schema_version",
        "principal_ref",
        "revision",
        "subject_id",
        "subject_type",
        "active",
        "roles",
        "capabilities",
        "authenticated_at",
        "expires_at",
    }
    with pytest.raises(FrozenInstanceError):
        snapshot.active = False  # type: ignore[misc]


def test_principal_authorization_rejects_caller_boolean_shape() -> None:
    with pytest.raises(TypeError):
        PrincipalAuthorizationSnapshot(principal=object(), authorized=True)  # type: ignore[call-arg]
