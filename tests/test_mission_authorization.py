"""Exact mission authorization snapshot tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from core.actions.target_scope import TargetKind, TargetScopeRule, TargetScopeSnapshot
from core.auth.missions import MissionAuthorizationSnapshot

pytestmark = pytest.mark.unit


def _snapshot() -> MissionAuthorizationSnapshot:
    return MissionAuthorizationSnapshot(
        schema_version="2.0",
        mission_ref="mission://one",
        revision=2,
        mission_id="mission-1",
        active=True,
        permitted_subject_ids=("subject-1",),
        target_scope=TargetScopeSnapshot(
            schema_version="2.0",
            revision=4,
            rules=(TargetScopeRule(None, TargetKind.FQDN, "target.example"),),
        ),
        permitted_capabilities=("capability-1",),
        permitted_stages=("stage-1",),
        expires_at=100.0,
    )


def test_mission_authorization_snapshot_exact_fields() -> None:
    snapshot = _snapshot()
    assert set(snapshot.__dataclass_fields__) == {
        "schema_version",
        "mission_ref",
        "revision",
        "mission_id",
        "active",
        "permitted_subject_ids",
        "target_scope",
        "permitted_capabilities",
        "permitted_stages",
        "expires_at",
    }
    with pytest.raises(FrozenInstanceError):
        snapshot.active = False  # type: ignore[misc]


def test_mission_scope_is_typed_not_string_tuple() -> None:
    with pytest.raises(ValueError, match="scope"):
        MissionAuthorizationSnapshot(
            schema_version="2.0",
            mission_ref="mission://one",
            revision=1,
            mission_id="mission-1",
            active=True,
            permitted_subject_ids=("subject-1",),
            target_scope=("target.example",),  # type: ignore[arg-type]
            permitted_capabilities=(),
            permitted_stages=(),
            expires_at=None,
        )
