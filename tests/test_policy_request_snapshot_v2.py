"""Exact V2 policy request snapshot tests."""

from __future__ import annotations

import pytest

from core.actions.policy_snapshots import ActionPolicyRequestHeaderV2, ActionPolicyRequestSnapshot
from core.actions.target_scope import TargetKind, TargetScopeRule, TargetScopeSnapshot
from core.auth.missions import MissionAuthorizationSnapshot
from core.auth.principals import PrincipalAuthorizationSnapshot
from core.auth.types import SubjectType

pytestmark = pytest.mark.unit


def _principal() -> PrincipalAuthorizationSnapshot:
    return PrincipalAuthorizationSnapshot(
        schema_version="2.0",
        principal_ref="principal://one",
        revision=1,
        subject_id="subject-1",
        subject_type=SubjectType.OPERATOR,
        active=True,
        roles=("operator",),
        capabilities=("capability-1",),
        authenticated_at=10.0,
        expires_at=None,
    )


def _mission() -> MissionAuthorizationSnapshot:
    return MissionAuthorizationSnapshot(
        schema_version="2.0",
        mission_ref="mission://one",
        revision=1,
        mission_id="mission-1",
        active=True,
        permitted_subject_ids=("subject-1",),
        target_scope=TargetScopeSnapshot(
            "2.0",
            1,
            (TargetScopeRule(None, TargetKind.FQDN, "target.example"),),
        ),
        permitted_capabilities=("capability-1",),
        permitted_stages=("stage-1",),
        expires_at=None,
    )


def test_action_policy_request_header_exact_fields() -> None:
    header = ActionPolicyRequestHeaderV2(
        schema_version="2.0",
        request_id="request-1",
        action_id="plugin:leaf",
        root_action_id="plugin:router",
        parent_action_id="plugin:router",
        execution_graph_id="graph-1",
        capability_class="capability-1",
        killchain_stage="stage-1",
        operation_id="run",
    )
    assert set(header.__dataclass_fields__) == {
        "schema_version",
        "request_id",
        "action_id",
        "root_action_id",
        "parent_action_id",
        "execution_graph_id",
        "capability_class",
        "killchain_stage",
        "operation_id",
    }


def test_action_policy_request_snapshot_finalized_in_pr4() -> None:
    header = ActionPolicyRequestHeaderV2(
        schema_version="2.0",
        request_id="request-1",
        action_id="plugin:leaf",
        root_action_id="plugin:leaf",
        parent_action_id=None,
        execution_graph_id="graph-1",
        capability_class="capability-1",
        killchain_stage="stage-1",
        operation_id=None,
    )
    snapshot = ActionPolicyRequestSnapshot(
        header=header,
        targets=(),
        principal=_principal(),
        mission=_mission(),
        approval=None,
        facts=(),
        references=(),
    )
    assert set(snapshot.__dataclass_fields__) == {
        "header",
        "targets",
        "principal",
        "mission",
        "approval",
        "facts",
        "references",
    }
