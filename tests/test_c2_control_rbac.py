"""Tests for C2 control RBAC policy."""

from __future__ import annotations

import time

import pytest

from core.c2.control_auth import AuthenticatedControlPrincipal, OperatorRole
from core.c2.control_commands import C2ControlActionV1
from core.c2.control_peer import PeerPrincipal
from core.c2.control_rbac import ControlRBACPolicy

pytestmark = pytest.mark.unit


def test_rbac_admin_full_access():
    policy = ControlRBACPolicy()
    principal = AuthenticatedControlPrincipal(
        operator_id="op_admin",
        subject_id="sub_admin",
        role=OperatorRole.ADMIN,
        peer=PeerPrincipal(pid=1, uid=0, gid=0),
        mission_id="m1",
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        authenticated_at=time.time(),
        expires_at=time.time() + 3600,
    )

    assert policy.evaluate(principal, C2ControlActionV1.PING) is True
    assert policy.evaluate(principal, C2ControlActionV1.MANAGE_OPERATORS_CREATE) is True
    assert policy.evaluate(principal, C2ControlActionV1.REVOKE_ENROLLMENT) is True


def test_rbac_operator_restricted_access():
    policy = ControlRBACPolicy()
    principal = AuthenticatedControlPrincipal(
        operator_id="op_normal",
        subject_id="sub_normal",
        role=OperatorRole.OPERATOR,
        peer=PeerPrincipal(pid=1, uid=100, gid=100),
        mission_id="m1",
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        authenticated_at=time.time(),
        expires_at=time.time() + 3600,
    )

    assert policy.evaluate(principal, C2ControlActionV1.PING) is True
    assert policy.evaluate(principal, C2ControlActionV1.PREPARE_ENROLLMENT_DEPLOYMENT) is True
    # Admin-only operator management actions denied
    assert policy.evaluate(principal, C2ControlActionV1.MANAGE_OPERATORS_CREATE) is False
    assert policy.evaluate(principal, C2ControlActionV1.MANAGE_OPERATORS_DEACTIVATE) is False


def test_rbac_readonly_access():
    policy = ControlRBACPolicy()
    principal = AuthenticatedControlPrincipal(
        operator_id="op_ro",
        subject_id="sub_ro",
        role=OperatorRole.READONLY,
        peer=PeerPrincipal(pid=1, uid=200, gid=200),
        mission_id="m1",
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        authenticated_at=time.time(),
        expires_at=time.time() + 3600,
    )

    assert policy.evaluate(principal, C2ControlActionV1.PING) is True
    assert policy.evaluate(principal, C2ControlActionV1.LIST_AGENTS) is True
    assert policy.evaluate(principal, C2ControlActionV1.CANCEL_TASK) is False
