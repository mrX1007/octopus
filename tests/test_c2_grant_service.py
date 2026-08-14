"""Revisioned peer/mission grant lifecycle tests."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from core.c2.control_auth import ControlAuthenticatorV1
from core.c2.control_peer import PeerPrincipal
from core.c2.grant_service import (
    SYSTEM_CONTROL_MISSION_ID,
    GrantConflictError,
    GrantService,
    PeerBinding,
    insert_initial_bootstrap_grants,
)
from core.c2.operators import ROLE_ADMIN, ROLE_OPERATOR, OperatorManager

pytestmark = pytest.mark.unit


def _setup(tmp_path: Path):
    db_path = tmp_path / "c2.db"
    operators = OperatorManager(str(db_path))
    admin_key = operators.create_operator(
        "admin",
        ROLE_ADMIN,
        subject_id="subject:admin",
    )
    target_key = operators.create_operator(
        "operator",
        ROLE_OPERATOR,
        subject_id="subject:operator",
    )
    admin = operators.authenticate(admin_key)
    target = operators.authenticate(target_key)
    assert admin is not None and target is not None
    grants = GrantService(str(db_path))
    with sqlite3.connect(db_path) as connection:
        insert_initial_bootstrap_grants(
            connection,
            operator_id=str(admin["operator_id"]),
            subject_id="subject:admin",
            peer_uid=0,
            peer_gid=0,
        )
        connection.execute(
            """
            INSERT INTO control_missions (mission_id, mission_kind, active, created_at)
            VALUES ('mission:test', 'operational', 1, ?)
            """,
            (time.time(),),
        )
    authenticator = ControlAuthenticatorV1(operators, grants)
    admin_principal = authenticator.authenticate_control(
        api_key=admin_key,
        peer=PeerPrincipal(10, 0, 0),
        mission_id=SYSTEM_CONTROL_MISSION_ID,
        subject_id="subject:admin",
    )
    return operators, grants, authenticator, admin_principal, target_key, target


def _grant_target(
    grants: GrantService,
    admin_principal,
    target_id: str,
) -> None:
    assert (
        grants.sync_operator_peer_bindings(
            admin_principal,
            operator_id=target_id,
            bindings=(PeerBinding(1000, 1001),),
            expected_revision=0,
        )
        == 1
    )
    assert (
        grants.sync_operator_mission_grants(
            admin_principal,
            operator_id=target_id,
            mission_ids=("mission:test",),
            expected_revision=0,
        )
        == 1
    )


def test_admin_sync_peer_bindings_revisioned(tmp_path: Path) -> None:
    _, grants, _, admin, _, target = _setup(tmp_path)
    target_id = str(target["operator_id"])
    revision = grants.sync_operator_peer_bindings(
        admin,
        operator_id=target_id,
        bindings=(PeerBinding(1000, 1001),),
        expected_revision=0,
    )
    assert revision == 1
    assert grants.resolve_peer_binding(target_id, uid=1000, gid=1001).revision == 1  # type: ignore[union-attr]
    assert (
        grants.sync_operator_peer_bindings(
            admin,
            operator_id=target_id,
            bindings=(PeerBinding(1000, 1001),),
            expected_revision=1,
        )
        == 1
    )
    with pytest.raises(GrantConflictError):
        grants.sync_operator_peer_bindings(
            admin,
            operator_id=target_id,
            bindings=(PeerBinding(2000, 2001),),
            expected_revision=0,
        )


def test_admin_revoke_peer_binding_invalidates_new_ingress(tmp_path: Path) -> None:
    _, grants, auth, admin, target_key, target = _setup(tmp_path)
    target_id = str(target["operator_id"])
    _grant_target(grants, admin, target_id)
    peer = PeerPrincipal(20, 1000, 1001)
    principal = auth.authenticate_control(
        api_key=target_key,
        peer=peer,
        mission_id="mission:test",
        subject_id="subject:operator",
    )
    assert (
        grants.revoke_operator_peer_binding(
            admin,
            operator_id=target_id,
            binding=PeerBinding(1000, 1001),
            expected_revision=1,
        )
        == 2
    )
    assert not auth.is_current_principal(principal)
    with pytest.raises(PermissionError, match="peer UID/GID"):
        auth.authenticate_control(
            api_key=target_key,
            peer=peer,
            mission_id="mission:test",
            subject_id="subject:operator",
        )


def test_admin_sync_mission_grants_revisioned(tmp_path: Path) -> None:
    _, grants, _, admin, _, target = _setup(tmp_path)
    target_id = str(target["operator_id"])
    revision = grants.sync_operator_mission_grants(
        admin,
        operator_id=target_id,
        mission_ids=("mission:test",),
        expected_revision=0,
    )
    assert revision == 1
    grant = grants.resolve_mission_grant(
        target_id,
        subject_id="subject:operator",
        mission_id="mission:test",
    )
    assert grant is not None and grant.revision == 1


def test_admin_revoke_mission_grant_invalidates_child_reentry(tmp_path: Path) -> None:
    _, grants, auth, admin, target_key, target = _setup(tmp_path)
    target_id = str(target["operator_id"])
    _grant_target(grants, admin, target_id)
    principal = auth.authenticate_control(
        api_key=target_key,
        peer=PeerPrincipal(20, 1000, 1001),
        mission_id="mission:test",
        subject_id="subject:operator",
    )
    assert (
        grants.revoke_operator_mission_grant(
            admin,
            operator_id=target_id,
            mission_id="mission:test",
            expected_revision=1,
        )
        == 2
    )
    assert not auth.is_current_principal(principal)
    with pytest.raises(PermissionError, match="mission grant"):
        auth.authenticate_control(
            api_key=target_key,
            peer=PeerPrincipal(20, 1000, 1001),
            mission_id="mission:test",
            subject_id="subject:operator",
        )


def test_grant_mutations_require_current_admin_principal(tmp_path: Path) -> None:
    _, grants, auth, admin, target_key, target = _setup(tmp_path)
    target_id = str(target["operator_id"])
    _grant_target(grants, admin, target_id)
    operator_principal = auth.authenticate_control(
        api_key=target_key,
        peer=PeerPrincipal(20, 1000, 1001),
        mission_id="mission:test",
        subject_id="subject:operator",
    )
    with pytest.raises(PermissionError, match="administrator"):
        grants.sync_operator_peer_bindings(
            operator_principal,
            operator_id=target_id,
            bindings=(),
            expected_revision=1,
        )
