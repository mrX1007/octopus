"""Operator authority comes from verified storage, never request claims."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from core.c2.control_auth import ControlAuthenticatorV1, OperatorRole
from core.c2.control_peer import PeerPrincipal
from core.c2.grant_service import GrantService, insert_initial_bootstrap_grants
from core.c2.operators import ROLE_READONLY, OperatorManager

pytestmark = pytest.mark.unit


def test_verified_readonly_key_cannot_claim_admin_role(tmp_path: Path) -> None:
    db_path = tmp_path / "c2.db"
    operators = OperatorManager(str(db_path))
    key = operators.create_operator(
        "viewer",
        ROLE_READONLY,
        subject_id="subject:viewer",
    )
    record = operators.authenticate(key)
    assert record is not None
    grants = GrantService(str(db_path))
    with sqlite3.connect(db_path) as connection:
        insert_initial_bootstrap_grants(
            connection,
            operator_id=str(record["operator_id"]),
            subject_id="subject:viewer",
            peer_uid=1000,
            peer_gid=1000,
        )
    auth = ControlAuthenticatorV1(operators, grants)
    with pytest.raises(PermissionError, match="request-supplied"):
        auth.authenticate_control(
            api_key=key,
            peer=PeerPrincipal(1, 1000, 1000),
            mission_id="system://c2-control",
            subject_id="subject:viewer",
            claimed_role=OperatorRole.ADMIN,
        )
    principal = auth.authenticate_control(
        api_key=key,
        peer=PeerPrincipal(1, 1000, 1000),
        mission_id="system://c2-control",
        subject_id="subject:viewer",
    )
    assert principal.role is OperatorRole.READONLY
    assert auth.check_permission(principal, "list_results")
    assert not auth.check_permission(principal, "ack_results")
