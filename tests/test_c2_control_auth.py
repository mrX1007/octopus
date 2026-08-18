"""Contract tests for C2 control authentication and revision fencing."""

from __future__ import annotations

import sqlite3
from dataclasses import fields
from pathlib import Path

import pytest

from core.c2.control_auth import (
    AuthenticatedControlPrincipal,
    AuthenticatedOperator,
    ControlAuthenticatorV1,
    OperatorRole,
)
from core.c2.control_commands import C2ControlActionV1
from core.c2.control_peer import PeerPrincipal
from core.c2.grant_service import (
    SYSTEM_CONTROL_MISSION_ID,
    GrantService,
    insert_initial_bootstrap_grants,
)
from core.c2.operators import ROLE_ADMIN, OperatorManager

pytestmark = pytest.mark.unit


def _authority(db_path: Path) -> tuple[ControlAuthenticatorV1, str, dict[str, object]]:
    operators = OperatorManager(str(db_path))
    key = operators.create_operator("Alice", ROLE_ADMIN, subject_id="subject:alice")
    record = operators.authenticate(key)
    assert record is not None
    grants = GrantService(str(db_path))
    with sqlite3.connect(db_path) as connection:
        insert_initial_bootstrap_grants(
            connection,
            operator_id=str(record["operator_id"]),
            subject_id=str(record["subject_id"]),
            peer_uid=1000,
            peer_gid=1001,
        )
    return ControlAuthenticatorV1(operators, grants), key, record


def _role_principal(db_path: Path, role: OperatorRole):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    operators = OperatorManager(str(db_path))
    key = operators.create_operator(
        role.value,
        role.value,
        subject_id=f"subject:{role.value}",
    )
    record = operators.authenticate(key)
    assert record is not None
    grants = GrantService(str(db_path))
    with sqlite3.connect(db_path) as connection:
        insert_initial_bootstrap_grants(
            connection,
            operator_id=str(record["operator_id"]),
            subject_id=f"subject:{role.value}",
            peer_uid=1000,
            peer_gid=1001,
        )
    auth = ControlAuthenticatorV1(operators, grants)
    principal = auth.authenticate_control(
        api_key=key,
        peer=PeerPrincipal(1, 1000, 1001),
        mission_id=SYSTEM_CONTROL_MISSION_ID,
        subject_id=f"subject:{role.value}",
    )
    return auth, principal


def test_exact_control_auth_models() -> None:
    assert [item.name for item in fields(AuthenticatedOperator)] == [
        "operator_id",
        "subject_id",
        "name",
        "role",
        "active",
        "authorization_revision",
        "allowed_peer_uids",
        "allowed_peer_gids",
    ]
    assert [item.name for item in fields(AuthenticatedControlPrincipal)] == [
        "operator_id",
        "subject_id",
        "role",
        "peer",
        "mission_id",
        "operator_revision",
        "peer_binding_revision",
        "mission_grant_revision",
        "authenticated_at",
        "expires_at",
    ]


def test_operator_peer_subject_mission_binding(tmp_path: Path) -> None:
    auth, key, record = _authority(tmp_path / "c2.db")
    principal = auth.authenticate_control(
        api_key=key,
        peer=PeerPrincipal(pid=1234, uid=1000, gid=1001),
        mission_id=SYSTEM_CONTROL_MISSION_ID,
        subject_id="subject:alice",
        now=10.0,
    )
    assert principal.operator_id == record["operator_id"]
    assert principal.role is OperatorRole.ADMIN
    assert principal.operator_revision == 1
    assert principal.peer_binding_revision == 1
    assert principal.mission_grant_revision == 1
    assert auth.is_current_principal(principal, now=11.0)


@pytest.mark.parametrize(
    ("key_selector", "peer", "mission_id", "subject_id"),
    [
        ("wrong", PeerPrincipal(1, 1000, 1001), SYSTEM_CONTROL_MISSION_ID, "subject:alice"),
        ("", PeerPrincipal(1, 1000, 1001), SYSTEM_CONTROL_MISSION_ID, "subject:alice"),
        ("valid", PeerPrincipal(1, 9999, 1001), SYSTEM_CONTROL_MISSION_ID, "subject:alice"),
        ("valid", PeerPrincipal(1, 1000, 1001), "mission:missing", "subject:alice"),
        ("valid", PeerPrincipal(1, 1000, 1001), SYSTEM_CONTROL_MISSION_ID, "subject:other"),
    ],
)
def test_authentication_requires_every_explicit_binding(
    tmp_path: Path,
    key_selector: str,
    peer: PeerPrincipal,
    mission_id: str,
    subject_id: str,
) -> None:
    auth, valid_key, _ = _authority(tmp_path / "c2.db")
    with pytest.raises(PermissionError):
        auth.authenticate_control(
            api_key=valid_key if key_selector == "valid" else key_selector,
            peer=peer,
            mission_id=mission_id,
            subject_id=subject_id,
        )


def test_request_role_cannot_escalate(tmp_path: Path) -> None:
    auth, key, _ = _authority(tmp_path / "c2.db")
    peer = PeerPrincipal(1, 1000, 1001)
    for claims in (
        {"claimed_role": OperatorRole.ADMIN},
        {"claimed_name": "Alice"},
        {"claimed_operator_id": "anything"},
    ):
        with pytest.raises(PermissionError, match="request-supplied"):
            auth.authenticate_control(
                api_key=key,
                peer=peer,
                mission_id=SYSTEM_CONTROL_MISSION_ID,
                subject_id="subject:alice",
                **claims,
            )


def test_existing_operator_requires_explicit_peer_and_mission_binding(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "c2.db"
    operators = OperatorManager(str(db_path))
    key = operators.create_operator("Alice", ROLE_ADMIN, subject_id="subject:alice")
    grants = GrantService(str(db_path))
    auth = ControlAuthenticatorV1(operators, grants)
    with pytest.raises(PermissionError, match="peer UID/GID"):
        auth.authenticate_control(
            api_key=key,
            peer=PeerPrincipal(1, 1000, 1001),
            mission_id=SYSTEM_CONTROL_MISSION_ID,
            subject_id="subject:alice",
        )


@pytest.mark.parametrize(
    ("role", "allowed"),
    [
        (OperatorRole.ADMIN, {action.value for action in C2ControlActionV1}),
        (
            OperatorRole.OPERATOR,
            {
                action.value
                for action in C2ControlActionV1
                if action.value
                not in {
                    "purge_results",
                    "manage_operators_list",
                    "manage_operators_create",
                    "manage_operators_deactivate",
                    "manage_operators_rotate",
                    "sync_operator_peer_bindings",
                    "revoke_operator_peer_binding",
                    "sync_operator_mission_grants",
                    "revoke_operator_mission_grant",
                }
            },
        ),
        (
            OperatorRole.READONLY,
            {"ping", "version", "readiness", "list_agents", "list_results"},
        ),
    ],
)
def test_full_rbac_matrix(
    tmp_path: Path,
    role: OperatorRole,
    allowed: set[str],
) -> None:
    db_path = tmp_path / role.value / "c2.db"
    auth, principal = _role_principal(db_path, role)
    actual = {action.value for action in C2ControlActionV1 if auth.check_permission(principal, action)}
    assert actual == allowed


def test_readonly_list_results_allowed(tmp_path: Path) -> None:
    auth, principal = _role_principal(tmp_path / "readonly.db", OperatorRole.READONLY)
    assert auth.check_permission(principal, "list_results")


def test_readonly_ack_results_denied(tmp_path: Path) -> None:
    auth, principal = _role_principal(tmp_path / "readonly.db", OperatorRole.READONLY)
    assert not auth.check_permission(principal, "ack_results")


def test_operator_purge_results_denied(tmp_path: Path) -> None:
    auth, principal = _role_principal(tmp_path / "operator.db", OperatorRole.OPERATOR)
    assert not auth.check_permission(principal, "purge_results")


def test_manually_constructed_principal_is_not_authenticated(tmp_path: Path) -> None:
    auth, _, record = _authority(tmp_path / "c2.db")
    principal = AuthenticatedControlPrincipal(
        operator_id=str(record["operator_id"]),
        subject_id="subject:alice",
        role=OperatorRole.ADMIN,
        peer=PeerPrincipal(1, 1000, 1001),
        mission_id=SYSTEM_CONTROL_MISSION_ID,
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        authenticated_at=0.0,
        expires_at=9999999999.0,
    )
    assert not auth.is_current_principal(principal)
    assert not auth.check_permission(principal, "ping")


def test_principal_expiry_is_fail_closed(tmp_path: Path) -> None:
    operators = OperatorManager(str(tmp_path / "c2.db"))
    key = operators.create_operator("Alice", ROLE_ADMIN, subject_id="subject:alice")
    record = operators.authenticate(key)
    assert record is not None
    grants = GrantService(operators.db_path)
    with sqlite3.connect(operators.db_path) as connection:
        insert_initial_bootstrap_grants(
            connection,
            operator_id=str(record["operator_id"]),
            subject_id="subject:alice",
            peer_uid=1,
            peer_gid=2,
        )
    auth = ControlAuthenticatorV1(operators, grants, default_ttl_seconds=5)
    principal = auth.authenticate_control(
        api_key=key,
        peer=PeerPrincipal(1, 1, 2),
        mission_id=SYSTEM_CONTROL_MISSION_ID,
        subject_id="subject:alice",
        now=10.0,
    )
    assert auth.check_permission(principal, "ping", now=14.9)
    assert not auth.check_permission(principal, "ping", now=15.0)


def test_control_authenticator_edge_cases_and_rejections(tmp_path: Path) -> None:
    """Verify all failure and branch conditions in ControlAuthenticatorV1."""
    db_path = tmp_path / "edge_cases.db"
    operators = OperatorManager(str(db_path))
    key = operators.create_operator("Bob", ROLE_ADMIN, subject_id="subject:bob")
    record = operators.authenticate(key)
    assert record is not None
    grants = GrantService(str(db_path))
    with sqlite3.connect(db_path) as connection:
        insert_initial_bootstrap_grants(
            connection,
            operator_id=str(record["operator_id"]),
            subject_id="subject:bob",
            peer_uid=1000,
            peer_gid=1001,
        )

    # 1. Invalid default_ttl_seconds
    with pytest.raises(ValueError, match="principal TTL must be positive"):
        ControlAuthenticatorV1(operators, grants, default_ttl_seconds=0)

    auth = ControlAuthenticatorV1(operators, grants, default_ttl_seconds=100)

    # 2. authenticate_peer compatibility wrapper
    peer = PeerPrincipal(pid=100, uid=1000, gid=1001)
    p1 = auth.authenticate_peer(
        peer=peer,
        mission_id=SYSTEM_CONTROL_MISSION_ID,
        api_key=key,
        subject_id="subject:bob",
    )
    assert p1.operator_id == str(record["operator_id"])

    # 3. authenticated_operator success & failure
    op_info = auth.authenticated_operator(key)
    assert op_info.operator_id == str(record["operator_id"])
    with pytest.raises(PermissionError, match="operator API-key verification failed"):
        auth.authenticated_operator("invalid_key_bytes")

    # 4. authenticate_control input type validations
    with pytest.raises(TypeError, match="server-observed PeerPrincipal"):
        auth.authenticate_control(
            api_key=key,
            peer="not_a_peer",  # type: ignore[arg-type]
            mission_id=SYSTEM_CONTROL_MISSION_ID,
            subject_id="subject:bob",
        )
    with pytest.raises(PermissionError, match="mission binding is required"):
        auth.authenticate_control(
            api_key=key,
            peer=peer,
            mission_id="",
            subject_id="subject:bob",
        )
    with pytest.raises(PermissionError, match="subject binding is required"):
        auth.authenticate_control(
            api_key=key,
            peer=peer,
            mission_id=SYSTEM_CONTROL_MISSION_ID,
            subject_id="",
        )

    # 5. require_current_principal raises PermissionError on invalid/expired principal
    auth.require_current_principal(p1, now=10.0)
    with pytest.raises(PermissionError, match="control principal is expired"):
        auth.require_current_principal(p1, now=9999999999.0)

    # 6. is_current_principal invalid input type
    assert auth.is_current_principal("not_a_principal") is False  # type: ignore[arg-type]

    # 7. check_permission with unknown action
    assert auth.check_permission(p1, "unknown_random_action") is False
