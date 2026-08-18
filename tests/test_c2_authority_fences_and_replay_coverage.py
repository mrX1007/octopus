"""Unit test coverage for read-only authority fences, durable replay protection, and idempotency in C2."""

from __future__ import annotations

import os
import sqlite3
import time

import pytest

from core.c2.control_auth import AuthenticatedControlPrincipal, AuthorityFence, OperatorRole
from core.c2.control_boundary import ResolvedControlKey
from core.c2.control_commands import C2ControlAction
from core.c2.control_idempotency import (
    IdempotencyConflictError,
    IdempotencyStateV1,
    IdempotencyStoreV1,
    compute_idempotency_fingerprint,
)
from core.c2.control_migrations import apply_control_migrations
from core.c2.control_peer import PeerPrincipal
from core.c2.control_rbac import ControlRBACPolicy
from tests.helpers.c2_authority import (
    create_test_control_key,
    create_test_mission_grant,
    create_test_operator,
    create_test_peer_binding,
)

pytestmark = pytest.mark.unit

TEST_ED_PUB = b"A" * 32


def test_authority_fence_revisions_and_deactivation(tmp_path):
    """Verify AuthorityFence strictly detects any revocation, revision bump, or deactivation."""
    db_file = str(tmp_path / "authority_fence_test.db")
    with sqlite3.connect(db_file) as conn:
        apply_control_migrations(conn)
        create_test_operator(
            conn,
            operator_id="op_fence",
            subject_id="s1",
            name="Op Fence",
            role="admin",
            authorization_revision=1,
            active=True,
        )
        create_test_peer_binding(
            conn,
            operator_id="op_fence",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
            revision=1,
            active=True,
        )
        create_test_mission_grant(
            conn,
            operator_id="op_fence",
            subject_id="s1",
            mission_id="m_real",
            revision=1,
            active=True,
        )
        create_test_control_key(
            conn,
            key_id="k_fence",
            operator_id="op_fence",
            public_key=TEST_ED_PUB,
            key_revision=1,
            active=True,
        )

        principal = AuthenticatedControlPrincipal(
            operator_id="op_fence",
            subject_id="s1",
            role=OperatorRole.ADMIN,
            peer=PeerPrincipal(pid=os.getpid(), uid=os.getuid(), gid=os.getgid()),
            mission_id="m_real",
            operator_revision=1,
            peer_binding_revision=1,
            mission_grant_revision=1,
            authenticated_at=time.time(),
            expires_at=time.time() + 60,
        )
        now_ms = int(time.time() * 1000)
        resolved_key = ResolvedControlKey(
            key_id="k_fence",
            operator_id="op_fence",
            verification_key=TEST_ED_PUB,
            algorithm="ed25519",
            key_revision=1,
            valid_from_ms=now_ms - 10000,
            valid_until_ms=now_ms + 10000,
            active=True,
        )

        # Baseline: fresh, active, matching revisions -> PASS
        AuthorityFence.verify_current(conn, principal, resolved_key)

        # 1. Operator revision bump
        conn.execute("UPDATE operators SET authorization_revision = 2 WHERE operator_id = 'op_fence'")
        with pytest.raises(PermissionError, match="operator_authority_stale_or_revoked"):
            AuthorityFence.verify_current(conn, principal, resolved_key)
        conn.execute("UPDATE operators SET authorization_revision = 1 WHERE operator_id = 'op_fence'")

        # 2. Operator deactivated
        conn.execute("UPDATE operators SET active = 0 WHERE operator_id = 'op_fence'")
        with pytest.raises(PermissionError, match="operator_authority_stale_or_revoked"):
            AuthorityFence.verify_current(conn, principal, resolved_key)
        conn.execute("UPDATE operators SET active = 1 WHERE operator_id = 'op_fence'")

        # 3. Peer binding revision bump
        conn.execute("UPDATE operator_peer_binding_revisions SET revision = 2 WHERE operator_id = 'op_fence'")
        with pytest.raises(PermissionError, match="peer_binding_stale_or_revoked"):
            AuthorityFence.verify_current(conn, principal, resolved_key)
        conn.execute("UPDATE operator_peer_binding_revisions SET revision = 1 WHERE operator_id = 'op_fence'")

        # 4. Peer binding deactivated
        conn.execute("UPDATE operator_peer_bindings SET active = 0 WHERE operator_id = 'op_fence'")
        with pytest.raises(PermissionError, match="peer_binding_stale_or_revoked"):
            AuthorityFence.verify_current(conn, principal, resolved_key)
        conn.execute("UPDATE operator_peer_bindings SET active = 1 WHERE operator_id = 'op_fence'")

        # 5. Mission grant revision bump
        conn.execute("UPDATE operator_mission_grant_revisions SET revision = 2 WHERE operator_id = 'op_fence'")
        with pytest.raises(PermissionError, match="mission_grant_stale_or_revoked"):
            AuthorityFence.verify_current(conn, principal, resolved_key)
        conn.execute("UPDATE operator_mission_grant_revisions SET revision = 1 WHERE operator_id = 'op_fence'")

        # 6. Mission grant deactivated
        conn.execute("UPDATE operator_mission_grants SET active = 0 WHERE operator_id = 'op_fence'")
        with pytest.raises(PermissionError, match="mission_grant_stale_or_revoked"):
            AuthorityFence.verify_current(conn, principal, resolved_key)
        conn.execute("UPDATE operator_mission_grants SET active = 1 WHERE operator_id = 'op_fence'")

        # 7. Inactive key
        conn.execute("UPDATE operator_control_signing_keys SET active = 0 WHERE key_id = 'k_fence'")
        with pytest.raises(PermissionError, match="key_authority_stale_or_revoked"):
            AuthorityFence.verify_current(conn, principal, resolved_key)
        conn.execute("UPDATE operator_control_signing_keys SET active = 1 WHERE key_id = 'k_fence'")

        # 8. Key revision bump
        conn.execute("UPDATE operator_control_signing_keys SET key_revision = 2 WHERE key_id = 'k_fence'")
        with pytest.raises(PermissionError, match="key_authority_stale_or_revoked"):
            AuthorityFence.verify_current(conn, principal, resolved_key)
        conn.execute("UPDATE operator_control_signing_keys SET key_revision = 1 WHERE key_id = 'k_fence'")


def test_readonly_authority_fences_rbac():
    """Verify that read-only authority fence strictly limits READONLY operators to side-effect-free actions."""
    policy = ControlRBACPolicy()

    now = time.time()
    principal_ro = AuthenticatedControlPrincipal(
        operator_id="op_reader",
        subject_id="s_reader",
        role=OperatorRole.READONLY,
        peer=PeerPrincipal(pid=os.getpid(), uid=os.getuid(), gid=os.getgid()),
        mission_id="m_read",
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        authenticated_at=now - 10,
        expires_at=now + 100,
    )

    # Allowed read-only actions
    assert policy.evaluate(principal_ro, C2ControlAction.PING, mission_id="m_read", now=now) is True
    assert policy.evaluate(principal_ro, C2ControlAction.VERSION, mission_id="m_read", now=now) is True
    assert policy.evaluate(principal_ro, C2ControlAction.READINESS, mission_id="m_read", now=now) is True
    assert policy.evaluate(principal_ro, C2ControlAction.LIST_AGENTS, mission_id="m_read", now=now) is True
    assert policy.evaluate(principal_ro, C2ControlAction.LIST_RESULTS, mission_id="m_read", now=now) is True

    # Denied state-changing actions
    assert policy.evaluate(principal_ro, C2ControlAction.PURGE_RESULTS, mission_id="m_read", now=now) is False
    assert policy.evaluate(principal_ro, C2ControlAction.MANAGE_OPERATORS_CREATE, mission_id="m_read", now=now) is False
    assert policy.evaluate(principal_ro, C2ControlAction.ABORT_C2_RESOURCE, mission_id="m_read", now=now) is False
    assert policy.evaluate(principal_ro, C2ControlAction.CANCEL_TASK, mission_id="m_read", now=now) is False
    assert policy.evaluate(principal_ro, C2ControlAction.REVOKE_ENROLLMENT, mission_id="m_read", now=now) is False


def test_durable_idempotency_and_replay_protection():
    """Verify IdempotencyStoreV1 provides deterministic, durable replay and detects replay conflicts."""
    store = IdempotencyStoreV1()

    # Fingerprint computation
    fp1 = compute_idempotency_fingerprint(
        operator_id="op1",
        subject_id="s1",
        mission_id="m1",
        action="action:test",
        payload_schema_id="schema:test",
        payload_digest="sha256:d1",
    )
    fp2 = compute_idempotency_fingerprint(
        operator_id="op1",
        subject_id="s1",
        mission_id="m1",
        action="action:test",
        payload_schema_id="schema:test",
        payload_digest="sha256:d1",
    )
    assert fp1 == fp2
    assert len(fp1) == 64

    # 1. Initial reservation
    rec1 = store.reserve(
        operator_id="op1",
        subject_id="s1",
        mission_id="m1",
        action="action:test",
        idempotency_key="key-123",
        request_id="req-1",
        payload_schema_id="schema:test",
        payload_digest="sha256:d1",
    )
    assert rec1.state == IdempotencyStateV1.PENDING
    assert rec1.operator_id == "op1"
    assert rec1.idempotency_key == "key-123"

    # 2. Idempotent replay of identical reservation returns identical record
    rec_replay = store.reserve(
        operator_id="op1",
        subject_id="s1",
        mission_id="m1",
        action="action:test",
        idempotency_key="key-123",
        request_id="req-1",
        payload_schema_id="schema:test",
        payload_digest="sha256:d1",
    )
    assert rec_replay is rec1

    # 3. Conflicting replay with different payload digest
    with pytest.raises(IdempotencyConflictError, match="already used with different"):
        store.reserve(
            operator_id="op1",
            subject_id="s1",
            mission_id="m1",
            action="action:test",
            idempotency_key="key-123",
            request_id="req-1",
            payload_schema_id="schema:test",
            payload_digest="sha256:DIFFERENT",
        )

    # 4. Conflicting replay with different action
    with pytest.raises(IdempotencyConflictError, match="already used with different"):
        store.reserve(
            operator_id="op1",
            subject_id="s1",
            mission_id="m1",
            action="action:DIFF",
            idempotency_key="key-123",
            request_id="req-1",
            payload_schema_id="schema:test",
            payload_digest="sha256:d1",
        )

    # 5. Conflicting request_id reuse
    with pytest.raises(IdempotencyConflictError, match="already used with different"):
        store.reserve(
            operator_id="op1",
            subject_id="s1",
            mission_id="m1",
            action="action:DIFF",
            idempotency_key="key-DIFF",
            request_id="req-1",  # reused request_id
            payload_schema_id="schema:test",
            payload_digest="sha256:d1",
        )

    # 6. Commit reservation
    store.commit(
        operator_id="op1",
        subject_id="s1",
        mission_id="m1",
        action="action:test",
        idempotency_key="key-123",
        response_data={"status": "ok"},
    )
    rec_committed = store.reserve(
        operator_id="op1",
        subject_id="s1",
        mission_id="m1",
        action="action:test",
        idempotency_key="key-123",
        request_id="req-1",
        payload_schema_id="schema:test",
        payload_digest="sha256:d1",
    )
    assert rec_committed.state == IdempotencyStateV1.COMMITTED
    assert rec_committed.response_json == '{"status": "ok"}'

    # 7. Commit on non-existent key raises KeyError
    with pytest.raises(KeyError, match="No pending reservation"):
        store.commit(
            operator_id="op1",
            subject_id="s1",
            mission_id="m1",
            action="action:nonexistent",
            idempotency_key="key-nonexistent",
            response_data={"status": "ok"},
        )
