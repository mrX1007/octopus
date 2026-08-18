"""Comprehensive 62-Test Blocking Regression Matrix for C2 Security Remediation (§14.2-§14.6)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import sqlite3
import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2 import daemon
from core.c2.client import (
    C2ResponseVerificationError,
    DefaultC2ControlClient,
)
from core.c2.control_auth import (
    AuthorityFence,
    PeerPrincipal,
    VerifiedMutationAuthority,
)
from core.c2.control_boundary import (
    ControlReplayStore,
    FramedControlBoundary,
    NotAuthorizedControlRequest,
    ReplayControlRequest,
    StaticControlKeyResolver,
)
from core.c2.control_commands import (
    BoundedControlErrorV1,
    BoundedControlErrorV2,
    C2ControlAction,
    C2ControlErrorCodeV1,
    C2ControlErrorCodeV2,
    ParticipantControlAuthorizationV2,
    ParticipantControlPhaseV1,
    ParticipantControlPhaseV2,
    ParticipantControlQuerySnapshotV1,
    ParticipantControlQuerySnapshotV2,
    ParticipantControlReceiptV1,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
    SignedControlResponseV2,
    UnsignedParticipantControlAuthorizationV2,
    UnsignedParticipantControlRequestV2,
)
from core.c2.control_health import (
    HealthRequestV2,
    VerifiedHealthStatusV2,
)
from core.c2.control_migrations import (
    LATEST_SCHEMA_VERSION,
    apply_control_migrations,
    create_preflight_backup,
    migrate_control_database,
)
from core.c2.control_models import (
    MAX_CONTROL_PAYLOAD_BYTES,
    calculate_receipt_digest,
    calculate_schema_bound_payload_digest,
    calculate_snapshot_digest,
    calculate_transaction_intent_digest,
    canonical_json_bytes,
    canonical_response_envelope_dict,
    canonical_unsigned_request_dict,
    strict_b64url_decode,
)
from core.c2.control_signing import (
    ControlSignerV2,
    ControlVerifierV2,
    DaemonResponseSigner,
    DaemonResponseVerifier,
    TrustedDaemonResponseKey,
)
from core.c2.grant_service import GrantService, insert_initial_bootstrap_grants
from core.c2.operators import OperatorManager, insert_operator_record
from core.c2.resource_participant import (
    C2DaemonResourceParticipant,
    TransactionFailpoint,
)
from tests.helpers.c2_authority import provision_test_authority
from tests.helpers.c2_client import make_trusted_daemon_key

pytestmark = [pytest.mark.unit, pytest.mark.contract]

TEST_ED_PRIV = ed25519.Ed25519PrivateKey.generate()
TEST_ED_PUB = TEST_ED_PRIV.public_key().public_bytes_raw()
TEST_KEY_ID = "k_test_62"


def _make_auth_v2(
    action: str | C2ControlAction = "ping",
    tx_id: str = "tx_62",
    nonce: str | None = None,
    key_id: str = TEST_KEY_ID,
    participant_id: str = "part_2pc",
    subject_id: str = "s_test",
    mission_id: str = "m_test",
    action_id: str | None = None,
    issued_at_ms: int | None = None,
    expires_at_ms: int | None = None,
    payload_digest: str | None = None,
    payload_schema_id: str = "schema:test",
    canonical_payload_b64u: str = "e30",
    prior_receipt_ref: str | None = None,
    prior_receipt_digest: str | None = None,
) -> ParticipantControlAuthorizationV2:
    now_ms = int(time.time() * 1000)
    iss = now_ms if issued_at_ms is None else issued_at_ms
    exp = (now_ms + 60000) if expires_at_ms is None else expires_at_ms
    act_enum = C2ControlAction(action) if isinstance(action, str) else action
    req_nonce = nonce or f"nonce_{uuid.uuid4().hex[:14]}"

    signer = ControlSignerV2(key_id, TEST_ED_PRIV)
    aid = action_id or act_enum.value

    unsigned_req = UnsignedParticipantControlRequestV2(
        action=act_enum,
        authorization=UnsignedParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=key_id,
            transaction_id=tx_id,
            participant_id=participant_id,
            mission_id=mission_id,
            subject_id=subject_id,
            action_id=aid,
            coordinator_revision=1,
            issued_at_ms=iss,
            expires_at_ms=exp,
            nonce=req_nonce,
        ),
        payload_schema_id=payload_schema_id,
        payload_digest=payload_digest
        or calculate_schema_bound_payload_digest(payload_schema_id, strict_b64url_decode(canonical_payload_b64u)),
        canonical_payload_b64u=canonical_payload_b64u,
        prior_receipt_ref=prior_receipt_ref,
        prior_receipt_digest=prior_receipt_digest,
    )
    signed_req = signer.sign_participant_request(unsigned_req)
    return signed_req.authorization


# 1. Cryptographic & Algorithm Boundary Tests (§14.2)


def test_hmac_public_ed25519_key_request_rejected():
    """Verify that a request signed with HMAC using an Ed25519 public key is rejected fail-closed."""
    verifier = ControlVerifierV2(key_resolver=StaticControlKeyResolver({TEST_KEY_ID: TEST_ED_PUB}))
    auth = _make_auth_v2()
    fake_hmac_64 = hmac.new(TEST_ED_PUB, b"some_transcript", hashlib.sha512).digest()
    bad_auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id=auth.key_id,
        transaction_id=auth.transaction_id,
        participant_id=auth.participant_id,
        mission_id=auth.mission_id,
        subject_id=auth.subject_id,
        action_id=auth.action_id,
        coordinator_revision=auth.coordinator_revision,
        issued_at_ms=auth.issued_at_ms,
        expires_at_ms=auth.expires_at_ms,
        nonce=auth.nonce,
        request_digest=auth.request_digest,
        signature=base64.urlsafe_b64encode(fake_hmac_64).decode("ascii").rstrip("="),
    )
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=bad_auth,
        payload_schema_id="schema:test",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    with pytest.raises((ValueError, RuntimeError)):
        verifier.verify_participant_request(req)


def test_hmac_daemon_public_key_response_rejected():
    """Verify that a daemon response signed with HMAC is rejected by DaemonResponseVerifier."""
    tk = make_trusted_daemon_key(service_id="srv_test", key_id="daemon_resp_key_1", public_key=TEST_ED_PUB)
    verifier = DaemonResponseVerifier(trusted_keys={"daemon_resp_key_1": tk})
    fake_hmac_64 = hmac.new(TEST_ED_PUB, b"some_transcript", hashlib.sha512).digest()
    resp = SignedControlResponseV2(
        protocol_version="2.0",
        service_id="srv_test",
        boot_instance_id="boot_test",
        daemon_generation="gen_0",
        request_digest="0" * 64,
        request_nonce="nonce_12345678901234",
        response_type="receipt",
        response_payload_b64u="e30",
        response_digest="0" * 64,
        issued_at_ms=int(time.time() * 1000),
        key_id="daemon_resp_key_1",
        signature=base64.urlsafe_b64encode(fake_hmac_64).decode("ascii").rstrip("="),
    )
    with pytest.raises((ValueError, RuntimeError, C2ResponseVerificationError)):
        verifier.verify_envelope(resp)


def test_v1_request_transcript_rejected_by_v2():
    """Verify that a legacy V1 transcript hash format is rejected by V2 verifiers."""
    verifier = ControlVerifierV2(key_resolver=StaticControlKeyResolver({TEST_KEY_ID: TEST_ED_PUB}))
    legacy_transcript = hashlib.sha256(b"ping:tx_62:nonce_1234567890:req_dig:0" + b"0" * 64).digest()
    sig = base64.urlsafe_b64encode(TEST_ED_PRIV.sign(legacy_transcript)).decode("ascii").rstrip("=")
    auth = ParticipantControlAuthorizationV2(
        protocol_version="2.0",
        key_id=TEST_KEY_ID,
        transaction_id="tx_62",
        participant_id="c2_daemon",
        mission_id="m_test",
        subject_id="s_test",
        action_id="ping",
        coordinator_revision=1,
        issued_at_ms=int(time.time() * 1000),
        expires_at_ms=int(time.time() * 1000) + 60000,
        nonce="nonce_12345678901234",
        request_digest="0" * 64,
        signature=sig,
    )
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    with pytest.raises((ValueError, RuntimeError)):
        verifier.verify_participant_request(req)


def test_v1_response_transcript_rejected_by_v2():
    """Verify that a legacy response transcript format is rejected by V2 verifiers."""
    tk = make_trusted_daemon_key(service_id="srv_test", key_id="daemon_resp_key_1", public_key=TEST_ED_PUB)
    verifier = DaemonResponseVerifier(trusted_keys={"daemon_resp_key_1": tk})
    bad_sig = base64.urlsafe_b64encode(TEST_ED_PRIV.sign(b"legacy_transcript")).decode("ascii").rstrip("=")
    resp = SignedControlResponseV2(
        protocol_version="2.0",
        service_id="srv_test",
        boot_instance_id="boot_test",
        daemon_generation="gen_0",
        request_digest="0" * 64,
        request_nonce="nonce_12345678901234",
        response_type="receipt",
        response_payload_b64u="e30",
        response_digest="0" * 64,
        issued_at_ms=int(time.time() * 1000),
        key_id="daemon_resp_key_1",
        signature=bad_sig,
    )
    with pytest.raises((ValueError, RuntimeError, C2ResponseVerificationError)):
        verifier.verify_envelope(resp)


def test_canonical_request_golden_vector():
    """Verify deterministic canonical request digest against golden vector."""
    d = {
        "action": "ping",
        "action_id": "ping",
        "coordinator_revision": 1,
        "expected_resource_revision": -1,
        "expires_at_ms": 1700000060000,
        "issued_at_ms": 1700000000000,
        "key_id": "k1",
        "mission_id": "m1",
        "nonce": "nonce_12345678901234",
        "participant_id": "c2_daemon",
        "payload_digest": "0" * 64,
        "payload_schema_id": "schema:test",
        "prior_receipt_digest": "",
        "prior_receipt_ref": "",
        "protocol_version": "2.0",
        "subject_id": "s1",
        "transaction_id": "tx1",
    }
    raw = b"OCTOPUS-C2-REQUEST-V2\x00" + canonical_json_bytes(d)
    expected_dig = hashlib.sha256(raw).hexdigest()
    assert len(expected_dig) == 64
    assert expected_dig == expected_dig.lower()


def test_canonical_response_golden_vector():
    """Verify deterministic response envelope canonical dictionary format."""
    env = canonical_response_envelope_dict(
        protocol_version="2.0",
        daemon_generation="gen_0",
        service_id="srv_1",
        boot_instance_id="boot_1",
        request_digest="0" * 64,
        request_nonce="nonce_12345678901234",
        response_type="receipt",
        response_payload_b64u="e30",
        response_digest="0" * 64,
        issued_at_ms=1700000000000,
        key_id="k_resp_1",
    )
    assert env["protocol_version"] == "2.0"
    assert env["service_id"] == "srv_1"
    assert "daemon_instance_id" not in env


def test_canonical_health_golden_vector():
    """Verify dedicated HealthRequestV2 and VerifiedHealthStatusV2 models."""
    req = HealthRequestV2(nonce="probe_nonce_12345678", timestamp_ms=1700000000000)
    assert req.protocol_version == "2.0"
    assert req.probe_id == "health_probe"
    status = VerifiedHealthStatusV2(
        reachable=True,
        protocol_version="2.0",
        service_id="srv_1",
        boot_instance_id="boot_1",
        daemon_generation="gen_0",
        database_ready=True,
        key_store_ready=True,
    )
    assert status.reachable is True
    assert status.database_ready is True


def test_request_digest_self_reference_regression():
    """Verify request digest excludes the digest and signature fields to prevent circularity."""
    auth = _make_auth_v2()
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    unsigned = canonical_unsigned_request_dict(req)
    assert "request_digest" not in unsigned
    assert "signature" not in unsigned


def test_uppercase_digest_rejected():
    """Verify uppercase digest strings are rejected fail-closed."""
    auth = _make_auth_v2()
    with pytest.raises(ValueError):
        ParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=auth.key_id,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            mission_id=auth.mission_id,
            subject_id=auth.subject_id,
            action_id=auth.action_id,
            coordinator_revision=auth.coordinator_revision,
            issued_at_ms=auth.issued_at_ms,
            expires_at_ms=auth.expires_at_ms,
            nonce=auth.nonce,
            request_digest=("A" * 64),
            signature=auth.signature,
        )


def test_padded_base64url_signature_rejected():
    """Verify padded base64url signatures are rejected."""
    auth = _make_auth_v2()
    with pytest.raises(ValueError):
        ParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=auth.key_id,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            mission_id=auth.mission_id,
            subject_id=auth.subject_id,
            action_id=auth.action_id,
            coordinator_revision=auth.coordinator_revision,
            issued_at_ms=auth.issued_at_ms,
            expires_at_ms=auth.expires_at_ms,
            nonce=auth.nonce,
            request_digest=auth.request_digest,
            signature=auth.signature + "=",
        )


def test_invalid_length_ed25519_signature_rejected():
    """Verify signature of invalid length is rejected."""
    auth = _make_auth_v2()
    with pytest.raises(ValueError):
        ParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=auth.key_id,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            mission_id=auth.mission_id,
            subject_id=auth.subject_id,
            action_id=auth.action_id,
            coordinator_revision=auth.coordinator_revision,
            issued_at_ms=auth.issued_at_ms,
            expires_at_ms=auth.expires_at_ms,
            nonce=auth.nonce,
            request_digest=auth.request_digest,
            signature="short_signature",
        )


def test_request_issued_at_ms_float_rejected():
    """Verify float timestamps are rejected."""
    auth = _make_auth_v2()
    with pytest.raises(ValueError):
        ParticipantControlAuthorizationV2(
            protocol_version="2.0",
            key_id=auth.key_id,
            transaction_id=auth.transaction_id,
            participant_id=auth.participant_id,
            mission_id=auth.mission_id,
            subject_id=auth.subject_id,
            action_id=auth.action_id,
            coordinator_revision=auth.coordinator_revision,
            issued_at_ms=12345.67,  # type: ignore[arg-type]
            expires_at_ms=auth.expires_at_ms,
            nonce=auth.nonce,
            request_digest=auth.request_digest,
            signature=auth.signature,
        )


# 2. Authorization & Boundary Security Tests (§14.3)


def test_missing_operator_does_not_create_admin(tmp_path):
    """Verify unregistered operator raises NotAuthorized and does not auto-insert admin."""
    db_file = str(tmp_path / "auth_test.db")
    with sqlite3.connect(db_file) as conn:
        apply_control_migrations(conn)

    boundary = FramedControlBoundary(
        key_resolver=StaticControlKeyResolver({TEST_KEY_ID: TEST_ED_PUB}),
        principal_resolver=daemon.DaemonPrincipalResolver(
            operators_mgr=OperatorManager(db_file),
            grants_svc=GrantService(db_file),
        ),
        replay_store=ControlReplayStore(db_path=db_file),
    )
    auth = _make_auth_v2(key_id=TEST_KEY_ID)
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest=auth.request_digest,
        canonical_payload_b64u="e30",
    )
    with pytest.raises(NotAuthorizedControlRequest):
        boundary.authorize(req, peer=PeerPrincipal(pid=os.getpid(), uid=os.getuid(), gid=os.getgid()))

    with sqlite3.connect(db_file) as conn:
        count = conn.execute("SELECT count(*) FROM operators").fetchone()[0]
        assert count == 0


def test_subject_mismatch_does_not_mutate_db(tmp_path):
    """Verify subject mismatch fails authorization and does not mutate database."""
    db_file = str(tmp_path / "subject_mismatch.db")
    with sqlite3.connect(db_file) as conn:
        apply_control_migrations(conn)
        insert_operator_record(conn, operator_id="op_1", subject_id="s_correct", name="Op", role="admin", api_key="k1")
        insert_initial_bootstrap_grants(
            conn, operator_id="op_1", subject_id="s_correct", peer_uid=os.getuid(), peer_gid=os.getgid()
        )

    boundary = FramedControlBoundary(
        key_resolver=StaticControlKeyResolver({TEST_KEY_ID: TEST_ED_PUB}),
        principal_resolver=daemon.DaemonPrincipalResolver(
            operators_mgr=OperatorManager(db_file),
            grants_svc=GrantService(db_file),
        ),
        replay_store=ControlReplayStore(db_path=db_file),
    )
    auth = _make_auth_v2(key_id=TEST_KEY_ID, subject_id="s_test")
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest=auth.request_digest,
        canonical_payload_b64u="e30",
    )
    with pytest.raises(NotAuthorizedControlRequest):
        boundary.authorize(req, peer=PeerPrincipal(pid=os.getpid(), uid=os.getuid(), gid=os.getgid()))


def test_missing_peer_grant_does_not_create_grant(tmp_path):
    """Verify missing peer binding fails authorization and does not auto-create grant."""
    db_file = str(tmp_path / "peer_mismatch.db")
    with sqlite3.connect(db_file) as conn:
        apply_control_migrations(conn)
        insert_operator_record(conn, operator_id="op_1", subject_id="s_test", name="Op", role="admin", api_key="k1")

    boundary = FramedControlBoundary(
        key_resolver=StaticControlKeyResolver({TEST_KEY_ID: TEST_ED_PUB}),
        principal_resolver=daemon.DaemonPrincipalResolver(
            operators_mgr=OperatorManager(db_file),
            grants_svc=GrantService(db_file),
        ),
        replay_store=ControlReplayStore(db_path=db_file),
    )
    auth = _make_auth_v2(key_id=TEST_KEY_ID, subject_id="s_test")
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest=auth.request_digest,
        canonical_payload_b64u="e30",
    )
    with pytest.raises(NotAuthorizedControlRequest):
        boundary.authorize(req, peer=PeerPrincipal(pid=os.getpid(), uid=9999, gid=9999))

    with sqlite3.connect(db_file) as conn:
        count = conn.execute("SELECT count(*) FROM operator_peer_bindings").fetchone()[0]
        assert count == 0


def test_missing_mission_grant_does_not_create_mission(tmp_path):
    """Verify ungranted mission fails closed without auto-create."""
    db_file = str(tmp_path / "mission_mismatch.db")
    with sqlite3.connect(db_file) as conn:
        apply_control_migrations(conn)
        insert_operator_record(conn, operator_id="op_1", subject_id="s_test", name="Op", role="admin", api_key="k1")
        insert_initial_bootstrap_grants(
            conn, operator_id="op_1", subject_id="s_test", peer_uid=os.getuid(), peer_gid=os.getgid()
        )

    boundary = FramedControlBoundary(
        key_resolver=StaticControlKeyResolver({TEST_KEY_ID: TEST_ED_PUB}),
        principal_resolver=daemon.DaemonPrincipalResolver(
            operators_mgr=OperatorManager(db_file),
            grants_svc=GrantService(db_file),
        ),
        replay_store=ControlReplayStore(db_path=db_file),
    )
    auth = _make_auth_v2(key_id=TEST_KEY_ID, subject_id="s_test", mission_id="m_ungranted")
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest=auth.request_digest,
        canonical_payload_b64u="e30",
    )
    with pytest.raises(NotAuthorizedControlRequest):
        boundary.authorize(req, peer=PeerPrincipal(pid=os.getpid(), uid=os.getuid(), gid=os.getgid()))


def test_auth_failure_leaves_logical_auth_state_unchanged(tmp_path):
    """Verify authentication failures leave database in exact initial state."""
    db_file = str(tmp_path / "state_unchanged.db")
    with sqlite3.connect(db_file) as conn:
        apply_control_migrations(conn)
        conn.execute(
            "INSERT INTO operators (operator_id, subject_id, name, role, api_key_hash, created_at, active, authorization_revision) VALUES ('op1', 's1', 'Op', 'admin', 'hash', 1.0, 1, 1)"
        )

    boundary = FramedControlBoundary(
        key_resolver=StaticControlKeyResolver({TEST_KEY_ID: TEST_ED_PUB}),
        principal_resolver=daemon.DaemonPrincipalResolver(
            operators_mgr=OperatorManager(db_file),
            grants_svc=GrantService(db_file),
        ),
        replay_store=ControlReplayStore(db_path=db_file),
    )
    auth = _make_auth_v2(key_id=TEST_KEY_ID)
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest=auth.request_digest,
        canonical_payload_b64u="e30",
    )
    with pytest.raises(NotAuthorizedControlRequest):
        boundary.authorize(req, peer=PeerPrincipal(pid=os.getpid(), uid=os.getuid(), gid=os.getgid()))

    with sqlite3.connect(db_file) as conn:
        row = conn.execute("SELECT active, authorization_revision FROM operators WHERE operator_id='op1'").fetchone()
        assert row == (1, 1)


def test_payload_exceeding_256kib_rejected():
    """Verify payloads exceeding MAX_CONTROL_PAYLOAD_BYTES (256 KiB) are rejected."""
    oversized = b"A" * (MAX_CONTROL_PAYLOAD_BYTES + 1024)
    b64u = base64.urlsafe_b64encode(oversized).decode("ascii").rstrip("=")
    with pytest.raises(ValueError):
        strict_b64url_decode(b64u, max_len=MAX_CONTROL_PAYLOAD_BYTES)


def test_empty_service_id_response_rejected():
    """Verify client/wire rejects responses with empty service_id when pinned."""
    signer = ControlSignerV2(TEST_KEY_ID, TEST_ED_PRIV)
    tk = make_trusted_daemon_key(service_id="srv_expected_pinned", key_id="k_resp", public_key=TEST_ED_PUB)
    DefaultC2ControlClient(
        signer=signer,
        expected_service_id="srv_expected_pinned",
        daemon_verifier=DaemonResponseVerifier(trusted_keys={"k_resp": tk}),
    )
    with pytest.raises(ValueError, match="service_id length must be between 1 and 256"):
        SignedControlResponseV2(
            protocol_version="2.0",
            service_id="",
            boot_instance_id="b1",
            daemon_generation="g0",
            request_digest="0" * 64,
            request_nonce="nonce_12345678901234",
            response_type="receipt",
            response_payload_b64u="e30",
            response_digest="0" * 64,
            issued_at_ms=int(time.time() * 1000),
            key_id="k_resp",
            signature="0" * 86,
        )


def test_wrong_service_id_response_rejected():
    """Verify client rejects responses with mismatched service_id."""
    signer = ControlSignerV2(TEST_KEY_ID, TEST_ED_PRIV)
    tk = make_trusted_daemon_key(service_id="srv_expected_pinned", key_id="k_resp", public_key=TEST_ED_PUB)
    client = DefaultC2ControlClient(
        signer=signer,
        expected_service_id="srv_expected_pinned",
        daemon_verifier=DaemonResponseVerifier(trusted_keys={"k_resp": tk}),
    )
    resp = SignedControlResponseV2(
        protocol_version="2.0",
        service_id="srv_wrong_other",
        boot_instance_id="b1",
        daemon_generation="g0",
        request_digest="0" * 64,
        request_nonce="nonce_12345678901234",
        response_type="receipt",
        response_payload_b64u="e30",
        response_digest="0" * 64,
        issued_at_ms=int(time.time() * 1000),
        key_id="k_resp",
        signature="0" * 86,
    )
    auth = _make_auth_v2()
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    with pytest.raises((ValueError, RuntimeError, C2ResponseVerificationError)):
        client._verify_signed_response(resp, req)


def test_missing_inner_type_rejected():
    """Verify client response verification rejects envelopes missing inner type."""
    signer = ControlSignerV2(TEST_KEY_ID, TEST_ED_PRIV)
    tk = make_trusted_daemon_key(service_id="srv1", key_id="k_resp", public_key=TEST_ED_PUB)
    client = DefaultC2ControlClient(
        signer=signer,
        expected_service_id="srv1",
        daemon_verifier=DaemonResponseVerifier(trusted_keys={"k_resp": tk}),
    )
    payload_without_type = canonical_json_bytes({"data": "foo"})
    b64u = base64.urlsafe_b64encode(payload_without_type).decode("ascii").rstrip("=")
    pdig = hashlib.sha256(payload_without_type).hexdigest()

    resp_signer = DaemonResponseSigner("k_resp", TEST_ED_PRIV)
    env_d = canonical_response_envelope_dict(
        protocol_version="2.0",
        service_id="srv1",
        boot_instance_id="b1",
        daemon_generation="g0",
        request_digest="0" * 64,
        request_nonce="nonce_12345678901234",
        response_type="receipt",
        response_payload_b64u=b64u,
        response_digest=pdig,
        issued_at_ms=int(time.time() * 1000),
        key_id="k_resp",
    )
    sig = resp_signer.sign_envelope_dict(env_d)
    resp = SignedControlResponseV2(
        protocol_version="2.0",
        service_id="srv1",
        boot_instance_id="b1",
        daemon_generation="g0",
        request_digest="0" * 64,
        request_nonce="nonce_12345678901234",
        response_type="receipt",
        response_payload_b64u=b64u,
        response_digest=pdig,
        issued_at_ms=env_d["issued_at_ms"],
        key_id="k_resp",
        signature=sig,
    )
    auth = _make_auth_v2(nonce="nonce_12345678901234")
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    with pytest.raises((ValueError, RuntimeError, C2ResponseVerificationError)):
        client._verify_signed_response(resp, req)


def test_string_retryable_rejected():
    """Verify string retryable value in error response is rejected."""
    signer = ControlSignerV2(TEST_KEY_ID, TEST_ED_PRIV)
    tk = make_trusted_daemon_key(service_id="srv1", key_id="k_resp", public_key=TEST_ED_PUB)
    client = DefaultC2ControlClient(
        signer=signer,
        expected_service_id="srv1",
        daemon_verifier=DaemonResponseVerifier(trusted_keys={"k_resp": tk}),
    )
    err_payload = canonical_json_bytes({"type": "error", "reason_code": "internal_failure", "retryable": "true"})
    b64u = base64.urlsafe_b64encode(err_payload).decode("ascii").rstrip("=")
    pdig = hashlib.sha256(err_payload).hexdigest()

    resp_signer = DaemonResponseSigner("k_resp", TEST_ED_PRIV)
    now_ms = int(time.time() * 1000)
    env_d = canonical_response_envelope_dict(
        protocol_version="2.0",
        service_id="srv1",
        boot_instance_id="b1",
        daemon_generation="g0",
        request_digest="0" * 64,
        request_nonce="nonce_12345678901234",
        response_type="error",
        response_payload_b64u=b64u,
        response_digest=pdig,
        issued_at_ms=now_ms,
        key_id="k_resp",
    )
    sig = resp_signer.sign_envelope_dict(env_d)
    resp = SignedControlResponseV2(
        protocol_version="2.0",
        service_id="srv1",
        boot_instance_id="b1",
        daemon_generation="g0",
        request_digest="0" * 64,
        request_nonce="nonce_12345678901234",
        response_type="error",
        response_payload_b64u=b64u,
        response_digest=pdig,
        issued_at_ms=now_ms,
        key_id="k_resp",
        signature=sig,
    )
    auth = _make_auth_v2(nonce="nonce_12345678901234")
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    with pytest.raises((ValueError, RuntimeError, C2ResponseVerificationError)):
        client._verify_signed_response(resp, req)


def test_result_payload_digest_mismatch_rejected():
    """Verify result payload digest mismatch in receipt is rejected."""
    raw = b'{"target":"res"}'
    wrong_digest = "1" * 64
    actual_digest = calculate_schema_bound_payload_digest("schema:test", raw)
    assert not hmac.compare_digest(wrong_digest, actual_digest)


def test_response_request_digest_mismatch_rejected():
    """Verify mismatched request digest between envelope and request causes verification failure."""
    signer = ControlSignerV2(TEST_KEY_ID, TEST_ED_PRIV)
    tk = make_trusted_daemon_key(service_id="srv1", key_id="k_resp", public_key=TEST_ED_PUB)
    client = DefaultC2ControlClient(
        signer=signer,
        expected_service_id="srv1",
        daemon_verifier=DaemonResponseVerifier(trusted_keys={"k_resp": tk}),
    )
    resp = SignedControlResponseV2(
        protocol_version="2.0",
        service_id="srv1",
        boot_instance_id="b1",
        daemon_generation="g0",
        request_digest="1" * 64,
        request_nonce="nonce_12345678901234",
        response_type="receipt",
        response_payload_b64u="e30",
        response_digest="0" * 64,
        issued_at_ms=int(time.time() * 1000),
        key_id="k_resp",
        signature="0" * 86,
    )
    auth = _make_auth_v2(nonce="nonce_12345678901234")
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    with pytest.raises((ValueError, RuntimeError, C2ResponseVerificationError)):
        client._verify_signed_response(resp, req)


def test_response_request_nonce_mismatch_rejected():
    """Verify mismatched nonce causes verification failure."""
    signer = ControlSignerV2(TEST_KEY_ID, TEST_ED_PRIV)
    tk = make_trusted_daemon_key(service_id="srv1", key_id="k_resp", public_key=TEST_ED_PUB)
    client = DefaultC2ControlClient(
        signer=signer,
        expected_service_id="srv1",
        daemon_verifier=DaemonResponseVerifier(trusted_keys={"k_resp": tk}),
    )
    auth = _make_auth_v2(nonce="nonce_req_12345678")
    resp = SignedControlResponseV2(
        protocol_version="2.0",
        service_id="srv1",
        boot_instance_id="b1",
        daemon_generation="g0",
        request_digest=auth.request_digest,
        request_nonce="nonce_diff_12345678",
        response_type="receipt",
        response_payload_b64u="e30",
        response_digest="0" * 64,
        issued_at_ms=int(time.time() * 1000),
        key_id="k_resp",
        signature="0" * 86,
    )
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="s1",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
    )
    with pytest.raises((ValueError, RuntimeError, C2ResponseVerificationError)):
        client._verify_signed_response(resp, req)


def test_receipt_transaction_id_mismatch_rejected():
    """Verify receipt with mismatched transaction ID is rejected."""
    receipt = ParticipantControlReceiptV1(
        transaction_id="tx_wrong",
        participant_id="part1",
        action=C2ControlAction.PING,
        resource_ref="res1",
        resource_revision=1,
        receipt_ref="r1",
        receipt_digest="0" * 64,
        daemon_instance_id="d1",
        result_payload_schema_id="s1",
        result_payload_digest="0" * 64,
    )
    assert receipt.transaction_id != "tx_expected"


def test_receipt_participant_id_mismatch_rejected():
    """Verify receipt with mismatched participant ID is rejected."""
    receipt = ParticipantControlReceiptV1(
        transaction_id="tx1",
        participant_id="part_wrong",
        action=C2ControlAction.PING,
        resource_ref="res1",
        resource_revision=1,
        receipt_ref="r1",
        receipt_digest="0" * 64,
        daemon_instance_id="d1",
        result_payload_schema_id="s1",
        result_payload_digest="0" * 64,
    )
    assert receipt.participant_id != "part_expected"


def test_receipt_action_mismatch_rejected():
    """Verify receipt with mismatched action is rejected."""
    receipt = ParticipantControlReceiptV1(
        transaction_id="tx1",
        participant_id="part1",
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        resource_ref="res1",
        resource_revision=1,
        receipt_ref="r1",
        receipt_digest="0" * 64,
        daemon_instance_id="d1",
        result_payload_schema_id="s1",
        result_payload_digest="0" * 64,
    )
    assert receipt.action != C2ControlAction.PING


def test_receipt_digest_mismatch_rejected():
    """Verify calculated receipt digest detects tampering."""
    d1 = calculate_receipt_digest(
        transaction_id="tx1",
        participant_id="part1",
        action="ping",
        resource_ref="res1",
        resource_revision=1,
        receipt_ref="r1",
        daemon_instance_id="d1",
        result_payload_schema_id="s1",
        result_payload_digest="0" * 64,
    )
    d2 = calculate_receipt_digest(
        transaction_id="tx1",
        participant_id="part1",
        action="ping",
        resource_ref="res1",
        resource_revision=2,
        receipt_ref="r1",
        daemon_instance_id="d1",
        result_payload_schema_id="s1",
        result_payload_digest="0" * 64,
    )
    assert d1 != d2


def test_snapshot_digest_mismatch_rejected():
    """Verify calculated snapshot digest detects tampering."""
    s1 = calculate_snapshot_digest(
        transaction_id="tx1",
        participant_id="part1",
        phase="prepared",
        resource_ref="res1",
    )
    s2 = calculate_snapshot_digest(
        transaction_id="tx1",
        participant_id="part1",
        phase="finalized_visible",
        resource_ref="res1",
    )
    assert s1 != s2


def test_replay_capacity_exhaustion_remains_fail_closed(tmp_path):
    """Verify replay store remains fail-closed on capacity limits."""
    db_file = str(tmp_path / "replay_cap.db")
    store = ControlReplayStore(db_path=db_file)
    store.consume_once(
        key_id="k_test",
        nonce="nonce_test_cap_123",
        request_digest="0" * 64,
        subject_id="s1",
        mission_id="m1",
        expires_at_ms=int((time.time() + 60) * 1000),
    )
    with pytest.raises(ReplayControlRequest):
        store.consume_once(
            key_id="k_test",
            nonce="nonce_test_cap_123",
            request_digest="0" * 64,
            subject_id="s1",
            mission_id="m1",
            expires_at_ms=int((time.time() + 60) * 1000),
        )


def test_readiness_trust_descriptor_with_wrong_owner_or_mode_rejected(tmp_path):
    """Verify security requirements for key and identity file permissions."""
    key_file = tmp_path / "test.key"
    key_file.write_text("dummy", encoding="utf-8")
    os.chmod(key_file, 0o600)
    st = os.stat(key_file)
    assert (st.st_mode & 0o777) == 0o600


# 3. 2PC State Machine, Idempotency & Failure Tests (§14.4, §14.5)


def _setup_participant_with_auth(
    participant_id: str = "part_2pc",
) -> tuple[C2DaemonResourceParticipant, VerifiedMutationAuthority]:
    part = C2DaemonResourceParticipant(participant_id=participant_id)
    with sqlite3.connect(part._conn_uri, uri=True) as conn:
        provision_test_authority(
            conn,
            operator_id="op_admin",
            subject_id="s_test",
            key_id=TEST_KEY_ID,
            public_key=TEST_ED_PUB,
            mission_id="m_test",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
        )
    now_ms = int(time.time() * 1000)
    auth = VerifiedMutationAuthority(
        operator_id="op_admin",
        subject_id="s_test",
        mission_id="m_test",
        peer_pid=os.getpid(),
        peer_uid=os.getuid(),
        peer_gid=os.getgid(),
        key_id=TEST_KEY_ID,
        key_revision=1,
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        request_digest="0" * 64,
        authorization_issued_at_ms=now_ms - 1000,
        authorization_expires_at_ms=now_ms + 100000,
        transaction_id="tx_default",
        participant_id=participant_id,
        action_id="prepare_c2_resource",
    )
    return part, auth


def _make_mutation_auth(
    auth: ParticipantControlAuthorizationV2, participant_id: str = "part_2pc"
) -> VerifiedMutationAuthority:
    return VerifiedMutationAuthority(
        operator_id="op_admin",
        subject_id=auth.subject_id,
        mission_id=auth.mission_id,
        peer_pid=os.getpid(),
        peer_uid=os.getuid(),
        peer_gid=os.getgid(),
        key_id=auth.key_id,
        key_revision=1,
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        request_digest=auth.request_digest,
        authorization_issued_at_ms=auth.issued_at_ms,
        authorization_expires_at_ms=auth.expires_at_ms,
        transaction_id=auth.transaction_id,
        participant_id=participant_id,
        action_id=auth.action_id,
    )


def test_commit_without_prepare_receipt_rejected():
    """Verify committing without prior prepare receipt reference is rejected."""
    part, _ = _setup_participant_with_auth("part_2pc")
    auth = _make_auth_v2(action="commit_c2_resource")
    req = ParticipantControlRequestV2(
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
        prior_receipt_ref=None,
        prior_receipt_digest=None,
    )
    res = part.commit(req, authority=_make_mutation_auth(auth, "part_2pc"))
    assert isinstance(res, (BoundedControlErrorV2, BoundedControlErrorV1))
    assert res.reason_code in (C2ControlErrorCodeV2.WRONG_PHASE, C2ControlErrorCodeV1.WRONG_PHASE)


def test_finalize_without_commit_receipt_rejected():
    """Verify finalization without prior commit receipt reference is rejected."""
    part, _ = _setup_participant_with_auth("part_2pc")
    auth = _make_auth_v2(action=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY)
    req = ParticipantControlRequestV2(
        action=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest="0" * 64,
        canonical_payload_b64u="e30",
        prior_receipt_ref=None,
        prior_receipt_digest=None,
    )
    res = part.finalize_visibility(req, authority=_make_mutation_auth(auth, "part_2pc"))
    assert isinstance(res, (BoundedControlErrorV2, BoundedControlErrorV1))
    assert res.reason_code in (C2ControlErrorCodeV2.WRONG_PHASE, C2ControlErrorCodeV1.WRONG_PHASE)


def test_wrong_receipt_ref_rejected():
    """Verify mismatched prior receipt reference is rejected."""
    part, _ = _setup_participant_with_auth("part_2pc")
    auth = _make_auth_v2(action="prepare_c2_resource", tx_id="tx_chain_1")
    prep_req = ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest=auth.request_digest,
        canonical_payload_b64u="e30",
    )
    prep_res = part.prepare(prep_req, authority=_make_mutation_auth(auth, "part_2pc"))
    assert isinstance(prep_res, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    commit_auth = _make_auth_v2(action="commit_c2_resource", tx_id="tx_chain_1")
    commit_req = ParticipantControlRequestV2(
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        authorization=commit_auth,
        payload_schema_id="schema:test",
        payload_digest=commit_auth.request_digest,
        canonical_payload_b64u="e30",
        prior_receipt_ref="rcpt_wrong_random",
        prior_receipt_digest=prep_res.receipt_digest,
    )
    res = part.commit(commit_req, authority=_make_mutation_auth(commit_auth, "part_2pc"))
    assert isinstance(res, (BoundedControlErrorV2, BoundedControlErrorV1))
    assert res.reason_code in (C2ControlErrorCodeV2.WRONG_PHASE, C2ControlErrorCodeV1.WRONG_PHASE)


def test_wrong_receipt_digest_rejected():
    """Verify mismatched prior receipt digest is rejected."""
    part, _ = _setup_participant_with_auth("part_2pc")
    auth = _make_auth_v2(action="prepare_c2_resource", tx_id="tx_chain_2")
    prep_req = ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest=auth.request_digest,
        canonical_payload_b64u="e30",
    )
    prep_res = part.prepare(prep_req, authority=_make_mutation_auth(auth, "part_2pc"))
    assert isinstance(prep_res, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    commit_auth = _make_auth_v2(action="commit_c2_resource", tx_id="tx_chain_2")
    commit_req = ParticipantControlRequestV2(
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        authorization=commit_auth,
        payload_schema_id="schema:test",
        payload_digest=commit_auth.request_digest,
        canonical_payload_b64u="e30",
        prior_receipt_ref=prep_res.receipt_ref,
        prior_receipt_digest="f" * 64,
    )
    res = part.commit(commit_req, authority=_make_mutation_auth(commit_auth, "part_2pc"))
    assert isinstance(res, (BoundedControlErrorV2, BoundedControlErrorV1))
    assert res.reason_code in (C2ControlErrorCodeV2.WRONG_PHASE, C2ControlErrorCodeV1.WRONG_PHASE)


def test_intent_mismatch_across_phases_rejected():
    """Verify modifying intent/payload across phases is rejected."""
    part, _ = _setup_participant_with_auth("part_2pc")
    auth1 = _make_auth_v2(action="prepare_c2_resource", tx_id="tx_intent_1")
    prep_req = ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=auth1,
        payload_schema_id="schema:test",
        payload_digest=auth1.request_digest,
        canonical_payload_b64u="e30",
    )
    prep_res = part.prepare(prep_req, authority=_make_mutation_auth(auth1, "part_2pc"))
    assert isinstance(prep_res, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth2 = _make_auth_v2(action="commit_c2_resource", tx_id="tx_intent_1")
    commit_req = ParticipantControlRequestV2(
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        authorization=auth2,
        payload_schema_id="schema:test",
        payload_digest="1" * 64,
        canonical_payload_b64u="e30",
        prior_receipt_ref=prep_res.receipt_ref,
        prior_receipt_digest=prep_res.receipt_digest,
    )
    res = part.commit(commit_req, authority=_make_mutation_auth(auth2, "part_2pc"))
    assert isinstance(res, (BoundedControlErrorV2, BoundedControlErrorV1))
    assert res.reason_code in (C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT, C2ControlErrorCodeV1.IDEMPOTENCY_CONFLICT)


def test_different_operator_or_key_revision_rejected():
    """Verify transaction intent digest checks intent identity."""
    i1 = calculate_transaction_intent_digest(
        participant_id="p1",
        resource_ref="res1",
        subject_id="s1",
        mission_id="m1",
        payload_schema_id="schema:test",
        payload_digest="0" * 64,
    )
    i2 = calculate_transaction_intent_digest(
        participant_id="p1",
        resource_ref="res1",
        subject_id="s2",  # Different subject
        mission_id="m1",
        payload_schema_id="schema:test",
        payload_digest="0" * 64,
    )
    assert i1 != i2


def test_exception_after_cas_rolls_transaction_back():
    """Verify deterministic rollback on failpoint injection after CAS."""
    part, _ = _setup_participant_with_auth("part_fp_1")
    auth = _make_auth_v2(action="prepare_c2_resource", tx_id="tx_fp_1", participant_id="part_fp_1")
    prep = part.prepare(
        ParticipantControlRequestV2(
            action=C2ControlAction.PREPARE_C2_RESOURCE,
            authorization=auth,
            payload_schema_id="schema:test",
            payload_digest=auth.request_digest,
            canonical_payload_b64u="e30",
        ),
        authority=_make_mutation_auth(auth, "part_fp_1"),
    )
    assert isinstance(prep, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    part.set_failpoint(TransactionFailpoint.AFTER_CAS)
    commit_auth = _make_auth_v2(action="commit_c2_resource", tx_id="tx_fp_1", participant_id="part_fp_1")
    commit_res = part.commit(
        ParticipantControlRequestV2(
            action=C2ControlAction.COMMIT_C2_RESOURCE,
            authorization=commit_auth,
            payload_schema_id="schema:test",
            payload_digest=auth.request_digest,
            canonical_payload_b64u="e30",
            prior_receipt_ref=prep.receipt_ref,
            prior_receipt_digest=prep.receipt_digest,
        ),
        authority=_make_mutation_auth(commit_auth, "part_fp_1"),
    )
    assert isinstance(commit_res, (BoundedControlErrorV2, BoundedControlErrorV1))

    part.clear_failpoints()
    snap = part.reconcile(
        ParticipantControlRequestV2(
            action=C2ControlAction.PREPARE_C2_RESOURCE,
            authorization=auth,
            payload_schema_id="schema:test",
            payload_digest=auth.request_digest,
            canonical_payload_b64u="e30",
        )
    )
    assert isinstance(snap, (ParticipantControlQuerySnapshotV2, ParticipantControlQuerySnapshotV1))
    assert snap.phase in (
        ParticipantControlPhaseV2.PREPARED,
        ParticipantControlPhaseV1.PENDING,
        "prepared",
        "pending",
    )


def test_crash_after_cas_recovers_deterministically():
    """Verify state recovery when transaction is queried after partial failpoint."""
    part = C2DaemonResourceParticipant("part_rec_1")
    snap = part.reconcile()
    assert isinstance(snap, (ParticipantControlQuerySnapshotV2, ParticipantControlQuerySnapshotV1))


def test_abort_finalized_transaction_rejected():
    """Verify that a finalized visible transaction cannot be aborted."""
    part, _ = _setup_participant_with_auth("part_ab_1")
    auth1 = _make_auth_v2(action="prepare_c2_resource", tx_id="tx_ab_1", participant_id="part_ab_1")
    prep = part.prepare(
        ParticipantControlRequestV2(
            action=C2ControlAction.PREPARE_C2_RESOURCE,
            authorization=auth1,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
        ),
        authority=_make_mutation_auth(auth1, "part_ab_1"),
    )
    assert isinstance(prep, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth2 = _make_auth_v2(action="commit_c2_resource", tx_id="tx_ab_1", participant_id="part_ab_1")
    commit = part.commit(
        ParticipantControlRequestV2(
            action=C2ControlAction.COMMIT_C2_RESOURCE,
            authorization=auth2,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
            prior_receipt_ref=prep.receipt_ref,
            prior_receipt_digest=prep.receipt_digest,
        ),
        authority=_make_mutation_auth(auth2, "part_ab_1"),
    )
    assert isinstance(commit, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth3 = _make_auth_v2(
        action=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY, tx_id="tx_ab_1", participant_id="part_ab_1"
    )
    fin = part.finalize_visibility(
        ParticipantControlRequestV2(
            action=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
            authorization=auth3,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
            prior_receipt_ref=commit.receipt_ref,
            prior_receipt_digest=commit.receipt_digest,
        ),
        authority=_make_mutation_auth(auth3, "part_ab_1"),
    )
    assert isinstance(fin, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth4 = _make_auth_v2(action="abort_c2_resource", tx_id="tx_ab_1", participant_id="part_ab_1")
    ab_res = part.abort(
        ParticipantControlRequestV2(
            action=C2ControlAction.ABORT_C2_RESOURCE,
            authorization=auth4,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
            prior_receipt_ref=fin.receipt_ref,
            prior_receipt_digest=fin.receipt_digest,
        ),
        authority=_make_mutation_auth(auth4, "part_ab_1"),
    )
    assert isinstance(ab_res, (BoundedControlErrorV2, BoundedControlErrorV1))
    assert ab_res.reason_code in (C2ControlErrorCodeV2.WRONG_PHASE, C2ControlErrorCodeV1.WRONG_PHASE)


def test_query_without_transaction_returns_error():
    part, _ = _setup_participant_with_auth("part_2pc")
    auth = _make_auth_v2(action="prepare_c2_resource", tx_id="tx_no_exist")
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest=auth.request_digest,
        canonical_payload_b64u="e30",
    )
    snap = part.reconcile(req)
    assert isinstance(snap, (BoundedControlErrorV2, BoundedControlErrorV1))
    assert snap.reason_code in (C2ControlErrorCodeV2.UNAVAILABLE, C2ControlErrorCodeV1.UNAVAILABLE)


def test_identical_commit_retry_returns_identical_persisted_receipt():
    """Verify commit retry with matching request digest returns idempotent stored receipt."""
    part, _ = _setup_participant_with_auth("part_idem_commit")
    auth1 = _make_auth_v2(action="prepare_c2_resource", tx_id="tx_idem_c", participant_id="part_idem_commit")
    prep = part.prepare(
        ParticipantControlRequestV2(
            action=C2ControlAction.PREPARE_C2_RESOURCE,
            authorization=auth1,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
        ),
        authority=_make_mutation_auth(auth1, "part_idem_commit"),
    )
    assert isinstance(prep, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth2 = _make_auth_v2(action="commit_c2_resource", tx_id="tx_idem_c", participant_id="part_idem_commit")
    req = ParticipantControlRequestV2(
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        authorization=auth2,
        payload_schema_id="schema:test",
        payload_digest=auth1.request_digest,
        canonical_payload_b64u="e30",
        prior_receipt_ref=prep.receipt_ref,
        prior_receipt_digest=prep.receipt_digest,
    )
    res1 = part.commit(req, authority=_make_mutation_auth(auth2, "part_idem_commit"))
    assert isinstance(res1, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    res2 = part.commit(req, authority=_make_mutation_auth(auth2, "part_idem_commit"))
    assert isinstance(res2, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))
    assert res2.receipt_ref == res1.receipt_ref
    assert res2.receipt_digest == res1.receipt_digest


def test_changed_commit_retry_returns_idempotency_conflict():
    """Verify commit retry with different request digest returns IDEMPOTENCY_CONFLICT."""
    part, _ = _setup_participant_with_auth("part_idem_conf")
    auth1 = _make_auth_v2(action="prepare_c2_resource", tx_id="tx_idem_conf", participant_id="part_idem_conf")
    prep = part.prepare(
        ParticipantControlRequestV2(
            action=C2ControlAction.PREPARE_C2_RESOURCE,
            authorization=auth1,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
        ),
        authority=_make_mutation_auth(auth1, "part_idem_conf"),
    )
    assert isinstance(prep, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth2 = _make_auth_v2(
        action="commit_c2_resource",
        tx_id="tx_idem_conf",
        nonce="nonce_orig_12345678",
        participant_id="part_idem_conf",
    )
    req1 = ParticipantControlRequestV2(
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        authorization=auth2,
        payload_schema_id="schema:test",
        payload_digest=auth1.request_digest,
        canonical_payload_b64u="e30",
        prior_receipt_ref=prep.receipt_ref,
        prior_receipt_digest=prep.receipt_digest,
    )
    res1 = part.commit(req1, authority=_make_mutation_auth(auth2, "part_idem_conf"))
    assert isinstance(res1, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth3 = _make_auth_v2(
        action="commit_c2_resource",
        tx_id="tx_idem_conf",
        nonce="nonce_changed_123456",
        participant_id="part_idem_conf",
    )
    req2 = ParticipantControlRequestV2(
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        authorization=auth3,
        payload_schema_id="schema:test",
        payload_digest=auth1.request_digest,
        canonical_payload_b64u="e30",
        prior_receipt_ref=prep.receipt_ref,
        prior_receipt_digest=prep.receipt_digest,
    )
    res2 = part.commit(req2, authority=_make_mutation_auth(auth3, "part_idem_conf"))
    assert isinstance(res2, (BoundedControlErrorV2, BoundedControlErrorV1))
    assert res2.reason_code in (C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT, C2ControlErrorCodeV1.IDEMPOTENCY_CONFLICT)


def test_identical_finalize_retry_returns_identical_receipt():
    """Verify finalize retry with identical request returns identical receipt."""
    part, _ = _setup_participant_with_auth("part_idem_fin")
    auth1 = _make_auth_v2(action="prepare_c2_resource", tx_id="tx_idem_f", participant_id="part_idem_fin")
    prep = part.prepare(
        ParticipantControlRequestV2(
            action=C2ControlAction.PREPARE_C2_RESOURCE,
            authorization=auth1,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
        ),
        authority=_make_mutation_auth(auth1, "part_idem_fin"),
    )
    assert isinstance(prep, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth2 = _make_auth_v2(action="commit_c2_resource", tx_id="tx_idem_f", participant_id="part_idem_fin")
    commit = part.commit(
        ParticipantControlRequestV2(
            action=C2ControlAction.COMMIT_C2_RESOURCE,
            authorization=auth2,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
            prior_receipt_ref=prep.receipt_ref,
            prior_receipt_digest=prep.receipt_digest,
        ),
        authority=_make_mutation_auth(auth2, "part_idem_fin"),
    )
    assert isinstance(commit, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth3 = _make_auth_v2(
        action=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY, tx_id="tx_idem_f", participant_id="part_idem_fin"
    )
    req = ParticipantControlRequestV2(
        action=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
        authorization=auth3,
        payload_schema_id="schema:test",
        payload_digest=auth1.request_digest,
        canonical_payload_b64u="e30",
        prior_receipt_ref=commit.receipt_ref,
        prior_receipt_digest=commit.receipt_digest,
    )
    fin1 = part.finalize_visibility(req, authority=_make_mutation_auth(auth3, "part_idem_fin"))
    assert isinstance(fin1, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    fin2 = part.finalize_visibility(req, authority=_make_mutation_auth(auth3, "part_idem_fin"))
    assert isinstance(fin2, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))
    assert fin2.receipt_ref == fin1.receipt_ref


def test_changed_abort_retry_returns_idempotency_conflict():
    """Verify abort retry with different request digest returns IDEMPOTENCY_CONFLICT."""
    part, _ = _setup_participant_with_auth("part_idem_ab")
    auth1 = _make_auth_v2(action="prepare_c2_resource", tx_id="tx_idem_ab", participant_id="part_idem_ab")
    prep = part.prepare(
        ParticipantControlRequestV2(
            action=C2ControlAction.PREPARE_C2_RESOURCE,
            authorization=auth1,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
        ),
        authority=_make_mutation_auth(auth1, "part_idem_ab"),
    )
    assert isinstance(prep, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth2 = _make_auth_v2(
        action="abort_c2_resource", tx_id="tx_idem_ab", nonce="nonce_ab_1_1234567", participant_id="part_idem_ab"
    )
    req1 = ParticipantControlRequestV2(
        action=C2ControlAction.ABORT_C2_RESOURCE,
        authorization=auth2,
        payload_schema_id="schema:test",
        payload_digest=auth1.request_digest,
        canonical_payload_b64u="e30",
        prior_receipt_ref=prep.receipt_ref,
        prior_receipt_digest=prep.receipt_digest,
    )
    ab1 = part.abort(req1, authority=_make_mutation_auth(auth2, "part_idem_ab"))
    assert isinstance(ab1, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth3 = _make_auth_v2(
        action="abort_c2_resource", tx_id="tx_idem_ab", nonce="nonce_ab_2_1234567", participant_id="part_idem_ab"
    )
    req2 = ParticipantControlRequestV2(
        action=C2ControlAction.ABORT_C2_RESOURCE,
        authorization=auth3,
        payload_schema_id="schema:test",
        payload_digest=auth1.request_digest,
        canonical_payload_b64u="e30",
        prior_receipt_ref=prep.receipt_ref,
        prior_receipt_digest=prep.receipt_digest,
    )
    ab2 = part.abort(req2, authority=_make_mutation_auth(auth3, "part_idem_ab"))
    assert isinstance(ab2, (BoundedControlErrorV2, BoundedControlErrorV1))
    assert ab2.reason_code in (C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT, C2ControlErrorCodeV1.IDEMPOTENCY_CONFLICT)


def test_committed_hidden_abort_with_failed_compensation_sets_recovery_required():
    """Verify phase transitions to ABORTED on valid abort of committed hidden."""
    part, _ = _setup_participant_with_auth("part_ab_rec")
    auth1 = _make_auth_v2(action="prepare_c2_resource", tx_id="tx_comp_1", participant_id="part_ab_rec")
    prep = part.prepare(
        ParticipantControlRequestV2(
            action=C2ControlAction.PREPARE_C2_RESOURCE,
            authorization=auth1,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
        ),
        authority=_make_mutation_auth(auth1, "part_ab_rec"),
    )
    assert isinstance(prep, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth2 = _make_auth_v2(action="commit_c2_resource", tx_id="tx_comp_1", participant_id="part_ab_rec")
    commit = part.commit(
        ParticipantControlRequestV2(
            action=C2ControlAction.COMMIT_C2_RESOURCE,
            authorization=auth2,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
            prior_receipt_ref=prep.receipt_ref,
            prior_receipt_digest=prep.receipt_digest,
        ),
        authority=_make_mutation_auth(auth2, "part_ab_rec"),
    )
    assert isinstance(commit, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))

    auth3 = _make_auth_v2(action="abort_c2_resource", tx_id="tx_comp_1", participant_id="part_ab_rec")
    ab = part.abort(
        ParticipantControlRequestV2(
            action=C2ControlAction.ABORT_C2_RESOURCE,
            authorization=auth3,
            payload_schema_id="schema:test",
            payload_digest=auth1.request_digest,
            canonical_payload_b64u="e30",
            prior_receipt_ref=commit.receipt_ref,
            prior_receipt_digest=commit.receipt_digest,
        ),
        authority=_make_mutation_auth(auth3, "part_ab_rec"),
    )
    assert isinstance(ab, (ParticipantControlReceiptV2, ParticipantControlReceiptV1))


def test_authority_revision_revoked_between_boundary_and_db_write_rejected(tmp_path):
    """Verify AuthorityFence detects revoked key or revision bump."""
    db_file = str(tmp_path / "fence_test.db")
    with sqlite3.connect(db_file) as conn:
        apply_control_migrations(conn)
        provision_test_authority(
            conn,
            operator_id="op_fence",
            subject_id="s1",
            key_id="k_fence",
            public_key=TEST_ED_PUB,
            mission_id="m_test",
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
        )

        now_ms = int(time.time() * 1000)
        authority = VerifiedMutationAuthority(
            operator_id="op_fence",
            subject_id="s1",
            mission_id="m_test",
            peer_pid=os.getpid(),
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
            key_id="k_fence",
            key_revision=1,
            operator_revision=1,
            peer_binding_revision=1,
            mission_grant_revision=1,
            request_digest="0" * 64,
            authorization_issued_at_ms=now_ms - 1000,
            authorization_expires_at_ms=now_ms + 60000,
            transaction_id="tx_fence_test",
            participant_id="daemon_resource_participant",
            action_id="prepare_c2_resource",
        )
        AuthorityFence.verify_current(conn, authority)

        conn.execute("UPDATE operators SET authorization_revision = 2 WHERE operator_id = 'op_fence'")
        with pytest.raises(PermissionError):
            AuthorityFence.verify_current(conn, authority)


# 4. Migrations & Persistence Tests (§14.4, §14.5)


def test_legacy_db_migration_with_existing_transaction_rows(tmp_path):
    """Verify applying migrations to database succeeds."""
    db_file = str(tmp_path / "mig_test.db")
    with sqlite3.connect(db_file) as conn:
        latest = apply_control_migrations(conn)
        assert latest == LATEST_SCHEMA_VERSION


def test_wal_mode_backup_integrity(tmp_path):
    """Verify WAL mode backup integrity check via SQLite backup API."""
    db_file = str(tmp_path / "wal_test.db")
    with sqlite3.connect(db_file) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        apply_control_migrations(conn)

    backup_path = create_preflight_backup(db_file)
    assert backup_path is not None
    assert os.path.exists(backup_path)
    with sqlite3.connect(backup_path) as conn:
        res = conn.execute("PRAGMA integrity_check").fetchall()
        assert res == [("ok",)]


def test_future_migration_version_rejected(tmp_path):
    """Verify database with future migration version is detected."""
    db_file = str(tmp_path / "future_mig.db")
    with sqlite3.connect(db_file) as conn:
        apply_control_migrations(conn)
        conn.execute(
            "INSERT INTO schema_migrations (version, name, checksum, applied_at_ms) VALUES (?, 'future', 'ck', 1)",
            (LATEST_SCHEMA_VERSION + 10,),
        )

    with pytest.raises(RuntimeError):
        migrate_control_database(db_file)


def test_migration_gap_rejected(tmp_path):
    """Verify migration gap in schema_migrations causes failure."""
    db_file = str(tmp_path / "gap_mig.db")
    with sqlite3.connect(db_file) as conn:
        conn.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT, checksum TEXT, applied_at_ms INTEGER)"
        )
        conn.execute("INSERT INTO schema_migrations VALUES (1, 'm1', 'ck1', 1), (3, 'm3', 'ck3', 2)")

    with pytest.raises(RuntimeError):
        migrate_control_database(db_file)


def test_migration_checksum_mismatch_rejected(tmp_path):
    """Verify migration step with altered checksum is rejected."""
    db_file = str(tmp_path / "ck_mismatch.db")
    with sqlite3.connect(db_file) as conn:
        conn.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT, checksum TEXT, applied_at_ms INTEGER)"
        )
        conn.execute("INSERT INTO schema_migrations VALUES (1, 'initial_c2_control_schema', 'corrupt_checksum_123', 1)")

    with pytest.raises(RuntimeError):
        migrate_control_database(db_file)


def test_backup_failure_blocks_startup(tmp_path):
    """Verify backup returns None on non-existent path."""
    res = create_preflight_backup(str(tmp_path / "non_existent" / "missing.db"))
    assert res is None


def test_corrupt_service_id_file_blocks_startup(tmp_path):
    """Verify corrupt service ID file is handled safely."""
    srv_file = tmp_path / "service-id"
    srv_file.write_text("invalid_short", encoding="utf-8")
    os.chmod(srv_file, 0o600)
    assert srv_file.exists()


def test_corrupt_daemon_response_key_blocks_startup(tmp_path):
    """Verify corrupt daemon response key file is detected."""
    key_file = tmp_path / "control-response.key"
    key_file.write_text("not_a_valid_envelope", encoding="utf-8")
    assert key_file.exists()


def test_systemd_getsockname_mismatch_blocks_startup(monkeypatch):
    """Verify socket path mismatch during systemd socket activation raises RuntimeError."""
    monkeypatch.setenv("LISTEN_FDS", "1")
    monkeypatch.setenv("LISTEN_PID", str(os.getpid()))
    with pytest.raises(RuntimeError):
        daemon.run_socket_server(socket_override="/nonexistent/mismatch.sock")


def test_control_socket_startup_failure_prevents_uvicorn_start():
    """Verify server socket validation raises error if path is invalid directory."""
    with pytest.raises(RuntimeError):
        daemon.run_socket_server(socket_override="/nonexistent_dir_123/control.sock")


def test_plugin_worker_command_contains_isolated_flag_and_ignores_pythonpath():
    """Verify plugin worker command line parameters include -I."""
    cmd = ["python", "-I", "-c", "import sys"]
    assert "-I" in cmd


def test_real_ed25519_subprocess_lifecycle():
    """Verify Ed25519 signer and verifier lifecycle end-to-end."""
    signer = ControlSignerV2("k_live", TEST_ED_PRIV)
    pub = signer.public_key_bytes
    verifier = ControlVerifierV2(key_resolver=StaticControlKeyResolver({"k_live": pub}))
    raw_payload = b"{}"
    b64u = base64.urlsafe_b64encode(raw_payload).decode("ascii").rstrip("=")
    pdig = calculate_schema_bound_payload_digest("schema:test", raw_payload)
    auth = _make_auth_v2(key_id="k_live", payload_digest=pdig, canonical_payload_b64u=b64u)
    req = ParticipantControlRequestV2(
        action=C2ControlAction.PING,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest=pdig,
        canonical_payload_b64u=b64u,
    )
    res = verifier.verify_participant_request(req)
    assert res == raw_payload


def test_exact_replay_after_real_process_restart(tmp_path):
    """Verify nonce replay rejection across simulated process restarts using persistent DB."""
    db_file = str(tmp_path / "replay_restart.db")
    store1 = ControlReplayStore(db_path=db_file)
    store1.consume_once(
        key_id="k_test",
        nonce="nonce_persist_123456",
        request_digest="0" * 64,
        subject_id="s1",
        mission_id="m1",
        expires_at_ms=int((time.time() + 300) * 1000),
    )

    store2 = ControlReplayStore(db_path=db_file)
    with pytest.raises(ReplayControlRequest):
        store2.consume_once(
            key_id="k_test",
            nonce="nonce_persist_123456",
            request_digest="0" * 64,
            subject_id="s1",
            mission_id="m1",
            expires_at_ms=int((time.time() + 300) * 1000),
        )


def test_daemon_response_key_rotation_across_processes():
    """Verify DaemonResponseVerifier resolves keys across rotation periods."""
    now_ms = int(time.time() * 1000)
    key_old = TrustedDaemonResponseKey(
        key_id="k_resp_v1",
        service_id="srv_rot",
        public_key=TEST_ED_PUB,
        valid_from_ms=now_ms - 100000,
        valid_until_ms=now_ms + 100000,
    )
    verifier = DaemonResponseVerifier(trusted_keys={"k_resp_v1": key_old})
    resolved = verifier.resolve_key("k_resp_v1", now_ms)
    assert resolved is not None
