"""Comprehensive security test suite for C2 Control Boundary (§14.4, §14.5, §14.6)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2 import daemon
from core.c2.client import (
    C2ResponseVerificationError,
    DefaultC2ControlClient,
)
from core.c2.control_auth import AuthenticatedControlPrincipal, OperatorRole, PeerPrincipal
from core.c2.control_boundary import (
    ControlBoundary,
    ControlReplayStore,
    ControlVerificationKeyStore,
    NotAuthorizedControlRequest,
    ReplayedControlRequest,
    ResolvedControlKey,
    StaticControlKeyResolver,
    VerifiedKeyPrincipalResolver,
)
from core.c2.control_commands import (
    C2ControlActionV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
    SignedControlResponseV1,
)
from core.c2.control_models import (
    canonical_json_bytes,
    canonical_response_envelope_dict,
)
from core.c2.control_protocol import ControlProtocolCodec
from core.c2.control_rbac import ControlRBACPolicy
from core.c2.control_signing import (
    ControlSignerV1,
    DaemonResponseVerifier,
)
from core.c2.grant_service import GrantService
from core.c2.operators import OperatorManager
from core.c2.protocol import C2_CONTROL_PROTOCOL_VERSION

pytestmark = [pytest.mark.unit, pytest.mark.security]

SECRET_KEY_A = b"secret_key_a_01234567890123456789"
SECRET_KEY_B = b"secret_key_b_01234567890123456789"
DAEMON_SECRET = b"daemon_root_secret_012345678901234"


class StaticPrincipalResolver:
    def __init__(self, principals: dict[str, AuthenticatedControlPrincipal]) -> None:
        self._principals = dict(principals)

    def resolve(
        self,
        *,
        key_id: str,
        peer: PeerPrincipal,
        mission_id: str,
        subject_id: str,
        now: float,
        resolved_key: ResolvedControlKey | None = None,
    ) -> AuthenticatedControlPrincipal:
        if key_id not in self._principals:
            raise NotAuthorizedControlRequest(f"unknown_key_id:{key_id}")
        p = self._principals[key_id]
        return AuthenticatedControlPrincipal(
            operator_id=p.operator_id,
            subject_id=subject_id or p.subject_id,
            role=p.role,
            peer=peer,
            mission_id=mission_id or p.mission_id,
            operator_revision=p.operator_revision,
            peer_binding_revision=p.peer_binding_revision,
            mission_grant_revision=p.mission_grant_revision,
            authenticated_at=now,
            expires_at=now + 300.0,
        )


def _make_fixture(db_path: str = ":memory:"):
    key_resolver = StaticControlKeyResolver(
        {
            "key_a": SECRET_KEY_A,
            "key_b": SECRET_KEY_B,
        }
    )
    peer_dummy = PeerPrincipal(pid=os.getpid(), uid=os.getuid(), gid=os.getgid())
    admin_principal = AuthenticatedControlPrincipal(
        operator_id="op_admin",
        subject_id="sub_admin",
        role=OperatorRole.ADMIN,
        peer=peer_dummy,
        mission_id="m_1",
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        authenticated_at=time.time(),
        expires_at=time.time() + 600.0,
    )
    readonly_principal = AuthenticatedControlPrincipal(
        operator_id="op_readonly",
        subject_id="sub_readonly",
        role=OperatorRole.READONLY,
        peer=peer_dummy,
        mission_id="m_1",
        operator_revision=1,
        peer_binding_revision=1,
        mission_grant_revision=1,
        authenticated_at=time.time(),
        expires_at=time.time() + 600.0,
    )
    principal_resolver = StaticPrincipalResolver(
        {
            "key_a": admin_principal,
            "key_b": readonly_principal,
        }
    )
    replay_store = ControlReplayStore(db_path=db_path)
    boundary = ControlBoundary(
        key_resolver=key_resolver,
        principal_resolver=principal_resolver,
        rbac=ControlRBACPolicy(),
        replay_store=replay_store,
    )
    return boundary, replay_store, peer_dummy


def _build_signed_request(
    signer: ControlSignerV1,
    action: C2ControlActionV1 = C2ControlActionV1.PING,
    mission_id: str = "m_1",
    subject_id: str = "sub_admin",
    participant_id: str = "c2_daemon",
    payload: dict | None = None,
    nonce: str | None = None,
    ttl_seconds: float = 300.0,
) -> ParticipantControlRequestV1:
    payload_dict = payload or {"test": "val"}
    payload_bytes = canonical_json_bytes(payload_dict)
    b64u = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
    p_dig = hashlib.sha256(payload_bytes).hexdigest()
    now = time.time()
    n = nonce or f"nonce_{uuid.uuid4().hex[:12]}"
    tx_id = f"tx_{uuid.uuid4().hex[:8]}"

    auth = ParticipantControlAuthorizationV1(
        key_id=signer.key_id,
        transaction_id=tx_id,
        participant_id=participant_id,
        mission_id=mission_id,
        subject_id=subject_id,
        action_id=action.value,
        coordinator_revision=1,
        request_digest="init_req_digest",
        expires_at=now + ttl_seconds,
        nonce=n,
        signature="",
    )
    req = ParticipantControlRequestV1(
        action=action,
        authorization=auth,
        payload_schema_id="schema:c2_control_v1",
        payload_digest=p_dig,
        canonical_payload_b64u=b64u,
    )
    return signer.sign_participant_request(req)


def test_valid_request_authorized():
    boundary, _, peer = _make_fixture()
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    req = _build_signed_request(signer)

    verified = boundary.authorize(req, peer)
    assert verified.principal.operator_id == "op_admin"
    assert verified.request.action == C2ControlActionV1.PING


def test_replay_attack_rejected():
    boundary, _, peer = _make_fixture()
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    req = _build_signed_request(signer)

    boundary.authorize(req, peer)
    with pytest.raises(ReplayedControlRequest):
        boundary.authorize(req, peer)


def test_expired_authorization_window_rejected():
    boundary, _, peer = _make_fixture()
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    req = _build_signed_request(signer, ttl_seconds=-10.0)

    with pytest.raises(NotAuthorizedControlRequest, match="authorization_expired"):
        boundary.authorize(req, peer)


def test_ttl_exceeds_maximum_rejected():
    boundary, _, peer = _make_fixture()
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    req = _build_signed_request(signer, ttl_seconds=600.0)

    with pytest.raises(NotAuthorizedControlRequest, match="ttl_beyond_maximum"):
        boundary.authorize(req, peer)


def test_action_id_mismatch_rejected():
    boundary, _, peer = _make_fixture()
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    req = _build_signed_request(signer)

    tampered_auth = ParticipantControlAuthorizationV1(
        key_id=req.authorization.key_id,
        transaction_id=req.authorization.transaction_id,
        participant_id=req.authorization.participant_id,
        mission_id=req.authorization.mission_id,
        subject_id=req.authorization.subject_id,
        action_id="manage_operators_create",
        coordinator_revision=req.authorization.coordinator_revision,
        request_digest=req.authorization.request_digest,
        expires_at=req.authorization.expires_at,
        nonce=req.authorization.nonce,
        signature=req.authorization.signature,
    )
    tampered_req = ParticipantControlRequestV1(
        action=req.action,
        authorization=tampered_auth,
        payload_schema_id=req.payload_schema_id,
        payload_digest=req.payload_digest,
        canonical_payload_b64u=req.canonical_payload_b64u,
    )

    with pytest.raises(NotAuthorizedControlRequest, match="action_mismatch"):
        boundary.authorize(tampered_req, peer)


def test_payload_tampering_detected():
    boundary, _, peer = _make_fixture()
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    req = _build_signed_request(signer)

    tampered_bytes = canonical_json_bytes({"test": "tampered"})
    tampered_b64u = base64.urlsafe_b64encode(tampered_bytes).decode("utf-8").rstrip("=")
    tampered_req = ParticipantControlRequestV1(
        action=req.action,
        authorization=req.authorization,
        payload_schema_id=req.payload_schema_id,
        payload_digest=req.payload_digest,
        canonical_payload_b64u=tampered_b64u,
    )

    with pytest.raises(NotAuthorizedControlRequest, match="payload_digest_mismatch"):
        boundary.authorize(tampered_req, peer)


def test_request_digest_tampering_detected():
    boundary, _, peer = _make_fixture()
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    req = _build_signed_request(signer)

    tampered_auth = ParticipantControlAuthorizationV1(
        key_id=req.authorization.key_id,
        transaction_id=req.authorization.transaction_id,
        participant_id=req.authorization.participant_id,
        mission_id=req.authorization.mission_id,
        subject_id=req.authorization.subject_id,
        action_id=req.authorization.action_id,
        coordinator_revision=req.authorization.coordinator_revision,
        request_digest=hashlib.sha256(b"tampered_digest").hexdigest(),
        expires_at=req.authorization.expires_at,
        nonce=req.authorization.nonce,
        signature=req.authorization.signature,
    )
    tampered_req = ParticipantControlRequestV1(
        action=req.action,
        authorization=tampered_auth,
        payload_schema_id=req.payload_schema_id,
        payload_digest=req.payload_digest,
        canonical_payload_b64u=req.canonical_payload_b64u,
    )

    with pytest.raises(NotAuthorizedControlRequest, match="request_digest_mismatch"):
        boundary.authorize(tampered_req, peer)


def test_invalid_signature_rejected():
    boundary, _, peer = _make_fixture()
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    req = _build_signed_request(signer)

    tampered_auth = ParticipantControlAuthorizationV1(
        key_id=req.authorization.key_id,
        transaction_id=req.authorization.transaction_id,
        participant_id=req.authorization.participant_id,
        mission_id=req.authorization.mission_id,
        subject_id=req.authorization.subject_id,
        action_id=req.authorization.action_id,
        coordinator_revision=req.authorization.coordinator_revision,
        request_digest=req.authorization.request_digest,
        expires_at=req.authorization.expires_at,
        nonce=req.authorization.nonce,
        signature=hashlib.sha256(b"corrupted_signature").hexdigest(),
    )
    tampered_req = ParticipantControlRequestV1(
        action=req.action,
        authorization=tampered_auth,
        payload_schema_id=req.payload_schema_id,
        payload_digest=req.payload_digest,
        canonical_payload_b64u=req.canonical_payload_b64u,
    )

    with pytest.raises(NotAuthorizedControlRequest, match="invalid_request_signature"):
        boundary.authorize(tampered_req, peer)


def test_unknown_key_id_rejected():
    boundary, _, peer = _make_fixture()
    signer = ControlSignerV1("unknown_key_99", SECRET_KEY_A)
    req = _build_signed_request(signer)

    with pytest.raises(NotAuthorizedControlRequest, match="unknown_key_id"):
        boundary.authorize(req, peer)


def test_rbac_insufficient_privilege_rejected():
    boundary, _, peer = _make_fixture()
    # key_b has READONLY role
    signer = ControlSignerV1("key_b", SECRET_KEY_B)
    # MANAGE_OPERATORS_CREATE requires ADMIN role
    req = _build_signed_request(signer, action=C2ControlActionV1.MANAGE_OPERATORS_CREATE, subject_id="sub_readonly")

    with pytest.raises(NotAuthorizedControlRequest, match="rbac_denied"):
        boundary.authorize(req, peer)


def test_db_backed_principal_resolver_complete_lifecycle(tmp_path):
    """Test full DB-backed operator authentication, Ed25519 signing, peer binding, and RBAC."""
    db_file = str(tmp_path / "security_lifecycle.db")
    op_mgr = OperatorManager(db_path=db_file)
    grant_svc = GrantService(db_path=db_file)
    key_store = ControlVerificationKeyStore(db_path=db_file)

    # 1. Create operator with OPERATOR role (not ADMIN)
    op_mgr.create_operator(
        operator_id="op_tester_1",
        subject_id="sub_tester_1",
        name="Tester Operator",
        role="operator",
        api_key="api_key_test_123456789012345",
    )

    # 2. Register operator Ed25519 key
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    key_store.register_key(
        key_id="op_ed_key_1",
        operator_id="op_tester_1",
        verification_key=ed_pub,
        algorithm="ed25519",
    )

    # 3. Bind peer UID/GID and grant mission
    current_uid = os.getuid()
    current_gid = os.getgid()
    grant_svc.set_peer_binding("op_tester_1", uid=current_uid, gid=current_gid, active=True)
    grant_svc.set_mission_grant("op_tester_1", subject_id="sub_tester_1", mission_id="mission_sec", active=True)

    # 4. Set up boundary with VerifiedKeyPrincipalResolver
    resolver = VerifiedKeyPrincipalResolver(operators=op_mgr, grants=grant_svc, key_store=key_store)
    replay_store = ControlReplayStore(db_path=db_file)
    boundary = ControlBoundary(
        key_resolver=key_store,
        principal_resolver=resolver,
        rbac=ControlRBACPolicy(),
        replay_store=replay_store,
    )

    signer = ControlSignerV1("op_ed_key_1", ed_priv)
    peer = PeerPrincipal(pid=os.getpid(), uid=current_uid, gid=current_gid)

    # 5. Authorize valid request
    req = _build_signed_request(signer, mission_id="mission_sec", subject_id="sub_tester_1")
    verified = boundary.authorize(req, peer)
    assert verified.principal.operator_id == "op_tester_1"
    assert verified.principal.role == OperatorRole.OPERATOR

    # 6. Revoke mission grant -> assert rejection
    grant_svc.set_mission_grant("op_tester_1", subject_id="sub_tester_1", mission_id="mission_sec", active=False)
    req2 = _build_signed_request(signer, mission_id="mission_sec", subject_id="sub_tester_1")
    with pytest.raises(NotAuthorizedControlRequest, match="mission_not_granted"):
        boundary.authorize(req2, peer)


def test_hardcoded_keys_rejected_in_production():
    """Verify that all legacy hardcoded test keys are rejected."""
    key_resolver = daemon.DaemonKeyResolver()
    for legacy_key in ("k_test", "key_test", "probe_key", "test_key", "daemon_root_key"):
        with pytest.raises(NotAuthorizedControlRequest):
            key_resolver.require_key(legacy_key, now=time.time())


def test_client_detects_tampered_response_signature():
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    codec = ControlProtocolCodec()
    verifier = DaemonResponseVerifier(trusted_keys={"daemon_key": DAEMON_SECRET})

    def mock_tampered_transport(req_bytes: bytes) -> bytes:
        req = codec.decode_request(req_bytes)
        res_dict = {
            "transaction_id": req.authorization.transaction_id,
            "participant_id": req.authorization.participant_id,
            "action": req.action.value,
            "resource_ref": "c2_daemon",
            "resource_revision": 1,
            "receipt_ref": "rcpt_100",
            "receipt_digest": hashlib.sha256(b"receipt_dig").hexdigest(),
            "daemon_instance_id": "daemon_inst_1",
            "result_payload_schema_id": req.payload_schema_id,
            "result_payload_digest": req.payload_digest,
            "result_payload_b64u": req.canonical_payload_b64u,
            "type": "receipt",
        }
        payload_bytes = canonical_json_bytes(res_dict)
        payload_b64u = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
        payload_digest = hashlib.sha256(payload_bytes).hexdigest()
        issued_at_ms = int(time.time() * 1000)

        signed_resp = SignedControlResponseV1(
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            daemon_instance_id="daemon_inst_1",
            daemon_generation="gen_1",
            request_digest=req.authorization.request_digest,
            request_nonce=req.authorization.nonce,
            response_type="receipt",
            response_payload_b64u=payload_b64u,
            response_digest=payload_digest,
            issued_at_ms=issued_at_ms,
            key_id="daemon_key",
            signature="f" * 64,  # Corrupted signature
        )
        return codec.encode_response(signed_resp)

    client = DefaultC2ControlClient(
        signer=signer,
        transport_handler=mock_tampered_transport,
        daemon_verifier=verifier,
    )
    with pytest.raises(C2ResponseVerificationError, match="daemon_signature_verification_failed"):
        client.ping(mission_id="m_1", subject_id="sub_1")


def test_client_detects_mismatched_response_nonce():
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    codec = ControlProtocolCodec()
    verifier = DaemonResponseVerifier(trusted_keys={"daemon_key": DAEMON_SECRET})

    def mock_mismatched_nonce_transport(req_bytes: bytes) -> bytes:
        req = codec.decode_request(req_bytes)
        res_dict = {
            "transaction_id": req.authorization.transaction_id,
            "participant_id": req.authorization.participant_id,
            "action": req.action.value,
            "resource_ref": "c2_daemon",
            "resource_revision": 1,
            "receipt_ref": "rcpt_100",
            "receipt_digest": hashlib.sha256(b"receipt_dig").hexdigest(),
            "daemon_instance_id": "daemon_inst_1",
            "result_payload_schema_id": req.payload_schema_id,
            "result_payload_digest": req.payload_digest,
            "result_payload_b64u": req.canonical_payload_b64u,
            "type": "receipt",
        }
        payload_bytes = canonical_json_bytes(res_dict)
        payload_b64u = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
        payload_digest = hashlib.sha256(payload_bytes).hexdigest()
        issued_at_ms = int(time.time() * 1000)

        envelope_dict = canonical_response_envelope_dict(
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            daemon_instance_id="daemon_inst_1",
            daemon_generation="gen_1",
            request_digest=req.authorization.request_digest,
            request_nonce="different_nonce_1234",
            response_type="receipt",
            response_payload_b64u=payload_b64u,
            response_digest=payload_digest,
            issued_at_ms=issued_at_ms,
            key_id="daemon_key",
        )
        sig = hmac.new(
            DAEMON_SECRET,
            b"OCTOPUS-C2-RESPONSE-V2\x00" + canonical_json_bytes(envelope_dict),
            hashlib.sha256,
        ).hexdigest()

        signed_resp = SignedControlResponseV1(
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            daemon_instance_id="daemon_inst_1",
            daemon_generation="gen_1",
            request_digest=req.authorization.request_digest,
            request_nonce="different_nonce_1234",
            response_type="receipt",
            response_payload_b64u=payload_b64u,
            response_digest=payload_digest,
            issued_at_ms=issued_at_ms,
            key_id="daemon_key",
            signature=sig,
        )
        return codec.encode_response(signed_resp)

    client = DefaultC2ControlClient(
        signer=signer,
        transport_handler=mock_mismatched_nonce_transport,
        daemon_verifier=verifier,
    )
    with pytest.raises(C2ResponseVerificationError, match="response_nonce_mismatch"):
        client.ping(mission_id="m_1", subject_id="sub_1")


def test_unsigned_response_rejected_by_client():
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    codec = ControlProtocolCodec()

    def mock_unsigned_transport(req_bytes: bytes) -> bytes:
        req = codec.decode_request(req_bytes)
        receipt = ParticipantControlReceiptV1(
            transaction_id=req.authorization.transaction_id,
            participant_id="c2_daemon",
            action=req.action,
            resource_ref="c2_daemon",
            resource_revision=1,
            receipt_ref="rcpt_1",
            receipt_digest=hashlib.sha256(b"dig").hexdigest(),
            daemon_instance_id="inst_1",
            result_payload_schema_id=req.payload_schema_id,
            result_payload_digest=req.payload_digest,
        )
        return codec.encode_response(receipt)

    verifier = DaemonResponseVerifier(trusted_keys={"daemon_key": DAEMON_SECRET})
    client = DefaultC2ControlClient(
        signer=signer,
        transport_handler=mock_unsigned_transport,
        daemon_verifier=verifier,
    )
    with pytest.raises(C2ResponseVerificationError, match="unsigned_daemon_response"):
        client.ping(mission_id="m_1", subject_id="sub_1")
