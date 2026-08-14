"""Comprehensive security test suite for C2 Control Boundary (§14.4, §14.5, §14.6)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import tempfile
import time
import uuid
import pytest

from core.c2.control_auth import AuthenticatedControlPrincipal, OperatorRole, PeerPrincipal
from core.c2.control_boundary import (
    ControlBoundary,
    ControlBoundaryError,
    ControlReplayStore,
    ExpiredControlRequest,
    ForbiddenControlRequest,
    MalformedControlRequest,
    NotAuthorizedControlRequest,
    ReplayedControlRequest,
    StaticControlKeyResolver,
)
from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlActionV1,
    C2ControlErrorCodeV1,
    ParticipantControlAuthorizationV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
    SignedControlResponseV1,
)
from core.c2.control_models import (
    calculate_canonical_request_digest,
    calculate_payload_digest,
    canonical_json_bytes,
    canonical_response_envelope_dict,
    strict_b64url_decode,
)
from core.c2.control_protocol import ControlProtocolCodec
from core.c2.control_rbac import ControlRBACPolicy
from core.c2.control_signing import ControlSignerV1, ControlVerifierV1
from core.c2.client import (
    C2ResponseVerificationError,
    DefaultC2ControlClient,
)

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
    key_resolver = StaticControlKeyResolver({
        "key_a": SECRET_KEY_A,
        "key_b": SECRET_KEY_B,
    })
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
    principal_resolver = StaticPrincipalResolver({
        "key_a": admin_principal,
        "key_b": readonly_principal,
    })
    replay_store = ControlReplayStore(db_path=db_path)
    rbac_policy = ControlRBACPolicy()
    boundary = ControlBoundary(
        key_resolver=key_resolver,
        principal_resolver=principal_resolver,
        replay_store=replay_store,
        rbac_policy=rbac_policy,
    )
    return boundary, replay_store, peer_dummy


def _build_request(
    key_id: str,
    secret: bytes,
    action: C2ControlActionV1 = C2ControlActionV1.PING,
    payload_dict: dict | None = None,
    ttl_seconds: float = 60.0,
    tx_id: str | None = None,
    nonce: str | None = None,
) -> ParticipantControlRequestV1:
    signer = ControlSignerV1(key_id, secret)
    payload_bytes = canonical_json_bytes(payload_dict or {})
    payload_b64u = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
    payload_dig = calculate_payload_digest(payload_bytes)
    t_id = tx_id or f"tx_{uuid.uuid4().hex[:8]}"
    n = nonce or uuid.uuid4().hex
    auth = ParticipantControlAuthorizationV1(
        key_id=key_id,
        transaction_id=t_id,
        participant_id="part_1",
        mission_id="m_1",
        subject_id="sub_1",
        action_id=action.value,
        coordinator_revision=1,
        request_digest="init_digest",
        expires_at=time.time() + ttl_seconds,
        nonce=n,
        signature="",
    )
    req = ParticipantControlRequestV1(
        action=action,
        authorization=auth,
        payload_schema_id="schema:test",
        payload_digest=payload_dig,
        canonical_payload_b64u=payload_b64u,
    )
    return signer.sign_participant_request(req)


def test_boundary_authorizes_valid_request():
    boundary, _, peer = _make_fixture()
    req = _build_request("key_a", SECRET_KEY_A, action=C2ControlActionV1.PING)
    verified = boundary.authorize(req, peer)
    assert verified.principal.operator_id == "op_admin"
    assert verified.principal.role == OperatorRole.ADMIN


def test_boundary_rejects_unknown_key_id():
    boundary, _, peer = _make_fixture()
    req = _build_request("unknown_key", b"fake_secret_12345678901234567890", action=C2ControlActionV1.PING)
    with pytest.raises(NotAuthorizedControlRequest, match="unknown_key_id"):
        boundary.authorize(req, peer)


def test_boundary_rejects_corrupted_signature():
    boundary, _, peer = _make_fixture()
    req = _build_request("key_a", SECRET_KEY_A, action=C2ControlActionV1.PING)
    # Corrupt signature
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
        signature="a" * 64,
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


def test_boundary_rejects_tampered_payload():
    boundary, _, peer = _make_fixture()
    req = _build_request("key_a", SECRET_KEY_A, action=C2ControlActionV1.PING, payload_dict={"hello": "world"})
    # Tamper payload bytes while keeping signature/digest
    tampered_bytes = canonical_json_bytes({"hello": "tampered"})
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


def test_boundary_rejects_tampered_action():
    boundary, _, peer = _make_fixture()
    req = _build_request("key_a", SECRET_KEY_A, action=C2ControlActionV1.PING)
    # Tamper outer action
    tampered_req = ParticipantControlRequestV1(
        action=C2ControlActionV1.READINESS,
        authorization=req.authorization,
        payload_schema_id=req.payload_schema_id,
        payload_digest=req.payload_digest,
        canonical_payload_b64u=req.canonical_payload_b64u,
    )
    with pytest.raises(NotAuthorizedControlRequest, match="action_mismatch"):
        boundary.authorize(tampered_req, peer)


def test_boundary_rejects_expired_request():
    boundary, _, peer = _make_fixture()
    req = _build_request("key_a", SECRET_KEY_A, action=C2ControlActionV1.PING, ttl_seconds=-10.0)
    with pytest.raises(ExpiredControlRequest, match="authorization_expired"):
        boundary.authorize(req, peer)


def test_boundary_rejects_replayed_nonce():
    boundary, _, peer = _make_fixture()
    fixed_nonce = "nonce_fixed_12345678"
    req1 = _build_request("key_a", SECRET_KEY_A, action=C2ControlActionV1.PING, nonce=fixed_nonce)
    req2 = _build_request("key_a", SECRET_KEY_A, action=C2ControlActionV1.PING, nonce=fixed_nonce)

    # First succeeds
    verified = boundary.authorize(req1, peer)
    assert verified is not None

    # Second fails with ReplayedControlRequest
    with pytest.raises(ReplayedControlRequest, match="nonce_replayed"):
        boundary.authorize(req2, peer)


def test_boundary_rejects_insufficient_role_mutation():
    boundary, _, peer = _make_fixture()
    # key_b has READONLY role
    req = _build_request("key_b", SECRET_KEY_B, action=C2ControlActionV1.PREPARE_C2_RESOURCE)
    with pytest.raises(ForbiddenControlRequest, match="rbac_denied"):
        boundary.authorize(req, peer)



def test_replay_store_persistence_over_restart():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = os.path.join(tmpdir, "replay.db")
        store1 = ControlReplayStore(db_path=db_file)
        store1.consume_once(
            key_id="k1",
            nonce="nonce_persistent",
            request_digest="dig1",
            subject_id="s1",
            mission_id="m1",
            expires_at_ms=int((time.time() + 300) * 1000),
            created_at_ms=int(time.time() * 1000),
        )

        # Simulate restart: open new store instance against same SQLite file
        store2 = ControlReplayStore(db_path=db_file)
        with pytest.raises(ReplayedControlRequest):
            store2.consume_once(
                key_id="k1",
                nonce="nonce_persistent",
                request_digest="dig1",
                subject_id="s1",
                mission_id="m1",
                expires_at_ms=int((time.time() + 300) * 1000),
                created_at_ms=int(time.time() * 1000),
            )


def test_client_verifies_valid_signed_response_envelope():
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    codec = ControlProtocolCodec()

    def mock_transport(req_bytes: bytes) -> bytes:
        req = codec.decode_request(req_bytes)
        receipt = ParticipantControlReceiptV1(
            transaction_id=req.authorization.transaction_id,
            participant_id=req.authorization.participant_id,
            action=req.action,
            resource_ref="c2_daemon",
            resource_revision=1,
            receipt_ref="rcpt_100",
            receipt_digest=hashlib.sha256(b"receipt_dig").hexdigest(),
            daemon_instance_id="daemon_inst_1",
            result_payload_schema_id=req.payload_schema_id,
            result_payload_digest=req.payload_digest,
            result_payload_b64u=req.canonical_payload_b64u,
        )
        # Sign response envelope with DAEMON_SECRET
        res_dict = {
            "transaction_id": receipt.transaction_id,
            "participant_id": receipt.participant_id,
            "action": receipt.action.value,
            "resource_ref": receipt.resource_ref,
            "resource_revision": receipt.resource_revision,
            "receipt_ref": receipt.receipt_ref,
            "receipt_digest": receipt.receipt_digest,
            "daemon_instance_id": receipt.daemon_instance_id,
            "result_payload_schema_id": receipt.result_payload_schema_id,
            "result_payload_digest": receipt.result_payload_digest,
            "result_payload_b64u": receipt.result_payload_b64u,
            "type": "receipt",
        }
        payload_bytes = canonical_json_bytes(res_dict)
        payload_b64u = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
        payload_digest = hashlib.sha256(payload_bytes).hexdigest()
        issued_at_ms = int(time.time() * 1000)

        envelope_dict = canonical_response_envelope_dict(
            protocol_version="1.0",
            daemon_instance_id="daemon_inst_1",
            daemon_generation="gen_1",
            request_digest=req.authorization.request_digest,
            request_nonce=req.authorization.nonce,
            response_type="receipt",
            response_payload_b64u=payload_b64u,
            response_digest=payload_digest,
            issued_at_ms=issued_at_ms,
            key_id="daemon_key",
        )
        sig = hmac.new(
            DAEMON_SECRET,
            b"OCTOPUS-C2-RESPONSE-V1\x00" + canonical_json_bytes(envelope_dict),
            hashlib.sha256,
        ).hexdigest()

        signed_resp = SignedControlResponseV1(
            protocol_version="1.0",
            daemon_instance_id="daemon_inst_1",
            daemon_generation="gen_1",
            request_digest=req.authorization.request_digest,
            request_nonce=req.authorization.nonce,
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
        transport_handler=mock_transport,
        daemon_secret_key=DAEMON_SECRET,
    )
    res = client.ping(mission_id="m_1", subject_id="sub_1")
    assert isinstance(res, ParticipantControlReceiptV1)
    assert res.receipt_ref == "rcpt_100"


def test_client_detects_tampered_response_signature():
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    codec = ControlProtocolCodec()

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
            protocol_version="1.0",
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
        daemon_secret_key=DAEMON_SECRET,
    )
    with pytest.raises(C2ResponseVerificationError, match="invalid_daemon_response_signature"):
        client.ping(mission_id="m_1", subject_id="sub_1")


def test_client_detects_mismatched_response_nonce():
    signer = ControlSignerV1("key_a", SECRET_KEY_A)
    codec = ControlProtocolCodec()

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
            protocol_version="1.0",
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
            b"OCTOPUS-C2-RESPONSE-V1\x00" + canonical_json_bytes(envelope_dict),
            hashlib.sha256,
        ).hexdigest()

        signed_resp = SignedControlResponseV1(
            protocol_version="1.0",
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
        daemon_secret_key=DAEMON_SECRET,
    )
    with pytest.raises(C2ResponseVerificationError, match="response_nonce_mismatch"):
        client.ping(mission_id="m_1", subject_id="sub_1")
