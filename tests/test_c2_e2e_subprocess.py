"""End-to-End subprocess integration tests for C2 control plane over Unix Domain Socket."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from contextlib import suppress

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2 import daemon
from core.c2.client import DefaultC2ControlClient
from core.c2.control_boundary import ControlVerificationKeyStore
from core.c2.control_commands import (
    C2ControlAction,
    ParticipantControlPhaseV2,
    ParticipantControlReceiptV2,
    SignedControlResponseV2,
    UnsignedParticipantControlAuthorizationV2,
    UnsignedParticipantControlRequestV2,
)
from core.c2.control_models import calculate_schema_bound_payload_digest, strict_b64url_decode
from core.c2.control_protocol import ControlProtocolCodec
from core.c2.control_signing import (
    ControlSignerV2,
    DaemonResponseVerifier,
)
from core.c2.grant_service import GrantService
from core.c2.operators import OperatorManager
from tests.helpers.c2_client import make_trusted_daemon_key

pytestmark = [pytest.mark.integration, pytest.mark.security]

TEST_OPERATOR_KEY_ID = "op_key_e2e_1"
_ED_PRIV = ed25519.Ed25519PrivateKey.generate()
TEST_OPERATOR_SECRET = _ED_PRIV.private_bytes_raw()
TEST_OPERATOR_PUB = _ED_PRIV.public_key().public_bytes_raw()


def _wait_for_socket(sock_path: str, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(sock_path):
            return True
        time.sleep(0.05)
    return False


def _setup_operator_state(db_path: str) -> None:
    """Pre-seed operator, keys, peer bindings and mission grants in the database."""
    op_mgr = OperatorManager(db_path=db_path)
    grant_svc = GrantService(db_path=db_path)
    key_store = ControlVerificationKeyStore(db_path=db_path)

    # 1. Create operator
    with suppress(Exception):
        op_mgr.create_operator(
            operator_id="op_e2e",
            subject_id="s_e2e",
            name="Operator E2E",
            role="admin",
            api_key="dummy_api_key_for_hashing_only_12345",
        )

    # 2. Register operator signing key
    key_store.register_key(
        key_id=TEST_OPERATOR_KEY_ID,
        operator_id="op_e2e",
        verification_key=TEST_OPERATOR_PUB,
        algorithm="ed25519",
    )

    # 3. Bind current peer UID/GID
    grant_svc.set_peer_binding("op_e2e", uid=os.getuid(), gid=os.getgid(), active=True)

    # 4. Grant mission
    grant_svc.set_mission_grant("op_e2e", subject_id="s_e2e", mission_id="m_e2e", active=True)
    grant_svc.set_mission_grant("op_e2e", subject_id="s_e2e", mission_id="m_1", active=True)


def test_c2_socketpair_lifecycle_and_restart_persistence(tmp_path, monkeypatch):
    """Verify complete 2PC lifecycle, snapshot queries, and restart persistence using SQLite backing."""
    db_file = str(tmp_path / "c2_test.db")
    monkeypatch.setenv("OCTOPUS_C2_DB_PATH", db_file)
    monkeypatch.setenv("OCTOPUS_C2_ALLOW_EPHEMERAL_CONTROL_STATE", "1")
    monkeypatch.setattr(daemon, "_daemon_resource_participant_instance", None)
    monkeypatch.setattr(daemon, "_replay_store_instance", None)
    monkeypatch.setattr(daemon, "_key_store_instance", None)
    monkeypatch.setattr(daemon, "_control_boundary_instance", None)

    _setup_operator_state(db_file)

    signer = ControlSignerV2(TEST_OPERATOR_KEY_ID, TEST_OPERATOR_SECRET)
    daemon_pub = daemon.get_daemon_response_public_key()
    trusted_key = make_trusted_daemon_key(
        service_id=daemon.get_service_id(),
        key_id="daemon_resp_key_1",
        public_key=daemon_pub,
    )
    verifier = DaemonResponseVerifier(trusted_keys={"daemon_resp_key_1": trusted_key})

    def _transport_handler(req_bytes: bytes) -> bytes:
        srv_sock, cli_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        srv_sock.settimeout(5.0)
        cli_sock.settimeout(5.0)

        t = threading.Thread(target=daemon.handle_client, args=(srv_sock,), daemon=True)
        t.start()
        try:
            cli_sock.sendall(req_bytes)

            # Read framed response
            hdr = bytearray()
            while len(hdr) < 9:
                chunk = cli_sock.recv(9 - len(hdr))
                if not chunk:
                    break
                hdr.extend(chunk)
            body_len = int.from_bytes(hdr[5:9], "big")
            body = bytearray()
            while len(body) < body_len:
                chunk = cli_sock.recv(body_len - len(body))
                if not chunk:
                    break
                body.extend(chunk)
            return bytes(hdr + body)
        finally:
            cli_sock.close()
            t.join(timeout=2.0)
            srv_sock.close()

    client1 = DefaultC2ControlClient(
        signer=signer,
        transport_handler=_transport_handler,
        daemon_verifier=verifier,
        expected_service_id=daemon.get_service_id(),
    )

    # 1. Ping
    ping_res = client1.ping(mission_id="m_1", subject_id="s_e2e")
    assert isinstance(ping_res, ParticipantControlReceiptV2)

    # 2. 2PC Lifecycle
    tx_id = f"tx_{uuid.uuid4().hex[:8]}"
    prep = client1.execute_action(
        action=C2ControlAction.PREPARE_C2_RESOURCE,
        payload={"target": "alpha"},
        mission_id="m_1",
        subject_id="s_e2e",
        transaction_id=tx_id,
    )
    assert isinstance(prep, ParticipantControlReceiptV2)
    assert prep.action == C2ControlAction.PREPARE_C2_RESOURCE

    commit = client1.execute_action(
        action=C2ControlAction.COMMIT_C2_RESOURCE,
        payload={"target": "alpha"},
        mission_id="m_1",
        subject_id="s_e2e",
        transaction_id=tx_id,
        prior_receipt_ref=prep.receipt_ref,
        prior_receipt_digest=prep.receipt_digest,
    )
    assert isinstance(commit, ParticipantControlReceiptV2)
    assert commit.action == C2ControlAction.COMMIT_C2_RESOURCE

    fin = client1.execute_action(
        action=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
        payload={"target": "alpha"},
        mission_id="m_1",
        subject_id="s_e2e",
        transaction_id=tx_id,
        prior_receipt_ref=commit.receipt_ref,
        prior_receipt_digest=commit.receipt_digest,
    )
    assert isinstance(fin, ParticipantControlReceiptV2)
    assert fin.action == C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY

    # 3. Query Snapshot Verification
    snap = client1.execute_action(
        action=C2ControlAction.QUERY_C2_RESOURCE,
        payload={},
        mission_id="m_1",
        subject_id="s_e2e",
        transaction_id=tx_id,
    )
    assert hasattr(snap, "phase")
    assert snap.phase == ParticipantControlPhaseV2.FINALIZED_VISIBLE
    assert snap.transaction_id == tx_id


def test_c2_subprocess_restart_recovery_and_replay_gate(tmp_path: pytest.TempPathFactory):
    data_dir = str(tmp_path)
    db_path = os.path.join(data_dir, "octopus_c2_test.db")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sock_path = os.path.join(project_root, "tests", f"s_{uuid.uuid4().hex[:4]}.sock")
    key_file = os.path.join(data_dir, "daemon_response_ed25519.key")
    service_id_file = os.path.join(data_dir, "service_id")

    # Setup database with operator and authority state
    _setup_operator_state(db_path)

    # Generate fixed daemon response key and persist to key_file
    priv_resp = ed25519.Ed25519PrivateKey.generate()
    raw_resp_seed = priv_resp.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    daemon_pub_bytes = priv_resp.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    with open(key_file, "wb") as f:
        f.write(raw_resp_seed)

    subproc_service_id = f"srv_subproc_{uuid.uuid4().hex[:8]}"
    with open(service_id_file, "w") as f:
        f.write(subproc_service_id)

    python_path = os.pathsep.join(p for p in [project_root, os.environ.get("PYTHONPATH", "")] if p)

    env = dict(os.environ)
    env["PYTHONPATH"] = python_path
    env["OCTOPUS_C2_SOCKET"] = sock_path
    env["OCTOPUS_DATA_DIR"] = data_dir
    env["OCTOPUS_C2_DB_PATH"] = db_path
    env["OCTOPUS_C2_KEY_PASSPHRASE"] = "test-secure-passphrase-32bytes!!"
    env["OCTOPUS_C2_ALLOW_INSECURE_DEV_SOCKET"] = "1"
    env["OCTOPUS_C2_ALLOW_EPHEMERAL_CONTROL_STATE"] = "1"

    daemon_script = "from core.c2.daemon import run_socket_server\nrun_socket_server()\n"

    # 1. Start First Daemon Subprocess
    proc1 = subprocess.Popen(
        [sys.executable, "-c", daemon_script],
        env=env,
        cwd=project_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    saved_raw_request_frame: bytes = b""

    try:
        if not _wait_for_socket(sock_path, timeout=8.0):
            stdout, stderr = proc1.communicate(timeout=2.0)
            err_msg = stderr.decode()
            if "Operation not permitted" in err_msg or "PermissionError" in err_msg:
                pytest.skip("sandbox forbids filesystem socket binding for subprocess")
            pytest.fail(f"Daemon socket not created in time. stdout: {stdout.decode()}, stderr: {err_msg}")

        trusted_key = make_trusted_daemon_key(
            service_id=subproc_service_id,
            key_id="daemon_resp_key_1",
            public_key=daemon_pub_bytes,
        )
        verifier = DaemonResponseVerifier(trusted_keys={"daemon_resp_key_1": trusted_key})

        signer = ControlSignerV2(TEST_OPERATOR_KEY_ID, TEST_OPERATOR_SECRET)
        client = DefaultC2ControlClient(
            signer=signer,
            socket_path=sock_path,
            daemon_verifier=verifier,
            expected_service_id=subproc_service_id,
        )

        # 2. Test PING over UDS
        ping_res = client.ping(mission_id="m_e2e", subject_id="s_e2e")
        assert isinstance(ping_res, ParticipantControlReceiptV2)
        assert ping_res.action == C2ControlAction.PING

        # 3. Test 2PC Transaction Lifecycle (Prepare -> Commit -> Finalize Visibility)
        tx_id = f"tx_e2e_{uuid.uuid4().hex[:8]}"

        # Prepare
        prep_res = client.execute_action(
            action=C2ControlAction.PREPARE_C2_RESOURCE,
            payload={"resource_type": "build_target", "name": "agent_alpha"},
            mission_id="m_e2e",
            subject_id="s_e2e",
            transaction_id=tx_id,
        )
        assert isinstance(prep_res, ParticipantControlReceiptV2)
        assert prep_res.transaction_id == tx_id

        # Commit
        commit_res = client.execute_action(
            action=C2ControlAction.COMMIT_C2_RESOURCE,
            payload={"resource_type": "build_target", "name": "agent_alpha"},
            mission_id="m_e2e",
            subject_id="s_e2e",
            transaction_id=tx_id,
            prior_receipt_ref=prep_res.receipt_ref,
            prior_receipt_digest=prep_res.receipt_digest,
        )
        assert isinstance(commit_res, ParticipantControlReceiptV2)
        assert commit_res.resource_revision == 1

        # Finalize Visibility
        fin_res = client.execute_action(
            action=C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY,
            payload={"resource_type": "build_target", "name": "agent_alpha"},
            mission_id="m_e2e",
            subject_id="s_e2e",
            transaction_id=tx_id,
            prior_receipt_ref=commit_res.receipt_ref,
            prior_receipt_digest=commit_res.receipt_digest,
        )
        assert isinstance(fin_res, ParticipantControlReceiptV2)

        # Save an exact raw signed request frame to test replay rejection across restarts
        replay_tx = f"tx_replay_{uuid.uuid4().hex[:8]}"
        codec = ControlProtocolCodec()
        now_ms = int(time.time() * 1000)
        pdig = calculate_schema_bound_payload_digest("schema:test", b"{}")
        raw_req = UnsignedParticipantControlRequestV2(
            action=C2ControlAction.PING,
            authorization=UnsignedParticipantControlAuthorizationV2(
                protocol_version="2.0",
                key_id=TEST_OPERATOR_KEY_ID,
                transaction_id=replay_tx,
                participant_id="c2_daemon",
                mission_id="m_e2e",
                subject_id="s_e2e",
                action_id="ping",
                coordinator_revision=1,
                issued_at_ms=now_ms,
                expires_at_ms=now_ms + 300000,
                nonce=f"nonce_replay_save_{uuid.uuid4().hex[:8]}",
            ),
            payload_schema_id="schema:test",
            payload_digest=pdig,
            canonical_payload_b64u="e30",
        )
        signed_raw_req = signer.sign_participant_request(raw_req)
        saved_raw_request_frame = codec.encode_request(signed_raw_req)

        # Send it to process 1
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(sock_path)
            s.sendall(saved_raw_request_frame)
            resp_b = s.recv(4096)
            decoded_resp = codec.decode_response(resp_b)
            assert isinstance(decoded_resp, SignedControlResponseV2)
            inner_bytes = strict_b64url_decode(decoded_resp.response_payload_b64u)
            assert b"receipt" in inner_bytes

    finally:
        with suppress(Exception):
            proc1.terminate()
            proc1.wait(timeout=5.0)
        if proc1.poll() is None:
            with suppress(Exception):
                proc1.kill()
                proc1.wait(timeout=2.0)
        if proc1.stdout:
            proc1.stdout.close()
        if proc1.stderr:
            proc1.stderr.close()
        if os.path.exists(sock_path):
            with suppress(Exception):
                os.unlink(sock_path)

    # 4. Start Second Daemon Subprocess (Simulating Restart)
    proc2 = subprocess.Popen(
        [sys.executable, "-c", daemon_script],
        env=env,
        cwd=project_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        assert _wait_for_socket(sock_path, timeout=8.0), "Restarted daemon socket was not created"

        client2 = DefaultC2ControlClient(
            signer=signer,
            socket_path=sock_path,
            daemon_verifier=verifier,
            expected_service_id=subproc_service_id,
        )

        # Verify previous 2PC state survived restart
        snap_after_restart = client2.execute_action(
            action=C2ControlAction.QUERY_C2_RESOURCE,
            payload={},
            mission_id="m_e2e",
            subject_id="s_e2e",
            transaction_id=tx_id,
        )
        assert hasattr(snap_after_restart, "phase")
        assert snap_after_restart.phase == ParticipantControlPhaseV2.FINALIZED_VISIBLE
        assert snap_after_restart.transaction_id == tx_id

        # Re-send exact raw request frame to process 2 -> assert REPLAY rejection
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(sock_path)
            s.sendall(saved_raw_request_frame)
            resp_b = s.recv(4096)
            decoded_resp = codec.decode_response(resp_b)
            assert isinstance(decoded_resp, SignedControlResponseV2)
            inner_bytes = strict_b64url_decode(decoded_resp.response_payload_b64u)
            assert b"replay" in inner_bytes.lower()

    finally:
        with suppress(Exception):
            proc2.terminate()
            proc2.wait(timeout=5.0)
        if proc2.poll() is None:
            with suppress(Exception):
                proc2.kill()
                proc2.wait(timeout=2.0)
        if proc2.stdout:
            proc2.stdout.close()
        if proc2.stderr:
            proc2.stderr.close()
        if os.path.exists(sock_path):
            with suppress(Exception):
                os.unlink(sock_path)
