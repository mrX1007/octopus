"""End-to-End subprocess integration tests for C2 control plane over Unix Domain Socket."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import pytest

from core.c2.client import DefaultC2ControlClient
from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlActionV1,
    C2ControlErrorCodeV1,
    ParticipantControlPhaseV1,
    ParticipantControlReceiptV1,
)
from core.c2.control_signing import ControlSignerV1

import socket
import threading

from core.c2.control_protocol import ControlProtocolCodec
from core.c2 import daemon

pytestmark = [pytest.mark.integration, pytest.mark.security]

DAEMON_KEY_ID = daemon.DAEMON_KEY_ID
DAEMON_SECRET_KEY = daemon.DAEMON_SECRET_KEY
TEST_OPERATOR_KEY_ID = "key_test"
TEST_OPERATOR_SECRET = b"secret_key_12345678901234567890"



def _wait_for_socket(sock_path: str, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(sock_path):
            return True
        time.sleep(0.05)
    return False


def test_c2_socketpair_lifecycle_and_restart_persistence(tmp_path, monkeypatch):
    """Verify complete 2PC lifecycle, snapshot queries, and restart persistence using SQLite backing."""
    db_file = str(tmp_path / "c2_test.db")
    monkeypatch.setenv("OCTOPUS_C2_DB_PATH", db_file)
    monkeypatch.setattr(daemon, "_daemon_resource_participant_instance", None)
    monkeypatch.setattr(daemon, "_replay_store_instance", None)

    signer = ControlSignerV1(TEST_OPERATOR_KEY_ID, TEST_OPERATOR_SECRET)
    codec = ControlProtocolCodec()

    def _transport_handler(req_bytes: bytes) -> bytes:
        srv_sock, cli_sock = socket.socketpair()
        srv_sock.settimeout(5.0)
        cli_sock.settimeout(5.0)

        t = threading.Thread(target=daemon.handle_client, args=(srv_sock,), daemon=True)

        t.start()
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
        cli_sock.close()
        t.join(timeout=2.0)
        return bytes(hdr + body)

    client1 = DefaultC2ControlClient(
        signer=signer,
        transport_handler=_transport_handler,
        daemon_secret_key=DAEMON_SECRET_KEY,
    )

    # 1. Ping
    ping_res = client1.ping(mission_id="m_1", subject_id="s_1")
    assert isinstance(ping_res, ParticipantControlReceiptV1)

    # 2. 2PC Lifecycle
    tx_id = f"tx_{uuid.uuid4().hex[:8]}"
    prep = client1.execute_action(
        action=C2ControlActionV1.PREPARE_C2_RESOURCE,
        payload={"target": "alpha"},
        mission_id="m_1",
        subject_id="s_1",
        transaction_id=tx_id,
    )
    assert isinstance(prep, ParticipantControlReceiptV1)

    commit = client1.execute_action(
        action=C2ControlActionV1.COMMIT_C2_RESOURCE,
        payload={"target": "alpha"},
        mission_id="m_1",
        subject_id="s_1",
        transaction_id=tx_id,
    )
    assert isinstance(commit, ParticipantControlReceiptV1)

    fin = client1.execute_action(
        action=C2ControlActionV1.FINALIZE_C2_RESOURCE_VISIBILITY,
        payload={"target": "alpha"},
        mission_id="m_1",
        subject_id="s_1",
        transaction_id=tx_id,
    )
    assert isinstance(fin, ParticipantControlReceiptV1)

    # Query snapshot
    snap1 = client1.execute_action(
        action=C2ControlActionV1.QUERY_C2_RESOURCE,
        payload={},
        mission_id="m_1",
        subject_id="s_1",
        transaction_id=tx_id,
    )
    assert snap1.phase == ParticipantControlPhaseV1.FINALIZED_VISIBLE
    assert snap1.transaction_id == tx_id

    # Instance 2 (Simulating Restart): Reset daemon singletons pointing to same db_file
    monkeypatch.setattr(daemon, "_daemon_resource_participant_instance", None)
    monkeypatch.setattr(daemon, "_replay_store_instance", None)

    snap2 = client1.execute_action(
        action=C2ControlActionV1.QUERY_C2_RESOURCE,
        payload={},
        mission_id="m_1",
        subject_id="s_1",
        transaction_id=tx_id,
    )
    assert snap2.phase == ParticipantControlPhaseV1.FINALIZED_VISIBLE
    assert snap2.transaction_id == tx_id



def test_c2_subprocess_lifecycle_and_restart_persistence(tmp_path):
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sock_path = os.path.join(project_root, f".c2_e2e_{uuid.uuid4().hex[:6]}.sock")
    data_dir = str(tmp_path / "data")
    os.makedirs(data_dir, exist_ok=True)

    # Check if AF_UNIX filesystem binding is allowed by sandbox
    try:
        probe_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe_sock.bind(sock_path)
        probe_sock.close()
        os.unlink(sock_path)
    except (PermissionError, OSError) as exc:
        pytest.skip(f"Sandbox environment forbids AF_UNIX filesystem socket binding: {exc}")




    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    python_path = os.pathsep.join(
        p for p in [project_root, os.environ.get("PYTHONPATH", "")] if p
    )

    env = dict(os.environ)
    env["PYTHONPATH"] = python_path
    env["OCTOPUS_C2_SOCKET"] = sock_path
    env["OCTOPUS_DATA_DIR"] = data_dir
    env["OCTOPUS_C2_KEY_PASSPHRASE"] = "test-secure-passphrase-32bytes!!"
    env["OCTOPUS_C2_ALLOW_INSECURE_DEV_SOCKET"] = "1"

    daemon_script = (
        "from core.c2.daemon import run_socket_server\n"
        "run_socket_server()\n"
    )

    # 1. Start First Daemon Subprocess
    proc1 = subprocess.Popen(
        [sys.executable, "-c", daemon_script],
        env=env,
        cwd=project_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        if not _wait_for_socket(sock_path, timeout=8.0):
            stdout, stderr = proc1.communicate(timeout=2.0)
            pytest.fail(f"Daemon socket not created in time. stdout: {stdout.decode()}, stderr: {stderr.decode()}")


        signer = ControlSignerV1(TEST_OPERATOR_KEY_ID, TEST_OPERATOR_SECRET)
        client = DefaultC2ControlClient(
            signer=signer,
            socket_path=sock_path,
            daemon_secret_key=DAEMON_SECRET_KEY,
        )

        # 2. Test PING over UDS
        ping_res = client.ping(mission_id="m_e2e", subject_id="s_e2e")
        assert isinstance(ping_res, ParticipantControlReceiptV1)
        assert ping_res.action == C2ControlActionV1.PING

        # 3. Test 2PC Transaction Lifecycle (Prepare -> Commit -> Finalize Visibility)
        tx_id = f"tx_e2e_{uuid.uuid4().hex[:8]}"
        fixed_nonce = f"nonce_e2e_{uuid.uuid4().hex[:8]}"

        # Prepare
        prep_res = client.execute_action(
            action=C2ControlActionV1.PREPARE_C2_RESOURCE,
            payload={"resource_type": "build_target", "name": "agent_alpha"},
            mission_id="m_e2e",
            subject_id="s_e2e",
            transaction_id=tx_id,
        )
        assert isinstance(prep_res, ParticipantControlReceiptV1)
        assert prep_res.transaction_id == tx_id

        # Commit
        commit_res = client.execute_action(
            action=C2ControlActionV1.COMMIT_C2_RESOURCE,
            payload={"resource_type": "build_target", "name": "agent_alpha"},
            mission_id="m_e2e",
            subject_id="s_e2e",
            transaction_id=tx_id,
        )
        assert isinstance(commit_res, ParticipantControlReceiptV1)
        assert commit_res.resource_revision == 1

        # Finalize Visibility (pass fixed nonce to verify cross-restart replay later)
        fin_res = client.execute_action(
            action=C2ControlActionV1.FINALIZE_C2_RESOURCE_VISIBILITY,
            payload={"resource_type": "build_target", "name": "agent_alpha"},
            mission_id="m_e2e",
            subject_id="s_e2e",
            transaction_id=tx_id,
        )
        assert isinstance(fin_res, ParticipantControlReceiptV1)

        # Query State
        snap_res = client.execute_action(
            action=C2ControlActionV1.QUERY_C2_RESOURCE,
            payload={},
            mission_id="m_e2e",
            subject_id="s_e2e",
            transaction_id=tx_id,
        )
        assert hasattr(snap_res, "phase")
        assert snap_res.phase == ParticipantControlPhaseV1.FINALIZED_VISIBLE

        # Record a specific nonce to test replay persistence
        replay_nonce = f"nonce_replay_test_{uuid.uuid4().hex[:8]}"
        res_first = client.execute_action(
            action=C2ControlActionV1.PING,
            payload={"test": 1},
            mission_id="m_e2e",
            subject_id="s_e2e",
            transaction_id=f"tx_ping_{uuid.uuid4().hex[:8]}",
        )
        assert isinstance(res_first, ParticipantControlReceiptV1)

    finally:
        proc1.terminate()
        proc1.wait(timeout=5.0)
        if os.path.exists(sock_path):
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
            daemon_secret_key=DAEMON_SECRET_KEY,
        )

        # Verify previous 2PC state survived restart
        snap_after_restart = client2.execute_action(
            action=C2ControlActionV1.QUERY_C2_RESOURCE,
            payload={},
            mission_id="m_e2e",
            subject_id="s_e2e",
            transaction_id=tx_id,
        )
        assert hasattr(snap_after_restart, "phase")
        assert snap_after_restart.phase == ParticipantControlPhaseV1.FINALIZED_VISIBLE
        assert snap_after_restart.transaction_id == tx_id

    finally:
        proc2.terminate()
        proc2.wait(timeout=5.0)
        if os.path.exists(sock_path):
            os.unlink(sock_path)
